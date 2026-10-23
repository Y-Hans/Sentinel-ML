"""
Ablation Study for Sentinel Messages V4.3 Candidate D.
Evaluates:
A. Structural only (19 dims)
B. Word TF-IDF only (1500 dims)
C. Char/subword only (2500 dims)
D. Structural + Word (1519 dims)
E. Structural + Char (2519 dims)
F. Word + Char (4000 dims)
G. Full Candidate D (4019 dims)
"""
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

import pickle
import json
import time
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(ROOT / "messages_v4_3/evaluation"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from eval_suite import read_jsonl, LABELS
from candidate_d_v4_3 import extract_structural_signals

def run_ablation_study():
    train_path = ROOT / "messages_v4_3/data/train_v4_3.jsonl"
    print(f"Loading training data from {train_path}...", flush=True)
    train_rows = read_jsonl(train_path)
    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)

    print("Extracting feature components for all 19,672 training rows...", flush=True)
    t0 = time.time()
    word_vec = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), sublinear_tf=True)
    char_vec = TfidfVectorizer(max_features=2500, analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)

    X_word_train = word_vec.fit_transform(train_texts).toarray().astype(np.float32)
    X_char_train = char_vec.fit_transform(train_texts).toarray().astype(np.float32)
    X_struct_train = np.asarray([extract_structural_signals(t) for t in train_texts], dtype=np.float32)
    print(f"Features extracted in {time.time()-t0:.1f}s", flush=True)

    # Load evaluation slices
    eval_slices = {
        "Test Split": ROOT / "data/processed/test.jsonl",
        "OOD Split": ROOT / "data/processed/ood.jsonl",
        "Hinglish Robustness": ROOT.parent / "7sep_messages_v3/data/bench_hinglish_robustness.jsonl",
        "Semantic Pairs": ROOT.parent / "7sep_messages_v3/data/bench_adversarial_semantic_pairs.jsonl",
        "Institutional": ROOT / "data/benchmarks/slice_institutional_partnerships.jsonl",
        "Sentinel Replay": ROOT.parent / "7sep_messages_v3/data/bench_sentinel_replay.jsonl",
    }
    slice_data = {}
    for sname, spath in eval_slices.items():
        rows = read_jsonl(spath)
        texts = [r.get("raw_text", "") for r in rows]
        y_true = np.array([LABELS.get(r.get("security_label"), 0) for r in rows], dtype=np.int32)
        X_w = word_vec.transform(texts).toarray().astype(np.float32)
        X_c = char_vec.transform(texts).toarray().astype(np.float32)
        X_s = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        slice_data[sname] = {
            "rows": rows, "y_true": y_true,
            "X_word": X_w, "X_char": X_c, "X_struct": X_s
        }

    # Load Val for threshold selection
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
    val_texts = [r.get("raw_text", "") for r in val_rows]
    val_y = np.array([LABELS.get(r.get("security_label"), 0) for r in val_rows], dtype=np.int32)
    val_X_w = word_vec.transform(val_texts).toarray().astype(np.float32)
    val_X_c = char_vec.transform(val_texts).toarray().astype(np.float32)
    val_X_s = np.asarray([extract_structural_signals(t) for t in val_texts], dtype=np.float32)

    configs = [
        ("A. Structural only", lambda s, w, c: s),
        ("B. Word TF-IDF only", lambda s, w, c: w),
        ("C. Char/subword only", lambda s, w, c: c),
        ("D. Structural + Word", lambda s, w, c: np.hstack([s, w])),
        ("E. Structural + Char", lambda s, w, c: np.hstack([s, c])),
        ("F. Word + Char", lambda s, w, c: np.hstack([w, c])),
        ("G. Full Candidate D", lambda s, w, c: np.hstack([s, w, c])),
    ]

    ablation_results = []

    print("\n" + "="*110)
    print(f"{'Ablation Configuration':<24s} | {'Dims':>5s} | {'Val tau':>7s} | {'Test Rec':>9s} | {'OOD Rec':>9s} | {'Hinglish':>9s} | {'Semantic':>9s} | {'Inst FP':>8s}")
    print("="*110)

    for cfg_name, feat_fn in configs:
        t_start = time.time()
        X_tr = feat_fn(X_struct_train, X_word_train, X_char_train)
        n_dims = X_tr.shape[1]

        sc = StandardScaler()
        X_tr_sc = sc.fit_transform(X_tr)

        clf = HistGradientBoostingClassifier(
            max_iter=300,
            learning_rate=0.08,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            class_weight={0: 1.5, 1: 1.0, 2: 1.0},
            random_state=20260914,
        )
        clf.fit(X_tr_sc, y_train)

        # Find threshold on Val (max recall at FPR <= 2.0%)
        val_X = feat_fn(val_X_s, val_X_w, val_X_c)
        val_probs = clf.predict_proba(sc.transform(val_X))
        
        best_tau = 0.61
        best_rec = -1.0
        val_ben_mask = (val_y == 0)
        val_mal_mask = (val_y == 2)
        n_val_ben = int(val_ben_mask.sum())
        n_val_mal = int(val_mal_mask.sum())

        for t_candidate in np.arange(0.40, 0.90, 0.01):
            t_cand = round(float(t_candidate), 2)
            p_nb = val_probs[:, 1] + val_probs[:, 2]
            y_p = np.where(p_nb >= t_cand, np.where(val_probs[:, 2] >= val_probs[:, 1], 2, 1), 0)
            fpr = float((y_p[val_ben_mask] != 0).sum()) / n_val_ben
            rec = float((y_p[val_mal_mask] == 2).sum()) / n_val_mal
            if fpr <= 0.02 and rec > best_rec:
                best_rec = rec
                best_tau = t_cand

        # Evaluate on slices
        res_cfg = {"name": cfg_name, "dims": n_dims, "tau": best_tau}
        slice_scores = {}
        for sname, sdata in slice_data.items():
            X_eval = feat_fn(sdata["X_struct"], sdata["X_word"], sdata["X_char"])
            probs = clf.predict_proba(sc.transform(X_eval))
            p_nb = probs[:, 1] + probs[:, 2]
            y_pred = np.where(p_nb >= best_tau, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

            y_true = sdata["y_true"]
            mal_mask = (y_true == 2)
            ben_mask = (y_true == 0)

            mal_rec = float((y_pred[mal_mask] == 2).sum()) / int(mal_mask.sum()) if mal_mask.sum() > 0 else None
            ben_fpr = float((y_pred[ben_mask] != 0).sum()) / int(ben_mask.sum()) if ben_mask.sum() > 0 else None
            slice_scores[sname] = {
                "mal_correct": int((y_pred[mal_mask] == 2).sum()) if mal_mask.sum() > 0 else 0,
                "n_mal": int(mal_mask.sum()),
                "mal_rec": mal_rec,
                "ben_fp": int((y_pred[ben_mask] != 0).sum()) if ben_mask.sum() > 0 else 0,
                "n_ben": int(ben_mask.sum()),
                "ben_fpr": ben_fpr,
            }
        res_cfg["slices"] = slice_scores
        ablation_results.append(res_cfg)

        test_rec_str = f"{slice_scores['Test Split']['mal_rec']*100:.1f}%"
        ood_rec_str = f"{slice_scores['OOD Split']['mal_rec']*100:.1f}%"
        hing_rec_str = f"{slice_scores['Hinglish Robustness']['mal_rec']*100:.1f}%"
        sem_rec_str = f"{slice_scores['Semantic Pairs']['mal_rec']*100:.1f}%"
        inst_fp_str = f"{slice_scores['Institutional']['ben_fp']}/{slice_scores['Institutional']['n_ben']}"

        print(f"{cfg_name:<24s} | {n_dims:5d} | {best_tau:7.2f} | {test_rec_str:>9s} | {ood_rec_str:>9s} | {hing_rec_str:>9s} | {sem_rec_str:>9s} | {inst_fp_str:>8s}", flush=True)

    out_file = ROOT / "messages_v4_3/evaluation/ablation_study_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(ablation_results, f, indent=2)
    print(f"\nSaved full ablation results to {out_file}")

if __name__ == "__main__":
    run_ablation_study()
