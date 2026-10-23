"""
Candidate B: Subword Character-Morpheme Multilingual Architecture.
High-capacity char_wb n-grams (3-5) + word n-grams (1-2) with HistGradientBoostingClassifier.
"""
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import json
import pickle
import time
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys_eval = str(ROOT / "messages_v4_3/evaluation")
import sys
sys.path.insert(0, sys_eval)
from eval_suite import run_full_evaluation, read_jsonl, LABELS

OUT = ROOT / "messages_v4_3"

def run_candidate_b():
    print("--- Candidate B: Subword Char-Morpheme Multilingual Model ---", flush=True)
    t0 = time.time()
    train_path = OUT / "data/train_v4_3.jsonl"
    print(f"Loading training data from {train_path}...", flush=True)
    train_rows = read_jsonl(train_path)
    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)
    print(f"Total training rows: {len(train_rows)}", flush=True)

    print("Fitting subword char-morpheme vectorizer (char_wb 3-5, 2000 dims) and word vectorizer (1-2 ngrams, 1500 dims)...", flush=True)
    word_vec = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), sublinear_tf=True)
    char_vec = TfidfVectorizer(max_features=2000, analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)

    X_word = word_vec.fit_transform(train_texts).toarray()
    X_char = char_vec.fit_transform(train_texts).toarray()
    X_train = np.hstack([X_word, X_char]).astype(np.float32)
    print(f"Feature matrix shape: {X_train.shape}", flush=True)

    print("Fitting standard scaler...", flush=True)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("Training HistGradientBoostingClassifier (max_iter=250, learning_rate=0.08)...", flush=True)
    clf = HistGradientBoostingClassifier(
        max_iter=250,
        learning_rate=0.08,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        class_weight="balanced",
        random_state=20260914,
    )
    clf.fit(X_train_scaled, y_train)
    print(f"Model fitted in {time.time()-t0:.1f}s", flush=True)

    def predict_proba_fn(texts):
        w = word_vec.transform(texts).toarray()
        c = char_vec.transform(texts).toarray()
        X = np.hstack([w, c]).astype(np.float32)
        X_sc = scaler.transform(X)
        return clf.predict_proba(X_sc)

    print("Running universal evaluation suite across all 19 benchmark suites & splits...", flush=True)
    res = run_full_evaluation(predict_proba_fn, threshold=None)

    threshold = res["threshold"]
    print(f"\nLocked Validation Threshold: {threshold}", flush=True)
    val = res["validation"]
    print(f"Validation: Malicious {val['malicious_correct']}/{val['n_malicious']} ({val['malicious_recall']:.4f}), Benign FP {val['benign_fp']}/{val['n_benign']} ({val['benign_fpr']:.4f})", flush=True)
    test = res["test"]
    print(f"Test:       Malicious {test['malicious_correct']}/{test['n_malicious']} ({test['malicious_recall']:.4f}), Benign FP {test['benign_fp']}/{test['n_benign']} ({test['benign_fpr']:.4f})", flush=True)
    ood = res["ood"]
    print(f"OOD:        Malicious {ood['malicious_correct']}/{ood['n_malicious']} ({ood['malicious_recall']:.4f}), Benign FP {ood['benign_fp']}/{ood['n_benign']} ({ood['benign_fpr']:.4f})", flush=True)

    print("\n--- Benchmark Slices ---", flush=True)
    for bname, bm in res["benchmarks"].items():
        mal_str = f"{bm['malicious_correct']}/{bm['n_malicious']}" if bm['n_malicious'] > 0 else "N/A"
        ben_str = f"{bm['benign_fp']}/{bm['n_benign']}" if bm['n_benign'] > 0 else "N/A"
        rec_str = f"{bm['malicious_recall']:.4f}" if bm['malicious_recall'] is not None else "N/A"
        fpr_str = f"{bm['benign_fpr']:.4f}" if bm['benign_fpr'] is not None else "N/A"
        print(f"{bname:38s} | Malicious: {mal_str:>7s} ({rec_str:>6s}) | Benign FP: {ben_str:>7s} ({fpr_str:>6s})", flush=True)

    res["model_name"] = "Candidate_B_Subword_Morpheme_Trees"
    res["training_time_s"] = time.time() - t0

    out_metrics = OUT / "reports/candidate_b_metrics.json"
    with open(out_metrics, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved Candidate B results to {out_metrics}", flush=True)

    # Also save model artifacts
    model_dir = OUT / "models/candidate_b"
    model_dir.mkdir(parents=True, exist_ok=True)
    with open(model_dir / "model.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open(model_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(model_dir / "word_vec.pkl", "wb") as f:
        pickle.dump(word_vec, f)
    with open(model_dir / "char_vec.pkl", "wb") as f:
        pickle.dump(char_vec, f)
    print(f"Artifacts saved to {model_dir}", flush=True)

if __name__ == "__main__":
    run_candidate_b()
