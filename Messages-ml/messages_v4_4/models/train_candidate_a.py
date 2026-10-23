"""
Trainer for Sentinel Messages V4.4 Candidate A:
Exact V4.3 Architecture (19 structural + 1500 word + 2500 char_wb = 4019 dims, HGB, seed 20260914)
trained on the corrected corpus train_v4_4.jsonl.
Strict validation-only threshold calibration (FPR <= 2.0%).
"""
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import hashlib
import json
import pickle
import time
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
V4_4_DIR = ROOT / "messages_v4_4"
MODEL_DIR = V4_4_DIR / "models/candidate_a_corrected"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

import sys
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

def main():
    print("=" * 80)
    print("TRAINING SENTINEL MESSAGES V4.4 — CANDIDATE A (CORRECTED CORPUS)")
    print("=" * 80)
    t0 = time.time()

    train_path = V4_4_DIR / "data/train_v4_4.jsonl"
    print(f"Loading training data from {train_path}...")
    train_rows = read_jsonl(train_path)
    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)
    print(f"Total training rows: {len(train_rows)}")

    print("\n1. Fitting vectorizers (1500 word ngrams [1-2], 2500 subword char_wb [2-5])...")
    word_vec = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), sublinear_tf=True)
    char_vec = TfidfVectorizer(max_features=2500, analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)

    X_word = word_vec.fit_transform(train_texts).toarray()
    X_char = char_vec.fit_transform(train_texts).toarray()

    print("2. Extracting 19 structural signals...")
    X_struct = np.asarray([extract_structural_signals(t) for t in train_texts], dtype=np.float32)

    X_train = np.hstack([X_struct, X_word, X_char]).astype(np.float32)
    print(f"Full feature matrix shape: {X_train.shape} (19 struct + 1500 word + 2500 char = 4019 dims)")

    print("3. Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("4. Fitting HistGradientBoostingClassifier (seed=20260914, max_iter=300, lr=0.08)...")
    clf = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.08,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        class_weight={0: 1.5, 1: 1.0, 2: 1.0},
        random_state=20260914,
    )
    clf.fit(X_train_scaled, y_train)
    t_train = time.time() - t0
    print(f"Model fitted in {t_train:.1f}s")

    def predict_proba(texts):
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        w = word_vec.transform(texts).toarray()
        c = char_vec.transform(texts).toarray()
        X = np.hstack([st, w, c]).astype(np.float32)
        return clf.predict_proba(scaler.transform(X))

    print("\n" + "=" * 80)
    print("5. THRESHOLD CALIBRATION STRICTLY ON VALIDATION SET (FPR <= 2.0%)")
    print("=" * 80)
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
    val_texts = [r["raw_text"] for r in val_rows]
    val_probs = predict_proba(val_texts)
    y_val = np.array([LABELS.get(r.get("security_label"), 0) for r in val_rows], dtype=np.int32)
    p_nonbenign = val_probs[:, 1] + val_probs[:, 2]

    mal_mask = (y_val == 2)
    ben_mask = (y_val == 0)
    n_mal = int(mal_mask.sum())
    n_ben = int(ben_mask.sum())

    sweep = []
    selected_threshold = None
    best_recall_at_gate = -1.0

    # Test sweep from 0.50 to 0.75
    for t_val in np.arange(0.50, 0.76, 0.01):
        t = round(float(t_val), 2)
        y_pred = np.where(p_nonbenign >= t, np.where(val_probs[:, 2] >= val_probs[:, 1], 2, 1), 0)
        mal_corr = int((y_pred[mal_mask] == 2).sum())
        mal_rec = mal_corr / n_mal
        ben_fp = int((y_pred[ben_mask] != 0).sum())
        ben_fpr = ben_fp / n_ben
        gate_pass = ben_fpr <= 0.02
        sweep.append({
            "threshold": t,
            "malicious_correct": mal_corr,
            "n_malicious": n_mal,
            "malicious_recall": mal_rec,
            "benign_fp": ben_fp,
            "n_benign": n_ben,
            "benign_fpr": ben_fpr,
            "gate_pass": gate_pass
        })
        if t in [0.55, 0.58, 0.60, 0.61, 0.62, 0.65, 0.70, 0.704]:
            print(f"tau={t:.2f} | Mal Rec: {mal_corr}/{n_mal} ({mal_rec*100:.2f}%) | Ben FP: {ben_fp}/{n_ben} ({ben_fpr*100:.2f}%) | Gate FPR<=2%: {'PASS' if gate_pass else 'FAIL'}")

    # Select threshold: smallest threshold that satisfies FPR <= 0.02 (maximizes recall under the hard constraint)
    for s in sweep:
        if s["gate_pass"]:
            selected_threshold = s["threshold"]
            break

    if selected_threshold is None:
        selected_threshold = 0.65
        print("WARNING: No threshold in sweep passed FPR <= 2%, defaulting to 0.65")

    print(f"\nLocked Validation Threshold for Candidate A: tau = {selected_threshold:.2f}")

    # Save artifacts
    print("\n6. Saving immutable artifacts for Candidate A...")
    with open(MODEL_DIR / "model.pkl", "wb") as f:
        pickle.dump(clf, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(MODEL_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(MODEL_DIR / "word_vec.pkl", "wb") as f:
        pickle.dump(word_vec, f, protocol=pickle.HIGHEST_PROTOCOL)
    with open(MODEL_DIR / "char_vec.pkl", "wb") as f:
        pickle.dump(char_vec, f, protocol=pickle.HIGHEST_PROTOCOL)

    config = {
        "candidate_name": "candidate_a_corrected",
        "date": "2026-09-19",
        "architecture": "HistGradientBoosting + 19 Structural + 1500 Word (1-2) + 2500 Char_wb (2-5)",
        "feature_dimensions": 4019,
        "structural_dimensions": 19,
        "word_dimensions": 1500,
        "char_dimensions": 2500,
        "random_state": 20260914,
        "threshold": selected_threshold,
        "training_rows": len(train_rows),
        "training_time_seconds": t_train,
        "training_data_file": "messages_v4_4/data/train_v4_4.jsonl",
        "selection_criterion": "Smallest threshold on val.jsonl satisfying Benign FPR <= 2.0%"
    }
    with open(MODEL_DIR / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    # Compute SHA256 hashes
    hashes = {}
    for name in ["model.pkl", "scaler.pkl", "word_vec.pkl", "char_vec.pkl", "config.json"]:
        p = MODEL_DIR / name
        hashes[name] = hashlib.sha256(p.read_bytes()).hexdigest()

    with open(MODEL_DIR / "hashes.json", "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)

    print("Artifact SHA256 hashes:")
    for k, v in hashes.items():
        print(f"  {k:<15s}: {v}")

    print("\nCandidate A training completed successfully!")

if __name__ == "__main__":
    main()
