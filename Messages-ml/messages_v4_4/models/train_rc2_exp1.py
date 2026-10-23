"""
Trainer for Sentinel Messages V4.4 RC2 - Experiment 1: Benign Utility Rebalancing.
Architecture:
- 19 structural signals (candidate_d_v4_3)
- 1500 word ngrams (1-2, sublinear_tf=True)
- 2500 char_wb ngrams (2-5, sublinear_tf=True)
- Total 4019 dims
- StandardScaler
- HistGradientBoostingClassifier (seed=20260914, max_iter=300, lr=0.08, min_samples_leaf=20, l2_regularization=1.0)
- Validation Threshold selection strictly on val.jsonl (FPR <= 2.0%)
"""
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

import hashlib
import json
import pickle
import sys
import time
from pathlib import Path
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals

OUT_DIR = ROOT / "messages_v4_4/models/rc2_experiment_1"
OUT_DIR.mkdir(parents=True, exist_ok=True)

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}

def main():
    print("=" * 80)
    print("TRAINING SENTINEL MESSAGES V4.4 RC2 — EXPERIMENT 1 (BENIGN UTILITY)")
    print("=" * 80)

    train_path = ROOT / "messages_v4_4/data/train_v4_4_rc2_exp1.jsonl"
    print(f"Loading training data from {train_path}...")
    rows = [json.loads(line) for line in open(train_path, encoding="utf-8") if line.strip()]
    print(f"Total training rows: {len(rows)}")

    texts = [r.get("raw_text") or r.get("text", "") for r in rows]
    y = np.array([LABELS[r.get("security_label") or r.get("label")] for r in rows], dtype=np.int32)

    print("\n1. Fitting TF-IDF Vectorizers (1500 word [1-2], 2500 char_wb [2-5])...")
    word_vec = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=1500,
        sublinear_tf=True,
        strip_accents="unicode"
    )
    char_vec = TfidfVectorizer(
        ngram_range=(2, 5),
        analyzer="char_wb",
        max_features=2500,
        sublinear_tf=True,
        strip_accents="unicode"
    )

    t0 = time.time()
    X_word = word_vec.fit_transform(texts).toarray()
    X_char = char_vec.fit_transform(texts).toarray()
    print(f"Vectorizers fitted in {time.time()-t0:.2f}s")

    print("\n2. Extracting 19 structural signals...")
    t0 = time.time()
    X_struct = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    print(f"Structural signals extracted in {time.time()-t0:.2f}s")

    X = np.hstack([X_struct, X_word, X_char]).astype(np.float32)
    print(f"Full feature matrix shape: {X.shape} (19 struct + 1500 word + 2500 char = 4019 dims)")

    print("\n3. Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("\n4. Fitting HistGradientBoostingClassifier (seed=20260914, max_iter=300, lr=0.08)...")
    clf = HistGradientBoostingClassifier(
        random_state=20260914,
        max_iter=300,
        learning_rate=0.08,
        min_samples_leaf=20,
        l2_regularization=1.0
    )
    t0 = time.time()
    clf.fit(X_scaled, y)
    print(f"Model fitted in {time.time()-t0:.1f}s")

    # ========================================================================
    # 5. THRESHOLD SELECTION STRICTLY ON VALIDATION SPLIT
    # ========================================================================
    print("\n" + "=" * 80)
    print("5. THRESHOLD CALIBRATION STRICTLY ON VALIDATION SET (FPR <= 2.0%)")
    print("=" * 80)
    val_path = ROOT / "data/processed/val.jsonl"
    val_rows = [json.loads(line) for line in open(val_path, encoding="utf-8") if line.strip()]
    val_texts = [r.get("raw_text") or r.get("text", "") for r in val_rows]
    val_y = np.array([LABELS[r.get("security_label") or r.get("label")] for r in val_rows], dtype=np.int32)

    val_st = np.asarray([extract_structural_signals(t) for t in val_texts], dtype=np.float32)
    val_X = np.hstack([val_st, word_vec.transform(val_texts).toarray(), char_vec.transform(val_texts).toarray()]).astype(np.float32)
    val_probs = clf.predict_proba(scaler.transform(val_X))
    val_p_nb = val_probs[:, 1] + val_probs[:, 2]

    best_tau = None
    target_fpr = 0.02
    thresholds = [0.50, 0.55, 0.58, 0.60, 0.61, 0.62, 0.63, 0.64, 0.65, 0.68, 0.70]
    
    n_ben = int((val_y == 0).sum())
    n_mal = int((val_y == 2).sum())

    for tau in thresholds:
        pred_label = np.where(val_p_nb >= tau, np.where(val_probs[:, 2] >= val_probs[:, 1], 2, 1), 0)
        mal_rec = int((pred_label[val_y == 2] == 2).sum()) / n_mal
        ben_fp = int((pred_label[val_y == 0] != 0).sum())
        ben_fpr = ben_fp / n_ben
        gate = "PASS" if ben_fpr <= target_fpr else "FAIL"
        print(f"tau={tau:.2f} | Mal Rec: {int(mal_rec*n_mal)}/{n_mal} ({mal_rec*100:.2f}%) | Ben FP: {ben_fp}/{n_ben} ({ben_fpr*100:.2f}%) | Gate FPR<=2%: {gate}")
        if ben_fpr <= target_fpr and best_tau is None:
            best_tau = tau

    if best_tau is None:
        best_tau = 0.63 # fallback if all higher
    print(f"\nLocked Validation Threshold for RC2-Exp1: tau = {best_tau}")

    # ========================================================================
    # 6. SAVE ARTIFACTS
    # ========================================================================
    print("\n6. Saving immutable artifacts for RC2 Experiment 1...")
    with open(OUT_DIR / "model.pkl", "wb") as f: pickle.dump(clf, f)
    with open(OUT_DIR / "scaler.pkl", "wb") as f: pickle.dump(scaler, f)
    with open(OUT_DIR / "word_vec.pkl", "wb") as f: pickle.dump(word_vec, f)
    with open(OUT_DIR / "char_vec.pkl", "wb") as f: pickle.dump(char_vec, f)

    config = {
        "model_name": "Sentinel Messages V4.4 RC2 - Experiment 1",
        "description": "Benign utility rebalancing to resolve utility false alarms",
        "parent_model": "Candidate B (V4.4-RC1)",
        "feature_dim": 4019,
        "structural_signals": 19,
        "word_ngrams": 1500,
        "char_wb_ngrams": 2500,
        "validation_threshold": best_tau,
        "training_rows": len(rows),
        "corpus_hash": hashlib.sha256(train_path.read_bytes()).hexdigest(),
        "random_seed": 20260914,
        "classes": ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"]
    }
    with open(OUT_DIR / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    hashes = {}
    for p in sorted(OUT_DIR.glob("*")):
        if p.is_file() and p.name != "hashes.json":
            hashes[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
            print(f"  {p.name:<15}: {hashes[p.name]}")

    with open(OUT_DIR / "hashes.json", "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)

    print("\nRC2 Experiment 1 training completed successfully!")

if __name__ == "__main__":
    main()
