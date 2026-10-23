"""
Diagnostic script for Candidate B threshold behavior.
"""
import pickle
import json
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "messages_v4_3/evaluation"))
from eval_suite import compute_detailed_metrics, read_jsonl

model_dir = ROOT / "messages_v4_3/models/candidate_b"
clf = pickle.load(open(model_dir / "model.pkl", "rb"))
scaler = pickle.load(open(model_dir / "scaler.pkl", "rb"))
word_vec = pickle.load(open(model_dir / "word_vec.pkl", "rb"))
char_vec = pickle.load(open(model_dir / "char_vec.pkl", "rb"))

val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
val_texts = [r.get("raw_text", "") for r in val_rows]
w = word_vec.transform(val_texts).toarray()
c = char_vec.transform(val_texts).toarray()
X = np.hstack([w, c]).astype(np.float32)
val_probs = clf.predict_proba(scaler.transform(X))

print("--- Threshold sweep on Validation for Candidate B ---")
for t in [0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.91]:
    m = compute_detailed_metrics(val_rows, val_probs, t)
    print(f"t={t:.2f} | Mal Recall: {m['malicious_correct']:>4d}/{m['n_malicious']:>4d} ({m['malicious_recall']:.4f}) | Benign FP: {m['benign_fp']:>3d}/{m['n_benign']:>3d} ({m['benign_fpr']:.4f}) | Macro F1: {m['macro_f1']:.4f}")

# Also check on bench_adversarial_semantic_pairs
adv_rows = read_jsonl(ROOT.parent / "7sep_messages_v3/data/bench_adversarial_semantic_pairs.jsonl")
adv_texts = [r.get("raw_text", "") for r in adv_rows]
w_adv = word_vec.transform(adv_texts).toarray()
c_adv = char_vec.transform(adv_texts).toarray()
X_adv = np.hstack([w_adv, c_adv]).astype(np.float32)
adv_probs = clf.predict_proba(scaler.transform(X_adv))

print("\n--- Threshold sweep on Adversarial Semantic Pairs ---")
for t in [0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.91]:
    m = compute_detailed_metrics(adv_rows, adv_probs, t)
    print(f"t={t:.2f} | Mal Recall: {m['malicious_correct']:>2d}/{m['n_malicious']:>2d} ({m['malicious_recall']:.4f}) | Benign FP: {m['benign_fp']:>2d}/{m['n_benign']:>2d} ({m['benign_fpr']:.4f})")

# Also check Hinglish robustness
hi_rows = read_jsonl(ROOT.parent / "7sep_messages_v3/data/bench_hinglish_robustness.jsonl")
hi_texts = [r.get("raw_text", "") for r in hi_rows]
w_hi = word_vec.transform(hi_texts).toarray()
c_hi = char_vec.transform(hi_texts).toarray()
X_hi = np.hstack([w_hi, c_hi]).astype(np.float32)
hi_probs = clf.predict_proba(scaler.transform(X_hi))

print("\n--- Threshold sweep on Hinglish Robustness ---")
for t in [0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.91]:
    m = compute_detailed_metrics(hi_rows, hi_probs, t)
    print(f"t={t:.2f} | Mal Recall: {m['malicious_correct']:>2d}/{m['n_malicious']:>2d} ({m['malicious_recall']:.4f}) | Benign FP: {m['benign_fp']:>2d}/{m['n_benign']:>2d} ({m['benign_fpr']:.4f})")
