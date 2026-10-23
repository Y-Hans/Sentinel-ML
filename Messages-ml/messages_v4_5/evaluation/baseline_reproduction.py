import os
import sys
import json
import pickle
import re
from pathlib import Path
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
LABEL_NAMES = ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"]

def read_jsonl(p: Path):
    return [json.loads(line) for line in open(p, "r", encoding="utf-8") if line.strip()]

def get_text(r: dict) -> str:
    return (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()

def get_label(r: dict) -> int:
    lbl_str = r.get("security_label") or r.get("label") or "BENIGN"
    if r.get("ground_truth_class") == "TRUE_POSITIVE_MALICIOUS_URL":
        lbl_str = "MALICIOUS"
    elif r.get("ground_truth_class") == "TRUE_NEGATIVE_BENIGN":
        lbl_str = "BENIGN"
    return LABELS.get(lbl_str, 0)

def norm_aggressive(s: str) -> str:
    t = s.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return " ".join(t.split())

def predict_model(texts, model, scaler, word_vec, char_vec):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    X = np.hstack([st, word_vec.transform(texts).toarray(), char_vec.transform(texts).toarray()]).astype(np.float32)
    return model.predict_proba(scaler.transform(X))

def compute_metrics(y_true, probs, threshold):
    # probs shape: (N, 3) -> [P(BENIGN), P(SPAM), P(MALICIOUS)]
    p_nb = probs[:, 1] + probs[:, 2]
    y_pred = np.where(p_nb >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

    # Confusion matrix: rows=True, cols=Pred
    cm = np.zeros((3, 3), dtype=np.int32)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    ben_mask = (y_true == 0)
    mal_mask = (y_true == 2)
    spam_mask = (y_true == 1)

    n_ben = int(ben_mask.sum())
    n_mal = int(mal_mask.sum())
    n_spam = int(spam_mask.sum())

    ben_fp = int((y_pred[ben_mask] != 0).sum())
    ben_fpr = (ben_fp / n_ben) if n_ben > 0 else 0.0

    mal_recall_mal = int((y_pred[mal_mask] == 2).sum())
    mal_recall_total = (mal_recall_mal / n_mal) if n_mal > 0 else 0.0

    # Also track MAL -> SPAM
    mal_to_spam = int((y_pred[mal_mask] == 1).sum())
    mal_to_ben = int((y_pred[mal_mask] == 0).sum())

    return {
        "threshold": float(threshold),
        "total": len(y_true),
        "n_benign": n_ben,
        "n_spam": n_spam,
        "n_malicious": n_mal,
        "benign_fp": ben_fp,
        "benign_fpr": float(ben_fpr),
        "malicious_detected": mal_recall_mal,
        "malicious_recall": float(mal_recall_total),
        "malicious_to_spam": mal_to_spam,
        "malicious_to_benign": mal_to_ben,
        "confusion_matrix": cm.tolist(),
        "mean_p_benign": float(np.mean(probs[:, 0])),
        "mean_p_spam": float(np.mean(probs[:, 1])),
        "mean_p_malicious": float(np.mean(probs[:, 2])),
    }

def main():
    print("=" * 80)
    print("REPRODUCING FROZEN BASELINES: V4.3, RC1, RC2-EXP3")
    print("=" * 80)

    # 1. Load V4.3
    v43_dir = ROOT / "messages_v4_3/models/candidate_d"
    with open(v43_dir / "model.pkl", "rb") as f: v43_m = pickle.load(f)
    with open(v43_dir / "scaler.pkl", "rb") as f: v43_s = pickle.load(f)
    with open(v43_dir / "word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
    with open(v43_dir / "char_vec.pkl", "rb") as f: v43_c = pickle.load(f)
    tau_v43 = 0.610

    # 2. Load RC1 / Candidate B
    rc1_dir = ROOT / "messages_v4_4/models/candidate_b_refined"
    with open(rc1_dir / "model.pkl", "rb") as f: rc1_m = pickle.load(f)
    with open(rc1_dir / "scaler.pkl", "rb") as f: rc1_s = pickle.load(f)
    with open(rc1_dir / "word_vec.pkl", "rb") as f: rc1_w = pickle.load(f)
    with open(rc1_dir / "char_vec.pkl", "rb") as f: rc1_c = pickle.load(f)
    tau_rc1 = 0.630

    # 3. Load RC2-Exp3
    exp3_dir = ROOT / "messages_v4_4/models/rc2_experiment_3"
    with open(exp3_dir / "model.pkl", "rb") as f: exp3_m = pickle.load(f)
    with open(exp3_dir / "scaler.pkl", "rb") as f: exp3_s = pickle.load(f)
    with open(exp3_dir / "word_vec.pkl", "rb") as f: exp3_w = pickle.load(f)
    with open(exp3_dir / "char_vec.pkl", "rb") as f: exp3_c = pickle.load(f)
    with open(exp3_dir / "config.json", "r") as f: exp3_cfg = json.load(f)
    tau_exp3 = exp3_cfg.get("validation_threshold", 0.740)

    print(f"Loaded models:")
    print(f"  V4.3: tau={tau_v43:.3f}")
    print(f"  RC1:  tau={tau_rc1:.3f}")
    print(f"  Exp3: tau={tau_exp3:.3f}")

    # Datasets
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
    test_rows = read_jsonl(ROOT / "data/processed/test.jsonl")
    ood_rows = read_jsonl(ROOT / "data/processed/ood.jsonl")

    # Clean OOD
    train_rows = read_jsonl(ROOT / "messages_v4_4/data/train_v4_4_rc2_exp3.jsonl")
    train_norm_keys = {norm_aggressive(get_text(r)) for r in train_rows}
    clean_ood_rows = [r for r in ood_rows if norm_aggressive(get_text(r)) not in train_norm_keys]

    # Real Mobile Simulation
    sim_path = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\6sep\simulation\SIMULATION_CASES.jsonl")
    sim_rows = read_jsonl(sim_path) if sim_path.exists() else []

    suites = [
        ("Validation Split", val_rows),
        ("Primary TEST", test_rows),
        ("Primary OOD", ood_rows),
        ("Clean OOD (Zero Overlap)", clean_ood_rows),
        ("Real Mobile Simulation", sim_rows),
    ]

    all_results = {}

    for suite_name, rows in suites:
        if not rows:
            continue
        texts = [get_text(r) for r in rows]
        y_true = np.array([get_label(r) for r in rows], dtype=np.int32)

        p_v43 = predict_model(texts, v43_m, v43_s, v43_w, v43_c)
        p_rc1 = predict_model(texts, rc1_m, rc1_s, rc1_w, rc1_c)
        p_exp3 = predict_model(texts, exp3_m, exp3_s, exp3_w, exp3_c)

        m_v43 = compute_metrics(y_true, p_v43, tau_v43)
        m_rc1 = compute_metrics(y_true, p_rc1, tau_rc1)
        m_exp3 = compute_metrics(y_true, p_exp3, tau_exp3)

        all_results[suite_name] = {
            "V4.3": m_v43,
            "RC1": m_rc1,
            "RC2-Exp3": m_exp3,
        }

        print(f"\n--- {suite_name} (N={len(rows)}) ---")
        print(f"  V4.3:     FPR={m_v43['benign_fpr']*100:.2f}% ({m_v43['benign_fp']}/{m_v43['n_benign']}) | Recall={m_v43['malicious_recall']*100:.2f}% ({m_v43['malicious_detected']}/{m_v43['n_malicious']})")
        print(f"  RC1:      FPR={m_rc1['benign_fpr']*100:.2f}% ({m_rc1['benign_fp']}/{m_rc1['n_benign']}) | Recall={m_rc1['malicious_recall']*100:.2f}% ({m_rc1['malicious_detected']}/{m_rc1['n_malicious']})")
        print(f"  RC2-Exp3: FPR={m_exp3['benign_fpr']*100:.2f}% ({m_exp3['benign_fp']}/{m_exp3['n_benign']}) | Recall={m_exp3['malicious_recall']*100:.2f}% ({m_exp3['malicious_detected']}/{m_exp3['n_malicious']})")

    # Verify primary TEST reference values
    test_res = all_results["Primary TEST"]
    v43_recall_count = test_res["V4.3"]["malicious_detected"]
    rc1_recall_count = test_res["RC1"]["malicious_detected"]
    exp3_recall_count = test_res["RC2-Exp3"]["malicious_detected"]

    print("\n" + "=" * 80)
    print("VERIFYING TEST RECALL REPRODUCTION AGAINST KNOWN REFERENCE VALUES:")
    print(f"  V4.3:     Expected 1510/1556 (97.04%) -> Actual: {v43_recall_count}/1556 ({v43_recall_count/1556*100:.2f}%) -> {'PASS' if v43_recall_count == 1510 else 'FAIL'}")
    print(f"  RC1:      Expected 1511/1556 (97.11%) -> Actual: {rc1_recall_count}/1556 ({rc1_recall_count/1556*100:.2f}%) -> {'PASS' if rc1_recall_count == 1511 else 'FAIL'}")
    print(f"  RC2-Exp3: Expected 1494/1556 (96.02%) -> Actual: {exp3_recall_count}/1556 ({exp3_recall_count/1556*100:.2f}%) -> {'PASS' if exp3_recall_count == 1494 else 'FAIL'}")
    print("=" * 80)

    # Save reproduction results
    out_path = ROOT / "messages_v4_5/reports/baseline_reproduction.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved baseline reproduction results to {out_path}")

if __name__ == "__main__":
    main()
