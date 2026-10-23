"""
Comprehensive 4-Way Comparative Evaluation Harness:
V2 (tau=0.704) vs V4.3 (tau=0.610) vs Candidate A (tau=0.560) vs Candidate B (tau=0.630).
"""
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

import json
import pickle
import sys
import time
from pathlib import Path
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
sys.path.insert(0, str(ROOT / "messages_v4_4/models"))

from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
THRESHOLD_V2 = 0.704
THRESHOLD_V43 = 0.610
THRESHOLD_V44_A = 0.560
THRESHOLD_V44_B = 0.630

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

# Load V2
with open(ROOT / "champion_v2_model.pkl", "rb") as f: v2_m = pickle.load(f)
with open(ROOT / "champion_v2_scaler.pkl", "rb") as f: v2_s = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_word.pkl", "rb") as f: v2_w = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_char.pkl", "rb") as f: v2_c = pickle.load(f)

# Load V4.3
with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f: v43_m = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f: v43_s = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f: v43_c = pickle.load(f)

# Load V4.4 Candidate A
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/model.pkl", "rb") as f: v44a_m = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/scaler.pkl", "rb") as f: v44a_s = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/word_vec.pkl", "rb") as f: v44a_w = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/char_vec.pkl", "rb") as f: v44a_c = pickle.load(f)

# Load V4.4 Candidate B
with open(ROOT / "messages_v4_4/models/candidate_b_refined/model.pkl", "rb") as f: v44b_m = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_b_refined/scaler.pkl", "rb") as f: v44b_s = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_b_refined/word_vec.pkl", "rb") as f: v44b_w = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_b_refined/char_vec.pkl", "rb") as f: v44b_c = pickle.load(f)

def predict_v2(texts):
    det = np.asarray([extract_feature_vector(t, None, FeatureConfig()) for t in texts], dtype=np.float32)
    w = v2_w.transform(texts).toarray()
    c = v2_c.transform(texts).toarray()
    X = np.hstack([det, w, c])
    return v2_m.predict_proba(v2_s.transform(X))

def predict_v43(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v43_w.transform(texts).toarray()
    c = v43_char = v43_c.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v43_m.predict_proba(v43_s.transform(X))

def predict_v44a(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v44a_w.transform(texts).toarray()
    c = v44a_c.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v44a_m.predict_proba(v44a_s.transform(X))

def predict_v44b(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v44b_w.transform(texts).toarray()
    c = v44b_c.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v44b_m.predict_proba(v44b_s.transform(X))

def eval_predictions(rows, probs, threshold):
    y_true = np.array([LABELS.get(r.get("security_label"), 0) for r in rows], dtype=np.int32)
    p_nonbenign = probs[:, 1] + probs[:, 2]
    y_pred = np.where(p_nonbenign >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

    n_total = len(rows)
    mal_mask = (y_true == 2)
    ben_mask = (y_true == 0)
    n_mal = int(mal_mask.sum())
    n_ben = int(ben_mask.sum())

    mal_correct = int((y_pred[mal_mask] == 2).sum())
    mal_recall = float(mal_correct / n_mal) if n_mal > 0 else None

    ben_fp = int((y_pred[ben_mask] != 0).sum())
    ben_fpr = float(ben_fp / n_ben) if n_ben > 0 else None

    return {
        "n_total": n_total,
        "n_benign": n_ben,
        "benign_fp": ben_fp,
        "benign_fpr": ben_fpr,
        "n_malicious": n_mal,
        "malicious_correct": mal_correct,
        "malicious_recall": mal_recall,
        "threshold": threshold,
    }

def main():
    suites = [
        ("Validation Split", ROOT / "data/processed/val.jsonl"),
        ("Test Split", ROOT / "data/processed/test.jsonl"),
        ("Out-of-Distribution (OOD)", ROOT / "data/processed/ood.jsonl"),
    ]
    suites += [(f"slice_{p.stem}", p) for p in sorted((ROOT / "data/benchmarks").glob("*.jsonl"))]
    suites += [(p.stem, p) for p in sorted((ROOT.parent / "7sep_messages_v3/data").glob("bench_*.jsonl"))]
    suites.append(("independent_semantic_suite", ROOT / "messages_v4_3/evaluation/independent_semantic_generalization.jsonl"))
    suites += [(f"v44_{p.stem}", p) for p in sorted((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))]

    results = []
    for suite_name, p in suites:
        if not p.exists(): continue
        rows = read_jsonl(p)
        if not rows: continue
        texts = [r.get("raw_text", "") for r in rows]

        m_v2 = eval_predictions(rows, predict_v2(texts), THRESHOLD_V2)
        m_v43 = eval_predictions(rows, predict_v43(texts), THRESHOLD_V43)
        m_v44a = eval_predictions(rows, predict_v44a(texts), THRESHOLD_V44_A)
        m_v44b = eval_predictions(rows, predict_v44b(texts), THRESHOLD_V44_B)

        results.append({
            "suite": suite_name,
            "n_total": len(rows),
            "n_benign": m_v44b["n_benign"],
            "n_malicious": m_v44b["n_malicious"],
            "v2": m_v2,
            "v43": m_v43,
            "v44a": m_v44a,
            "v44b": m_v44b,
        })

    out_json = ROOT / "messages_v4_4/reports/candidate_b_comparative_eval.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "thresholds": {"V2": THRESHOLD_V2, "V4.3": THRESHOLD_V43, "V4.4_A": THRESHOLD_V44_A, "V4.4_B": THRESHOLD_V44_B},
            "suites": results
        }, f, indent=2)

    print("\n" + "=" * 175, flush=True)
    print("4-WAY COMPARATIVE EVALUATION MATRIX")
    print(f"V2 (tau={THRESHOLD_V2}) | V4.3 (tau={THRESHOLD_V43}) | V4.4-A (tau={THRESHOLD_V44_A}) | V4.4-B (tau={THRESHOLD_V44_B})")
    print("=" * 175, flush=True)
    header = f"{'Suite Name':<38s} | {'N':>5s} | {'V2 FP':>7s} | {'V4.3 FP':>7s} | {'V4.4-B FP':>9s} | {'V2 Mal':>8s} | {'V4.3 Mal':>8s} | {'V4.4-B Mal':>10s} | {'Delta vs V4.3':>14s}"
    print(header, flush=True)
    print("-" * len(header), flush=True)

    for r in results:
        nb = r["n_benign"]
        nm = r["n_malicious"]
        v2_b = f"{r['v2']['benign_fp']}/{nb}" if nb > 0 else "—"
        v43_b = f"{r['v43']['benign_fp']}/{nb}" if nb > 0 else "—"
        v44b_b = f"{r['v44b']['benign_fp']}/{nb}" if nb > 0 else "—"

        v2_m = f"{r['v2']['malicious_correct']}/{nm}" if nm > 0 else "—"
        v43_m = f"{r['v43']['malicious_correct']}/{nm}" if nm > 0 else "—"
        v44b_m = f"{r['v44b']['malicious_correct']}/{nm}" if nm > 0 else "—"

        if nm > 0 and r['v43']['malicious_recall'] is not None and r['v44b']['malicious_recall'] is not None:
            d_rec = (r['v44b']['malicious_recall'] - r['v43']['malicious_recall']) * 100
            d_str = f"Rec: {d_rec:+.2f}%"
        elif nb > 0 and r['v43']['benign_fpr'] is not None and r['v44b']['benign_fpr'] is not None:
            d_fp = (r['v44b']['benign_fpr'] - r['v43']['benign_fpr']) * 100
            d_str = f"FPR: {d_fp:+.2f}%"
        else:
            d_str = "—"

        print(f"{r['suite']:<38s} | {r['n_total']:5d} | {v2_b:>7s} | {v43_b:>7s} | {v44b_b:>9s} | {v2_m:>8s} | {v43_m:>8s} | {v44b_m:>10s} | {d_str:>14s}", flush=True)

    # Forensic Probes
    print("\n" + "=" * 100, flush=True)
    print("FORENSIC DIAGNOSTIC PROBES (V4.3 vs V4.4-B)", flush=True)
    print("=" * 100, flush=True)
    probe_cases = [
        ("ELEC_001", "Dear consumer, your electricity power will be disconnected at 9:30 PM tonight because your previous month bill was not updated. Call electricity officer immediately at 9800000030."),
        ("ELEC_002", "Electricity Alert: Your power supply will be cut tonight at 10 PM. Contact light office manager at 9800000031 to avoid disconnection."),
        ("ELEC_003", "Bijli Bill Notice: Unpaid bill dues detected. Your meter will be disconnected today. Call 9800000032 now."),
        ("GREET_01", "Hello"),
        ("GREET_02", "Hi"),
        ("GREET_03", "Hello!"),
        ("GREET_04", "Good morning"),
        ("CONV_01", "Bhai jaldi se bhej de code jo aaya hai, urgency hai"),
        ("CONV_02", "Yaar ek OTP gaya hoga tere number pe, forward kar dena turant"),
        ("CONV_03", "Nahi toh SIM block ho jayegi ... Call customer care at 9876543210"),
        ("CONV_04", "approve this Google Pay collect request for Rs 5000"),
        ("NOTIF_01", "Uploading: 789 kB of 789 kB (100%)"),
        ("NOTIF_02", "WhatsApp backup paused. Waiting for Wi-Fi"),
        ("NOTIF_03", "Sync complete: All photos backed up"),
        ("NOTIF_04", "Hotspot active: 1 device connected"),
        ("NOTIF_05", "USB debugging connected"),
        ("APK_01",   "Download our official partner rewards app at rewards.apk"),
    ]

    texts = [p[1] for p in probe_cases]
    pr_v43 = predict_v43(texts)
    pr_v44b = predict_v44b(texts)

    for i, (cid, txt) in enumerate(probe_cases):
        nb43 = pr_v43[i, 1] + pr_v43[i, 2]
        nb44b = pr_v44b[i, 1] + pr_v44b[i, 2]

        p43_str = f"p={nb43:.4f} ({'MAL/SUSP' if nb43>=THRESHOLD_V43 else 'BENIGN'})"
        p44b_str = f"p={nb44b:.4f} ({'MAL/SUSP' if nb44b>=THRESHOLD_V44_B else 'BENIGN'})"

        print(f"[{cid}] '{txt}'", flush=True)
        print(f"  V4.3 (tau={THRESHOLD_V43:.2f}):   {p43_str}", flush=True)
        print(f"  V4.4-B (tau={THRESHOLD_V44_B:.2f}): {p44b_str}", flush=True)
        print(flush=True)

if __name__ == "__main__":
    main()
