"""
Comprehensive 3-Way Comparative Evaluation Harness for Sentinel Messages:
Champion V2 (tau=0.704) vs Sentinel V4.3 (tau=0.610) vs Candidate A V4.4 (tau=0.560).
Evaluates all 22 baseline suites + independent semantic suite + 7 new V4.4 holdouts + diagnostic probes.
"""
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

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

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

# 1. Load V2 Artifacts
print("Loading Champion V2 artifacts...", flush=True)
with open(ROOT / "champion_v2_model.pkl", "rb") as f: v2_m = pickle.load(f)
with open(ROOT / "champion_v2_scaler.pkl", "rb") as f: v2_s = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_word.pkl", "rb") as f: v2_w = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_char.pkl", "rb") as f: v2_c = pickle.load(f)

# 2. Load V4.3 Artifacts
print("Loading Sentinel V4.3 artifacts...", flush=True)
with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f: v43_m = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f: v43_s = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f: v43_c = pickle.load(f)

# 3. Load V4.4 Candidate A Artifacts
print("Loading Sentinel V4.4 Candidate A artifacts...", flush=True)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/model.pkl", "rb") as f: v44_m = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/scaler.pkl", "rb") as f: v44_s = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/word_vec.pkl", "rb") as f: v44_w = pickle.load(f)
with open(ROOT / "messages_v4_4/models/candidate_a_corrected/char_vec.pkl", "rb") as f: v44_c = pickle.load(f)

def predict_v2(texts):
    det = np.asarray([extract_feature_vector(t, None, FeatureConfig()) for t in texts], dtype=np.float32)
    w = v2_w.transform(texts).toarray()
    c = v2_c.transform(texts).toarray()
    X = np.hstack([det, w, c])
    return v2_m.predict_proba(v2_s.transform(X))

def predict_v43(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v43_w.transform(texts).toarray()
    c = v43_c.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v43_m.predict_proba(v43_s.transform(X))

def predict_v44_a(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v44_w.transform(texts).toarray()
    c = v44_c.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v44_m.predict_proba(v44_s.transform(X))

def evaluate_predictions(rows, probs, threshold):
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

    print(f"\nTotal suites to evaluate: {len(suites)}", flush=True)

    results = []
    for suite_name, p in suites:
        if not p.exists():
            continue
        rows = read_jsonl(p)
        if not rows:
            continue
        texts = [r.get("raw_text", "") for r in rows]

        # V2
        p_v2 = predict_v2(texts)
        m_v2 = evaluate_predictions(rows, p_v2, THRESHOLD_V2)

        # V4.3
        p_v43 = predict_v43(texts)
        m_v43 = evaluate_predictions(rows, p_v43, THRESHOLD_V43)

        # V4.4 Candidate A
        p_v44 = predict_v44_a(texts)
        m_v44 = evaluate_predictions(rows, p_v44, THRESHOLD_V44_A)

        results.append({
            "suite": suite_name,
            "path": str(p),
            "n_total": m_v44["n_total"],
            "n_benign": m_v44["n_benign"],
            "n_malicious": m_v44["n_malicious"],
            "v2": m_v2,
            "v43": m_v43,
            "v44_a": m_v44,
        })

    # Save JSON results
    out_json = ROOT / "messages_v4_4/reports/candidate_a_comparative_eval.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "thresholds": {"V2": THRESHOLD_V2, "V4.3": THRESHOLD_V43, "V4.4_Candidate_A": THRESHOLD_V44_A},
            "suites": results
        }, f, indent=2)
    print(f"\nSaved full comparative JSON to {out_json}", flush=True)

    # Print Table
    print("\n" + "=" * 160)
    print("SENTINEL MESSAGES 3-WAY COMPARATIVE EVALUATION MATRIX")
    print(f"V2 (tau={THRESHOLD_V2}) vs V4.3 (tau={THRESHOLD_V43}) vs V4.4 Candidate A (tau={THRESHOLD_V44_A})")
    print("=" * 160)
    header = f"{'Suite Name':<38s} | {'N':>5s} | {'V2 Ben FP':>10s} | {'V4.3 Ben FP':>11s} | {'V4.4 Ben FP':>11s} | {'V2 Mal Rec':>11s} | {'V4.3 Mal Rec':>12s} | {'V4.4 Mal Rec':>12s} | {'Delta vs V4.3':>13s}"
    print(header)
    print("-" * len(header))

    for r in results:
        nb = r["n_benign"]
        nm = r["n_malicious"]

        v2_b = f"{r['v2']['benign_fp']}/{nb}" if nb > 0 else "—"
        v43_b = f"{r['v43']['benign_fp']}/{nb}" if nb > 0 else "—"
        v44_b = f"{r['v44_a']['benign_fp']}/{nb}" if nb > 0 else "—"

        v2_m = f"{r['v2']['malicious_correct']}/{nm}" if nm > 0 else "—"
        v43_m = f"{r['v43']['malicious_correct']}/{nm}" if nm > 0 else "—"
        v44_m = f"{r['v44_a']['malicious_correct']}/{nm}" if nm > 0 else "—"

        if nm > 0 and r['v43']['malicious_recall'] is not None and r['v44_a']['malicious_recall'] is not None:
            d_rec = (r['v44_a']['malicious_recall'] - r['v43']['malicious_recall']) * 100
            d_str = f"{d_rec:+.2f}%"
        elif nb > 0 and r['v43']['benign_fpr'] is not None and r['v44_a']['benign_fpr'] is not None:
            d_fp = (r['v44_a']['benign_fpr'] - r['v43']['benign_fpr']) * 100
            d_str = f"FPR: {d_fp:+.2f}%"
        else:
            d_str = "—"

        print(f"{r['suite']:<38s} | {r['n_total']:5d} | {v2_b:>10s} | {v43_b:>11s} | {v44_b:>11s} | {v2_m:>11s} | {v43_m:>12s} | {v44_m:>12s} | {d_str:>13s}")

    # Specific Forensic Diagnostic Probes
    print("\n" + "=" * 100)
    print("SPECIFIC FORENSIC DIAGNOSTIC PROBES")
    print("=" * 100)
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
        ("APK_01", "Download our official partner rewards app at rewards.apk"),
    ]

    texts = [p[1] for p in probe_cases]
    pr_v2 = predict_v2(texts)
    pr_v43 = predict_v43(texts)
    pr_v44 = predict_v44_a(texts)

    for i, (cid, txt) in enumerate(probe_cases):
        nb2 = pr_v2[i, 1] + pr_v2[i, 2]
        nb43 = pr_v43[i, 1] + pr_v43[i, 2]
        nb44 = pr_v44[i, 1] + pr_v44[i, 2]

        pred2 = "MAL/SUSP" if nb2 >= THRESHOLD_V2 else "BENIGN"
        pred43 = "MAL/SUSP" if nb43 >= THRESHOLD_V43 else "BENIGN"
        pred44 = "MAL/SUSP" if nb44 >= THRESHOLD_V44_A else "BENIGN"

        print(f"[{cid}] '{txt}'")
        print(f"  V2   (tau={THRESHOLD_V2:.3f}): p(non-benign) = {nb2:.4f} -> {pred2}")
        print(f"  V4.3 (tau={THRESHOLD_V43:.3f}): p(non-benign) = {nb43:.4f} -> {pred43}")
        print(f"  V4.4 (tau={THRESHOLD_V44_A:.3f}): p(non-benign) = {nb44:.4f} -> {pred44}")
        print()

if __name__ == "__main__":
    main()
