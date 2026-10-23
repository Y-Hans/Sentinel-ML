"""
Comparative Evaluation Harness for Sentinel Messages V4.4 RC2 - Experiment 2:
Compares:
- V4.3 (tau=0.610)
- Candidate B / V4.4-RC1 (tau=0.630)
- RC2-Experiment-1 (tau=0.680)
- RC2-Experiment-2 (tau from validation calibration)
"""
import os
os.environ["OMP_NUM_THREADS"] = "4"
os.environ["LOKY_MAX_CPU_COUNT"] = "4"

import json
import pickle
import re
import sys
import time
from pathlib import Path
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
THRESHOLD_V43 = 0.610
THRESHOLD_V44_B = 0.630
THRESHOLD_EXP1 = 0.680

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

def norm_aggressive(s: str) -> str:
    t = s.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return " ".join(t.split())

def main():
    print("Loading models for RC2 Experiment 2 comparative evaluation...", flush=True)

    # 1. V4.3
    with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f: v43_m = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f: v43_s = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f: v43_c = pickle.load(f)

    # 2. RC1 (Candidate B)
    with open(ROOT / "messages_v4_4/models/candidate_b_refined/model.pkl", "rb") as f: rc1_m = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/candidate_b_refined/scaler.pkl", "rb") as f: rc1_s = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/candidate_b_refined/word_vec.pkl", "rb") as f: rc1_w = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/candidate_b_refined/char_vec.pkl", "rb") as f: rc1_c = pickle.load(f)

    # 3. RC2-Exp1
    with open(ROOT / "messages_v4_4/models/rc2_experiment_1/model.pkl", "rb") as f: exp1_m = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/rc2_experiment_1/scaler.pkl", "rb") as f: exp1_s = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/rc2_experiment_1/word_vec.pkl", "rb") as f: exp1_w = pickle.load(f)
    with open(ROOT / "messages_v4_4/models/rc2_experiment_1/char_vec.pkl", "rb") as f: exp1_c = pickle.load(f)

    # 4. RC2-Exp2
    exp2_dir = ROOT / "messages_v4_4/models/rc2_experiment_2"
    with open(exp2_dir / "model.pkl", "rb") as f: exp2_m = pickle.load(f)
    with open(exp2_dir / "scaler.pkl", "rb") as f: exp2_s = pickle.load(f)
    with open(exp2_dir / "word_vec.pkl", "rb") as f: exp2_w = pickle.load(f)
    with open(exp2_dir / "char_vec.pkl", "rb") as f: exp2_c = pickle.load(f)
    with open(exp2_dir / "config.json", "r", encoding="utf-8") as f: exp2_cfg = json.load(f)
    THRESHOLD_EXP2 = exp2_cfg.get("validation_threshold", 0.680)

    print(f"Loaded all models. Thresholds: V4.3={THRESHOLD_V43}, RC1={THRESHOLD_V44_B}, Exp1={THRESHOLD_EXP1}, Exp2={THRESHOLD_EXP2}", flush=True)

    def predict_m(texts, m, s, w, c):
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        X = np.hstack([st, w.transform(texts).toarray(), c.transform(texts).toarray()]).astype(np.float32)
        return m.predict_proba(s.transform(X))

    def eval_suite(rows, probs, threshold):
        y_true = np.array([LABELS.get(r.get("security_label") or r.get("label"), 0) for r in rows], dtype=np.int32)
        p_nb = probs[:, 1] + probs[:, 2]
        y_pred = np.where(p_nb >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

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

    suites = [
        ("Validation Split", ROOT / "data/processed/val.jsonl", "INTERNAL_VALIDATION"),
        ("Test Split", ROOT / "data/processed/test.jsonl", "PRIMARY_BENCHMARK"),
        ("Out-of-Distribution (OOD)", ROOT / "data/processed/ood.jsonl", "PRIMARY_BENCHMARK"),
    ]
    suites += [(f"slice_{p.stem}", p, "LEGACY_BENCHMARK") for p in sorted((ROOT / "data/benchmarks").glob("*.jsonl"))]
    suites += [(p.stem, p, "LEGACY_BENCHMARK") for p in sorted((ROOT.parent / "7sep_messages_v3/data").glob("bench_*.jsonl"))]
    suites.append(("independent_semantic_suite", ROOT / "messages_v4_3/evaluation/independent_semantic_generalization.jsonl", "INDEPENDENT_EVALUATION"))
    suites += [(f"regression_probe_{p.stem}", p, "TARGETED_REGRESSION_PROBE") for p in sorted((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))]

    # Clean OOD
    train_rows = [json.loads(line) for line in open(ROOT / "messages_v4_4/data/train_v4_4_rc2_exp2.jsonl", encoding="utf-8") if line.strip()]
    train_norm_keys = {norm_aggressive(r.get("raw_text", "")) for r in train_rows}
    all_ood = [json.loads(line) for line in open(ROOT / "data/processed/ood.jsonl", encoding="utf-8") if line.strip()]
    clean_ood = [r for r in all_ood if norm_aggressive(r.get("raw_text", "")) not in train_norm_keys]

    results = []
    print("\nEvaluating across all suites...", flush=True)

    for suite_name, p, prov_type in suites:
        if not p.exists(): continue
        rows = read_jsonl(p)
        if not rows: continue
        texts = [r.get("raw_text") or r.get("text", "") for r in rows]

        pv43 = predict_m(texts, v43_m, v43_s, v43_w, v43_c)
        prc1 = predict_m(texts, rc1_m, rc1_s, rc1_w, rc1_c)
        pexp1 = predict_m(texts, exp1_m, exp1_s, exp1_w, exp1_c)
        pexp2 = predict_m(texts, exp2_m, exp2_s, exp2_w, exp2_c)

        results.append({
            "suite": suite_name,
            "provenance_type": prov_type,
            "n_total": len(rows),
            "n_benign": eval_suite(rows, pexp2, THRESHOLD_EXP2)["n_benign"],
            "n_malicious": eval_suite(rows, pexp2, THRESHOLD_EXP2)["n_malicious"],
            "v43": eval_suite(rows, pv43, THRESHOLD_V43),
            "rc1": eval_suite(rows, prc1, THRESHOLD_V44_B),
            "exp1": eval_suite(rows, pexp1, THRESHOLD_EXP1),
            "exp2": eval_suite(rows, pexp2, THRESHOLD_EXP2),
        })

    # Clean OOD
    clean_texts = [r.get("raw_text") for r in clean_ood]
    pv43 = predict_m(clean_texts, v43_m, v43_s, v43_w, v43_c)
    prc1 = predict_m(clean_texts, rc1_m, rc1_s, rc1_w, rc1_c)
    pexp1 = predict_m(clean_texts, exp1_m, exp1_s, exp1_w, exp1_c)
    pexp2 = predict_m(clean_texts, exp2_m, exp2_s, exp2_w, exp2_c)
    results.append({
        "suite": "Clean_OOD_Zero_Overlap",
        "provenance_type": "PROVENANCE_CLEAN_OOD",
        "n_total": len(clean_ood),
        "n_benign": int(sum(1 for r in clean_ood if r.get("security_label") == "BENIGN")),
        "n_malicious": int(sum(1 for r in clean_ood if r.get("security_label") == "MALICIOUS")),
        "v43": eval_suite(clean_ood, pv43, THRESHOLD_V43),
        "rc1": eval_suite(clean_ood, prc1, THRESHOLD_V44_B),
        "exp1": eval_suite(clean_ood, pexp1, THRESHOLD_EXP1),
        "exp2": eval_suite(clean_ood, pexp2, THRESHOLD_EXP2),
    })

    # Real Mobile Simulation
    sim_path = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\6sep\simulation\SIMULATION_CASES.jsonl")
    sim_rows = [json.loads(line) for line in open(sim_path, encoding="utf-8") if line.strip()]
    sim_texts = [r.get("content") or "" for r in sim_rows]
    sim_formatted = [{"raw_text": r.get("content") or "", "security_label": "MALICIOUS" if r.get("ground_truth_class") == "TRUE_POSITIVE_MALICIOUS_URL" else "BENIGN"} for r in sim_rows]

    pv43 = predict_m(sim_texts, v43_m, v43_s, v43_w, v43_c)
    prc1 = predict_m(sim_texts, rc1_m, rc1_s, rc1_w, rc1_c)
    pexp1 = predict_m(sim_texts, exp1_m, exp1_s, exp1_w, exp1_c)
    pexp2 = predict_m(sim_texts, exp2_m, exp2_s, exp2_w, exp2_c)

    results.append({
        "suite": "Real_Mobile_Simulation_Cases",
        "provenance_type": "REAL_DEVICE_SIMULATION",
        "n_total": len(sim_rows),
        "n_benign": 291,
        "n_malicious": 3,
        "v43": eval_suite(sim_formatted, pv43, THRESHOLD_V43),
        "rc1": eval_suite(sim_formatted, prc1, THRESHOLD_V44_B),
        "exp1": eval_suite(sim_formatted, pexp1, THRESHOLD_EXP1),
        "exp2": eval_suite(sim_formatted, pexp2, THRESHOLD_EXP2),
    })

    # Save results json
    out_json = ROOT / "messages_v4_4/reports/rc2_exp2_comparative_eval.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "thresholds": {"V4.3": THRESHOLD_V43, "V4.4_RC1": THRESHOLD_V44_B, "RC2_Exp1": THRESHOLD_EXP1, "RC2_Exp2": THRESHOLD_EXP2},
            "suites": results
        }, f, indent=2)

    # Print Table
    print("\n" + "=" * 170)
    print("SENTINEL MESSAGES RC2 EXPERIMENT 2 COMPARATIVE EVALUATION MATRIX")
    print(f"V4.3 (tau={THRESHOLD_V43}) | V4.4-RC1 (tau={THRESHOLD_V44_B}) | RC2-Exp1 (tau={THRESHOLD_EXP1}) | RC2-Exp2 (tau={THRESHOLD_EXP2})")
    print("=" * 170)
    header = f"{'Suite Name':<38s} | {'Type':<18s} | {'N':>5s} | {'V4.3 FP':>7s} | {'RC1 FP':>7s} | {'Exp1 FP':>7s} | {'Exp2 FP':>7s} | {'V4.3 Mal':>8s} | {'RC1 Mal':>8s} | {'Exp2 Mal':>8s}"
    print(header)
    print("-" * len(header))

    for r in results:
        sname = r["suite"]
        ptype = r["provenance_type"][:18]
        n_tot = r["n_total"]
        nb = r["n_benign"]
        nm = r["n_malicious"]

        v43_fp = f"{r['v43']['benign_fp']}/{nb}" if nb > 0 else "N/A"
        rc1_fp = f"{r['rc1']['benign_fp']}/{nb}" if nb > 0 else "N/A"
        exp1_fp = f"{r['exp1']['benign_fp']}/{nb}" if nb > 0 else "N/A"
        exp2_fp = f"{r['exp2']['benign_fp']}/{nb}" if nb > 0 else "N/A"

        v43_mal = f"{r['v43']['malicious_correct']}/{nm}" if nm > 0 else "N/A"
        rc1_mal = f"{r['rc1']['malicious_correct']}/{nm}" if nm > 0 else "N/A"
        exp2_mal = f"{r['exp2']['malicious_correct']}/{nm}" if nm > 0 else "N/A"

        print(f"{sname:<38s} | {ptype:<18s} | {n_tot:>5d} | {v43_fp:>7s} | {rc1_fp:>7s} | {exp1_fp:>7s} | {exp2_fp:>7s} | {v43_mal:>8s} | {rc1_mal:>8s} | {exp2_mal:>8s}")

    # Key Probes
    probes = {
        "ELEC_001": ("Dear customer your electricity power will be disconnected tonight at 9:30 PM because your previous bill was not updated. Please immediately contact our electricity officer at 9876543210.", "MALICIOUS"),
        "ELEC_002": ("Dear consumer, your electricity power will be disconnected today at 9.30 pm from electricity office because your previous month bill was not update please immediately contact our officer 8249033481 thank you.", "MALICIOUS"),
        "ELEC_003": ("Bijli bill update nahi hua hai. Aaj raat line disconnect ho jayegi. Turant call kare: 9812345678", "MALICIOUS"),
        "GREET_HI": ("Hi", "BENIGN"),
        "GREET_HELLO": ("Hello", "BENIGN"),
        "GREET_HELLO_P": ("Hello.", "BENIGN"),
        "GREET_HEY_BRO": ("Hey bro, what are you doing tonight?", "BENIGN"),
        "APK_PAYLOAD": ("Your cashback coupon is ready. Download our partner app to redeem: http://cashback-hub.net/rewards.apk", "MALICIOUS"),
        "BENIGN_UTIL_2": ("Dear Consumer, your electricity bill of Rs 1,420 for Consumer No 10293847 is due on 22-Sep. Pay online via msedcl.gov.in", "BENIGN"),
    }

    probe_texts = [p[0] for p in probes.values()]
    pv43 = predict_m(probe_texts, v43_m, v43_s, v43_w, v43_c)
    prc1 = predict_m(probe_texts, rc1_m, rc1_s, rc1_w, rc1_c)
    pexp1 = predict_m(probe_texts, exp1_m, exp1_s, exp1_w, exp1_c)
    pexp2 = predict_m(probe_texts, exp2_m, exp2_s, exp2_w, exp2_c)

    print("\n" + "=" * 135)
    print("DIAGNOSTIC PROBE COMPARISON: V4.3 vs V4.4-RC1 vs RC2-Exp1 vs RC2-Exp2")
    print("=" * 135)
    print(f"{'Probe ID':<15} | {'Expected':<10} | {'V4.3 Prob':<10} | {'RC1 Prob':<10} | {'Exp1 Prob':<10} | {'Exp2 Prob':<10} | {'Exp2 Label':<10} | {'Status'}")
    print("-" * 135)

    for i, (pid, (text, exp)) in enumerate(probes.items()):
        p43 = pv43[i, 1] + pv43[i, 2]
        pr = prc1[i, 1] + prc1[i, 2]
        pe1 = pexp1[i, 1] + pexp1[i, 2]
        pe2 = pexp2[i, 1] + pexp2[i, 2]
        pred_label = "MALICIOUS" if pe2 >= THRESHOLD_EXP2 and pexp2[i, 2] >= pexp2[i, 1] else ("SUSPICIOUS_SPAM" if pe2 >= THRESHOLD_EXP2 else "BENIGN")
        status = "PASS" if pred_label == exp else "FAIL"
        print(f"{pid:<15} | {exp:<10} | {p43:<10.4f} | {pr:<10.4f} | {pe1:<10.4f} | {pe2:<10.4f} | {pred_label:<10} | {status}")

if __name__ == "__main__":
    main()
