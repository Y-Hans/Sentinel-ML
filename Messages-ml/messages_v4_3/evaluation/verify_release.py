"""
Verification script for Sentinel Messages V4.3 release.
Independent re-evaluation of all 19 benchmark suites + splits from scratch.
"""
import pickle
import json
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

# Load V2 Baseline
print("Loading Champion V2 artifacts...")
with open(ROOT / "champion_v2_model.pkl", "rb") as f:
    v2_model = pickle.load(f)
with open(ROOT / "champion_v2_scaler.pkl", "rb") as f:
    v2_scaler = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_word.pkl", "rb") as f:
    v2_word = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_char.pkl", "rb") as f:
    v2_char = pickle.load(f)

# Load V4.3 Candidate D
print("Loading Candidate D V4.3 artifacts...")
with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f:
    v43_model = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f:
    v43_scaler = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f:
    v43_word = pickle.load(f)
with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f:
    v43_char = pickle.load(f)

def v2_predict_proba(texts):
    det = np.asarray([extract_feature_vector(t, None, FeatureConfig()) for t in texts], dtype=np.float32)
    w = v2_word.transform(texts).toarray()
    c = v2_char.transform(texts).toarray()
    X = np.hstack([det, w, c])
    return v2_model.predict_proba(v2_scaler.transform(X))

def v43_predict_proba(texts):
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w = v43_word.transform(texts).toarray()
    c = v43_char.transform(texts).toarray()
    X = np.hstack([st, w, c]).astype(np.float32)
    return v43_model.predict_proba(v43_scaler.transform(X))

def compute_suite_metrics(rows, probs, threshold):
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

    pred_ben = int((y_pred == 0).sum())
    pred_susp = int((y_pred == 1).sum())
    pred_mal = int((y_pred == 2).sum())

    return {
        "n_total": n_total,
        "n_benign": n_ben,
        "benign_fp": ben_fp,
        "benign_fpr": ben_fpr,
        "n_malicious": n_mal,
        "malicious_correct": mal_correct,
        "malicious_recall": mal_recall,
        "pred_benign": pred_ben,
        "pred_suspicious": pred_susp,
        "pred_malicious": pred_mal,
        "threshold": threshold,
    }

def main():
    # 1. Validation Threshold Sweep (V4.3)
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
    val_texts = [r["raw_text"] for r in val_rows]
    val_probs = v43_predict_proba(val_texts)

    print("\n" + "="*80)
    print("VALIDATION THRESHOLD SWEEP (V4.3) — GATE CRITERION: FPR <= 2.0%")
    print("="*80)
    sweep_table = []
    for t_val in np.arange(0.50, 0.76, 0.01):
        t = round(float(t_val), 2)
        m = compute_suite_metrics(val_rows, val_probs, t)
        gate_status = "PASS" if m["benign_fpr"] <= 0.02 else "FAIL"
        sweep_table.append((t, m["malicious_correct"], m["n_malicious"], m["malicious_recall"], m["benign_fp"], m["n_benign"], m["benign_fpr"], gate_status))
        if t in [0.55, 0.58, 0.60, 0.61, 0.62, 0.65, 0.70, 0.704]:
            print(f"tau={t:.2f} | Mal Recall: {m['malicious_correct']}/{m['n_malicious']} ({m['malicious_recall']*100:.2f}%) | Benign FP: {m['benign_fp']}/{m['n_benign']} ({m['benign_fpr']*100:.2f}%) | Gate FPR <= 2%: {gate_status}")

    frozen_v43_threshold = 0.61
    frozen_v2_threshold = 0.704
    print(f"\nLocked V4.3 Validation Threshold: {frozen_v43_threshold}")
    print(f"Frozen V2 Baseline Threshold:     {frozen_v2_threshold}")

    # 2. Gather All Suites
    all_suites = [
        ("Validation Split", ROOT / "data/processed/val.jsonl"),
        ("Test Split", ROOT / "data/processed/test.jsonl"),
        ("Out-of-Distribution (OOD)", ROOT / "data/processed/ood.jsonl"),
    ]

    p1 = sorted(list((ROOT / "data/benchmarks").glob("*.jsonl")), key=lambda x: x.name)
    for p in p1:
        all_suites.append((f"slice_{p.stem}", p))

    p2 = sorted(list((ROOT.parent / "7sep_messages_v3/data").glob("bench_*.jsonl")), key=lambda x: x.name)
    for p in p2:
        all_suites.append((p.stem, p))

    print(f"\nTotal Evaluation Suites to Report: {len(all_suites)}")

    # 3. Machine-Generate the 19+ Suite Table
    results = []
    print("\nEvaluating all suites independently across V2 and V4.3...")
    for suite_name, p in all_suites:
        if not p.exists():
            print(f"Skipping {suite_name} (file not found: {p})")
            continue
        rows = read_jsonl(p)
        if not rows:
            continue
        texts = [r.get("raw_text", "") for r in rows]

        # V2 eval
        probs_v2 = v2_predict_proba(texts)
        m_v2 = compute_suite_metrics(rows, probs_v2, frozen_v2_threshold)

        # V4.3 eval
        probs_v43 = v43_predict_proba(texts)
        m_v43 = compute_suite_metrics(rows, probs_v43, frozen_v43_threshold)

        results.append({
            "suite": suite_name,
            "path": str(p),
            "n_total": m_v43["n_total"],
            "n_benign": m_v43["n_benign"],
            "v2_benign_fp": m_v2["benign_fp"],
            "v2_benign_fpr": m_v2["benign_fpr"],
            "v43_benign_fp": m_v43["benign_fp"],
            "v43_benign_fpr": m_v43["benign_fpr"],
            "n_malicious": m_v43["n_malicious"],
            "v2_mal_correct": m_v2["malicious_correct"],
            "v2_mal_recall": m_v2["malicious_recall"],
            "v43_mal_correct": m_v43["malicious_correct"],
            "v43_mal_recall": m_v43["malicious_recall"],
            "v2_pred_susp": m_v2["pred_suspicious"],
            "v43_pred_susp": m_v43["pred_suspicious"],
        })

    # Output JSON and Markdown
    out_json = ROOT / "messages_v4_3/evaluation/independent_release_verification.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "threshold_v4_3": frozen_v43_threshold,
            "threshold_v2": frozen_v2_threshold,
            "sweep": sweep_table,
            "suites": results
        }, f, indent=2)
    print(f"Saved full JSON to {out_json}")

    # Print Table
    print("\n" + "="*140)
    print("COMPLETE MACHINE-GENERATED 19-SUITE RELEASE TABLE")
    print("="*140)
    header = f"{'Suite Name':<38s} | {'N':>5s} | {'Ben N':>5s} | {'V2 Ben FP':>11s} | {'V4.3 Ben FP':>11s} | {'Mal N':>5s} | {'V2 Mal Rec':>11s} | {'V4.3 Mal Rec':>12s} | {'Delta Rec':>10s} | {'V4.3 Susp':>9s}"
    print(header)
    print("-" * len(header))

    for r in results:
        v2_ben_str = f"{r['v2_benign_fp']}/{r['n_benign']}" if r['n_benign'] > 0 else "N/A"
        v43_ben_str = f"{r['v43_benign_fp']}/{r['n_benign']}" if r['n_benign'] > 0 else "N/A"
        
        v2_rec_str = f"{r['v2_mal_correct']}/{r['n_malicious']}" if r['n_malicious'] > 0 else "N/A"
        v43_rec_str = f"{r['v43_mal_correct']}/{r['n_malicious']}" if r['n_malicious'] > 0 else "N/A"

        if r['n_malicious'] > 0:
            d_rec = (r['v43_mal_recall'] - r['v2_mal_recall']) * 100
            delta_str = f"{d_rec:+.2f}%"
        else:
            delta_str = "N/A"

        print(f"{r['suite']:<38s} | {r['n_total']:5d} | {r['n_benign']:5d} | {v2_ben_str:>11s} | {v43_ben_str:>11s} | {r['n_malicious']:5d} | {v2_rec_str:>11s} | {v43_rec_str:>12s} | {delta_str:>10s} | {r['v43_pred_susp']:9d}")

if __name__ == "__main__":
    main()
