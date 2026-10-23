"""
Sentinel Phase 1D.1: Isolated Apex-Threshold Prototype (A0 / A1 / A2)
Author: Sentinel AI ML Engineering Team
Status: AUTHORIZED ISOLATED EVALUATION STAGE 1

Scope & Safeguards:
1. Operates exclusively on frozen V8 champion binary (hash: 073e70f2...).
2. Zero model retraining. Zero production code edits. Zero Git mutations.
3. Tests A0 (tau=0.2800), A1 (apex tau=0.5500), and A2 (apex tau=0.6500) independently.
4. Uses identical frozen raw model predictions across all three policies.
5. Employs exact V8 normalization for bare-apex qualification with excluded IP hosts and suspicious TLDs.
6. Evaluates against all seven pre-registered gates with explicit PASS / WARNING / HARD_FAIL boundaries.
"""

from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sys
import time
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

# Path configuration
EXP_DIR = Path(__file__).resolve().parent
URL_ML_DIR = EXP_DIR.parents[1]
DATA_DIR = URL_ML_DIR / "data"
MODELS_DIR = URL_ML_DIR / "models"
REPORTS_DIR = URL_ML_DIR / "reports"
SCRIPTS_DIR = URL_ML_DIR / "scripts"
PROJECT_ROOT = EXP_DIR.parents[3]
ANDROID_RES_DIR = PROJECT_ROOT / "sentinel-ai" / "android-app" / "core" / "src" / "test" / "resources"

sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(URL_ML_DIR / "experiments" / "phase_1c_2b_2a_s2_f"))

import run_balanced_experiment_protocol_repaired as proto
proto.ANDROID_RES_DIR = ANDROID_RES_DIR

from v7_features import vectorize_v7, V7_FEATURE_NAMES, SUSPICIOUS_TLDS, _subdomain_depth
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url

EXPECTED_V8_CHAMPION_HASH = "073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58"


def get_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Calculate score and Wilson score interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    z = 1.959963984540054  # 95% confidence
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    spread = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n) / denom
    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return float(p), float(lower), float(upper)


def compute_binary_metrics(y_true: np.ndarray, preds: np.ndarray, probs: np.ndarray) -> Dict[str, Any]:
    """Compute detailed binary classification metrics given binary predictions and probabilities."""
    n = len(y_true)
    y_true_bin = (y_true == 1).astype(int)
    preds_bin = (preds == 1).astype(int)

    tp = int(np.sum((preds_bin == 1) & (y_true_bin == 1)))
    fp = int(np.sum((preds_bin == 1) & (y_true_bin == 0)))
    fn = int(np.sum((preds_bin == 0) & (y_true_bin == 1)))
    tn = int(np.sum((preds_bin == 0) & (y_true_bin == 0)))

    n_pos = tp + fn
    n_neg = tn + fp

    rec, rec_lo, rec_hi = wilson_ci(tp, n_pos) if n_pos > 0 else (0.0, 0.0, 0.0)
    fpr, fpr_lo, fpr_hi = wilson_ci(fp, n_neg) if n_neg > 0 else (0.0, 0.0, 0.0)
    prec, prec_lo, prec_hi = wilson_ci(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0, 0.0)

    return {
        "n_total": n,
        "n_pos": n_pos,
        "n_neg": n_neg,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "recall": rec,
        "recall_95ci": [rec_lo, rec_hi],
        "fpr": fpr,
        "fpr_95ci": [fpr_lo, fpr_hi],
        "precision": prec,
        "precision_95ci": [prec_lo, prec_hi],
        "mean_prob": float(np.mean(probs)) if n > 0 else 0.0
    }


IDX_SUSP_TLD = V7_FEATURE_NAMES.index("SuspiciousTLD")
IDX_IS_IP = V7_FEATURE_NAMES.index("IsDomainIP")


def is_bare_apex_qualified(url: str, feat_vec: np.ndarray | None = None) -> bool:
    """Exact bare-apex qualification under V8 normalization with excluded IP and suspicious TLDs."""
    p = parse_v8_url(url)
    
    # 1. IP Host exclusion
    if p.is_ip:
        return False
        
    # 2. Suspicious TLD exclusion
    tld = p.parent_domain.split(".")[-1].lower() if "." in p.parent_domain else ""
    if tld in SUSPICIOUS_TLDS:
        return False
    if feat_vec is not None:
        if feat_vec[IDX_SUSP_TLD] > 0.0 or feat_vec[IDX_IS_IP] > 0.0:
            return False

    # 3. Path and Query must be strictly empty
    clean_p = p.clean_path.strip("/")
    if clean_p != "":
        return False
    if p.query.strip() != "":
        return False

    # 4. Zero subdomains under multi-label public suffix normalization
    if len(p.subdomain_labels) != 0:
        return False

    return True


def evaluate_policy_on_corpus(
    urls: List[str],
    y_true: np.ndarray,
    X_mat: np.ndarray,
    raw_probs: np.ndarray,
    v8_adj_probs: np.ndarray,
    policy_name: str,
    apex_threshold: float = 0.2800,
    standard_threshold: float = 0.2800
) -> Dict[str, Any]:
    """Evaluate a specific threshold policy against frozen probabilities."""
    n = len(urls)
    is_apex = np.array([is_bare_apex_qualified(urls[i], X_mat[i]) for i in range(n)], dtype=bool)

    # Predictions
    # Non-apex URLs always evaluate at standard_threshold (0.2800)
    # Qualified bare-apex URLs evaluate at apex_threshold
    preds = np.empty(n, dtype=int)
    for i in range(n):
        thresh = apex_threshold if is_apex[i] else standard_threshold
        preds[i] = 1 if v8_adj_probs[i] >= thresh else 0

    metrics = compute_binary_metrics(y_true, preds, v8_adj_probs)
    metrics["n_apex_qualified"] = int(np.sum(is_apex))
    metrics["apex_threshold"] = float(apex_threshold)
    metrics["standard_threshold"] = float(standard_threshold)
    metrics["policy_name"] = policy_name

    return {
        "metrics": metrics,
        "is_apex": is_apex,
        "preds": preds
    }


def verify_gate_policy(
    results: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Verify all 7 pre-registered gates under the 3-tier PASS / WARNING / HARD_FAIL policy."""
    gates = {}
    
    # Gate 1: Clean Test Malicious Recall (N = 23,158)
    # Target: >= 98.600%, Warning: [98.400%, 98.600%), Hard Fail: < 98.400%
    g1_rec = results["clean_test"]["metrics"]["recall"]
    if g1_rec >= 0.98600:
        g1_stat = "PASS"
    elif g1_rec >= 0.98400:
        g1_stat = "WARNING_REVIEW"
    else:
        g1_stat = "HARD_FAIL"
    gates["Gate_1_Clean_Test_Recall"] = {
        "target": ">= 0.98600", "warning_range": "[0.98400, 0.98600)", "hard_fail": "< 0.98400",
        "value": float(g1_rec), "tp": int(results["clean_test"]["metrics"]["tp"]),
        "n": int(results["clean_test"]["metrics"]["n_pos"]), "status": g1_stat
    }

    # Gate 2: Clean Test Benign FPR (N = 27,353)
    # Target: <= 0.962%, Warning: (0.962%, 1.000%], Hard Fail: > 1.000%
    g2_fpr = results["clean_test"]["metrics"]["fpr"]
    if g2_fpr <= 0.00962:
        g2_stat = "PASS"
    elif g2_fpr <= 0.01000:
        g2_stat = "WARNING_REVIEW"
    else:
        g2_stat = "HARD_FAIL"
    gates["Gate_2_Clean_Test_FPR"] = {
        "target": "<= 0.00962", "warning_range": "(0.00962, 0.01000]", "hard_fail": "> 0.01000",
        "value": float(g2_fpr), "fp": int(results["clean_test"]["metrics"]["fp"]),
        "n": int(results["clean_test"]["metrics"]["n_neg"]), "status": g2_stat
    }

    # Gate 3: Benchmark Bare-Apex FPR (N = 200, Category 1)
    # Target: <= 10.00%, Warning: (10.00%, 15.00%], Hard Fail: > 15.00%
    g3_fpr = results["benchmark_bare_apex"]["metrics"]["fpr"]
    if g3_fpr <= 0.1000:
        g3_stat = "PASS"
    elif g3_fpr <= 0.1500:
        g3_stat = "WARNING_REVIEW"
    else:
        g3_stat = "HARD_FAIL"
    gates["Gate_3_Benchmark_Bare_Apex_FPR"] = {
        "target": "<= 0.1000", "warning_range": "(0.1000, 0.1500]", "hard_fail": "> 0.1500",
        "value": float(g3_fpr), "fp": int(results["benchmark_bare_apex"]["metrics"]["fp"]),
        "n": int(results["benchmark_bare_apex"]["metrics"]["n_neg"]), "status": g3_stat
    }

    # Gate 4: Benchmark Overall FPR (N = 500)
    # Target: <= 45.00%, Warning: (45.00%, 50.00%], Hard Fail: > 50.00%
    g4_fpr = results["benchmark_overall"]["metrics"]["fpr"]
    if g4_fpr <= 0.4500:
        g4_stat = "PASS"
    elif g4_fpr <= 0.5000:
        g4_stat = "WARNING_REVIEW"
    else:
        g4_stat = "HARD_FAIL"
    gates["Gate_4_Benchmark_Overall_FPR"] = {
        "target": "<= 0.4500", "warning_range": "(0.4500, 0.5000]", "hard_fail": "> 0.5000",
        "value": float(g4_fpr), "fp": int(results["benchmark_overall"]["metrics"]["fp"]),
        "n": int(results["benchmark_overall"]["metrics"]["n_neg"]), "status": g4_stat
    }

    # Gate 5: Clean Test Phishing Bare-Apex Recall (N = 4,254)
    # Target: >= 98.000%, Warning: [97.500%, 98.000%), Hard Fail: < 97.500%
    g5_rec = results["test_phishing_bare_apex"]["metrics"]["recall"]
    if g5_rec >= 0.98000:
        g5_stat = "PASS"
    elif g5_rec >= 0.97500:
        g5_stat = "WARNING_REVIEW"
    else:
        g5_stat = "HARD_FAIL"
    gates["Gate_5_Test_Phishing_Apex_Recall"] = {
        "target": ">= 0.98000", "warning_range": "[0.97500, 0.98000)", "hard_fail": "< 0.97500",
        "value": float(g5_rec), "tp": int(results["test_phishing_bare_apex"]["metrics"]["tp"]),
        "n": int(results["test_phishing_bare_apex"]["metrics"]["n_pos"]), "status": g5_stat
    }

    # Gate 6: Remediation Adversarial Recall (N = 3,900)
    # Target: >= 97.000%, Warning: [96.500%, 97.000%), Hard Fail: < 96.500%
    g6_rec = results["adversarial_split"]["metrics"]["recall"]
    if g6_rec >= 0.97000:
        g6_stat = "PASS"
    elif g6_rec >= 0.96500:
        g6_stat = "WARNING_REVIEW"
    else:
        g6_stat = "HARD_FAIL"
    gates["Gate_6_Adversarial_Recall"] = {
        "target": ">= 0.97000", "warning_range": "[0.96500, 0.97000)", "hard_fail": "< 0.96500",
        "value": float(g6_rec), "tp": int(results["adversarial_split"]["metrics"]["tp"]),
        "n": int(results["adversarial_split"]["metrics"]["n_pos"]), "status": g6_stat
    }

    # Gate 7: Android Golden Parity (N = 174)
    # Target: Exactly 0 regressions, Hard Fail: >= 1 regression
    g7_reg = results["golden_fixtures"]["regressions_count"]
    g7_stat = "PASS" if g7_reg == 0 else "HARD_FAIL"
    gates["Gate_7_Android_Golden_Parity"] = {
        "target": "0 regressions", "warning_range": "None permitted", "hard_fail": ">= 1 regression",
        "regressions_count": int(g7_reg), "status": g7_stat
    }

    # Overall Verdict
    statuses = [g["status"] for g in gates.values()]
    if "HARD_FAIL" in statuses:
        overall = "HARD_FAIL"
    elif "WARNING_REVIEW" in statuses:
        overall = "WARNING_REVIEW"
    else:
        overall = "ALL_GATES_PASSED"

    return {"gates": gates, "overall_verdict": overall}


def main():
    start_time = time.time()
    iso_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))
    print("=" * 80)
    print(f"SENTINEL PHASE 1D.1: ISOLATED APEX-THRESHOLD PROTOTYPE (A0/A1/A2): {iso_time}")
    print("=" * 80)

    # 1. Verify V8 Champion Model Invariance
    champ_path = MODELS_DIR / "v8_champion.joblib"
    assert champ_path.exists(), f"Missing champion: {champ_path}"
    champ_sha = get_file_sha256(champ_path)
    champ_sz = champ_path.stat().st_size
    print(f"\n[+] Champion V8 Hash: {champ_sha} ({champ_sz} bytes)")
    assert champ_sha == EXPECTED_V8_CHAMPION_HASH, f"FATAL: Champion hash mismatch: {champ_sha}"

    # Record input hashes
    input_files = {
        "v8_champion": champ_path,
        "cleaned_dataset": DATA_DIR / "cleaned_dataset.csv",
        "hard_benign_benchmark": DATA_DIR / "hard_benign_benchmark_500.json",
        "adversarial_predictions": REPORTS_DIR / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv",
        "golden_urls_v8": ANDROID_RES_DIR / "golden_urls_v8.json"
    }
    input_hashes = {}
    for k, p in input_files.items():
        assert p.exists(), f"Missing file: {p}"
        h = get_file_sha256(p)
        input_hashes[k] = {"path": str(p), "sha256": h, "size": p.stat().st_size}
        print(f"  Verified {k}: {h} ({p.stat().st_size} bytes)")

    # 2. Load Evaluation Datasets
    print("\n--- Loading Evaluation Corpora ---")
    data = proto.prepare_datasets()
    val_df = data["val_df"]
    test_df = data["test_df"]
    bench_data = data["bench_data"]
    adv_df = data["adv_df"]
    golden_data = data["golden_data"]

    test_urls = test_df["url"].tolist()
    y_test = test_df["label"].to_numpy()

    bench_urls = [b["url"] for b in bench_data]
    y_bench = np.zeros(len(bench_urls), dtype=int)
    bench_apex_idx = [i for i, b in enumerate(bench_data) if b.get("category") == "bare_apex"]

    adv_urls = adv_df["url"].tolist()
    y_adv = adv_df["label"].to_numpy()

    golden_urls = [g["url"] for g in golden_data]
    y_golden = np.array([int(g["isMalicious"]) for g in golden_data])

    val_urls = val_df["url"].tolist()
    y_val = val_df["label"].to_numpy()

    print(f"Loaded Clean Test: {len(test_urls)} (Malicious: {int(np.sum(y_test==1))}, Benign: {int(np.sum(y_test==0))})")
    print(f"Loaded Diagnostic Benchmark: {len(bench_urls)} (Bare Apex: {len(bench_apex_idx)})")
    print(f"Loaded Adversarial: {len(adv_urls)}")
    print(f"Loaded Golden Fixtures: {len(golden_urls)}")

    # 3. Vectorization and Inference on Frozen V8 Champion
    print("\n--- Running Single Authorized Inference on Frozen V8 Champion ---")
    champ_model: V8RelationalURLClassifier = joblib.load(champ_path)

    corpora = [
        ("clean_test", test_urls, y_test),
        ("benchmark_overall", bench_urls, y_bench),
        ("adversarial_split", adv_urls, y_adv),
        ("golden_fixtures", golden_urls, y_golden),
        ("validation", val_urls, y_val)
    ]

    frozen_preds = {}
    for name, urls, y_arr in corpora:
        print(f"Vectorizing & Scoring {name} (N = {len(urls)})...")
        t0 = time.time()
        X_mat, feat_names = vectorize_v7(urls)
        raw_p = champ_model.base_model.predict_proba(X_mat)[:, 1]
        final_p = champ_model.predict_proba(X_mat, urls=urls)[:, 1]
        print(f"  Finished {name} in {time.time()-t0:.2f}s (mean raw: {np.mean(raw_p):.4f}, mean final: {np.mean(final_p):.4f})")
        frozen_preds[name] = {
            "urls": urls,
            "y_true": y_arr,
            "X": X_mat,
            "raw_probs": raw_p,
            "v8_adj_probs": final_p
        }

    # 4. Save Frozen Prediction Tables for Complete Traceability
    print("\n--- Preserving Frozen Model Predictions on Disk ---")
    df_test_preds = pd.DataFrame({
        "url": test_urls,
        "y_true": y_test,
        "raw_prob": frozen_preds["clean_test"]["raw_probs"],
        "v8_adj_prob": frozen_preds["clean_test"]["v8_adj_probs"]
    })
    test_preds_path = EXP_DIR / "clean_test_predictions_v8.csv"
    df_test_preds.to_csv(test_preds_path, index=False)
    print(f"Saved: {test_preds_path.name} ({test_preds_path.stat().st_size} bytes)")

    df_bench_preds = pd.DataFrame({
        "url": bench_urls,
        "category": [b.get("category", "") for b in bench_data],
        "y_true": y_bench,
        "raw_prob": frozen_preds["benchmark_overall"]["raw_probs"],
        "v8_adj_prob": frozen_preds["benchmark_overall"]["v8_adj_probs"]
    })
    bench_preds_path = EXP_DIR / "benchmark_predictions_v8.csv"
    df_bench_preds.to_csv(bench_preds_path, index=False)
    print(f"Saved: {bench_preds_path.name} ({bench_preds_path.stat().st_size} bytes)")

    df_adv_preds = pd.DataFrame({
        "url": adv_urls,
        "y_true": y_adv,
        "raw_prob": frozen_preds["adversarial_split"]["raw_probs"],
        "v8_adj_prob": frozen_preds["adversarial_split"]["v8_adj_probs"]
    })
    adv_preds_path = EXP_DIR / "adversarial_predictions_v8.csv"
    df_adv_preds.to_csv(adv_preds_path, index=False)
    print(f"Saved: {adv_preds_path.name} ({adv_preds_path.stat().st_size} bytes)")

    df_gold_preds = pd.DataFrame({
        "id": [g["id"] for g in golden_data],
        "url": golden_urls,
        "isMalicious": y_golden,
        "raw_prob": frozen_preds["golden_fixtures"]["raw_probs"],
        "v8_adj_prob": frozen_preds["golden_fixtures"]["v8_adj_probs"]
    })
    gold_preds_path = EXP_DIR / "golden_predictions_v8.csv"
    df_gold_preds.to_csv(gold_preds_path, index=False)
    print(f"Saved: {gold_preds_path.name} ({gold_preds_path.stat().st_size} bytes)")

    # 5. Evaluate Policies: A0, A1, A2
    print("\n--- Evaluating Independent Policies: A0, A1, A2 ---")
    policies = [
        ("A0_Baseline_V8", 0.2800),
        ("A1_Apex_Threshold_05500", 0.5500),
        ("A2_Apex_Threshold_06500", 0.6500)
    ]

    all_eval_results = {}
    decision_tables = {}

    for pol_name, apex_tau in policies:
        print(f"\nEvaluating Policy: {pol_name} (Apex tau = {apex_tau:.4f}, Standard tau = 0.2800)...")
        pol_res = {}

        # 1. Clean Test
        ct_eval = evaluate_policy_on_corpus(
            frozen_preds["clean_test"]["urls"],
            frozen_preds["clean_test"]["y_true"],
            frozen_preds["clean_test"]["X"],
            frozen_preds["clean_test"]["raw_probs"],
            frozen_preds["clean_test"]["v8_adj_probs"],
            pol_name,
            apex_threshold=apex_tau,
            standard_threshold=0.2800
        )
        pol_res["clean_test"] = ct_eval

        # 2. Test Phishing Bare Apex (Gate 5 cohort, N = 4,254)
        # Using exact V8 normalization bare apex definition
        mask_4254 = np.array([len(parse_v8_url(u).subdomain_labels) == 0 and y_test[i] == 1 for i, u in enumerate(test_urls)])
        idx_4254 = np.where(mask_4254)[0]
        apex_4254_preds = ct_eval["preds"][idx_4254]
        apex_4254_y = y_test[idx_4254]
        apex_4254_probs = frozen_preds["clean_test"]["v8_adj_probs"][idx_4254]
        pol_res["test_phishing_bare_apex"] = {
            "metrics": compute_binary_metrics(apex_4254_y, apex_4254_preds, apex_4254_probs)
        }

        # 3. Diagnostic Benchmark Overall (N = 500)
        bm_eval = evaluate_policy_on_corpus(
            frozen_preds["benchmark_overall"]["urls"],
            frozen_preds["benchmark_overall"]["y_true"],
            frozen_preds["benchmark_overall"]["X"],
            frozen_preds["benchmark_overall"]["raw_probs"],
            frozen_preds["benchmark_overall"]["v8_adj_probs"],
            pol_name,
            apex_threshold=apex_tau,
            standard_threshold=0.2800
        )
        pol_res["benchmark_overall"] = bm_eval

        # 4. Diagnostic Benchmark Bare Apex (N = 200, Category 1)
        bm_apex_preds = bm_eval["preds"][bench_apex_idx]
        bm_apex_y = y_bench[bench_apex_idx]
        bm_apex_probs = frozen_preds["benchmark_overall"]["v8_adj_probs"][bench_apex_idx]
        pol_res["benchmark_bare_apex"] = {
            "metrics": compute_binary_metrics(bm_apex_y, bm_apex_preds, bm_apex_probs)
        }

        # 5. Adversarial Split (N = 3,900)
        adv_eval = evaluate_policy_on_corpus(
            frozen_preds["adversarial_split"]["urls"],
            frozen_preds["adversarial_split"]["y_true"],
            frozen_preds["adversarial_split"]["X"],
            frozen_preds["adversarial_split"]["raw_probs"],
            frozen_preds["adversarial_split"]["v8_adj_probs"],
            pol_name,
            apex_threshold=apex_tau,
            standard_threshold=0.2800
        )
        pol_res["adversarial_split"] = adv_eval

        # 6. Golden Fixtures (N = 174)
        gold_eval = evaluate_policy_on_corpus(
            frozen_preds["golden_fixtures"]["urls"],
            frozen_preds["golden_fixtures"]["y_true"],
            frozen_preds["golden_fixtures"]["X"],
            frozen_preds["golden_fixtures"]["raw_probs"],
            frozen_preds["golden_fixtures"]["v8_adj_probs"],
            pol_name,
            apex_threshold=apex_tau,
            standard_threshold=0.2800
        )
        # Compute regressions vs V8 baseline
        # In baseline A0, v8 gold regressions is 0
        gold_preds = gold_eval["preds"]
        gold_regressions = int(np.sum(gold_preds != y_golden))
        gold_eval["regressions_count"] = gold_regressions
        pol_res["golden_fixtures"] = gold_eval

        # 7. Validation Split (N = 44,106)
        val_eval = evaluate_policy_on_corpus(
            frozen_preds["validation"]["urls"],
            frozen_preds["validation"]["y_true"],
            frozen_preds["validation"]["X"],
            frozen_preds["validation"]["raw_probs"],
            frozen_preds["validation"]["v8_adj_probs"],
            pol_name,
            apex_threshold=apex_tau,
            standard_threshold=0.2800
        )
        pol_res["validation"] = val_eval

        # 8. Evaluate 7 Gates
        gate_verdicts = verify_gate_policy(pol_res)
        pol_res["gate_verdicts"] = gate_verdicts

        print(f"Policy {pol_name} Gate Verdict: {gate_verdicts['overall_verdict']}")
        for g_id, g_info in gate_verdicts["gates"].items():
            print(f"  {g_id:<32}: {g_info['status']:<15} (Value: {g_info.get('value', g_info.get('regressions_count'))}, Target: {g_info['target']})")

        all_eval_results[pol_name] = pol_res
        decision_tables[pol_name] = {
            "clean_test_preds": ct_eval["preds"],
            "bench_preds": bm_eval["preds"],
            "adv_preds": adv_eval["preds"],
            "gold_preds": gold_eval["preds"]
        }

    # 6. Detailed Decision Deltas Analysis (Recording Every Flipped URL)
    print("\n--- Compiling Decision Change Records ---")
    decision_changes = []

    # A. Clean Test
    ct_preds_a0 = decision_tables["A0_Baseline_V8"]["clean_test_preds"]
    ct_preds_a1 = decision_tables["A1_Apex_Threshold_05500"]["clean_test_preds"]
    ct_preds_a2 = decision_tables["A2_Apex_Threshold_06500"]["clean_test_preds"]
    ct_adj_p = frozen_preds["clean_test"]["v8_adj_probs"]
    ct_raw_p = frozen_preds["clean_test"]["raw_probs"]

    for i in range(len(test_urls)):
        p0 = ct_preds_a0[i]
        p1 = ct_preds_a1[i]
        p2 = ct_preds_a2[i]
        if p1 != p0 or p2 != p0:
            u = test_urls[i]
            y = int(y_test[i])
            pu = parse_v8_url(u)
            impact_a1 = "NONE"
            if p1 != p0:
                impact_a1 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p1 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p1 == 0) else "OTHER")
            impact_a2 = "NONE"
            if p2 != p0:
                impact_a2 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p2 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p2 == 0) else "OTHER")

            decision_changes.append({
                "dataset": "clean_test",
                "id": f"test_{i:05d}",
                "url": u,
                "host": pu.host,
                "label": "MALICIOUS" if y == 1 else "BENIGN",
                "y_true": y,
                "raw_prob": float(ct_raw_p[i]),
                "v8_adj_prob": float(ct_adj_p[i]),
                "pred_a0": int(p0),
                "pred_a1": int(p1),
                "pred_a2": int(p2),
                "impact_a1": impact_a1,
                "impact_a2": impact_a2
            })

    # B. Benchmark v1.0
    bm_preds_a0 = decision_tables["A0_Baseline_V8"]["bench_preds"]
    bm_preds_a1 = decision_tables["A1_Apex_Threshold_05500"]["bench_preds"]
    bm_preds_a2 = decision_tables["A2_Apex_Threshold_06500"]["bench_preds"]
    bm_adj_p = frozen_preds["benchmark_overall"]["v8_adj_probs"]
    bm_raw_p = frozen_preds["benchmark_overall"]["raw_probs"]

    for i in range(len(bench_urls)):
        p0 = bm_preds_a0[i]
        p1 = bm_preds_a1[i]
        p2 = bm_preds_a2[i]
        if p1 != p0 or p2 != p0:
            u = bench_urls[i]
            pu = parse_v8_url(u)
            impact_a1 = "FP_ELIMINATED" if (p0 == 1 and p1 == 0) else "OTHER"
            impact_a2 = "FP_ELIMINATED" if (p0 == 1 and p2 == 0) else "OTHER"
            decision_changes.append({
                "dataset": "benchmark_v1",
                "id": f"bench_{i:03d}",
                "url": u,
                "host": pu.host,
                "label": "BENIGN",
                "y_true": 0,
                "raw_prob": float(bm_raw_p[i]),
                "v8_adj_prob": float(bm_adj_p[i]),
                "pred_a0": int(p0),
                "pred_a1": int(p1),
                "pred_a2": int(p2),
                "impact_a1": impact_a1,
                "impact_a2": impact_a2
            })

    # C. Adversarial Split
    adv_preds_a0 = decision_tables["A0_Baseline_V8"]["adv_preds"]
    adv_preds_a1 = decision_tables["A1_Apex_Threshold_05500"]["adv_preds"]
    adv_preds_a2 = decision_tables["A2_Apex_Threshold_06500"]["adv_preds"]
    adv_adj_p = frozen_preds["adversarial_split"]["v8_adj_probs"]
    adv_raw_p = frozen_preds["adversarial_split"]["raw_probs"]

    for i in range(len(adv_urls)):
        p0 = adv_preds_a0[i]
        p1 = adv_preds_a1[i]
        p2 = adv_preds_a2[i]
        if p1 != p0 or p2 != p0:
            u = adv_urls[i]
            y = int(y_adv[i])
            pu = parse_v8_url(u)
            impact_a1 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p1 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p1 == 0) else "OTHER")
            impact_a2 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p2 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p2 == 0) else "OTHER")
            decision_changes.append({
                "dataset": "adversarial_split",
                "id": f"adv_{i:04d}",
                "url": u,
                "host": pu.host,
                "label": "MALICIOUS" if y == 1 else "BENIGN",
                "y_true": y,
                "raw_prob": float(adv_raw_p[i]),
                "v8_adj_prob": float(adv_adj_p[i]),
                "pred_a0": int(p0),
                "pred_a1": int(p1),
                "pred_a2": int(p2),
                "impact_a1": impact_a1,
                "impact_a2": impact_a2
            })

    # D. Golden Fixtures
    gd_preds_a0 = decision_tables["A0_Baseline_V8"]["gold_preds"]
    gd_preds_a1 = decision_tables["A1_Apex_Threshold_05500"]["gold_preds"]
    gd_preds_a2 = decision_tables["A2_Apex_Threshold_06500"]["gold_preds"]
    gd_adj_p = frozen_preds["golden_fixtures"]["v8_adj_probs"]
    gd_raw_p = frozen_preds["golden_fixtures"]["raw_probs"]

    for i in range(len(golden_urls)):
        p0 = gd_preds_a0[i]
        p1 = gd_preds_a1[i]
        p2 = gd_preds_a2[i]
        if p1 != p0 or p2 != p0:
            u = golden_urls[i]
            y = int(y_golden[i])
            pu = parse_v8_url(u)
            impact_a1 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p1 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p1 == 0) else "REGRESSION")
            impact_a2 = "FP_ELIMINATED" if (y == 0 and p0 == 1 and p2 == 0) else ("TP_LOST_NEW_FN" if (y == 1 and p0 == 1 and p2 == 0) else "REGRESSION")
            decision_changes.append({
                "dataset": "golden_fixtures",
                "id": golden_data[i]["id"],
                "url": u,
                "host": pu.host,
                "label": "MALICIOUS" if y == 1 else "BENIGN",
                "y_true": y,
                "raw_prob": float(gd_raw_p[i]),
                "v8_adj_prob": float(gd_adj_p[i]),
                "pred_a0": int(p0),
                "pred_a1": int(p1),
                "pred_a2": int(p2),
                "impact_a1": impact_a1,
                "impact_a2": impact_a2
            })

    df_changes = pd.DataFrame(decision_changes)
    changes_path = EXP_DIR / "decision_changes_a0_a1_a2.csv"
    df_changes.to_csv(changes_path, index=False)
    print(f"Recorded {len(df_changes)} total decision flips across all corpora -> {changes_path.name}")
    print(f"  Clean Test Flips: {sum(1 for x in decision_changes if x['dataset'] == 'clean_test')}")
    print(f"  Benchmark Flips: {sum(1 for x in decision_changes if x['dataset'] == 'benchmark_v1')}")
    print(f"  Golden Fixture Flips: {sum(1 for x in decision_changes if x['dataset'] == 'golden_fixtures')}")

    # 7. Strip non-serializable arrays and compile final JSON
    clean_output_results = {}
    for p_k, p_v in all_eval_results.items():
        clean_output_results[p_k] = {}
        for corp_k, corp_v in p_v.items():
            if corp_k == "gate_verdicts":
                clean_output_results[p_k][corp_k] = corp_v
            else:
                clean_output_results[p_k][corp_k] = {
                    "metrics": corp_v["metrics"],
                    "regressions_count": corp_v.get("regressions_count", 0)
                }

    total_duration = time.time() - start_time
    final_output = {
        "status": "PHASE_1D_1_STAGE_1_COMPLETE",
        "timestamp": iso_time,
        "total_duration_sec": total_duration,
        "environment": {
            "platform": platform.platform(),
            "python_version": sys.version,
            "numpy_version": np.__version__,
            "pandas_version": pd.__version__,
            "sklearn_version": joblib.__version__
        },
        "input_hashes": input_hashes,
        "output_artifacts": {
            "clean_test_predictions": {"path": str(test_preds_path), "sha256": get_file_sha256(test_preds_path)},
            "benchmark_predictions": {"path": str(bench_preds_path), "sha256": get_file_sha256(bench_preds_path)},
            "adversarial_predictions": {"path": str(adv_preds_path), "sha256": get_file_sha256(adv_preds_path)},
            "golden_predictions": {"path": str(gold_preds_path), "sha256": get_file_sha256(gold_preds_path)},
            "decision_changes": {"path": str(changes_path), "sha256": get_file_sha256(changes_path)}
        },
        "evaluation_summary": clean_output_results
    }

    metrics_json_path = EXP_DIR / "phase_1d_1_a0_a1_a2_metrics.json"
    with open(metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)
    print(f"\nFinal Metrics JSON Saved: {metrics_json_path.name}")
    print(f"Total Stage 1 Duration: {total_duration:.1f}s")
    print("=" * 80)
    print("PHASE 1D.1-A0/A1/A2 EVALUATION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
