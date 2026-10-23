"""
Sentinel Phase 1C.2B-2A-S2-E: Authorized Isolated Balanced Bare-Apex Execution Protocol
Author: Sentinel AI ML Engineering Team
Status: AUTHORIZED SINGLE ISOLATED EXECUTION
Operating Mode: STRICT SAFEGUARDS ACTIVE

Safeguard Enforcements:
1. Frozen V8 champion and production artifacts preserved unchanged.
2. C0 reproduction check run first with strict tolerance (+/-0.05 pp recall, +/-0.01 pp FPR).
3. If C0 is non-equivalent, execution stops before candidate training.
4. Candidate evaluated against all 7 pre-registered gates with raw and adjudicated outputs separated.
5. All outputs strictly isolated in phase_1c_2b_2a_s2_f/.
6. Benchmark v1.0 evaluated strictly as diagnostic reference.
7. Final decision: EXPERIMENT COMPLETE — CANDIDATE NOT PROMOTED (or BLOCKED).
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
import sklearn

# Directory layout
EXP_DIR = Path(__file__).resolve().parent
URL_ML_DIR = EXP_DIR.parents[1]
DATA_DIR = URL_ML_DIR / "data"
MODELS_DIR = URL_ML_DIR / "models"
REPORTS_DIR = URL_ML_DIR / "reports"
SCRIPTS_DIR = URL_ML_DIR / "scripts"
PROJECT_ROOT = EXP_DIR.parents[3]
ANDROID_RES_DIR = PROJECT_ROOT / "sentinel-ai" / "android-app" / "core" / "src" / "test" / "resources"

sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(EXP_DIR))

import run_balanced_experiment_protocol_repaired as proto
from v7_features import vectorize_v7, V7_FEATURE_NAMES, _subdomain_depth
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url

# Override ANDROID_RES_DIR in proto to resolve project root structure correctly
proto.ANDROID_RES_DIR = ANDROID_RES_DIR

EXPECTED_V8_CHAMPION_HASH = "073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58"


def get_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_prediction_agreement(
    y_true: np.ndarray,
    probs_a: np.ndarray,
    probs_b: np.ndarray,
    threshold: float = 0.28
) -> Dict[str, Any]:
    """Compute exact prediction agreement and divergence between two classifiers."""
    preds_a = (probs_a >= threshold).astype(int)
    preds_b = (probs_b >= threshold).astype(int)
    n = len(y_true)
    agreement_count = int(np.sum(preds_a == preds_b))
    agreement_rate = float(agreement_count / n) if n > 0 else 1.0
    disagreement_count = n - agreement_count

    # Broken down by class
    mal_mask = (y_true == 1)
    ben_mask = (y_true == 0)

    mal_agree = float(np.mean(preds_a[mal_mask] == preds_b[mal_mask])) if np.sum(mal_mask) > 0 else 1.0
    ben_agree = float(np.mean(preds_a[ben_mask] == preds_b[ben_mask])) if np.sum(ben_mask) > 0 else 1.0

    return {
        "n_samples": n,
        "agreement_count": agreement_count,
        "disagreement_count": disagreement_count,
        "overall_agreement_rate": agreement_rate,
        "malicious_agreement_rate": mal_agree,
        "benign_agreement_rate": ben_agree,
    }


def evaluate_model_on_corpus_fixed(
    classifier: V8RelationalURLClassifier,
    urls: List[str],
    y_true: np.ndarray,
    X_precomputed: np.ndarray | None = None,
    threshold: float = 0.2800
) -> Dict[str, Any]:
    """Evaluate a V8 relational classifier tracking both raw and post-adjudication scores."""
    if X_precomputed is None:
        X_eval, _ = vectorize_v7(urls)
    else:
        X_eval = X_precomputed

    # 1. Raw base estimator predictions
    raw_probs = classifier.base_model.predict_proba(X_eval)[:, 1]

    # 2. Post-adjudication relational predictions using classifier's predict_proba
    final_probs = classifier.predict_proba(X_eval, urls=urls)[:, 1]

    raw_metrics = proto.compute_binary_metrics(y_true, raw_probs, threshold=threshold)
    final_metrics = proto.compute_binary_metrics(y_true, final_probs, threshold=threshold)

    return {
        "raw_scores": raw_metrics,
        "adjudicated_scores": final_metrics,
        "mean_raw_prob": float(np.mean(raw_probs)),
        "mean_final_prob": float(np.mean(final_probs)),
        "raw_probs_sample": [float(p) for p in raw_probs[:5]],
        "final_probs_sample": [float(p) for p in final_probs[:5]],
        "_raw_probs": raw_probs,
        "_final_probs": final_probs
    }


def execute_s2_e_protocol() -> Dict[str, Any]:
    start_time = time.time()
    iso_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time))
    print(f"=== Sentinel Phase 1C.2B-2A-S2-E Execution Started: {iso_timestamp} ===")

    # 1. Environment & Dependency Capture
    env_info = {
        "timestamp": iso_timestamp,
        "platform": platform.platform(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "sklearn_version": sklearn.__version__,
        "joblib_version": joblib.__version__
    }
    print("Environment & Dependencies:")
    for k, v in env_info.items():
        print(f"  {k}: {v}")

    # 2. Input Hash Verification Preflight
    input_files = {
        "v8_champion": MODELS_DIR / "v8_champion.joblib",
        "public_suffix_list": EXP_DIR / "public_suffix_list.dat",
        "candidate_malicious_repaired": EXP_DIR / "candidate_malicious_bare_apex_repaired_2843.csv",
        "exclusions_audit": EXP_DIR / "exclusions_audit.csv",
        "candidate_manifest": EXP_DIR / "candidate_malicious_bare_apex_repaired_manifest.json",
        "protocol_script": EXP_DIR / "run_balanced_experiment_protocol_repaired.py",
        "candidate_benign_15k": URL_ML_DIR / "experiments" / "phase_1c_2b_prototypes" / "candidate_bare_apex_15k.csv",
        "cleaned_dataset": DATA_DIR / "cleaned_dataset.csv",
        "v7_structural_benign": DATA_DIR / "v7_structural_benign.csv",
        "hard_benign_benchmark": DATA_DIR / "hard_benign_benchmark_500.json",
        "adversarial_predictions": REPORTS_DIR / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv",
        "golden_urls_v8": ANDROID_RES_DIR / "golden_urls_v8.json"
    }

    input_hashes = {}
    for name, fpath in input_files.items():
        if not fpath.exists():
            raise FileNotFoundError(f"Missing required input file: {fpath}")
        h = get_file_sha256(fpath)
        input_hashes[name] = {"path": str(fpath), "sha256": h, "size": fpath.stat().st_size}
        print(f"  Verified {name}: {h} ({fpath.stat().st_size} bytes)")

    assert input_hashes["v8_champion"]["sha256"] == EXPECTED_V8_CHAMPION_HASH, "FATAL: Champion V8 hash mismatch!"

    # 3. Load Datasets & Vectorize
    print("\n--- Step 1: Loading Datasets & Performing Disjointness Safety Assertions ---")
    data = proto.prepare_datasets()
    ctrl_urls, ctrl_y, ctrl_weights = data["ctrl_train"]
    cand_urls, cand_y, cand_weights = data["cand_train"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    bench_data = data["bench_data"]
    adv_df = data["adv_df"]
    golden_data = data["golden_data"]

    print(f"Control Training rows: {len(ctrl_urls)}")
    print(f"Candidate Training rows: {len(cand_urls)}")

    print("\nVectorizing Corpora...")
    t_vec = time.time()
    X_ctrl, feat_names = vectorize_v7(ctrl_urls)
    X_cand, _ = vectorize_v7(cand_urls)

    val_urls = val_df["url"].tolist()
    y_val = val_df["label"].to_numpy()
    X_val, _ = vectorize_v7(val_urls)

    test_urls = test_df["url"].tolist()
    y_test = test_df["label"].to_numpy()
    X_test, _ = vectorize_v7(test_urls)

    # Subgroups
    apex_mask = np.array([_subdomain_depth(parse_v8_url(u).parent_domain or "") == 0 and y_test[i] == 1 for i, u in enumerate(test_urls)])
    sub_apex_urls = [test_urls[i] for i in range(len(test_urls)) if apex_mask[i]]
    y_sub_apex = y_test[apex_mask]
    X_sub_apex = X_test[apex_mask]

    bench_urls = [b["url"] for b in bench_data]
    y_bench = np.zeros(len(bench_urls), dtype=int)
    X_bench, _ = vectorize_v7(bench_urls)

    bench_apex_idx = [i for i, b in enumerate(bench_data) if b.get("category") == "bare_apex"]
    bench_apex_urls = [bench_urls[i] for i in bench_apex_idx]
    y_bench_apex = y_bench[bench_apex_idx]
    X_bench_apex = X_bench[bench_apex_idx]

    adv_urls = adv_df["url"].tolist()
    y_adv = adv_df["label"].to_numpy()
    X_adv, _ = vectorize_v7(adv_urls)

    golden_urls = [g["url"] for g in golden_data]
    y_golden = np.array([int(g["isMalicious"]) for g in golden_data])
    X_golden, _ = vectorize_v7(golden_urls)
    print(f"Vectorization completed in {time.time() - t_vec:.2f}s")

    # 4. Fit Control Model C0
    print("\n--- Step 2: Training Control Model C0 ---")
    t_train_c0 = time.time()
    ctrl_model = proto.fit_model(X_ctrl, ctrl_y, ctrl_weights, feat_names)
    c0_train_elapsed = time.time() - t_train_c0
    ctrl_path = EXP_DIR / "control_model_reproduced.joblib"
    joblib.dump(ctrl_model, ctrl_path)
    print(f"C0 Training complete in {c0_train_elapsed:.2f}s. Saved: {ctrl_path.name}")

    # 5. Load Frozen V8 Champion & Run Reproduction Comparison (Safeguards 4 & 5)
    print("\n--- Step 3: Safeguard 4 — C0 vs Frozen V8 Reproduction Audit ---")
    champ_model: V8RelationalURLClassifier = joblib.load(MODELS_DIR / "v8_champion.joblib")

    corpora_eval = [
        ("validation", val_urls, y_val, X_val),
        ("clean_test", test_urls, y_test, X_test),
        ("test_subgroup_malicious_apex", sub_apex_urls, y_sub_apex, X_sub_apex),
        ("benchmark_overall", bench_urls, y_bench, X_bench),
        ("benchmark_bare_apex", bench_apex_urls, y_bench_apex, X_bench_apex),
        ("adversarial_split", adv_urls, y_adv, X_adv),
        ("golden_fixtures", golden_urls, y_golden, X_golden)
    ]

    c0_eval_results = {}
    v8_eval_results = {}
    agreement_results = {}
    deltas = {}

    for name, urls, y_true, X_mat in corpora_eval:
        print(f"Evaluating V8 and C0 on {name} (N = {len(urls)})...")
        v8_res = evaluate_model_on_corpus_fixed(champ_model, urls, y_true, X_mat)
        c0_res = evaluate_model_on_corpus_fixed(ctrl_model, urls, y_true, X_mat)

        raw_agree = compute_prediction_agreement(
            y_true,
            v8_res["_raw_probs"],
            c0_res["_raw_probs"],
            threshold=0.28
        )
        adj_agree = compute_prediction_agreement(
            y_true,
            v8_res["_final_probs"],
            c0_res["_final_probs"],
            threshold=0.28
        )

        agreement_results[name] = {
            "raw_agreement": raw_agree,
            "adjudicated_agreement": adj_agree
        }

        # Metric deltas: C0 - V8
        c0_rec = c0_res["adjudicated_scores"]["recall"]
        v8_rec = v8_res["adjudicated_scores"]["recall"]
        c0_fpr = c0_res["adjudicated_scores"]["fpr"]
        v8_fpr = v8_res["adjudicated_scores"]["fpr"]

        deltas[name] = {
            "v8_recall": v8_rec,
            "c0_recall": c0_rec,
            "delta_recall": float(c0_rec - v8_rec),
            "delta_recall_pp": float((c0_rec - v8_rec) * 100.0),
            "v8_fpr": v8_fpr,
            "c0_fpr": c0_fpr,
            "delta_fpr": float(c0_fpr - v8_fpr),
            "delta_fpr_pp": float((c0_fpr - v8_fpr) * 100.0)
        }

        # Remove temporary internal arrays from output JSON
        del v8_res["_raw_probs"]
        del v8_res["_final_probs"]
        del c0_res["_raw_probs"]
        del c0_res["_final_probs"]

        v8_eval_results[name] = v8_res
        c0_eval_results[name] = c0_res

    # Golden Fixture Regressions Check
    v8_gold_res = int(np.sum((np.array(v8_eval_results["golden_fixtures"]["final_probs_sample"]) >= 0.28) != y_golden[:5]))  # placeholder, let's do exact
    v8_gold_preds = (champ_model.predict_proba(X_golden, urls=golden_urls)[:, 1] >= 0.28).astype(int)
    c0_gold_preds = (ctrl_model.predict_proba(X_golden, urls=golden_urls)[:, 1] >= 0.28).astype(int)
    v8_gold_regressions = int(np.sum(v8_gold_preds != y_golden))
    c0_gold_regressions = int(np.sum(c0_gold_preds != y_golden))

    c0_eval_results["golden_fixtures"]["regressions_count"] = c0_gold_regressions
    v8_eval_results["golden_fixtures"]["regressions_count"] = v8_gold_regressions

    print("\n--- C0 Reproduction Tolerance Audit ---")
    test_delta_rec_pp = deltas["clean_test"]["delta_recall_pp"]
    test_delta_fpr_pp = deltas["clean_test"]["delta_fpr_pp"]
    print(f"Clean Test Delta Recall: {test_delta_rec_pp:+.4f} percentage points (Tolerance: +/-0.05 pp)")
    print(f"Clean Test Delta Benign FPR: {test_delta_fpr_pp:+.4f} percentage points (Tolerance: +/-0.01 pp)")
    print(f"Golden Fixture Regressions: V8 = {v8_gold_regressions}, C0 = {c0_gold_regressions}")
    print(f"Clean Test Adjudicated Agreement: {agreement_results['clean_test']['adjudicated_agreement']['overall_agreement_rate'] * 100.0:.3f}%")

    # Evaluate C0 gates
    c0_gates = proto.verify_evaluation_gates(c0_eval_results)
    c0_eval_results["gate_verdicts"] = c0_gates

    # Strict Tolerance Enforcement (Safeguard 4 & 5)
    rec_pass = abs(test_delta_rec_pp) <= 0.0500 + 1e-6
    fpr_pass = abs(test_delta_fpr_pp) <= 0.0100 + 1e-6
    c0_equivalent = rec_pass and fpr_pass and (c0_gold_regressions == 0)

    reproduction_summary = {
        "c0_equivalent": bool(c0_equivalent),
        "clean_test_delta_recall_pp": test_delta_rec_pp,
        "clean_test_delta_fpr_pp": test_delta_fpr_pp,
        "recall_tolerance_pp": 0.05,
        "fpr_tolerance_pp": 0.01,
        "recall_passed": bool(rec_pass),
        "fpr_passed": bool(fpr_pass),
        "golden_regressions_passed": bool(c0_gold_regressions == 0),
        "deltas": deltas,
        "agreement": agreement_results
    }

    if not c0_equivalent:
        print("\n[!] SAFEGUARD 5 TRIGGERED: C0 Reproduction exceeded tolerance!")
        print(f"    Recall delta {test_delta_rec_pp:+.4f} pp (pass: {rec_pass})")
        print(f"    FPR delta {test_delta_fpr_pp:+.4f} pp (pass: {fpr_pass})")
        print("    STOPPING BEFORE CANDIDATE TRAINING. Candidate training aborted.")

        final_output = {
            "status": "BLOCKED",
            "decision": "BLOCKED — C0 CONTROL NON-EQUIVALENT",
            "reproduction_summary": reproduction_summary,
            "environment": env_info,
            "input_hashes": input_hashes,
            "c0_eval": c0_eval_results,
            "v8_eval": v8_eval_results,
            "candidate_eval": None
        }
        with open(EXP_DIR / "s2_e_execution_metrics.json", "w", encoding="utf-8") as f:
            json.dump(final_output, f, indent=2)
        return final_output

    print("\n[+] SAFEGUARD 4 PASSED: C0 is statistically equivalent to V8 within tolerances.")
    print("Proceeding to Step 4: Candidate Training & Evaluation...")

    # 6. Fit Candidate Model A1
    print("\n--- Step 4: Training Balanced Candidate Model A1 ---")
    t_train_cand = time.time()
    cand_model = proto.fit_model(X_cand, cand_y, cand_weights, feat_names)
    cand_train_elapsed = time.time() - t_train_cand
    cand_path = EXP_DIR / "candidate_balanced_repaired_model.joblib"
    joblib.dump(cand_model, cand_path)
    print(f"Candidate Training complete in {cand_train_elapsed:.2f}s. Saved: {cand_path.name}")

    # 7. Evaluate Candidate Model A1 across all corpora
    print("\n--- Step 5: Evaluating Candidate Model A1 ---")
    cand_eval_results = {}
    for name, urls, y_true, X_mat in corpora_eval:
        print(f"Evaluating Candidate A1 on {name} (N = {len(urls)})...")
        cand_res = evaluate_model_on_corpus_fixed(cand_model, urls, y_true, X_mat)
        del cand_res["_raw_probs"]
        del cand_res["_final_probs"]
        cand_eval_results[name] = cand_res

    # Golden Regressions for Candidate
    cand_gold_preds = (cand_model.predict_proba(X_golden, urls=golden_urls)[:, 1] >= 0.28).astype(int)
    cand_gold_regressions = int(np.sum(cand_gold_preds != y_golden))
    cand_eval_results["golden_fixtures"]["regressions_count"] = cand_gold_regressions

    # 8. Gate Evaluation
    print("\n--- Step 6: Pre-Registered Gate Evaluation ---")
    cand_gates = proto.verify_evaluation_gates(cand_eval_results)
    cand_eval_results["gate_verdicts"] = cand_gates

    for g_id, g_info in cand_gates["gates"].items():
        print(f"  {g_id}: {g_info['status']} (Value: {g_info.get('value', g_info.get('regressions_count'))}, Target: {g_info['target']})")
    print(f"Overall Candidate Gate Verdict: {cand_gates['overall_verdict']}")

    # Candidate vs C0 deltas
    cand_vs_c0_deltas = {}
    for name in ["clean_test", "test_subgroup_malicious_apex", "benchmark_overall", "benchmark_bare_apex", "adversarial_split"]:
        c0_r = c0_eval_results[name]["adjudicated_scores"]["recall"]
        cand_r = cand_eval_results[name]["adjudicated_scores"]["recall"]
        c0_f = c0_eval_results[name]["adjudicated_scores"]["fpr"]
        cand_f = cand_eval_results[name]["adjudicated_scores"]["fpr"]
        cand_vs_c0_deltas[name] = {
            "c0_recall": c0_r,
            "candidate_recall": cand_r,
            "delta_recall_pp": float((cand_r - c0_r) * 100.0),
            "c0_fpr": c0_f,
            "candidate_fpr": cand_f,
            "delta_fpr_pp": float((cand_f - c0_f) * 100.0)
        }

    # Output compilation
    total_duration = time.time() - start_time
    final_output = {
        "status": "EXPERIMENT_COMPLETE",
        "decision": "EXPERIMENT COMPLETE — CANDIDATE NOT PROMOTED",
        "timestamp": iso_timestamp,
        "total_duration_sec": total_duration,
        "environment": env_info,
        "input_hashes": input_hashes,
        "reproduction_summary": reproduction_summary,
        "v8_eval": v8_eval_results,
        "c0_eval": c0_eval_results,
        "candidate_eval": cand_eval_results,
        "cand_vs_c0_deltas": cand_vs_c0_deltas,
        "output_artifacts": {
            "control_model": {"path": str(ctrl_path), "sha256": get_file_sha256(ctrl_path)},
            "candidate_model": {"path": str(cand_path), "sha256": get_file_sha256(cand_path)},
        }
    }

    eval_json_path = EXP_DIR / "repaired_balanced_eval_metrics.json"
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)

    with open(EXP_DIR / "s2_e_execution_metrics.json", "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=2)

    print(f"\nExecution Complete in {total_duration:.1f}s.")
    print(f"Metrics saved to: {eval_json_path.name} and s2_e_execution_metrics.json")
    print(f"Final Decision: {final_output['decision']}")

    return final_output


if __name__ == "__main__":
    execute_s2_e_protocol()
