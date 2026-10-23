"""
Sentinel Phase 1C.2B-2A-S2-F: Repaired Balanced Bare-Apex Training & Evaluation Protocol
Author: Sentinel AI ML Engineering Team
Status: PREPARED & AUDITED — UNEXECUTED (NO TRAINING)
Operating Mode: STRICT EXECUTION GUARD ACTIVE (Execution requires explicit authorization)

Safety Guarantees & Constraints:
- Zero modifications to production code, Android assets, or V8 champion artifacts.
- Champion artifact SHA-256 verified invariant: 073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58.
- Exact V8 hyperparameter parity: lr=0.06, l2=5.0, max_iter=350, max_leaf_nodes=40, min_samples_leaf=20, max_depth=None.
- Exact V8 sample weighting: malicious clean train=1.35, benign clean train=1.0, syn=1.0, aug_benign=1.0, aug_malicious=1.35.
- Fixed operating threshold: 0.2800.
- Adjudicator parameters: conf_bound=0.80, threshold=0.2800, feature_names=V7_FEATURE_NAMES.
- All writes strictly confined to this isolated directory (phase_1c_2b_2a_s2_f).
- Diagnostic Benchmark v1.0 evaluated strictly as diagnostic reference, never as untouched holdout.
"""

from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

# Isolated directory invariants
EXP_DIR = Path(__file__).resolve().parent
URL_ML_DIR = EXP_DIR.parents[1]
DATA_DIR = URL_ML_DIR / "data"
MODELS_DIR = URL_ML_DIR / "models"
REPORTS_DIR = URL_ML_DIR / "reports"
SCRIPTS_DIR = URL_ML_DIR / "scripts"
ANDROID_RES_DIR = URL_ML_DIR.parent / "sentinel-ai" / "android-app" / "core" / "src" / "test" / "resources"

sys.path.insert(0, str(SCRIPTS_DIR))
from v7_features import vectorize_v7, V7_FEATURE_NAMES, _subdomain_depth
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url
from url_features import domain_group

EXPECTED_V8_CHAMPION_HASH = "073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58"


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Compute Wilson score confidence interval."""
    if n == 0:
        return 0.0, 0.0, 0.0
    z = 1.95996  # 95%
    p = k / n
    denom = 1.0 + (z**2) / n
    center = (p + (z**2) / (2.0 * n)) / denom
    spread = z * math.sqrt((p * (1.0 - p) + (z**2) / (4.0 * n)) / n) / denom
    return p, max(0.0, center - spread), min(1.0, center + spread)


def compute_binary_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.28) -> Dict[str, Any]:
    """Compute confusion matrix and performance metrics with confidence intervals."""
    pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    n_benign = int(tn + fp)
    n_malicious = int(fn + tp)
    n_total = int(len(y_true))

    fpr, fpr_low, fpr_high = wilson_ci(int(fp), n_benign) if n_benign > 0 else (0.0, 0.0, 0.0)
    recall, rec_low, rec_high = wilson_ci(int(tp), n_malicious) if n_malicious > 0 else (0.0, 0.0, 0.0)
    prec, prec_low, prec_high = wilson_ci(int(tp), int(tp + fp)) if (tp + fp) > 0 else (0.0, 0.0, 0.0)

    auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan")

    return {
        "n_total": n_total,
        "n_benign": n_benign,
        "n_malicious": n_malicious,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": float(fpr),
        "fpr_95ci": [float(fpr_low), float(fpr_high)],
        "recall": float(recall),
        "recall_95ci": [float(rec_low), float(rec_high)],
        "precision": float(prec),
        "precision_95ci": [float(prec_low), float(prec_high)],
        "roc_auc": float(auc)
    }


def evaluate_model_on_corpus(
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

    # 2. Post-adjudication relational predictions
    final_probs = np.zeros(len(urls), dtype=np.float32)
    for i, u in enumerate(urls):
        row_feat = {V7_FEATURE_NAMES[k]: X_eval[i, k] for k in range(len(V7_FEATURE_NAMES))}
        final_probs[i] = classifier.adjudicate(u, raw_probs[i], row_feat)

    raw_metrics = compute_binary_metrics(y_true, raw_probs, threshold=threshold)
    final_metrics = compute_binary_metrics(y_true, final_probs, threshold=threshold)

    return {
        "raw_scores": raw_metrics,
        "adjudicated_scores": final_metrics,
        "mean_raw_prob": float(np.mean(raw_probs)),
        "mean_final_prob": float(np.mean(final_probs)),
        "raw_probs_sample": [float(p) for p in raw_probs[:5]],
        "final_probs_sample": [float(p) for p in final_probs[:5]]
    }


def verify_evaluation_gates(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Encode the seven pre-registered evaluation gates with explicit Target,
    Warning, and Hard-Fail decision rules.
    """
    gates = {}

    # Gate 1: Clean Test Malicious Recall (N = 23,158)
    test_rec = metrics["clean_test"]["adjudicated_scores"]["recall"]
    if test_rec >= 0.98200:
        g1_status = "PASS"
    elif test_rec >= 0.98000:
        g1_status = "WARNING"
    else:
        g1_status = "HARD_FAIL"
    gates["Gate_1_Clean_Test_Recall"] = {
        "target": ">= 0.98200", "warning_zone": "[0.98000, 0.98200)", "hard_fail": "< 0.98000",
        "value": float(test_rec), "status": g1_status
    }

    # Gate 2: Clean Test Benign FPR (N = 27,353)
    test_fpr = metrics["clean_test"]["adjudicated_scores"]["fpr"]
    if test_fpr <= 0.01000:
        g2_status = "PASS"
    elif test_fpr <= 0.01100:
        g2_status = "WARNING"
    else:
        g2_status = "HARD_FAIL"
    gates["Gate_2_Clean_Test_Benign_FPR"] = {
        "target": "<= 0.01000", "warning_zone": "(0.01000, 0.01100]", "hard_fail": "> 0.01100",
        "value": float(test_fpr), "status": g2_status
    }

    # Gate 3: Benchmark v1.0 Bare-Apex FPR (N = 200, Diagnostic)
    bench_apex_fpr = metrics["benchmark_bare_apex"]["adjudicated_scores"]["fpr"]
    if bench_apex_fpr <= 0.0600:
        g3_status = "PASS"
    elif bench_apex_fpr <= 0.1000:
        g3_status = "WARNING"
    else:
        g3_status = "HARD_FAIL"
    gates["Gate_3_Benchmark_Bare_Apex_FPR"] = {
        "target": "<= 0.0600", "warning_zone": "(0.0600, 0.1000]", "hard_fail": "> 0.1000",
        "value": float(bench_apex_fpr), "status": g3_status
    }

    # Gate 4: Benchmark v1.0 Overall FPR (N = 500, Diagnostic)
    # Corrected target reflects the 220 non-apex FP floor
    bench_overall_fpr = metrics["benchmark_overall"]["adjudicated_scores"]["fpr"]
    if bench_overall_fpr <= 0.4600:
        g4_status = "PASS"
    elif bench_overall_fpr <= 0.5000:
        g4_status = "WARNING"
    else:
        g4_status = "HARD_FAIL"
    gates["Gate_4_Benchmark_Overall_FPR"] = {
        "target": "<= 0.4600 (Corrected; Historical S2 preflight was <= 0.2500)",
        "warning_zone": "(0.4600, 0.5000]", "hard_fail": "> 0.5000",
        "value": float(bench_overall_fpr), "status": g4_status
    }

    # Gate 5: Clean Test Bare-Apex Malicious Recall Subgroup (N = 4,254)
    apex_rec = metrics["test_subgroup_malicious_apex"]["adjudicated_scores"]["recall"]
    if apex_rec >= 0.9600:
        g5_status = "PASS"
    elif apex_rec >= 0.9500:
        g5_status = "WARNING"
    else:
        g5_status = "HARD_FAIL"
    gates["Gate_5_Test_Apex_Malicious_Recall"] = {
        "target": ">= 0.9600", "warning_zone": "[0.9500, 0.9600)", "hard_fail": "< 0.9500",
        "value": float(apex_rec), "status": g5_status
    }

    # Gate 6: Remediation Adversarial Recall (N = 3,900)
    adv_rec = metrics["adversarial_split"]["adjudicated_scores"]["recall"]
    if adv_rec >= 0.9650:
        g6_status = "PASS"
    elif adv_rec >= 0.9600:
        g6_status = "WARNING"
    else:
        g6_status = "HARD_FAIL"
    gates["Gate_6_Adversarial_Recall"] = {
        "target": ">= 0.9650 (Corrected; Baseline is 0.97051 on N=3900)",
        "warning_zone": "[0.9600, 0.9650)", "hard_fail": "< 0.9600",
        "value": float(adv_rec), "status": g6_status
    }

    # Gate 7: Android Golden Fixture Parity (N = 174)
    golden_regressions = metrics["golden_fixtures"]["regressions_count"]
    if golden_regressions == 0:
        g7_status = "PASS"
    else:
        g7_status = "HARD_FAIL"
    gates["Gate_7_Android_Golden_Parity"] = {
        "target": "== 0 regressions", "hard_fail": ">= 1 regression",
        "regressions_count": int(golden_regressions), "status": g7_status
    }

    # Overall Decision Engine
    statuses = [g["status"] for g in gates.values()]
    if any(s == "HARD_FAIL" for s in statuses):
        overall_verdict = "REJECTED"
    elif any(s == "WARNING" for s in statuses):
        overall_verdict = "CONDITIONAL_REVIEW_REQUIRED"
    else:
        overall_verdict = "ALL_GATES_PASSED"

    return {"gates": gates, "overall_verdict": overall_verdict}


def prepare_datasets() -> Dict[str, Any]:
    """Load, split, and audit all training and evaluation datasets with safety assertions."""
    # 1. Base dataset & splits
    clean = pd.read_csv(DATA_DIR / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)  # 1 = malicious, 0 = benign

    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))

    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    val_idx = rest[vr]
    test_idx = rest[te_r]

    val_df = clean.iloc[val_idx].copy()
    test_df = clean.iloc[test_idx].copy()

    # 2. Structural synthetic benign
    v7_syn = pd.read_csv(DATA_DIR / "v7_structural_benign.csv")
    syn_urls = v7_syn.url.tolist()
    y_syn = np.zeros(len(syn_urls), dtype=np.float32)

    train_clean_urls = clean.url.iloc[tr].tolist()
    y_tr = y[tr]

    # Baseline Control Dataset (N = 189,468)
    ctrl_urls = train_clean_urls + syn_urls
    ctrl_y = np.r_[y_tr, y_syn].astype(np.float32)
    ctrl_weights = np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]

    # 3. Augmentations
    cand_15k_path = URL_ML_DIR / "experiments" / "phase_1c_2b_prototypes" / "candidate_bare_apex_15k.csv"
    df_ben_apex = pd.read_csv(cand_15k_path)
    cand_ben_urls = df_ben_apex.url.tolist()
    cand_ben_y = np.zeros(len(cand_ben_urls), dtype=np.float32)
    cand_ben_weights = np.full(len(cand_ben_urls), 1.0, dtype=np.float32)

    cand_repaired_path = EXP_DIR / "candidate_malicious_bare_apex_repaired_2843.csv"
    df_mal_repaired = pd.read_csv(cand_repaired_path)
    cand_mal_urls = df_mal_repaired.url.tolist()
    cand_mal_y = np.ones(len(cand_mal_urls), dtype=np.float32)
    cand_mal_weights = np.full(len(cand_mal_urls), 1.35, dtype=np.float32)

    cand_urls = ctrl_urls + cand_ben_urls + cand_mal_urls
    cand_y = np.r_[ctrl_y, cand_ben_y, cand_mal_y].astype(np.float32)
    cand_weights = np.r_[ctrl_weights, cand_ben_weights, cand_mal_weights].astype(np.float32)

    # 4. Evaluation Fixtures
    bench_data = json.load(open(DATA_DIR / "hard_benign_benchmark_500.json", encoding="utf-8"))
    adv_df = pd.read_csv(REPORTS_DIR / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")
    golden_data = json.load(open(ANDROID_RES_DIR / "golden_urls_v8.json", encoding="utf-8"))

    # SAFETY ASSERTIONS
    cand_reg_domains = set(df_mal_repaired["registrable_domain"])
    cand_url_set = set(cand_mal_urls)
    test_doms = set(parse_v8_url(u).parent_domain for u in test_df["url"] if parse_v8_url(u).parent_domain)
    val_doms = set(parse_v8_url(u).parent_domain for u in val_df["url"] if parse_v8_url(u).parent_domain)
    bench_doms = set(parse_v8_url(b["url"]).parent_domain for b in bench_data if parse_v8_url(b["url"]).parent_domain)
    golden_doms = set(parse_v8_url(g["url"]).parent_domain for g in golden_data if parse_v8_url(g["url"]).parent_domain)
    adv_doms = set(parse_v8_url(u).parent_domain for u in adv_df["url"] if parse_v8_url(u).parent_domain)

    assert len(cand_reg_domains & test_doms) == 0, "FATAL: Repaired candidate overlaps with Test domains!"
    assert len(cand_reg_domains & val_doms) == 0, "FATAL: Repaired candidate overlaps with Val domains!"
    assert len(cand_reg_domains & bench_doms) == 0, "FATAL: Repaired candidate overlaps with Benchmark domains!"
    assert len(cand_reg_domains & golden_doms) == 0, "FATAL: Repaired candidate overlaps with Golden domains!"
    assert len(cand_reg_domains & adv_doms) == 0, "FATAL: Repaired candidate overlaps with Adversarial domains!"
    assert len(cand_url_set & set(clean.iloc[tr]["url"])) == 0, "FATAL: Repaired candidate has verbatim duplicates in base train!"
    assert len(cand_url_set & set(cand_ben_urls)) == 0, "FATAL: Repaired candidate has label collision with 15k benign!"

    return {
        "ctrl_train": (ctrl_urls, ctrl_y, ctrl_weights),
        "cand_train": (cand_urls, cand_y, cand_weights),
        "val_df": val_df,
        "test_df": test_df,
        "bench_data": bench_data,
        "adv_df": adv_df,
        "golden_data": golden_data
    }


def fit_model(X_train: np.ndarray, y_train: np.ndarray, sample_weight: np.ndarray, feat_names: List[str]) -> V8RelationalURLClassifier:
    """Train HistGradientBoostingClassifier matching frozen V8 parameters."""
    hgb = HistGradientBoostingClassifier(
        learning_rate=0.06,
        l2_regularization=5.0,
        max_iter=350,
        max_leaf_nodes=40,
        min_samples_leaf=20,
        max_depth=None,
        random_state=42,
        loss="log_loss",
        max_bins=255,
        scoring="loss",
        early_stopping="auto",
        n_iter_no_change=10,
        tol=1e-7
    )
    hgb.fit(X_train, y_train, sample_weight=sample_weight)
    return V8RelationalURLClassifier(base_model=hgb, feature_names=feat_names, threshold=0.2800, conf_bound=0.80)


def execute_training_and_evaluation_pipeline():
    """
    Complete execution pipeline for future authorized execution.
    Contains strict write boundaries ensuring zero writes outside EXP_DIR.
    """
    print("=== STARTING REPAIRED BALANCED BARE-APEX EXPERIMENT ===")

    # Verify Champion hash
    champ_path = MODELS_DIR / "v8_champion.joblib"
    actual_hash = hashlib.sha256(champ_path.read_bytes()).hexdigest()
    assert actual_hash == EXPECTED_V8_CHAMPION_HASH, f"FATAL: Champion hash mismatch! {actual_hash}"
    print(f"Verified Champion V8 Hash: {actual_hash}")

    # 1. Load Data
    data = prepare_datasets()
    ctrl_urls, ctrl_y, ctrl_weights = data["ctrl_train"]
    cand_urls, cand_y, cand_weights = data["cand_train"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    bench_data = data["bench_data"]
    adv_df = data["adv_df"]
    golden_data = data["golden_data"]

    print(f"Control Training Rows: {len(ctrl_urls)}")
    print(f"Candidate Training Rows: {len(cand_urls)} (Baseline: {len(ctrl_urls)}, +BenignApex: 15,000, +MaliciousApex: 2,843)")

    # 2. Vectorize Datasets
    print("Vectorizing Training Sets...")
    X_ctrl, feat_names = vectorize_v7(ctrl_urls)
    X_cand, _ = vectorize_v7(cand_urls)

    print("Pre-Vectorizing Evaluation Fixtures...")
    val_urls = val_df["url"].tolist()
    y_val = val_df["label"].to_numpy()
    X_val, _ = vectorize_v7(val_urls)

    test_urls = test_df["url"].tolist()
    y_test = test_df["label"].to_numpy()
    X_test, _ = vectorize_v7(test_urls)

    bench_urls = [b["url"] for b in bench_data]
    y_bench = np.zeros(len(bench_urls), dtype=int)
    X_bench, _ = vectorize_v7(bench_urls)

    adv_urls = adv_df["url"].tolist()
    y_adv = adv_df["label"].to_numpy()
    X_adv, _ = vectorize_v7(adv_urls)

    golden_urls = [g["url"] for g in golden_data]
    y_golden = np.array([g["expected_label"] for g in golden_data])
    X_golden, _ = vectorize_v7(golden_urls)

    # 3. Train Models
    print("Fitting Control Model C0 (Reproducing V8)...")
    ctrl_model = fit_model(X_ctrl, ctrl_y, ctrl_weights, feat_names)
    ctrl_path = EXP_DIR / "control_model_reproduced.joblib"
    joblib.dump(ctrl_model, ctrl_path)
    print(f"Saved Control Model: {ctrl_path.name}")

    print("Fitting Repaired Candidate Model A1...")
    cand_model = fit_model(X_cand, cand_y, cand_weights, feat_names)
    cand_path = EXP_DIR / "candidate_balanced_repaired_model.joblib"
    joblib.dump(cand_model, cand_path)
    print(f"Saved Candidate Model: {cand_path.name}")

    # 4. Evaluation Suite
    results = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "control_eval": {}, "candidate_eval": {}}

    for model_name, clf in [("control_eval", ctrl_model), ("candidate_eval", cand_model)]:
        print(f"\nEvaluating {model_name}...")
        m_res = {}

        # Validation
        m_res["validation"] = evaluate_model_on_corpus(clf, val_urls, y_val, X_val)

        # Clean Test
        m_res["clean_test"] = evaluate_model_on_corpus(clf, test_urls, y_test, X_test)

        # Test Subgroups
        apex_mask = np.array([_subdomain_depth(parse_v8_url(u).parent_domain or "") == 0 and y_test[i] == 1 for i, u in enumerate(test_urls)])
        sub_apex_urls = [test_urls[i] for i in range(len(test_urls)) if apex_mask[i]]
        y_sub_apex = y_test[apex_mask]
        X_sub_apex = X_test[apex_mask]
        m_res["test_subgroup_malicious_apex"] = evaluate_model_on_corpus(clf, sub_apex_urls, y_sub_apex, X_sub_apex)

        # Benchmark v1.0 Overall (Diagnostic)
        m_res["benchmark_overall"] = evaluate_model_on_corpus(clf, bench_urls, y_bench, X_bench)

        # Benchmark Bare Apex
        bench_apex_idx = [i for i, b in enumerate(bench_data) if b.get("category") == "bare_apex"]
        bench_apex_urls = [bench_urls[i] for i in bench_apex_idx]
        X_bench_apex = X_bench[bench_apex_idx]
        m_res["benchmark_bare_apex"] = evaluate_model_on_corpus(clf, bench_apex_urls, y_bench[bench_apex_idx], X_bench_apex)

        # Adversarial Split
        m_res["adversarial_split"] = evaluate_model_on_corpus(clf, adv_urls, y_adv, X_adv)

        # Android Golden Fixtures
        golden_eval = evaluate_model_on_corpus(clf, golden_urls, y_golden, X_golden)
        golden_preds = (np.array(golden_eval["adjudicated_scores"]["tp"]) + np.array(golden_eval["adjudicated_scores"]["fp"])) # checks agreement
        final_preds = (np.array(golden_eval["adjudicated_scores"].get("pred", [])) if "pred" in golden_eval["adjudicated_scores"] else (np.array([clf.adjudicate(u, clf.base_model.predict_proba(X_golden[i:i+1])[:, 1][0], {V7_FEATURE_NAMES[k]: X_golden[i, k] for k in range(len(V7_FEATURE_NAMES))}) >= 0.2800 for i, u in enumerate(golden_urls)])).astype(int))
        regressions = int(np.sum(final_preds != y_golden))
        golden_eval["regressions_count"] = regressions
        m_res["golden_fixtures"] = golden_eval

        # Gate Verification
        gate_verdicts = verify_evaluation_gates(m_res)
        m_res["gate_verdicts"] = gate_verdicts

        results[model_name] = m_res

    # Output Results
    eval_json_path = EXP_DIR / "repaired_balanced_eval_metrics.json"
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nEvaluation Complete. Saved metrics: {eval_json_path.name}")
    print(f"Candidate Overall Gate Verdict: {results['candidate_eval']['gate_verdicts']['overall_verdict']}")


if __name__ == "__main__":
    # MANDATORY HARD CONSTRAINT ENFORCEMENT
    raise RuntimeError(
        "EXECUTION BLOCKED: Phase 1C.2B-2A-S2-F is strictly an isolated repair and preparation phase. "
        "No training or evaluation is authorized. Await explicit user authorization for subsequent execution."
    )
