"""Sentinel Phase 1C.2B-2A: Bare-Apex Candidate Training Experiment.

Strict Isolated Execution Protocol:
- Zero production code modifications.
- Zero changes to original datasets or frozen V8 model artifacts.
- Exact controlled comparison:
    * Control: Reproduced V8 baseline configuration (67 features, HistGradientBoostingClassifier, sample weights, V8RelationalURLClassifier).
    * Candidate: Identical configuration, differing ONLY by the addition of candidate_bare_apex_15k.csv to the training split.
- Fixed operating threshold: 0.2800.
- Comprehensive evaluation across:
    * Validation Split (N = 44,106)
    * Test Split (N = 50,511)
    * Remediation Adversarial Split (N = 3,900)
    * Diagnostic Benchmark v1.0 (N = 500)
"""
from __future__ import annotations
import hashlib
import json
import math
from pathlib import Path
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
PROT_DIR = ROOT / "experiments" / "phase_1c_2b_prototypes"
EXP_DIR = HERE.parent

sys.path.insert(0, str(ROOT / "scripts"))
from url_features import domain_group
from v8_normalization import parse_v8_url
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from v8_classifier import V8RelationalURLClassifier


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float, float]:
    if n == 0:
        return 0.0, 0.0, 0.0
    z = 1.95996  # 95%
    p = k / n
    denom = 1.0 + z**2 / n
    center = (p + z**2 / (2.0 * n)) / denom
    spread = z * math.sqrt((p * (1.0 - p) + z**2 / (4.0 * n)) / n) / denom
    return p, max(0.0, center - spread), min(1.0, center + spread)


def compute_eval_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.28) -> dict:
    pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    n_benign = int(tn + fp)
    n_mal = int(fn + tp)
    fpr, fpr_lo, fpr_hi = wilson_ci(int(fp), n_benign)
    rec, rec_lo, rec_hi = wilson_ci(int(tp), n_mal)
    prec = float(tp / max(1, tp + fp))
    auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan")
    return {
        "threshold": threshold,
        "n_total": int(len(y_true)),
        "n_benign": n_benign,
        "n_malicious": n_mal,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": fpr,
        "fpr_95ci": [fpr_lo, fpr_hi],
        "recall": rec,
        "recall_95ci": [rec_lo, rec_hi],
        "precision": prec,
        "roc_auc": auc
    }


def main():
    print("=" * 80)
    print("STARTING SENTINEL PHASE 1C.2B-2A: BARE-APEX CANDIDATE EXPERIMENT")
    print("=" * 80)
    start_total_time = time.time()

    # 1. Verify candidate data integrity
    cand_path = PROT_DIR / "candidate_bare_apex_15k.csv"
    assert cand_path.exists(), f"Missing candidate data: {cand_path}"
    cand_bytes = cand_path.read_bytes()
    cand_sha = hashlib.sha256(cand_bytes).hexdigest()
    print(f"Candidate dataset: {cand_path.name}")
    print(f"Candidate SHA-256: {cand_sha}")
    df_cand = pd.read_csv(cand_path)
    assert len(df_cand) == 15000, f"Expected 15,000 records, got {len(df_cand)}"
    print(f"Loaded {len(df_cand)} candidate bare-apex records.")

    # 2. Load splits exactly matching V8 reproduction
    print("\n--- Loading Core Dataset Splits ---")
    clean = pd.read_csv(DATA_DIR / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)  # 0 = Benign, 1 = Malicious
    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))

    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    va, te = rest[vr], rest[te_r]

    v7_syn = pd.read_csv(DATA_DIR / "v7_structural_benign.csv")
    adv_df = pd.read_csv(REPORTS_DIR / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")
    with open(DATA_DIR / "hard_benign_benchmark_500.json", "r", encoding="utf-8") as f:
        bench_json = json.load(f)

    train_clean_urls = clean.url.iloc[tr].tolist()
    y_tr = y[tr]
    syn_urls = v7_syn.url.tolist()
    y_syn = v7_syn.label.to_numpy()

    val_urls = clean.url.iloc[va].tolist()
    y_val = y[va]
    test_urls = clean.url.iloc[te].tolist()
    y_test = y[te]
    adv_urls = adv_df.url.tolist()
    y_adv = adv_df.label.to_numpy()
    bench_urls = [x["url"] for x in bench_json]
    y_bench = np.zeros(len(bench_json), dtype=int)

    print(f"Data Counts: Train Clean={len(train_clean_urls)}, Syn={len(syn_urls)}, Val={len(val_urls)}, Test={len(test_urls)}, Adv={len(adv_urls)}, Benchmark={len(bench_urls)}")

    # 3. Vectorize Shared Validation, Test, Adversarial, and Benchmark Splits
    print("\n--- Pre-Vectorizing Evaluation Splits (67 features) ---")
    t0 = time.time()
    X_val, _ = vectorize_v7(val_urls)
    X_test, _ = vectorize_v7(test_urls)
    X_adv, _ = vectorize_v7(adv_urls)
    X_bench, _ = vectorize_v7(bench_urls)
    print(f"Evaluation splits vectorized in {time.time() - t0:.2f}s.")

    # 4. Control Configuration (Baseline Reproduction)
    print("\n" + "=" * 80)
    print("TRAINING CONFIGURATION 1: CONTROL (REPRODUCED V8 BASELINE)")
    print("=" * 80)
    ctrl_urls = train_clean_urls + syn_urls
    ctrl_y = np.r_[y_tr, y_syn].astype(np.float32)
    ctrl_weights = np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]

    print("Vectorizing Control Training Split...")
    t0 = time.time()
    X_tr_ctrl, feat_names = vectorize_v7(ctrl_urls)
    print(f"Vectorized Control Train ({X_tr_ctrl.shape}) in {time.time() - t0:.2f}s.")

    print("Fitting Control HistGradientBoostingClassifier...")
    t0 = time.time()
    hgb_ctrl = HistGradientBoostingClassifier(
        max_iter=350,
        learning_rate=0.06,
        max_leaf_nodes=40,
        min_samples_leaf=20,
        l2_regularization=5.0,
        random_state=42
    )
    hgb_ctrl.fit(X_tr_ctrl, ctrl_y, sample_weight=ctrl_weights)
    print(f"Control model fitted in {time.time() - t0:.2f}s.")

    clf_ctrl = V8RelationalURLClassifier(hgb_ctrl, feature_names=feat_names, threshold=0.2800, conf_bound=0.85)
    ctrl_model_path = EXP_DIR / "control_model.joblib"
    joblib.dump(clf_ctrl, ctrl_model_path)
    print(f"Saved Control model to {ctrl_model_path.name}")

    # 5. Candidate Configuration (Track A: +15k Bare-Apex Benign)
    print("\n" + "=" * 80)
    print("TRAINING CONFIGURATION 2: CANDIDATE (TRACK A: +15,000 BARE APEX)")
    print("=" * 80)
    cand_urls_add = df_cand["url"].tolist()
    cand_y_add = np.zeros(len(cand_urls_add), dtype=np.float32)

    cand_urls = train_clean_urls + syn_urls + cand_urls_add
    cand_y = np.r_[y_tr, y_syn, cand_y_add].astype(np.float32)
    cand_weights = np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0), np.full(len(cand_urls_add), 1.0)]

    print(f"Candidate Training Set Size: {len(cand_urls)} ({len(ctrl_urls)} control + {len(cand_urls_add)} bare apex additions)")

    print("Vectorizing Candidate Training Split...")
    t0 = time.time()
    X_tr_cand, _ = vectorize_v7(cand_urls)
    print(f"Vectorized Candidate Train ({X_tr_cand.shape}) in {time.time() - t0:.2f}s.")

    print("Fitting Candidate HistGradientBoostingClassifier (Exact Same Hyperparameters)...")
    t0 = time.time()
    hgb_cand = HistGradientBoostingClassifier(
        max_iter=350,
        learning_rate=0.06,
        max_leaf_nodes=40,
        min_samples_leaf=20,
        l2_regularization=5.0,
        random_state=42
    )
    hgb_cand.fit(X_tr_cand, cand_y, sample_weight=cand_weights)
    print(f"Candidate model fitted in {time.time() - t0:.2f}s.")

    clf_cand = V8RelationalURLClassifier(hgb_cand, feature_names=feat_names, threshold=0.2800, conf_bound=0.85)
    cand_model_path = EXP_DIR / "candidate_model.joblib"
    joblib.dump(clf_cand, cand_model_path)
    print(f"Saved Candidate model to {cand_model_path.name}")

    # 6. Multi-Split Comparative Evaluation
    print("\n" + "=" * 80)
    print("EVALUATING CONTROL VS. CANDIDATE ACROSS APPROVED BENCHMARKS")
    print("=" * 80)

    def evaluate_suite(name: str, clf_model: V8RelationalURLClassifier):
        print(f"\n--- Evaluating {name} ---")
        t0 = time.time()

        # Predict with adjudication at threshold 0.28
        p_val = clf_model.predict_proba(X_val, urls=val_urls)[:, 1]
        p_test = clf_model.predict_proba(X_test, urls=test_urls)[:, 1]
        p_adv = clf_model.predict_proba(X_adv, urls=adv_urls)[:, 1]
        p_bench = clf_model.predict_proba(X_bench, urls=bench_urls)[:, 1]

        raw_val = clf_model.base_model.predict_proba(X_val)[:, 1]
        raw_test = clf_model.base_model.predict_proba(X_test)[:, 1]
        raw_adv = clf_model.base_model.predict_proba(X_adv)[:, 1]
        raw_bench = clf_model.base_model.predict_proba(X_bench)[:, 1]

        m_val = compute_eval_metrics(y_val, p_val, 0.28)
        m_test = compute_eval_metrics(y_test, p_test, 0.28)
        m_adv = compute_eval_metrics(y_adv, p_adv, 0.28)
        m_bench = compute_eval_metrics(y_bench, p_bench, 0.28)

        # Subgroup evaluations on benchmark v1.0
        bench_cats = [x["category"] for x in bench_json]
        df_b_res = pd.DataFrame({
            "url": bench_urls,
            "category": bench_cats,
            "y_true": y_bench,
            "raw_p": raw_bench,
            "final_p": p_bench,
            "pred": (p_bench >= 0.28).astype(int)
        })

        cat_metrics = {}
        for cat_name, grp in df_b_res.groupby("category"):
            n_tot = len(grp)
            n_fp = int((grp["final_p"] >= 0.28).sum())
            fpr, lo, hi = wilson_ci(n_fp, n_tot)
            raw_fp = int((grp["raw_p"] >= 0.28).sum())
            cat_metrics[cat_name] = {
                "n": n_tot,
                "raw_fp_28": raw_fp,
                "raw_fpr": float(raw_fp / n_tot),
                "final_fp_28": n_fp,
                "final_fpr": fpr,
                "final_fpr_95ci": [lo, hi],
                "mean_raw": float(grp["raw_p"].mean()),
                "mean_final": float(grp["final_p"].mean())
            }

        # Subgroup evaluations on Test Split: Bare Apex vs Subdomain
        test_is_bare = [len(parse_v8_url(u).subdomain_labels) == 0 for u in test_urls]
        df_test_res = pd.DataFrame({
            "url": test_urls,
            "y_true": y_test,
            "is_bare": test_is_bare,
            "raw_p": raw_test,
            "final_p": p_test,
            "pred": (p_test >= 0.28).astype(int)
        })

        test_subgroups = {}
        b_test = df_test_res[df_test_res["y_true"] == 0]
        for is_b, grp in b_test.groupby("is_bare"):
            sub_name = "bare_apex" if is_b else "subdomain"
            n_tot = len(grp)
            n_fp = int(grp["pred"].sum())
            fpr, lo, hi = wilson_ci(n_fp, n_tot)
            test_subgroups[f"benign_{sub_name}"] = {
                "n": n_tot,
                "fp": n_fp,
                "fpr": fpr,
                "fpr_95ci": [lo, hi],
                "mean_raw": float(grp["raw_p"].mean()),
                "mean_final": float(grp["final_p"].mean())
            }

        m_test_grp = df_test_res[df_test_res["y_true"] == 1]
        for is_b, grp in m_test_grp.groupby("is_bare"):
            sub_name = "bare_apex" if is_b else "subdomain"
            n_tot = len(grp)
            n_tp = int(grp["pred"].sum())
            rec, lo, hi = wilson_ci(n_tp, n_tot)
            test_subgroups[f"malicious_{sub_name}"] = {
                "n": n_tot,
                "tp": n_tp,
                "recall": rec,
                "recall_95ci": [lo, hi],
                "mean_raw": float(grp["raw_p"].mean()),
                "mean_final": float(grp["final_p"].mean())
            }

        elapsed = time.time() - t0
        print(f"Evaluation completed in {elapsed:.2f}s.")
        return {
            "val_metrics": m_val,
            "test_metrics": m_test,
            "adv_metrics": m_adv,
            "bench_overall": m_bench,
            "bench_categories": cat_metrics,
            "test_subgroups": test_subgroups,
            "benchmark_df": df_b_res
        }

    eval_ctrl = evaluate_suite("Control (Reproduced V8)", clf_ctrl)
    eval_cand = evaluate_suite("Candidate (Track A: +15k Bare-Apex)", clf_cand)

    # 7. Save Artifacts & Evaluation JSON
    results_summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "threshold": 0.2800,
        "candidate_sha256": cand_sha,
        "control_eval": {
            "val": eval_ctrl["val_metrics"],
            "test": eval_ctrl["test_metrics"],
            "adv": eval_ctrl["adv_metrics"],
            "bench_overall": eval_ctrl["bench_overall"],
            "bench_categories": eval_ctrl["bench_categories"],
            "test_subgroups": eval_ctrl["test_subgroups"]
        },
        "candidate_eval": {
            "val": eval_cand["val_metrics"],
            "test": eval_cand["test_metrics"],
            "adv": eval_cand["adv_metrics"],
            "bench_overall": eval_cand["bench_overall"],
            "bench_categories": eval_cand["bench_categories"],
            "test_subgroups": eval_cand["test_subgroups"]
        }
    }

    metrics_path = EXP_DIR / "candidate_eval_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(results_summary, f, indent=2)
    print(f"\nSaved metrics summary to {metrics_path.name}")

    df_diag = pd.DataFrame({
        "url": bench_urls,
        "category": [x["category"] for x in bench_json],
        "ctrl_raw_p": eval_ctrl["benchmark_df"]["raw_p"],
        "ctrl_final_p": eval_ctrl["benchmark_df"]["final_p"],
        "ctrl_pred": eval_ctrl["benchmark_df"]["pred"],
        "cand_raw_p": eval_cand["benchmark_df"]["raw_p"],
        "cand_final_p": eval_cand["benchmark_df"]["final_p"],
        "cand_pred": eval_cand["benchmark_df"]["pred"]
    })
    diag_csv_path = EXP_DIR / "benchmark_diagnostic_predictions.csv"
    df_diag.to_csv(diag_csv_path, index=False)
    print(f"Saved diagnostic benchmark predictions to {diag_csv_path.name}")

    # 8. Print Direct Comparison Table
    print("\n" + "=" * 80)
    print("CONTROL VS. CANDIDATE EXPERIMENTAL COMPARISON")
    print("=" * 80)

    print(f"{'Metric / Slice':<38} | {'Control (V8 Base)':<18} | {'Candidate (Track A)':<18} | {'Delta':<10}")
    print("-" * 92)

    c_m = eval_ctrl["test_metrics"]
    k_m = eval_cand["test_metrics"]
    print(f"{'Clean Test Benign FPR (N=27,353)':<38} | {c_m['fpr']*100:6.3f}% ({c_m['fp']:3d})   | {k_m['fpr']*100:6.3f}% ({k_m['fp']:3d})   | {(k_m['fpr']-c_m['fpr'])*100:+6.3f}%")
    print(f"{'Clean Test Malicious Recall (N=23,158)':<38} | {c_m['recall']*100:6.3f}% ({c_m['tp']:5d}) | {k_m['recall']*100:6.3f}% ({k_m['tp']:5d}) | {(k_m['recall']-c_m['recall'])*100:+6.3f}%")

    c_a = eval_ctrl["adv_metrics"]
    k_a = eval_cand["adv_metrics"]
    print(f"{'Adversarial Recall (N=3,900)':<38} | {c_a['recall']*100:6.3f}% ({c_a['tp']:5d}) | {k_a['recall']*100:6.3f}% ({k_a['tp']:5d}) | {(k_a['recall']-c_a['recall'])*100:+6.3f}%")

    print("-" * 92)
    print("TEST SUBGROUP: MALICIOUS BARE APEX VS SUBDOMAIN:")
    c_m_bare = eval_ctrl["test_subgroups"]["malicious_bare_apex"]
    k_m_bare = eval_cand["test_subgroups"]["malicious_bare_apex"]
    print(f"{'  Malicious Bare Apex Recall':<38} | {c_m_bare['recall']*100:6.2f}% ({c_m_bare['tp']:4d}/{c_m_bare['n']:4d}) | {k_m_bare['recall']*100:6.2f}% ({k_m_bare['tp']:4d}/{k_m_bare['n']:4d}) | {(k_m_bare['recall']-c_m_bare['recall'])*100:+6.2f}%")

    c_m_sub = eval_ctrl["test_subgroups"]["malicious_subdomain"]
    k_m_sub = eval_cand["test_subgroups"]["malicious_subdomain"]
    print(f"{'  Malicious Subdomain Recall':<38} | {c_m_sub['recall']*100:6.2f}% ({c_m_sub['tp']:5d}/{c_m_sub['n']:5d}) | {k_m_sub['recall']*100:6.2f}% ({k_m_sub['tp']:5d}/{k_m_sub['n']:5d}) | {(k_m_sub['recall']-c_m_sub['recall'])*100:+6.2f}%")

    print("-" * 92)
    print("DIAGNOSTIC BENCHMARK V1.0 SLICES (FPR @ 0.28):")
    for cat in ["bare_apex", "deep_repo_path", "search_query"]:
        c_c = eval_ctrl["bench_categories"][cat]
        k_c = eval_cand["bench_categories"][cat]
        print(f"  Category: {cat:<26} | {c_c['final_fpr']*100:6.2f}% ({c_c['final_fp_28']:3d}/{c_c['n']:3d}) | {k_c['final_fpr']*100:6.2f}% ({k_c['final_fp_28']:3d}/{k_c['n']:3d}) | {(k_c['final_fpr']-c_c['final_fpr'])*100:+6.2f}%")

    c_ov = eval_ctrl["bench_overall"]
    k_ov = eval_cand["bench_overall"]
    print(f"{'Overall Hard-Benign FPR (N=500)':<38} | {c_ov['fpr']*100:6.2f}% ({c_ov['fp']:3d})   | {k_ov['fpr']*100:6.2f}% ({k_ov['fp']:3d})   | {(k_ov['fpr']-c_ov['fpr'])*100:+6.2f}%")

    print("\nTotal Experiment Duration: {:.2f}s".format(time.time() - start_total_time))
    print("=" * 80)


if __name__ == "__main__":
    main()
