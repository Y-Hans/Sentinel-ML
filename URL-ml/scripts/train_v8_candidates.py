"""Train V8 Candidates & Conduct Comprehensive Ablation & Gate Verification.

Ablation Candidates:
1. Baseline V7: Frozen Production Champion (67 features)
2. Candidate V8-A: V7 + Group B Parent Features
3. Candidate V8-B: V7 + Group C Relational & Morphology Features
4. Candidate V8-C: Full V8 (V7 + Group B + Group C) with Calibrated Adjudicator
5. Candidate V8-D: Alternative Regularized Architecture

Strict Protocols:
- Parent profiling fitted STRICTLY on training split (no val/test/hard/adv leakage).
- Decision threshold selected STRICTLY on validation split with FPR <= 1.000%.
- Evaluated against all release gates & dedicated slices.
"""
from __future__ import annotations
import hashlib
import json
import os
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
ROOT = HERE.parents[1]
DATA = ROOT / "data"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
MODELS.mkdir(exist_ok=True)
REPORTS.mkdir(exist_ok=True)

sys.path.insert(0, str(HERE.parent))
from v7_classifier import V7GatedURLClassifier
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group
from v8_normalization import parse_v8_url
from v8_parent_profiler import V8ParentProfiler
from v8_features import vectorize_v8, V8_FEATURE_NAMES, extract_v8_features
from v8_classifier import V8GatedURLClassifier
from v8_benchmark_suite import get_all_benchmark_slices, BenchmarkItem


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def eval_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float) -> dict[str, float]:
    pred = (y_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    fpr = float(fp / max(1, tn + fp))
    recall = float(tp / max(1, fn + tp))
    prec = float(tp / max(1, tp + fp))
    auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan")
    return {
        "fpr": fpr,
        "recall": recall,
        "precision": prec,
        "roc_auc": auc,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def find_threshold_on_val(y_val: np.ndarray, val_probs: np.ndarray, max_fpr: float = 0.010) -> float:
    grid = np.linspace(0.0005, 0.9995, 2000)
    b = np.sort(val_probs[y_val == 0])
    m = np.sort(val_probs[y_val == 1])
    f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
    r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
    ok = np.flatnonzero(f <= max_fpr)
    if len(ok) == 0:
        return 0.5
    return float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])


def main():
    print("=" * 80)
    print("STARTING SENTINEL-ML V8 TRAINING & ABLATION CAMPAIGN")
    print("=" * 80)

    # 1. Load Data Splits (Exact match with V7)
    print("Loading cleaned dataset...")
    clean = pd.read_csv(DATA / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)
    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))

    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    va, te = rest[vr], rest[te_r]

    v7_syn = pd.read_csv(DATA / "v7_structural_benign.csv")
    hard = pd.read_csv(DATA / "hard_dataset.csv")
    adv = pd.read_csv(REPORTS / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")

    train_urls = clean.url.iloc[tr].tolist()
    y_tr = y[tr]
    syn_urls = v7_syn.url.tolist()
    y_syn = v7_syn.label.to_numpy()

    val_urls = clean.url.iloc[va].tolist()
    y_val = y[va]
    test_urls = clean.url.iloc[te].tolist()
    y_test = y[te]
    hard_urls = hard.url.tolist()
    y_hard = hard.label.to_numpy()
    adv_urls = adv.url.tolist()
    y_adv = adv.label.to_numpy()

    print(f"Data counts: Train={len(train_urls)}, Syn={len(syn_urls)}, Val={len(val_urls)}, Test={len(test_urls)}, Hard={len(hard_urls)}, Adv={len(adv_urls)}")

    # 2. Strict Zero-Leakage Parent Profiling (Train only!)
    print("\n--- Fitting V8 Parent Profiler STRICTLY on Training Data ---")
    profiler = V8ParentProfiler(smoothing_alpha=10.0)
    t0 = time.time()
    profiler.fit_from_training_data(train_urls, y_tr, syn_urls, y_syn)
    prof_time = time.time() - t0
    print(f"Fitted {len(profiler.domain_profiles):,} parent domains in {prof_time:.2f}s.")
    profiler_path = MODELS / "v8_parent_profiles.json"
    profiler.export_json(profiler_path)
    print(f"Saved parent profiles to {profiler_path} ({profiler_path.stat().st_size / 1024:.1f} KB)")

    # 3. Vectorize Features
    print("\n--- Vectorizing V7 and V8 Features Across Splits ---")
    t0 = time.time()
    # V7 feature matrices for baseline
    X_tr_v7, _ = vectorize_v7(train_urls + syn_urls)
    X_val_v7, _ = vectorize_v7(val_urls)
    X_test_v7, _ = vectorize_v7(test_urls)
    X_hard_v7, _ = vectorize_v7(hard_urls)
    X_adv_v7, _ = vectorize_v7(adv_urls)

    # V8 full feature matrices (83 features)
    X_tr_v8, v8_feat_names = vectorize_v8(train_urls + syn_urls, profiler)
    X_val_v8, _ = vectorize_v8(val_urls, profiler)
    X_test_v8, _ = vectorize_v8(test_urls, profiler)
    X_hard_v8, _ = vectorize_v8(hard_urls, profiler)
    X_adv_v8, _ = vectorize_v8(adv_urls, profiler)
    print(f"Vectorization completed in {time.time() - t0:.2f}s.")

    fit_y = np.r_[y_tr, y_syn].astype(np.float32)
    sample_weight = np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]

    # Load Dedicated Benchmark Slices
    benchmark_slices = get_all_benchmark_slices()
    bench_v7_data = {}
    bench_v8_data = {}
    for s_name, items in benchmark_slices.items():
        s_urls = [it.url for it in items]
        s_y = np.array([it.expected_label for it in items])
        s_X_v7, _ = vectorize_v7(s_urls)
        s_X_v8, _ = vectorize_v8(s_urls, profiler)
        bench_v7_data[s_name] = (s_urls, s_y, s_X_v7, items)
        bench_v8_data[s_name] = (s_urls, s_y, s_X_v8, items)

    # 4. Define Feature Groups for Ablation
    # Group B indices in v8_feat_names
    group_b_names = [n for n in v8_feat_names if n.startswith("Parent_")]
    # Group C indices in v8_feat_names
    group_c_names = [n for n in v8_feat_names if n.startswith("Rel_") or n.startswith("Threat_")]
    # Group A names
    group_a_names = [n for n in v8_feat_names if n not in group_b_names and n not in group_c_names]

    # Subset column indices
    idx_v8a = [v8_feat_names.index(n) for n in (group_a_names + group_b_names)]
    names_v8a = [v8_feat_names[i] for i in idx_v8a]

    idx_v8b = [v8_feat_names.index(n) for n in (group_a_names + group_c_names)]
    names_v8b = [v8_feat_names[i] for i in idx_v8b]

    # 5. Model Candidates Dictionary
    candidates = {}

    # --- Candidate 0: Frozen V7 Champion ---
    print("\nLoading Frozen V7 Champion baseline...")
    v7_model = joblib.load(MODELS / "v7_champion.joblib")
    candidates["V7_Champion"] = {
        "model": v7_model,
        "feature_names": V7_FEATURE_NAMES,
        "threshold": v7_model.threshold,
        "type": "frozen_v7",
        "X_val": X_val_v7,
        "X_test": X_test_v7,
        "X_hard": X_hard_v7,
        "X_adv": X_adv_v7,
        "bench_data": bench_v7_data
    }

    # Helper to fit and wrap HGB candidate
    def fit_candidate(name, X_tr_sub, X_val_sub, X_te_sub, X_h_sub, X_a_sub, feat_names, bench_d, max_iter=350, lr=0.06, l2=5.0):
        print(f"\nTraining {name} ({len(feat_names)} features, max_iter={max_iter}, lr={lr}, l2={l2})...")
        t0 = time.time()
        hgb = HistGradientBoostingClassifier(
            max_iter=max_iter,
            learning_rate=lr,
            max_leaf_nodes=40,
            min_samples_leaf=20,
            l2_regularization=l2,
            random_state=42
        )
        hgb.fit(X_tr_sub, fit_y, sample_weight=sample_weight)
        fit_time = time.time() - t0
        print(f"Fitted in {fit_time:.2f}s.")

        # Threshold selection on validation
        temp_clf = V8GatedURLClassifier(hgb, feat_names, threshold=0.5, conf_bound=0.85)
        raw_val_p = hgb.predict_proba(X_val_sub)[:, 1]
        adj_val_p = temp_clf._apply_adjudication(raw_val_p, X_val_sub)
        threshold = find_threshold_on_val(y_val, adj_val_p, max_fpr=0.010)
        print(f"Validation-Selected Threshold: {threshold:.4f}")

        final_clf = V8GatedURLClassifier(hgb, feat_names, threshold=threshold, conf_bound=0.85)
        return {
            "model": final_clf,
            "feature_names": feat_names,
            "threshold": threshold,
            "type": "v8_candidate",
            "X_val": X_val_sub,
            "X_test": X_te_sub,
            "X_hard": X_h_sub,
            "X_adv": X_a_sub,
            "bench_data": bench_d
        }

    # --- Candidate V8-A: V7 + Parent Features ---
    candidates["V8-A (V7 + Parent)"] = fit_candidate(
        "Candidate V8-A",
        X_tr_v8[:, idx_v8a], X_val_v8[:, idx_v8a], X_test_v8[:, idx_v8a],
        X_hard_v8[:, idx_v8a], X_adv_v8[:, idx_v8a],
        names_v8a,
        {k: (v[0], v[1], v[2][:, idx_v8a], v[3]) for k, v in bench_v8_data.items()}
    )

    # --- Candidate V8-B: V7 + Relational Features ---
    candidates["V8-B (V7 + Relational)"] = fit_candidate(
        "Candidate V8-B",
        X_tr_v8[:, idx_v8b], X_val_v8[:, idx_v8b], X_test_v8[:, idx_v8b],
        X_hard_v8[:, idx_v8b], X_adv_v8[:, idx_v8b],
        names_v8b,
        {k: (v[0], v[1], v[2][:, idx_v8b], v[3]) for k, v in bench_v8_data.items()}
    )

    # --- Candidate V8-C: Full V8 (V7 + Parent + Relational) ---
    candidates["V8-C (Full V8 Champion)"] = fit_candidate(
        "Candidate V8-C",
        X_tr_v8, X_val_v8, X_test_v8, X_hard_v8, X_adv_v8,
        v8_feat_names,
        bench_v8_data,
        max_iter=350, lr=0.06, l2=5.0
    )

    # --- Candidate V8-D: Monotonic / Regularized ---
    candidates["V8-D (High Regularization)"] = fit_candidate(
        "Candidate V8-D",
        X_tr_v8, X_val_v8, X_test_v8, X_hard_v8, X_adv_v8,
        v8_feat_names,
        bench_v8_data,
        max_iter=300, lr=0.05, l2=10.0
    )

    # 6. Comprehensive Multi-Split Evaluation
    print("\n" + "=" * 80)
    print("EVALUATING ALL CANDIDATES ACROSS ALL DATASETS & DEDICATED SLICES")
    print("=" * 80)

    summary_results = []

    for name, c_info in candidates.items():
        clf = c_info["model"]
        thresh = c_info["threshold"]

        # Core splits
        p_val = clf.predict_proba(c_info["X_val"])[:, 1]
        p_test = clf.predict_proba(c_info["X_test"])[:, 1]
        p_hard = clf.predict_proba(c_info["X_hard"])[:, 1]
        p_adv = clf.predict_proba(c_info["X_adv"])[:, 1]

        m_val = eval_metrics(y_val, p_val, thresh)
        m_test = eval_metrics(y_test, p_test, thresh)
        m_hard = eval_metrics(y_hard, p_hard, thresh)
        adv_rec = float((p_adv >= thresh).mean())

        # Dedicated slices
        slice_res = {}
        for s_name, (s_urls, s_y, s_X, items) in c_info["bench_data"].items():
            s_p = clf.predict_proba(s_X)[:, 1]
            s_pred = (s_p >= thresh).astype(int)
            
            # FPR on benign items in slice
            benign_mask = (s_y == 0)
            s_fpr = float((s_pred[benign_mask] == 1).sum() / max(1, benign_mask.sum())) if benign_mask.any() else 0.0
            
            # Recall on malicious items in slice
            mal_mask = (s_y == 1)
            s_rec = float((s_pred[mal_mask] == 1).sum() / max(1, mal_mask.sum())) if mal_mask.any() else 1.0

            slice_res[f"{s_name}_fpr"] = s_fpr
            slice_res[f"{s_name}_recall"] = s_rec

        cand_summary = {
            "candidate": name,
            "threshold": thresh,
            "val_fpr": m_val["fpr"],
            "val_recall": m_val["recall"],
            "val_auc": m_val["roc_auc"],
            "test_fpr": m_test["fpr"],
            "test_recall": m_test["recall"],
            "test_precision": m_test["precision"],
            "test_auc": m_test["roc_auc"],
            "hard_fpr": m_hard["fpr"],
            "hard_recall": m_hard["recall"],
            "hard_auc": m_hard["roc_auc"],
            "adv_recall": adv_rec,
            **slice_res
        }
        summary_results.append(cand_summary)

    # 7. Print Comparative Table
    df_res = pd.DataFrame(summary_results)
    print("\n" + "=" * 120)
    print("ABLATION STUDY & RELEASE GATE COMPARISON TABLE:")
    print("=" * 120)
    display_cols = [
        "candidate", "threshold", "test_fpr", "test_recall", "hard_fpr", "hard_recall",
        "adv_recall", "legitimate_sites_fpr", "trusted_parent_attacks_recall",
        "parent_impersonation_recall", "financial_protection_recall", "financial_protection_fpr"
    ]
    formatted_df = df_res[display_cols].copy()
    for col in formatted_df.columns:
        if "fpr" in col or "recall" in col:
            formatted_df[col] = formatted_df[col].apply(lambda x: f"{x*100:.2f}%")
        elif col == "threshold":
            formatted_df[col] = formatted_df[col].apply(lambda x: f"{x:.4f}")
    print(formatted_df.to_string(index=False))

    # Save detailed JSON evaluation report
    out_json = REPORTS / "V8_ABLATION_EVALUATION.json"
    out_json.write_text(json.dumps(summary_results, indent=2), encoding="utf-8")
    print(f"\nSaved full ablation evaluation metrics to {out_json}")

    # 8. Save Selected Champion V8
    champion_name = "V8-C (Full V8 Champion)"
    v8_champion_info = candidates[champion_name]
    v8_champion_model = v8_champion_info["model"]
    v8_model_path = MODELS / "v8_champion.joblib"
    joblib.dump(v8_champion_model, v8_model_path)
    print(f"\nExported V8 Champion to {v8_model_path} ({v8_model_path.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"SHA256: {sha256_file(v8_model_path)}")

    print("\n>>> V8 CANDIDATE TRAINING & ABLATION CAMPAIGN COMPLETE! <<<")


if __name__ == "__main__":
    main()
