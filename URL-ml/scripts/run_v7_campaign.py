"""URL-ML V7 Autonomous Research & Optimization Campaign Driver (Round 2).

Trains, validates, selects validation-only thresholds, and evaluates challengers
across TEST, Protected Hard-Source, and Adversarial benchmarks under strict
domain isolation, <=10 MB model bundle constraint, and cryptographic provenance.
"""
from __future__ import annotations
import hashlib
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
DATA = ROOT / "data"
REPORTS = ROOT / "reports"
MODELS = ROOT / "model" / "challengers"
sys.path.insert(0, str(HERE.parent))

from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group


def sha(p: Path | str) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def calc_metrics(y_true, y_prob, thresh):
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    y_pred = (y_prob >= thresh).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    try:
        auc = float(roc_auc_score(y_true, y_prob))
    except ValueError:
        auc = float("nan")
    return {
        "n": int(len(y_true)),
        "benign_fpr": float(fp / max(1, tn + fp)),
        "malicious_recall": float(tp / max(1, fn + tp)),
        "roc_auc": auc,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]
    }


def find_optimal_threshold(y_val, p_val, max_fpr=0.010):
    """Find threshold strictly on validation set satisfying FPR <= max_fpr while maximizing recall."""
    y_val = np.asarray(y_val)
    p_val = np.asarray(p_val)
    grid = np.linspace(0.0005, 0.9995, 2000)
    benign_scores = np.sort(p_val[y_val == 0])
    mal_scores = np.sort(p_val[y_val == 1])
    
    fprs = (benign_scores.size - np.searchsorted(benign_scores, grid, "left")) / max(1, benign_scores.size)
    recalls = (mal_scores.size - np.searchsorted(mal_scores, grid, "left")) / max(1, mal_scores.size)
    
    valid_idx = np.flatnonzero(fprs <= max_fpr)
    if len(valid_idx) == 0:
        valid_idx = np.arange(len(grid))
    
    best_i = valid_idx[np.lexsort((grid[valid_idx], fprs[valid_idx], -recalls[valid_idx]))[0]]
    return float(grid[best_i])


def run_campaign():
    print("=" * 70)
    print("STARTING URL-ML V7 RESEARCH & OPTIMIZATION CAMPAIGN (ROUND 2)")
    print("=" * 70)

    clean_path = DATA / "cleaned_dataset.csv"
    clean = pd.read_csv(clean_path, usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)
    
    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))

    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    va, te = rest[vr], rest[te_r]

    ntr, nv, nt = len(tr), len(va), len(te)
    print(f"Clean splits: Train={ntr}, Val={nv}, Test={nt}")

    v7_syn_path = DATA / "v7_structural_benign.csv"
    v7_syn = pd.read_csv(v7_syn_path)
    ns = len(v7_syn)
    print(f"V7 Structural Benign Rows: {ns}")

    hard_path = DATA / "hard_dataset.csv"
    hard = pd.read_csv(hard_path)
    nh = len(hard)
    print(f"Protected Hard-Source Rows: {nh}")

    adv_path = REPORTS / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv"
    adv = pd.read_csv(adv_path, usecols=["url", "label", "attack_family"]) if adv_path.exists() else None
    print(f"Adversarial Evaluation Rows: {len(adv) if adv is not None else 0}")

    print("Extracting refined V7 features across all splits...")
    start_feat = time.perf_counter()
    train_urls = clean.url.iloc[tr].tolist()
    syn_urls = v7_syn.url.tolist()
    val_urls = clean.url.iloc[va].tolist()
    test_urls = clean.url.iloc[te].tolist()
    hard_urls = hard.url.tolist()
    adv_urls = adv.url.tolist() if adv is not None else []

    all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls + adv_urls
    X_all, feature_names = vectorize_v7(all_urls)
    feat_time = time.perf_counter() - start_feat
    print(f"Extracted {len(feature_names)} features for {len(all_urls)} URLs in {feat_time:.2f}s")

    cuts = np.cumsum([ntr, ns, nv, nt, nh])
    Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])
    Xa = X_all[cuts[-1]:] if len(adv_urls) > 0 else None

    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr)
    Xs_s = scaler.transform(Xs)
    Xv_s = scaler.transform(Xv)
    Xt_s = scaler.transform(Xt)
    Xh_s = scaler.transform(Xh)
    Xa_s = scaler.transform(Xa) if Xa is not None else None

    y_tr = y[tr]
    y_syn = v7_syn.label.to_numpy()
    y_val = y[va]
    y_test = y[te]
    y_hard = hard.label.to_numpy()
    y_adv = adv.label.to_numpy() if adv is not None else None

    fit_X_raw = np.vstack([Xtr, Xs])
    fit_X_s = np.vstack([Xtr_s, Xs_s])
    fit_y = np.r_[y_tr, y_syn]

    configs = [
        {
            "id": "v7_et_compact_w1",
            "name": "ExtraTrees Compact (80 Trees, Depth 16, W=1)",
            "hypothesis": "Refined normalization + 15k-domain structural corpus prevents path false positives within <=10MB bundle",
            "model": ExtraTreesClassifier(n_estimators=80, max_depth=16, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=1),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 1.0)],
            "syn_weight": 1.0
        },
        {
            "id": "v7_et_compact_w3",
            "name": "ExtraTrees Compact (80 Trees, Depth 16, W=3)",
            "hypothesis": "3x sample weight on 48k structural benigns eliminates residual hard-source shift",
            "model": ExtraTreesClassifier(n_estimators=80, max_depth=16, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=1),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 3.0)],
            "syn_weight": 3.0
        },
        {
            "id": "v7_et_compact_w5",
            "name": "ExtraTrees Compact (80 Trees, Depth 16, W=5)",
            "hypothesis": "5x sample weight further drives down hard-source FPR while monitoring TEST recall",
            "model": ExtraTreesClassifier(n_estimators=80, max_depth=16, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=1),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 5.0)],
            "syn_weight": 5.0
        },
        {
            "id": "v7_hgb_reg_w1",
            "name": "HistGradientBoosting Regularized (W=1)",
            "hypothesis": "Refined features + L2 regularized HGB achieves smooth non-linear separation on continuous threat features",
            "model": HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, max_leaf_nodes=31, min_samples_leaf=25, l2_regularization=3.0, random_state=42),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 1.0)],
            "syn_weight": 1.0
        },
        {
            "id": "v7_hgb_reg_w3",
            "name": "HistGradientBoosting Regularized (W=3)",
            "hypothesis": "3x weighted HGB balances clean TEST recall and hard-source false positives in a ~1MB bundle",
            "model": HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, max_leaf_nodes=31, min_samples_leaf=25, l2_regularization=3.0, random_state=42),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 3.0)],
            "syn_weight": 3.0
        },
        {
            "id": "v7_rf_compact_w3",
            "name": "RandomForest Compact (80 Trees, Depth 16, W=3)",
            "hypothesis": "RandomForest bootstrap aggregation provides alternative split variance reduction vs ExtraTrees",
            "model": RandomForestClassifier(n_estimators=80, max_depth=16, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=1),
            "use_scaled": False,
            "sample_weight": np.r_[np.ones(ntr), np.full(ns, 3.0)],
            "syn_weight": 3.0
        },
        {
            "id": "v7_mlp_dense_w1",
            "name": "Compact Neural MLP (W=1)",
            "hypothesis": "Smooth continuous neural boundaries on StandardScaled features prevent sharp split artifacts",
            "model": MLPClassifier(hidden_layer_sizes=(128, 64, 32), activation="relu", alpha=1e-3, max_iter=200, early_stopping=True, n_iter_no_change=10, random_state=42),
            "use_scaled": True,
            "sample_weight": None,
            "syn_weight": 1.0
        }
    ]

    results = []
    saved_probs = {}

    for cfg in configs:
        exp_id = cfg["id"]
        print("-" * 60)
        print(f"Running Experiment: {exp_id} ({cfg['name']})")
        print(f"Hypothesis: {cfg['hypothesis']}")

        model = cfg["model"]
        use_scaled = cfg["use_scaled"]
        train_X = fit_X_s if use_scaled else fit_X_raw
        val_X = Xv_s if use_scaled else Xv
        test_X = Xt_s if use_scaled else Xt
        hard_X = Xh_s if use_scaled else Xh
        adv_X = Xa_s if (use_scaled and Xa_s is not None) else Xa

        t0 = time.perf_counter()
        if cfg["sample_weight"] is not None and hasattr(model, "fit"):
            try:
                model.fit(train_X, fit_y, sample_weight=cfg["sample_weight"])
            except TypeError:
                model.fit(train_X, fit_y)
        else:
            model.fit(train_X, fit_y)
        fit_time = time.perf_counter() - t0
        print(f"Fit completed in {fit_time:.2f}s")

        p_val = model.predict_proba(val_X)[:, 1]
        thresh = find_optimal_threshold(y_val, p_val, max_fpr=0.010)
        print(f"Validation-Selected Threshold (at <=1% Val FPR): {thresh:.5f}")

        p_test = model.predict_proba(test_X)[:, 1]
        p_hard = model.predict_proba(hard_X)[:, 1]
        p_adv = model.predict_proba(adv_X)[:, 1] if adv_X is not None else np.zeros(len(adv_urls))

        saved_probs[exp_id] = {
            "p_val": p_val,
            "p_test": p_test,
            "p_hard": p_hard,
            "p_adv": p_adv,
            "model": model,
            "scaler": scaler,
            "use_scaled": use_scaled,
            "threshold": thresh
        }

        val_metrics = calc_metrics(y_val, p_val, thresh)
        test_metrics = calc_metrics(y_test, p_test, thresh)
        hard_metrics = calc_metrics(y_hard, p_hard, thresh)
        adv_metrics = calc_metrics(y_adv, p_adv, thresh) if adv is not None else {"malicious_recall": float("nan")}

        out_dir = MODELS / exp_id
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, out_dir / "model.joblib")
        joblib.dump(scaler, out_dir / "scaler.joblib")
        model_size = sum(f.stat().st_size for f in out_dir.iterdir())

        pass_test_fpr = test_metrics["benign_fpr"] <= 0.0100
        pass_test_rec = test_metrics["malicious_recall"] >= 0.9800
        pass_hard_fpr = hard_metrics["benign_fpr"] <= 0.0100
        pass_hard_rec = hard_metrics["malicious_recall"] >= 0.9500
        pass_adv_rec = adv_metrics["malicious_recall"] >= 0.9500
        pass_size = model_size <= 10 * 1024 * 1024
        all_passed = all([pass_test_fpr, pass_test_rec, pass_hard_fpr, pass_hard_rec, pass_adv_rec, pass_size])

        meta = {
            "campaign": "URL-ML V7",
            "experiment_id": exp_id,
            "name": cfg["name"],
            "hypothesis": cfg["hypothesis"],
            "architecture": type(model).__name__,
            "feature_count": len(feature_names),
            "feature_schema_sha256": sha(HERE.parent / "v7_features.py"),
            "seed": getattr(model, "random_state", 42),
            "structural_weight": cfg["syn_weight"],
            "threshold": thresh,
            "source_dataset_sha256": sha(clean_path),
            "structural_dataset_sha256": sha(v7_syn_path),
            "hard_dataset_sha256": sha(hard_path),
            "train_rows": ntr,
            "structural_rows": ns,
            "validation": val_metrics,
            "test": test_metrics,
            "hard_source_holdout": hard_metrics,
            "adversarial": adv_metrics,
            "fit_seconds": fit_time,
            "artifact": str(out_dir.relative_to(ROOT)).replace("\\", "/"),
            "model_size_bytes": model_size,
            "gates": {
                "test_fpr_pass": bool(pass_test_fpr),
                "test_recall_pass": bool(pass_test_rec),
                "hard_fpr_pass": bool(pass_hard_fpr),
                "hard_recall_pass": bool(pass_hard_rec),
                "adversarial_recall_pass": bool(pass_adv_rec),
                "bundle_size_pass": bool(pass_size),
                "all_gates_pass": bool(all_passed)
            },
            "promotion_status": "candidate_for_reproduction" if all_passed else "challenger_only"
        }

        (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        results.append(meta)

        print(f"Results for {exp_id}:")
        print(f"  TEST: Benign FPR = {test_metrics['benign_fpr']*100:.3f}%, Malicious Recall = {test_metrics['malicious_recall']*100:.3f}% (AUC={test_metrics['roc_auc']:.4f})")
        print(f"  HARD: Benign FPR = {hard_metrics['benign_fpr']*100:.3f}%, Malicious Recall = {hard_metrics['malicious_recall']*100:.3f}% (AUC={hard_metrics['roc_auc']:.4f})")
        print(f"  ADV : Malicious Recall = {adv_metrics['malicious_recall']*100:.3f}%")
        print(f"  SIZE: {model_size} bytes ({model_size / (1024*1024):.2f} MB)")
        print(f"  ALL GATES PASS: {all_passed}")

    # Test Calibrated Hybrid Ensembles
    print("-" * 60)
    print("Running Experiment: v7_hybrid_blend_et_hgb (Compact ExtraTrees + Regularized HGB)")
    et_p_val = saved_probs["v7_et_compact_w3"]["p_val"]
    hgb_p_val = saved_probs["v7_hgb_reg_w3"]["p_val"]
    blend_p_val = 0.50 * et_p_val + 0.50 * hgb_p_val
    blend_thresh = find_optimal_threshold(y_val, blend_p_val, max_fpr=0.010)

    blend_p_test = 0.50 * saved_probs["v7_et_compact_w3"]["p_test"] + 0.50 * saved_probs["v7_hgb_reg_w3"]["p_test"]
    blend_p_hard = 0.50 * saved_probs["v7_et_compact_w3"]["p_hard"] + 0.50 * saved_probs["v7_hgb_reg_w3"]["p_hard"]
    blend_p_adv = 0.50 * saved_probs["v7_et_compact_w3"]["p_adv"] + 0.50 * saved_probs["v7_hgb_reg_w3"]["p_adv"]

    b_val_m = calc_metrics(y_val, blend_p_val, blend_thresh)
    b_test_m = calc_metrics(y_test, blend_p_test, blend_thresh)
    b_hard_m = calc_metrics(y_hard, blend_p_hard, blend_thresh)
    b_adv_m = calc_metrics(y_adv, blend_p_adv, blend_thresh)

    b_dir = MODELS / "v7_hybrid_blend_et_hgb"
    b_dir.mkdir(parents=True, exist_ok=True)
    b_spec = {
        "weights": {"v7_et_compact_w3": 0.50, "v7_hgb_reg_w3": 0.50},
        "threshold": blend_thresh
    }
    (b_dir / "ensemble_spec.json").write_text(json.dumps(b_spec, indent=2), encoding="utf-8")
    b_size = sum(f.stat().st_size for f in (MODELS / "v7_et_compact_w3").iterdir()) + sum(f.stat().st_size for f in (MODELS / "v7_hgb_reg_w3").iterdir())

    pass_all_b = all([
        b_test_m["benign_fpr"] <= 0.0100,
        b_test_m["malicious_recall"] >= 0.9800,
        b_hard_m["benign_fpr"] <= 0.0100,
        b_hard_m["malicious_recall"] >= 0.9500,
        b_adv_m["malicious_recall"] >= 0.9500,
        b_size <= 10 * 1024 * 1024
    ])

    b_meta = {
        "campaign": "URL-ML V7",
        "experiment_id": "v7_hybrid_blend_et_hgb",
        "name": "Hybrid Blend (Compact ExtraTrees + Regularized HGB)",
        "hypothesis": "Equal blend of compact ExtraTrees and regularized HGB provides stable joint operating point under 8 MB bundle size",
        "architecture": "Ensemble(ExtraTrees+HistGradientBoosting)",
        "feature_count": len(feature_names),
        "threshold": blend_thresh,
        "validation": b_val_m,
        "test": b_test_m,
        "hard_source_holdout": b_hard_m,
        "adversarial": b_adv_m,
        "model_size_bytes": b_size,
        "gates": {
            "test_fpr_pass": bool(b_test_m["benign_fpr"] <= 0.0100),
            "test_recall_pass": bool(b_test_m["malicious_recall"] >= 0.9800),
            "hard_fpr_pass": bool(b_hard_m["benign_fpr"] <= 0.0100),
            "hard_recall_pass": bool(b_hard_m["malicious_recall"] >= 0.9500),
            "adversarial_recall_pass": bool(b_adv_m["malicious_recall"] >= 0.9500),
            "bundle_size_pass": bool(b_size <= 10 * 1024 * 1024),
            "all_gates_pass": bool(pass_all_b)
        },
        "promotion_status": "candidate_for_reproduction" if pass_all_b else "challenger_only"
    }
    (b_dir / "metadata.json").write_text(json.dumps(b_meta, indent=2), encoding="utf-8")
    results.append(b_meta)

    print(f"Results for v7_hybrid_blend_et_hgb:")
    print(f"  TEST: Benign FPR = {b_test_m['benign_fpr']*100:.3f}%, Malicious Recall = {b_test_m['malicious_recall']*100:.3f}% (AUC={b_test_m['roc_auc']:.4f})")
    print(f"  HARD: Benign FPR = {b_hard_m['benign_fpr']*100:.3f}%, Malicious Recall = {b_hard_m['malicious_recall']*100:.3f}% (AUC={b_hard_m['roc_auc']:.4f})")
    print(f"  ADV : Malicious Recall = {b_adv_m['malicious_recall']*100:.3f}%")
    print(f"  SIZE: {b_size} bytes ({b_size / (1024*1024):.2f} MB)")
    print(f"  ALL GATES PASS: {pass_all_b}")

    reg = {
        "campaign": "URL-ML V7",
        "protocol": {
            "train_source": "cleaned_dataset.csv + v7_structural_benign.csv (15k domains)",
            "threshold_selection": "validation_only",
            "protected_evaluation": ["hard_dataset.csv", "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv"],
            "frozen_champion_untouched": True,
            "champion_sha256": sha(ROOT / "model/champion/model.joblib")
        },
        "generated_at": pd.Timestamp.now(tz="UTC").isoformat(),
        "experiments": results
    }
    (REPORTS / "URL_V7_EXPERIMENT_REGISTRY.json").write_text(json.dumps(reg, indent=2), encoding="utf-8")
    print("=" * 70)
    print("ROUND 2 CAMPAIGN COMPLETE.")
    print("=" * 70)


if __name__ == "__main__":
    run_campaign()
