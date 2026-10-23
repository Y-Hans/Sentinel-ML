"""V7 Independent Clean Reproduction & Release Candidate Verification.

This script executes a clean, deterministic, end-to-end training and validation loop:
1. Re-vectorizes all datasets using V7 deterministic feature extractor (v7_features.py).
2. Fits the V7 Champion (HistGradientBoosting with threat-regularization and safe-domain adjudication).
3. Selects the decision threshold strictly on the validation split with max FPR <= 1.00%.
4. Evaluates against all release gates simultaneously:
   - TEST Benign FPR <= 1.000%
   - TEST Malicious Recall >= 98.000%
   - HARD Benign FPR <= 1.000%
   - HARD Malicious Recall >= 95.000%
   - Adversarial Recall >= 95.000%
   - Serialized Model Bundle Size <= 10.00 MB
5. Asserts all release criteria and saves model artifact to models/v7_champion.joblib.
"""
from __future__ import annotations
import hashlib
import io
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
from v7_features import vectorize_v7, V7_FEATURE_NAMES, extract_v7_features
from v7_classifier import V7GatedURLClassifier
from url_features import domain_group


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_verification():
    print("=================================================================")
    print("STARTING V7 INDEPENDENT VERIFICATION & REPRODUCTION PIPELINE")
    print("=================================================================")

    # 1. Load Datasets
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

    ntr, ns, nv, nt, nh, na = len(tr), len(v7_syn), len(va), len(te), len(hard), len(adv)
    print(f"Split sizes: Train={ntr:,}, Structural_Benign={ns:,}, Val={nv:,}, Test={nt:,}, Hard={nh:,}, Adv={na:,}")

    # 2. Vectorize Features
    train_urls = clean.url.iloc[tr].tolist()
    syn_urls = v7_syn.url.tolist()
    val_urls = clean.url.iloc[va].tolist()
    test_urls = clean.url.iloc[te].tolist()
    hard_urls = hard.url.tolist()
    adv_urls = adv.url.tolist()

    all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls + adv_urls
    print(f"Vectorizing {len(all_urls):,} total URLs across 67 deterministic V7.5 features...")
    t0 = time.time()
    X_all, feature_names = vectorize_v7(all_urls)
    vec_time = time.time() - t0
    print(f"Vectorization completed in {vec_time:.2f}s ({vec_time/len(all_urls)*1000:.3f} ms/url)")

    cuts = np.cumsum([ntr, ns, nv, nt, nh])
    Xtr, Xs, Xv, Xt, Xh, Xa = np.split(X_all, cuts)

    y_tr = y[tr]
    y_syn = v7_syn.label.to_numpy()
    y_val = y[va]
    y_test = y[te]
    y_hard = hard.label.to_numpy()
    y_adv = adv.label.to_numpy()

    fit_X = np.vstack([Xtr, Xs])
    fit_y = np.r_[y_tr, y_syn].astype(np.float32)

    # 3. Train Model
    sample_weight = np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(ns, 1.0)]
    print("\nFitting HistGradientBoostingClassifier (max_iter=350, lr=0.06, l2=5.0)...")
    t0 = time.time()
    hgb = HistGradientBoostingClassifier(
        max_iter=350,
        learning_rate=0.06,
        max_leaf_nodes=40,
        min_samples_leaf=20,
        l2_regularization=5.0,
        random_state=42
    )
    hgb.fit(fit_X, fit_y, sample_weight=sample_weight)
    fit_time = time.time() - t0
    print(f"Model fitted in {fit_time:.2f}s")

    # 4. Strictly Validation-Only Threshold Selection
    raw_val_p = hgb.predict_proba(Xv)[:, 1]
    temp_clf = V7GatedURLClassifier(hgb, feature_names, threshold=0.5, conf_bound=0.80)
    gated_val_p = temp_clf._apply_gating(raw_val_p, Xv)

    grid = np.linspace(0.0005, 0.9995, 2000)
    b = np.sort(gated_val_p[y_val == 0])
    m = np.sort(gated_val_p[y_val == 1])
    f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
    r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
    ok = np.flatnonzero(f <= 0.010)
    threshold = float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])
    print(f"\nOptimal Validation-Selected Threshold: {threshold:.4f} (Validation FPR: {f[ok[0]]*100:.3f}%)")

    # 5. Build Final Gated Model Instance
    v7_champion = V7GatedURLClassifier(hgb, feature_names, threshold=threshold, conf_bound=0.80)

    # 6. Evaluate on Test, Hard, and Adversarial Splits
    p_test = v7_champion.predict_proba(Xt)[:, 1]
    p_hard = v7_champion.predict_proba(Xh)[:, 1]
    p_adv = v7_champion.predict_proba(Xa)[:, 1]

    def eval_split(y_true, y_prob, t):
        pred = (y_prob >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
        fpr = float(fp / max(1, tn + fp))
        recall = float(tp / max(1, fn + tp))
        auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan")
        return fpr, recall, auc, tn, fp, fn, tp

    test_fpr, test_rec, test_auc, t_tn, t_fp, t_fn, t_tp = eval_split(y_test, p_test, threshold)
    hard_fpr, hard_rec, hard_auc, h_tn, h_fp, h_fn, h_tp = eval_split(y_hard, p_hard, threshold)
    adv_rec = float((p_adv >= threshold).mean())

    # Measure Serialized Bundle Size
    model_path = MODELS / "v7_champion.joblib"
    joblib.dump(v7_champion, model_path)
    bundle_size_bytes = model_path.stat().st_size
    bundle_size_mb = bundle_size_bytes / (1024 * 1024)
    model_sha256 = sha256_file(model_path)

    # 7. Verification Audit Report
    print("\n" + "=" * 65)
    print("V7 INDEPENDENT VERIFICATION RELEASE AUDIT:")
    print("=" * 65)
    
    gates = [
        ("TEST Benign FPR", test_fpr * 100, "<= 1.000%", test_fpr <= 0.0100),
        ("TEST Malicious Recall", test_rec * 100, ">= 98.000%", test_rec >= 0.9800),
        ("HARD Benign FPR", hard_fpr * 100, "<= 1.000%", hard_fpr <= 0.0100),
        ("HARD Malicious Recall", hard_rec * 100, ">= 95.000%", hard_rec >= 0.9500),
        ("Adversarial Recall", adv_rec * 100, ">= 95.000%", adv_rec >= 0.9500),
        ("Model Bundle Size", bundle_size_mb, "<= 10.00 MB", bundle_size_mb <= 10.00),
    ]

    all_passed = True
    for name, val, target, passed in gates:
        status = "PASS" if passed else "FAIL"
        if not passed: all_passed = False
        val_str = f"{val:.3f}%" if "%" in target else f"{val:.2f} MB"
        print(f"  {name:<25}: {val_str:<10} (Gate: {target:<12}) -> {status}")

    print(f"\n  TEST ROC-AUC           : {test_auc:.4f}")
    print(f"  HARD ROC-AUC           : {hard_auc:.4f}")
    print(f"  Model Artifact SHA256  : {model_sha256}")
    print(f"  ALL GATES SATISFIED    : {all_passed}")
    print("=" * 65)

    assert all_passed, "VERIFICATION FAILURE: Not all release gates were satisfied simultaneously!"
    print("\n>>> INDEPENDENT VERIFICATION SUCCEEDED! ALL RELEASE GATES SATISFIED! <<<")
    return {
        "status": "PASSED",
        "threshold": threshold,
        "test_fpr": test_fpr,
        "test_recall": test_rec,
        "test_auc": test_auc,
        "hard_fpr": hard_fpr,
        "hard_recall": hard_rec,
        "hard_auc": hard_auc,
        "adv_recall": adv_rec,
        "bundle_size_bytes": bundle_size_bytes,
        "bundle_size_mb": bundle_size_mb,
        "model_sha256": model_sha256,
        "all_passed": all_passed
    }


if __name__ == "__main__":
    run_verification()
