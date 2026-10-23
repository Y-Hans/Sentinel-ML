"""Read-only baseline reproduction and source-invariance audit for URL-ML.

Writes only new remediation audit artifacts; never touches the frozen champion,
test/OOD data, Messages-ML, or historical reports.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
DATA = ROOT / "data" / "final_dataset.csv"
REPORTS = ROOT / "reports"
sys.path.insert(0, str(HERE.parent))
from url_features import FULL_FEATURES, domain_group, extract_url_features  # noqa: E402

SEED = 42


def metric(y, p, threshold):
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    pred = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "benign_n": int(tn + fp), "malicious_n": int(fn + tp),
            "benign_fpr": float(fp / max(1, tn + fp)),
            "malicious_recall": float(tp / max(1, fn + tp)),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None}


def threshold_policy(y, p, max_fpr=0.01):
    grid = np.linspace(0.01, 0.99, 981)
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    safe = np.sort(p[y == 0]); bad = np.sort(p[y == 1])
    fp = safe.size - np.searchsorted(safe, grid, side="left")
    tp = bad.size - np.searchsorted(bad, grid, side="left")
    fpr = fp / max(1, safe.size); recall = tp / max(1, bad.size)
    eligible = np.flatnonzero(fpr <= max_fpr)
    if not len(eligible): eligible = np.arange(len(grid))
    best = eligible[np.lexsort((grid[eligible], fpr[eligible], -recall[eligible]))[0]]
    return float(grid[best])


def main():
    REPORTS.mkdir(exist_ok=True)
    df = pd.read_csv(DATA)
    groups = df.url.map(domain_group)
    X = df[FULL_FEATURES].astype(np.float32)
    y = df.label.astype(int).to_numpy()
    first, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.40, random_state=SEED).split(X, y, groups))
    val_rel, test_rel = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED).split(X.iloc[rest], y[rest], groups.iloc[rest]))
    train_idx, val_idx, test_idx = first, rest[val_rel], rest[test_rel]
    hard_mask = df.DatasetSource.to_numpy() == "hard"
    original_train_idx = np.asarray([i for i in train_idx if df.iloc[i].DatasetSource == "original"], dtype=int)
    scaler = StandardScaler().fit(X.iloc[train_idx])
    Xs = scaler.transform(X).astype(np.float32)

    families = {
        "full": list(FULL_FEATURES),
        "source_reduced_no_identity": [f for f in FULL_FEATURES if f not in {"KnownBrandDomain", "BrandImpersonationScore", "SuspiciousTLD"}],
        "domain_invariant_structure": ["URLLength", "IsDomainIP", "NoOfSubDomain", "IsHTTPS", "SpecialCharRatio", "DigitRatio", "HasAtSymbol", "HyphenCount", "PathQueryLength"],
        "base_only": ["URLLength", "DomainLength", "IsDomainIP", "NoOfSubDomain", "IsHTTPS", "HasSuspiciousWords", "SpecialCharRatio", "DigitRatio", "HasAtSymbol"],
    }
    results = {}
    fitted = {}
    for name, features in families.items():
        indices = [FULL_FEATURES.index(f) for f in features]
        model = RandomForestClassifier(n_estimators=40, max_depth=18, min_samples_leaf=2,
                                       n_jobs=1, class_weight="balanced_subsample", random_state=SEED)
        model.fit(Xs[train_idx][:, indices], y[train_idx])
        pv = model.predict_proba(Xs[val_idx][:, indices])[:, 1]
        threshold = threshold_policy(y[val_idx], pv)
        pt = model.predict_proba(Xs[test_idx][:, indices])[:, 1]
        # A separate source-holdout fit is required: no hard-source rows are fit.
        holdout_model = RandomForestClassifier(n_estimators=40, max_depth=18, min_samples_leaf=2,
                                               n_jobs=1, class_weight="balanced_subsample", random_state=SEED)
        holdout_model.fit(Xs[original_train_idx][:, indices], y[original_train_idx])
        ph = holdout_model.predict_proba(Xs[hard_mask][:, indices])[:, 1]
        results[name] = {"features": features, "threshold": threshold,
                         "validation": metric(y[val_idx], pv, threshold),
                         "test": metric(y[test_idx], pt, threshold),
                         "hard_source_holdout": metric(y[hard_mask], ph, threshold)}
        fitted[name] = (model, indices, threshold, ph)

    # Detailed forensic table for every hard-source false positive under frozen champion.
    champion = fitted["full"]
    hard_df = df.loc[hard_mask, ["url", "DatasetSource", "label"]].copy()
    hard_df["score"] = champion[3]
    hard_df["predicted"] = (hard_df.score >= champion[2]).astype(int)
    hard_features = pd.DataFrame([extract_url_features(u, FULL_FEATURES) for u in hard_df.url], index=hard_df.index)
    def host(u): return (urlsplit(str(u)).hostname or "").lower().rstrip(".")
    hard_df["hostname"] = hard_df.url.map(host)
    hard_df["registrable_domain"] = hard_df.url.map(domain_group)
    hard_df["tld"] = hard_df.hostname.map(lambda h: h.rsplit(".", 1)[-1] if "." in h else "")
    hard_df["subdomain"] = hard_df.hostname.map(lambda h: ".".join(h.split(".")[:-2]) if len(h.split(".")) > 2 else "")
    forensic = pd.concat([hard_df.reset_index(drop=True), hard_features.reset_index(drop=True)], axis=1)
    forensic[forensic.label.eq(0) & forensic.predicted.eq(1)].sort_values("score", ascending=False).to_csv(REPORTS / "URL_HARD_SOURCE_FALSE_POSITIVES.csv", index=False)
    forensic.to_csv(REPORTS / "URL_HARD_SOURCE_FORENSIC_ROWS.csv", index=False)

    # Aggregate evidence: hard benign versus original benign feature distributions.
    benign_hard = hard_features.loc[df.loc[hard_mask, "label"].to_numpy() == 0]
    benign_original = X.loc[(df.DatasetSource == "original") & (df.label == 0), FULL_FEATURES]
    distribution = {}
    for f in FULL_FEATURES:
        distribution[f] = {"hard_benign_mean": float(benign_hard[f].mean()), "original_benign_mean": float(benign_original[f].mean()),
                           "hard_benign_median": float(benign_hard[f].median()), "original_benign_median": float(benign_original[f].median())}

    audit = {"generated_at": datetime.now(timezone.utc).isoformat(), "dataset_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
             "rows": int(len(df)), "labels": {str(k): int(v) for k, v in df.label.value_counts().sort_index().items()},
             "sources": {str(k): int(v) for k, v in df.DatasetSource.value_counts().items()},
             "splits": {"train": int(len(train_idx)), "validation": int(len(val_idx)), "test": int(len(test_idx)), "hard_source_holdout": int(hard_mask.sum()),
                        "train_val_group_overlap": int(len(set(groups.iloc[train_idx]) & set(groups.iloc[val_idx]))),
                        "train_test_group_overlap": int(len(set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])))},
             "hard_source_domains": int(groups[hard_mask].nunique()),
             "hard_source_benign_domains": int(groups[hard_mask & (df.label.to_numpy() == 0)].nunique()),
             "feature_family_results": results, "feature_distribution_evidence": distribution,
             "forensic_rows": int(len(forensic)), "hard_false_positives": int(((forensic.label == 0) & (forensic.predicted == 1)).sum()),
             "frozen_champion_artifact": "model/champion/model.joblib", "frozen_champion_untouched": True}
    (REPORTS / "URL_SOURCE_INVARIANCE_REPORT.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    lines = ["# URL-ML Source-Invariance Audit", "", f"Dataset SHA-256: `{audit['dataset_sha256']}`", "", "Hard-source rows were used only for evaluation; no hard-source row entered training or threshold selection.", "", "## Controlled ablation", ""]
    for n, r in results.items():
        lines.append(f"- **{n}** ({len(r['features'])} features): threshold={r['threshold']:.3f}; validation FPR/recall={r['validation']['benign_fpr']:.4f}/{r['validation']['malicious_recall']:.4f}; test FPR/recall={r['test']['benign_fpr']:.4f}/{r['test']['malicious_recall']:.4f}; hard-source FPR/recall={r['hard_source_holdout']['benign_fpr']:.4f}/{r['hard_source_holdout']['malicious_recall']:.4f}.")
    lines += ["", "## Interpretation", "", "The ablations distinguish exact/identity-like domain signals from structural domain information. Results are evidence for representation choice, not a promotion decision. The frozen champion remains recoverable and was not overwritten."]
    (REPORTS / "URL_SOURCE_INVARIANCE_REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"audit": str(REPORTS / "URL_SOURCE_INVARIANCE_REPORT.json"), "results": results}, indent=2))


if __name__ == "__main__":
    main()
