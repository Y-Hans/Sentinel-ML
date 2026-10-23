"""V5 controlled model-class experiment.

The clean source split is constructed only from cleaned_dataset.csv. The
protected hard dataset and adversarial suite are loaded only after fitting and
validation-only threshold selection.
"""
from __future__ import annotations
import hashlib, json, os, sys, time
from pathlib import Path
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve(); ROOT = HERE.parents[1]
DATA = ROOT / "data"; REPORTS = ROOT / "reports"
sys.path.insert(0, str(HERE.parent))
from v4_features import vectorize_deterministic
from url_features import domain_group

FAMILIES = ("host", "path", "query", "interactions")

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def metrics(y, p, threshold):
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    pred = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "benign_fpr": float(fp / max(1, tn + fp)),
            "malicious_recall": float(tp / max(1, fn + tp)),
            "roc_auc": float(roc_auc_score(y, p)),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]}

def choose_threshold(y, p):
    grid = np.linspace(0.0005, 0.9995, 1999)
    y = np.asarray(y); benign = np.sort(np.asarray(p)[y == 0]); malicious = np.sort(np.asarray(p)[y == 1])
    fpr = (benign.size - np.searchsorted(benign, grid, side="left")) / max(1, benign.size)
    rec = (malicious.size - np.searchsorted(malicious, grid, side="left")) / max(1, malicious.size)
    eligible = np.flatnonzero(fpr <= 0.01)
    if not len(eligible): eligible = np.arange(len(grid))
    i = eligible[np.lexsort((grid[eligible], fpr[eligible], -rec[eligible]))[0]]
    return float(grid[i])

def main():
    clean = pd.read_csv(DATA / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean["label"].astype(int)
    hard = pd.read_csv(DATA / "hard_dataset.csv")
    rem = pd.read_csv(DATA / "remediation_hard_negatives_v3.csv")
    y = clean.label.to_numpy(); groups = clean.url.map(domain_group)
    idx = np.arange(len(clean))
    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.40, random_state=42).split(idx, y, groups))
    va_rel, te_rel = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    va, te = rest[va_rel], rest[te_rel]
    urls = clean.url.tolist(); rem_urls = rem.url.tolist(); hard_urls = hard.url.tolist()
    X, names = vectorize_deterministic([urls[i] for i in tr] + rem_urls + [urls[i] for i in va] + [urls[i] for i in te] + hard_urls, FAMILIES)
    ntr, nrem, nva, nte = len(tr), len(rem), len(va), len(te)
    Xtr, Xrem = X[:ntr], X[ntr:ntr+nrem]
    Xva = X[ntr+nrem:ntr+nrem+nva]
    Xte = X[ntr+nrem+nva:ntr+nrem+nva+nte]
    Xhard = X[ntr+nrem+nva+nte:]
    scaler = StandardScaler().fit(Xtr)
    Xtr, Xrem, Xva, Xte, Xhard = [scaler.transform(z) for z in (Xtr, Xrem, Xva, Xte, Xhard)]
    fit_x = np.vstack([Xtr, Xrem]); fit_y = np.r_[y[tr], rem.label.astype(int).to_numpy()]
    results = []
    for weight in (40.0, 160.0):
        start = time.perf_counter()
        model = HistGradientBoostingClassifier(max_iter=180, learning_rate=0.08, max_leaf_nodes=31,
            min_samples_leaf=20, l2_regularization=1.0, random_state=42)
        model.fit(fit_x, fit_y, sample_weight=np.r_[np.ones(ntr), np.full(nrem, weight)])
        pv = model.predict_proba(Xva)[:, 1]; threshold = choose_threshold(y[va], pv)
        pt = model.predict_proba(Xte)[:, 1]; ph = model.predict_proba(Xhard)[:, 1]
        name = f"v5_hgb92_rem{int(weight)}"
        artifact = ROOT / "model" / "challengers" / name; artifact.mkdir(parents=True, exist_ok=False)
        joblib.dump(model, artifact / "model.joblib"); joblib.dump(scaler, artifact / "scaler.joblib")
        adversarial_path = REPORTS / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv"
        adv = pd.read_csv(adversarial_path, usecols=["url", "label"])
        ax, _ = vectorize_deterministic(adv.url.tolist(), FAMILIES)
        adv_score = model.predict_proba(scaler.transform(ax))[:, 1]
        adv_metric = metrics(adv.label.to_numpy(), adv_score, threshold)
        meta = {"campaign": "URL-ML V5", "experiment_id": name, "architecture": type(model).__name__,
          "families": list(FAMILIES), "feature_count": len(names), "feature_schema_sha256": sha(HERE.parent / "v4_features.py"),
          "seed": 42, "remediation_weight": weight, "threshold": threshold,
          "source_dataset_sha256": sha(DATA / "cleaned_dataset.csv"), "remediation_sha256": sha(DATA / "remediation_hard_negatives_v3.csv"),
          "hard_dataset_sha256": sha(DATA / "hard_dataset.csv"), "train_rows": ntr, "remediation_rows": nrem,
          "validation": metrics(y[va], pv, threshold), "test": metrics(y[te], pt, threshold),
          "hard_source_holdout": metrics(hard.label.to_numpy(), ph, threshold), "adversarial": adv_metric,
          "fit_seconds": time.perf_counter() - start,
          "artifact": str(artifact.relative_to(ROOT)).replace("\\", "/"),
          "model_size_bytes": sum(p.stat().st_size for p in artifact.iterdir())}
        (artifact / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        results.append(meta); print(json.dumps(meta, indent=2))
    out = {"campaign": "URL-ML V5", "protocol": {"train_source": "cleaned_dataset.csv only", "threshold_selection": "validation_only", "protected_evaluation": ["hard_dataset.csv", "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv"], "frozen_champion_untouched": True, "champion_sha256": sha(ROOT / "model/champion/model.joblib")}, "experiments": results}
    (REPORTS / "URL_V5_EXPERIMENT_REGISTRY.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    with (REPORTS / "EXPERIMENT_REGISTRY.jsonl").open("a", encoding="utf-8") as f:
        for r in results: f.write(json.dumps(r) + "\n")

if __name__ == "__main__": main()
