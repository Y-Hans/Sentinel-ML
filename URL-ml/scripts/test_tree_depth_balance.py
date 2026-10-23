import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
import time
sys.path.insert(0, "scripts")
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score

ROOT = Path(".")
DATA = ROOT / "data"

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

ntr, ns, nv, nt, nh = len(tr), len(v7_syn), len(va), len(te), len(hard)

train_urls = clean.url.iloc[tr].tolist()
syn_urls = v7_syn.url.tolist()
val_urls = clean.url.iloc[va].tolist()
test_urls = clean.url.iloc[te].tolist()
hard_urls = hard.url.tolist()

all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls
X_all, feature_names = vectorize_v7(all_urls)

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])

y_tr = y[tr]
y_syn = v7_syn.label.to_numpy()
y_val = y[va]
y_test = y[te]
y_hard = hard.label.to_numpy()

fit_X = np.vstack([Xtr, Xs])
fit_y = np.r_[y_tr, y_syn]

def met(yt, yp, t):
    pred = (yp >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(yt, pred, labels=[0, 1]).ravel()
    auc = roc_auc_score(yt, yp) if len(np.unique(yt)) > 1 else float("nan")
    return float(fp / max(1, tn + fp)), float(tp / max(1, fn + tp)), float(auc)

def find_t(yv, pv, max_fpr=0.010):
    grid = np.linspace(0.0005, 0.9995, 2000)
    b = np.sort(pv[yv == 0])
    m = np.sort(pv[yv == 1])
    f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
    r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
    ok = np.flatnonzero(f <= max_fpr)
    if len(ok) == 0: ok = np.arange(len(grid))
    return float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])

# Sweep depths and sample weights
experiments = [
    # (name, n_est, depth, min_leaf, mal_weight, syn_weight)
    ("ET_d20_leaf2_mw1.2_sw1", 70, 20, 2, 1.2, 1.0),
    ("ET_d20_leaf2_mw1.5_sw1", 70, 20, 2, 1.5, 1.0),
    ("ET_d22_leaf2_mw1.2_sw1", 60, 22, 2, 1.2, 1.0),
    ("ET_d22_leaf2_mw1.5_sw1", 60, 22, 2, 1.5, 1.0),
    ("ET_d22_leaf2_mw1.0_sw1", 60, 22, 2, 1.0, 1.0),
    ("ET_d24_leaf2_mw1.0_sw1", 50, 24, 2, 1.0, 1.0),
    ("ET_d20_leaf1_mw1.2_sw1", 60, 20, 1, 1.2, 1.0),
    ("ET_d22_leaf1_mw1.0_sw1", 50, 22, 1, 1.0, 1.0),
]

for name, n_est, depth, leaf, mw, sw in experiments:
    t0 = time.perf_counter()
    sample_weights = np.r_[np.where(y_tr == 1, mw, 1.0), np.full(ns, sw)]
    model = ExtraTreesClassifier(n_estimators=n_est, max_depth=depth, min_samples_leaf=leaf, class_weight="balanced", random_state=42, n_jobs=1)
    model.fit(fit_X, fit_y, sample_weight=sample_weights)
    fit_t = time.perf_counter() - t0
    
    pv = model.predict_proba(Xv)[:, 1]
    t = find_t(y_val, pv, max_fpr=0.010)
    
    pt = model.predict_proba(Xt)[:, 1]
    ph = model.predict_proba(Xh)[:, 1]
    
    tfpr, trec, tauc = met(y_test, pt, t)
    hfpr, hrec, hauc = met(y_hard, ph, t)
    
    # Measure serialized size
    import io
    buf = io.BytesIO()
    joblib.dump(model, buf)
    sz = buf.getbuffer().nbytes
    
    print(f"\n{name} (Fit={fit_t:.1f}s, Thresh={t:.4f}, Size={sz/(1024*1024):.2f}MB):")
    print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
    print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
    print(f"  PASS ALL GATES: {tfpr <= 0.01 and trec >= 0.98 and hfpr <= 0.01 and hrec >= 0.95 and sz <= 10*1024*1024}")
