import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
import time
import io
sys.path.insert(0, "scripts")
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.ensemble import HistGradientBoostingClassifier, ExtraTreesClassifier
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

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
adv_path = Path("reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")
adv = pd.read_csv(adv_path) if adv_path.exists() else None

ntr, ns, nv, nt, nh = len(tr), len(v7_syn), len(va), len(te), len(hard)
na = len(adv) if adv is not None else 0

train_urls = clean.url.iloc[tr].tolist()
syn_urls = v7_syn.url.tolist()
val_urls = clean.url.iloc[va].tolist()
test_urls = clean.url.iloc[te].tolist()
hard_urls = hard.url.tolist()
adv_urls = adv.url.tolist() if adv is not None else []

all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls + adv_urls
X_all, feature_names = vectorize_v7(all_urls)

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])
Xa = X_all[cuts[-1]:] if na > 0 else None

y_tr = y[tr]
y_syn = v7_syn.label.to_numpy()
y_val = y[va]
y_test = y[te]
y_hard = hard.label.to_numpy()
y_adv = adv.label.to_numpy() if adv is not None else None

fit_X = np.vstack([Xtr, Xs])
fit_y = np.r_[y_tr, y_syn].astype(np.float32)

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

# Test 1: HGB with various sample weights and l2
sample_weight_1 = np.r_[np.where(y_tr==1, 1.2, 1.0), np.full(ns, 1.0)]
sample_weight_3 = np.r_[np.where(y_tr==1, 1.0, 1.0), np.full(ns, 3.0)]
sample_weight_5 = np.r_[np.where(y_tr==1, 1.0, 1.0), np.full(ns, 5.0)]

hgb1 = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=3.0, random_state=42)
hgb1.fit(fit_X, fit_y, sample_weight=sample_weight_1)

pv1 = hgb1.predict_proba(Xv)[:, 1]
t1 = find_t(y_val, pv1, max_fpr=0.010)
pt1 = hgb1.predict_proba(Xt)[:, 1]
ph1 = hgb1.predict_proba(Xh)[:, 1]
pa1 = hgb1.predict_proba(Xa)[:, 1] if Xa is not None else None

tfpr, trec, tauc = met(y_test, pt1, t1)
hfpr, hrec, hauc = met(y_hard, ph1, t1)
arec = (pa1 >= t1).mean() if pa1 is not None else 0.0
buf = io.BytesIO(); joblib.dump(hgb1, buf); sz1 = buf.getbuffer().nbytes

print(f"HGB (W=1, Thresh={t1:.4f}, Size={sz1/(1024*1024):.2f}MB):")
print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
print(f"  --> ALL GATES PASS: {tfpr <= 0.0100 and trec >= 0.9800 and hfpr <= 0.0100 and hrec >= 0.9500 and arec >= 0.9500}\n")

# Test 2: ExtraTrees
et = ExtraTreesClassifier(n_estimators=80, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
et.fit(fit_X, fit_y, sample_weight=sample_weight_1)

pve = et.predict_proba(Xv)[:, 1]
te = find_t(y_val, pve, max_fpr=0.010)
pte = et.predict_proba(Xt)[:, 1]
phe = et.predict_proba(Xh)[:, 1]
pae = et.predict_proba(Xa)[:, 1] if Xa is not None else None

tfpr, trec, tauc = met(y_test, pte, te)
hfpr, hrec, hauc = met(y_hard, phe, te)
arec = (pae >= te).mean() if pae is not None else 0.0
buf = io.BytesIO(); joblib.dump(et, buf); sze = buf.getbuffer().nbytes

print(f"ET (80 Trees, Depth 20, Thresh={te:.4f}, Size={sze/(1024*1024):.2f}MB):")
print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
print(f"  --> ALL GATES PASS: {tfpr <= 0.0100 and trec >= 0.9800 and hfpr <= 0.0100 and hrec >= 0.9500 and arec >= 0.9500}\n")
