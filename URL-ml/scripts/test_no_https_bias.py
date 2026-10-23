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

# Remove IsHTTPS from feature set
drop_idx = feature_names.index("IsHTTPS")
keep_idx = [i for i in range(len(feature_names)) if i != drop_idx]
feature_names = [feature_names[i] for i in keep_idx]
X_all = X_all[:, keep_idx]
print(f"Features remaining without raw IsHTTPS: {len(feature_names)}")

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

# Train HGB
sample_weight = np.r_[np.where(y_tr==1, 1.2, 1.0), np.full(ns, 1.0)]
hgb = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=3.0, random_state=42)
hgb.fit(fit_X, fit_y, sample_weight=sample_weight)

hgb_pv = hgb.predict_proba(Xv)[:, 1]
t_hgb = find_t(y_val, hgb_pv, max_fpr=0.010)
hgb_pt = hgb.predict_proba(Xt)[:, 1]
hgb_ph = hgb.predict_proba(Xh)[:, 1]
hgb_pa = hgb.predict_proba(Xa)[:, 1] if Xa is not None else None

tfpr, trec, tauc = met(y_test, hgb_pt, t_hgb)
hfpr, hrec, hauc = met(y_hard, hgb_ph, t_hgb)
arec = (hgb_pa >= t_hgb).mean() if hgb_pa is not None else 0.0

print(f"\nHGB (No IsHTTPS, Thresh={t_hgb:.4f}):")
print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")

# Train ET
et = ExtraTreesClassifier(n_estimators=70, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
et.fit(fit_X, fit_y, sample_weight=sample_weight)

et_pv = et.predict_proba(Xv)[:, 1]
t_et = find_t(y_val, et_pv, max_fpr=0.010)
et_pt = et.predict_proba(Xt)[:, 1]
et_ph = et.predict_proba(Xh)[:, 1]
et_pa = et.predict_proba(Xa)[:, 1] if Xa is not None else None

tfpr, trec, tauc = met(y_test, et_pt, t_et)
hfpr, hrec, hauc = met(y_hard, et_ph, t_et)
arec = (et_pa >= t_et).mean() if et_pa is not None else 0.0

print(f"\nET (No IsHTTPS, Thresh={t_et:.4f}):")
print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")

print("\n--- Sweeping Blend Weights without IsHTTPS ---")
for w_et in np.linspace(0.1, 0.9, 9):
    w_hgb = 1.0 - w_et
    bpv = w_et * et_pv + w_hgb * hgb_pv
    t = find_t(y_val, bpv, max_fpr=0.010)
    
    bpt = w_et * et_pt + w_hgb * hgb_pt
    bph = w_et * et_ph + w_hgb * hgb_ph
    bpa = w_et * et_pa + w_hgb * hgb_pa if et_pa is not None else None
    
    tfpr, trec, tauc = met(y_test, bpt, t)
    hfpr, hrec, hauc = met(y_hard, bph, t)
    arec = (bpa >= t).mean() if bpa is not None else 0.0
    
    pass_all = (tfpr <= 0.0100 and trec >= 0.9800 and hfpr <= 0.0100 and hrec >= 0.9500 and arec >= 0.9500)
    print(f"ET={w_et:.2f}, HGB={w_hgb:.2f} | T={t:.4f} | TEST: FPR={tfpr*100:.2f}%, Rec={trec*100:.2f}% | HARD: FPR={hfpr*100:.2f}%, Rec={hrec*100:.2f}% | ADV: {arec*100:.2f}% | PASS={pass_all}")
