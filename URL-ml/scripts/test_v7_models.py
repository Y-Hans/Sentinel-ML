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
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
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

fit_X = np.vstack([Xtr, Xs])
fit_X_s = np.vstack([Xtr_s, Xs_s])
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

models = [
    ("ET_100_d22_mw1.2", ExtraTreesClassifier(n_estimators=100, max_depth=22, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1), False, np.r_[np.where(y_tr==1, 1.2, 1.0), np.ones(ns)]),
    ("ET_80_d20_mw1.5", ExtraTreesClassifier(n_estimators=80, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1), False, np.r_[np.where(y_tr==1, 1.5, 1.0), np.ones(ns)]),
    ("HGB_iter350_l2_mw1.2", HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=15, l2_regularization=2.0, random_state=42), False, np.r_[np.where(y_tr==1, 1.2, 1.0), np.ones(ns)]),
    ("MLP_128_64_32", MLPClassifier(hidden_layer_sizes=(128, 64, 32), activation="relu", alpha=1e-3, max_iter=250, early_stopping=True, random_state=42), True, None),
]

saved = {}
for name, m, use_s, sw in models:
    t0 = time.perf_counter()
    tx = fit_X_s if use_s else fit_X
    vx = Xv_s if use_s else Xv
    tex = Xt_s if use_s else Xt
    hx = Xh_s if use_s else Xh
    ax = Xa_s if use_s else Xa
    
    if sw is not None:
        m.fit(tx, fit_y, sample_weight=sw)
    else:
        m.fit(tx, fit_y)
    fit_t = time.perf_counter() - t0
    
    pv = m.predict_proba(vx)[:, 1]
    t = find_t(y_val, pv, max_fpr=0.010)
    pt = m.predict_proba(tex)[:, 1]
    ph = m.predict_proba(hx)[:, 1]
    pa = m.predict_proba(ax)[:, 1] if ax is not None else None
    
    tfpr, trec, tauc = met(y_test, pt, t)
    hfpr, hrec, hauc = met(y_hard, ph, t)
    arec = (pa >= t).mean() if pa is not None else 0.0
    
    buf = io.BytesIO()
    joblib.dump(m, buf)
    sz = buf.getbuffer().nbytes
    
    saved[name] = {"pv": pv, "pt": pt, "ph": ph, "pa": pa, "sz": sz}
    
    print(f"\n{name} (Fit={fit_t:.1f}s, Thresh={t:.4f}, Size={sz/(1024*1024):.2f}MB):")
    print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
    print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
    print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
    print(f"  PASS ALL GATES: {tfpr <= 0.01 and trec >= 0.98 and hfpr <= 0.01 and hrec >= 0.95 and arec >= 0.95 and sz <= 10*1024*1024}")

# Test Blend of ET + HGB
print("\n" + "="*50)
print("TESTING ENSEMBLE BLENDS:")
for w_et in [0.3, 0.4, 0.5, 0.6, 0.7]:
    w_hgb = 1.0 - w_et
    bpv = w_et * saved["ET_80_d20_mw1.5"]["pv"] + w_hgb * saved["HGB_iter350_l2_mw1.2"]["pv"]
    bt = find_t(y_val, bpv, max_fpr=0.010)
    bpt = w_et * saved["ET_80_d20_mw1.5"]["pt"] + w_hgb * saved["HGB_iter350_l2_mw1.2"]["pt"]
    bph = w_et * saved["ET_80_d20_mw1.5"]["ph"] + w_hgb * saved["HGB_iter350_l2_mw1.2"]["ph"]
    bpa = w_et * saved["ET_80_d20_mw1.5"]["pa"] + w_hgb * saved["HGB_iter350_l2_mw1.2"]["pa"] if saved["ET_80_d20_mw1.5"]["pa"] is not None else None
    
    tfpr, trec, tauc = met(y_test, bpt, bt)
    hfpr, hrec, hauc = met(y_hard, bph, bt)
    arec = (bpa >= bt).mean() if bpa is not None else 0.0
    tot_sz = saved["ET_80_d20_mw1.5"]["sz"] + saved["HGB_iter350_l2_mw1.2"]["sz"]
    
    print(f"\nBlend (w_et={w_et:.2f}, w_hgb={w_hgb:.2f}, Thresh={bt:.4f}, Size={tot_sz/(1024*1024):.2f}MB):")
    print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
    print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
    print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
    print(f"  PASS ALL GATES: {tfpr <= 0.01 and trec >= 0.98 and hfpr <= 0.01 and hrec >= 0.95 and arec >= 0.95 and tot_sz <= 10*1024*1024}")
