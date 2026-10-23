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

# Apply log1p transform on long-tailed count/length features
log_cols = ["URLLength", "DomainLength", "PathLength", "QueryLength", "HostHyphenCount", "HostUnderscoreCount", "HostNumericLabels", "QueryParamCount"]
for col in log_cols:
    if col in feature_names:
        idx_c = feature_names.index(col)
        X_all[:, idx_c] = np.log1p(X_all[:, idx_c])

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])
Xa = X_all[cuts[-1]:] if na > 0 else None

mean = Xtr.mean(axis=0)
std = Xtr.std(axis=0)
std[std < 1e-5] = 1.0

def scale(mat):
    return np.clip((mat - mean) / std, -5.0, 5.0)

Xtr_s = scale(Xtr)
Xs_s = scale(Xs)
Xv_s = scale(Xv)
Xt_s = scale(Xt)
Xh_s = scale(Xh)
Xa_s = scale(Xa) if Xa is not None else None

y_tr = y[tr]
y_syn = v7_syn.label.to_numpy()
y_val = y[va]
y_test = y[te]
y_hard = hard.label.to_numpy()
y_adv = adv.label.to_numpy() if adv is not None else None

fit_X = np.vstack([Xtr, Xs])
fit_X_s = np.vstack([Xtr_s, Xs_s])
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

# 1. Train MLP
tf.random.set_seed(42)
inputs = keras.Input(shape=(fit_X_s.shape[1],))
x = layers.Dense(128, kernel_regularizer=keras.regularizers.l2(1e-4))(inputs)
x = layers.LayerNormalization()(x)
x = layers.Activation("relu")(x)
x = layers.Dropout(0.2)(x)
x = layers.Dense(64, kernel_regularizer=keras.regularizers.l2(1e-4))(x)
x = layers.LayerNormalization()(x)
x = layers.Activation("relu")(x)
x = layers.Dropout(0.2)(x)
x = layers.Dense(32, kernel_regularizer=keras.regularizers.l2(1e-4))(x)
x = layers.Activation("relu")(x)
outputs = layers.Dense(1, activation="sigmoid")(x)
mlp = keras.Model(inputs=inputs, outputs=outputs)
mlp.compile(optimizer=keras.optimizers.Adam(learning_rate=1e-3), loss="binary_crossentropy")

sample_weight = np.r_[np.where(y_tr==1, 1.2, 1.0), np.full(ns, 1.0)]
mlp.fit(fit_X_s, fit_y, sample_weight=sample_weight, validation_data=(Xv_s, y_val.astype(np.float32)), epochs=15, batch_size=256, verbose=0)

mlp_pv = mlp.predict(Xv_s, batch_size=1024, verbose=0).ravel()
mlp_pt = mlp.predict(Xt_s, batch_size=1024, verbose=0).ravel()
mlp_ph = mlp.predict(Xh_s, batch_size=1024, verbose=0).ravel()
mlp_pa = mlp.predict(Xa_s, batch_size=1024, verbose=0).ravel() if Xa_s is not None else None

# 2. Train HGB
hgb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=2.0, random_state=42)
hgb.fit(fit_X, fit_y, sample_weight=sample_weight)

hgb_pv = hgb.predict_proba(Xv)[:, 1]
hgb_pt = hgb.predict_proba(Xt)[:, 1]
hgb_ph = hgb.predict_proba(Xh)[:, 1]
hgb_pa = hgb.predict_proba(Xa)[:, 1] if Xa is not None else None

# 3. Train ExtraTrees
et = ExtraTreesClassifier(n_estimators=70, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
et.fit(fit_X, fit_y, sample_weight=sample_weight)

et_pv = et.predict_proba(Xv)[:, 1]
et_pt = et.predict_proba(Xt)[:, 1]
et_ph = et.predict_proba(Xh)[:, 1]
et_pa = et.predict_proba(Xa)[:, 1] if Xa is not None else None

# Measure sizes
tflite = tf.lite.TFLiteConverter.from_keras_model(mlp).convert()
mlp_sz = len(tflite)

buf = io.BytesIO(); joblib.dump(hgb, buf); hgb_sz = buf.getbuffer().nbytes
buf = io.BytesIO(); joblib.dump(et, buf); et_sz = buf.getbuffer().nbytes

print(f"Sizes: MLP={mlp_sz/1024:.1f}KB, HGB={hgb_sz/(1024*1024):.2f}MB, ET={et_sz/(1024*1024):.2f}MB")

# Test 3-way blend grids
print("\nTesting Blends:")
for w_mlp in [0.2, 0.3, 0.4, 0.5, 0.6]:
    for w_et in [0.1, 0.2, 0.3, 0.4]:
        w_hgb = round(1.0 - w_mlp - w_et, 2)
        if w_hgb < 0: continue
        
        bpv = w_mlp * mlp_pv + w_et * et_pv + w_hgb * hgb_pv
        t = find_t(y_val, bpv, max_fpr=0.010)
        
        bpt = w_mlp * mlp_pt + w_et * et_pt + w_hgb * hgb_pt
        bph = w_mlp * mlp_ph + w_et * et_ph + w_hgb * hgb_ph
        bpa = w_mlp * mlp_pa + w_et * et_pa + w_hgb * hgb_pa if mlp_pa is not None else None
        
        tfpr, trec, tauc = met(y_test, bpt, t)
        hfpr, hrec, hauc = met(y_hard, bph, t)
        arec = (bpa >= t).mean() if bpa is not None else 0.0
        tot_sz = mlp_sz + (hgb_sz if w_hgb > 0 else 0) + (et_sz if w_et > 0 else 0)
        
        all_pass = (tfpr <= 0.0100 and trec >= 0.9800 and hfpr <= 0.0100 and hrec >= 0.9500 and arec >= 0.9500 and tot_sz <= 10*1024*1024)
        if hfpr <= 0.02 or all_pass:
            print(f"Blend (MLP={w_mlp:.2f}, ET={w_et:.2f}, HGB={w_hgb:.2f}, Thresh={t:.4f}, Size={tot_sz/(1024*1024):.2f}MB):")
            print(f"  TEST: FPR={tfpr*100:.3f}%, Recall={trec*100:.3f}%, AUC={tauc:.4f}")
            print(f"  HARD: FPR={hfpr*100:.3f}%, Recall={hrec*100:.3f}%, AUC={hauc:.4f}")
            print(f"  ADV : Recall={arec*100:.3f}%")
            print(f"  --> ALL GATES PASS: {all_pass}\n")
