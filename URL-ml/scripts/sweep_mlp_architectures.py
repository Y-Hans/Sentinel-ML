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

fit_X = np.vstack([Xtr_s, Xs_s])
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

# Sweep architectures: width, depth, dropout, weight decay, epochs
architectures = [
    # (name, [layers], dropout, l2_reg, lr, mal_weight, epochs)
    ("MLP_w128_64_d0.15_l2e4", [128, 64], 0.15, 1e-4, 1e-3, 1.2, 18),
    ("MLP_w128_64_32_d0.15_l2e4", [128, 64, 32], 0.15, 1e-4, 1e-3, 1.3, 18),
    ("MLP_w192_96_48_d0.20_l2e4", [192, 96, 48], 0.20, 1e-4, 1e-3, 1.3, 20),
    ("MLP_w256_128_64_d0.20_l2e4", [256, 128, 64], 0.20, 1e-4, 8e-4, 1.3, 20),
    ("MLP_w128_64_32_d0.10_l2e5", [128, 64, 32], 0.10, 1e-5, 1e-3, 1.2, 20),
    ("MLP_w192_96_32_d0.15_l2e5", [192, 96, 32], 0.15, 1e-5, 1e-3, 1.3, 22),
]

for name, h_dims, drop, l2_v, lr, mw, ep in architectures:
    tf.random.set_seed(42)
    inputs = keras.Input(shape=(fit_X.shape[1],))
    x = inputs
    for dim in h_dims:
        x = layers.Dense(dim, kernel_regularizer=keras.regularizers.l2(l2_v))(x)
        x = layers.LayerNormalization()(x)
        x = layers.Activation("relu")(x)
        if drop > 0:
            x = layers.Dropout(drop)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)
    
    model = keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=lr), loss="binary_crossentropy")
    
    sample_weight = np.r_[np.where(y_tr==1, mw, 1.0), np.full(ns, 1.0)]
    model.fit(fit_X, fit_y, sample_weight=sample_weight, validation_data=(Xv_s, y_val.astype(np.float32)), epochs=ep, batch_size=256, verbose=0)
    
    pv = model.predict(Xv_s, batch_size=1024, verbose=0).ravel()
    t = find_t(y_val, pv, max_fpr=0.010)
    
    pt = model.predict(Xt_s, batch_size=1024, verbose=0).ravel()
    ph = model.predict(Xh_s, batch_size=1024, verbose=0).ravel()
    pa = model.predict(Xa_s, batch_size=1024, verbose=0).ravel() if Xa_s is not None else None
    
    tfpr, trec, tauc = met(y_test, pt, t)
    hfpr, hrec, hauc = met(y_hard, ph, t)
    arec = (pa >= t).mean() if pa is not None else 0.0
    
    tflite = tf.lite.TFLiteConverter.from_keras_model(model).convert()
    sz = len(tflite)
    
    all_pass = (tfpr <= 0.0100 and trec >= 0.9800 and hfpr <= 0.0100 and hrec >= 0.9500 and arec >= 0.9500 and sz <= 10*1024*1024)
    
    print(f"\n{name} (Thresh={t:.4f}, TFLite Size={sz/1024:.1f}KB):")
    print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
    print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
    print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
    print(f"  --> ALL GATES PASS: {all_pass}")
