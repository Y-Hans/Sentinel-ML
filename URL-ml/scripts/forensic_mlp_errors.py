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

ntr, ns, nv, nt, nh = len(tr), len(v7_syn), len(va), len(te), len(hard)

train_urls = clean.url.iloc[tr].tolist()
syn_urls = v7_syn.url.tolist()
val_urls = clean.url.iloc[va].tolist()
test_urls = clean.url.iloc[te].tolist()
hard_urls = hard.url.tolist()

all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls
X_all, feature_names = vectorize_v7(all_urls)

log_cols = ["URLLength", "DomainLength", "PathLength", "QueryLength", "HostHyphenCount", "HostUnderscoreCount", "HostNumericLabels", "QueryParamCount"]
for col in log_cols:
    if col in feature_names:
        idx_c = feature_names.index(col)
        X_all[:, idx_c] = np.log1p(X_all[:, idx_c])

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])

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

y_tr = y[tr]
y_syn = v7_syn.label.to_numpy()
y_val = y[va]
y_test = y[te]
y_hard = hard.label.to_numpy()

fit_X = np.vstack([Xtr_s, Xs_s])
fit_y = np.r_[y_tr, y_syn].astype(np.float32)

def find_t(yv, pv, max_fpr=0.010):
    grid = np.linspace(0.0005, 0.9995, 2000)
    b = np.sort(pv[yv == 0])
    m = np.sort(pv[yv == 1])
    f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
    r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
    ok = np.flatnonzero(f <= max_fpr)
    if len(ok) == 0: ok = np.arange(len(grid))
    return float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])

tf.random.set_seed(42)
inputs = keras.Input(shape=(fit_X.shape[1],))
x = layers.Dense(256, kernel_regularizer=keras.regularizers.l2(1e-4))(inputs)
x = layers.LayerNormalization()(x)
x = layers.Activation("relu")(x)
x = layers.Dropout(0.20)(x)
x = layers.Dense(128, kernel_regularizer=keras.regularizers.l2(1e-4))(x)
x = layers.LayerNormalization()(x)
x = layers.Activation("relu")(x)
x = layers.Dropout(0.20)(x)
x = layers.Dense(64, kernel_regularizer=keras.regularizers.l2(1e-4))(x)
x = layers.Activation("relu")(x)
outputs = layers.Dense(1, activation="sigmoid")(x)
mlp = keras.Model(inputs=inputs, outputs=outputs)
mlp.compile(optimizer=keras.optimizers.Adam(learning_rate=8e-4), loss="binary_crossentropy")

sample_weight = np.r_[np.where(y_tr==1, 1.3, 1.0), np.full(ns, 1.0)]
mlp.fit(fit_X, fit_y, sample_weight=sample_weight, validation_data=(Xv_s, y_val.astype(np.float32)), epochs=20, batch_size=256, verbose=0)

pv = mlp.predict(Xv_s, batch_size=1024, verbose=0).ravel()
t = find_t(y_val, pv, max_fpr=0.010)
pt = mlp.predict(Xt_s, batch_size=1024, verbose=0).ravel()
ph = mlp.predict(Xh_s, batch_size=1024, verbose=0).ravel()

# Inspect Hard False Positives
hard_benign_mask = (y_hard == 0)
hard_fp_mask = hard_benign_mask & (ph >= t)
print(f"Total Hard Benign: {hard_benign_mask.sum()}")
print(f"Hard False Positives at Thresh {t:.4f}: {hard_fp_mask.sum()} ({hard_fp_mask.mean()*100:.2f}%)")

df_hard = hard.copy()
df_hard["score"] = ph
print("\nHard False Positives (sorted by score):")
for idx, r in df_hard[hard_fp_mask].sort_values("score", ascending=False).iterrows():
    u = r["url"]
    score = r["score"]
    active = {feature_names[i]: Xh[idx, i] for i in range(len(feature_names)) if Xh[idx, i] != 0 and feature_names[i] not in ("URLLength", "DomainLength", "PathLength")}
    print(f"URL: {u} (Score={score:.4f})")
    print(f"  Active features: {list(active.items())[:6]}")
