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

# Apply log1p transform on long-tailed count/length features
log_cols = ["URLLength", "DomainLength", "PathLength", "QueryLength", "HostHyphenCount", "HostUnderscoreCount", "HostNumericLabels", "QueryParamCount"]
for col in log_cols:
    if col in feature_names:
        idx_c = feature_names.index(col)
        X_all[:, idx_c] = np.log1p(X_all[:, idx_c])

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])
Xa = X_all[cuts[-1]:] if na > 0 else None

# Fit robust scaler on train data
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

# Build DeepRiskMLP in Keras / TensorFlow
tf.random.set_seed(42)
np.random.seed(42)

def build_mlp(input_dim):
    inputs = keras.Input(shape=(input_dim,))
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
    model = keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=1e-3), loss="binary_crossentropy", metrics=["AUC"])
    return model

mlp = build_mlp(fit_X.shape[1])
mlp.summary()

# Train with early stopping on validation split
callbacks = [
    keras.callbacks.EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
]

sample_weight = np.r_[np.where(y_tr==1, 1.2, 1.0), np.full(ns, 1.0)]

history = mlp.fit(
    fit_X, fit_y,
    sample_weight=sample_weight,
    validation_data=(Xv_s, y_val.astype(np.float32)),
    epochs=30,
    batch_size=256,
    callbacks=callbacks,
    verbose=1
)

pv = mlp.predict(Xv_s, batch_size=1024).ravel()
t = find_t(y_val, pv, max_fpr=0.010)
pt = mlp.predict(Xt_s, batch_size=1024).ravel()
ph = mlp.predict(Xh_s, batch_size=1024).ravel()
pa = mlp.predict(Xa_s, batch_size=1024).ravel() if Xa_s is not None else None

tfpr, trec, tauc = met(y_test, pt, t)
hfpr, hrec, hauc = met(y_hard, ph, t)
arec = (pa >= t).mean() if pa is not None else 0.0

# Convert to TFLite to check size
converter = tf.lite.TFLiteConverter.from_keras_model(mlp)
tflite_model = converter.convert()
sz = len(tflite_model)

print(f"\nDeepRiskMLP Results (Thresh={t:.4f}, TFLite Size={sz} bytes / {sz/1024:.1f} KB):")
print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
print(f"  PASS ALL GATES: {tfpr <= 0.01 and trec >= 0.98 and hfpr <= 0.01 and hrec >= 0.95 and arec >= 0.95 and sz <= 10*1024*1024}")
