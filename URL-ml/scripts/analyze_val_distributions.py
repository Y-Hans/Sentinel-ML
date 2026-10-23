import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, "scripts")
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import ExtraTreesClassifier

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
X_all, names = vectorize_v7(all_urls)

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh = np.split(X_all[:cuts[-1]], cuts[:-1])

y_tr, y_syn, y_val, y_test, y_hard = y[tr], v7_syn.label.to_numpy(), y[va], y[te], hard.label.to_numpy()

fit_X = np.vstack([Xtr, Xs])
fit_y = np.r_[y_tr, y_syn]

# Let's train a model and inspect validation scores
model = ExtraTreesClassifier(n_estimators=70, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
model.fit(fit_X, fit_y)

pv = model.predict_proba(Xv)[:, 1]
pt = model.predict_proba(Xt)[:, 1]
ph = model.predict_proba(Xh)[:, 1]

val_benign_scores = pv[y_val == 0]
val_mal_scores = pv[y_val == 1]
test_benign_scores = pt[y_test == 0]
test_mal_scores = pt[y_test == 1]
hard_benign_scores = ph[y_hard == 0]
hard_mal_scores = ph[y_hard == 1]

print("Score Percentiles:")
print("Val Benign p50, p90, p95, p99, p99.5, max:")
print(np.percentile(val_benign_scores, [50, 90, 95, 99, 99.5, 100]))

print("\nVal Malicious p0.5, p1, p5, p10, p50:")
print(np.percentile(val_mal_scores, [0.5, 1, 5, 10, 50]))

print("\nHard Benign p50, p90, p95, p99, p99.5, max:")
print(np.percentile(hard_benign_scores, [50, 90, 95, 99, 99.5, 100]))

print("\nHard Malicious p0.5, p1, p5, p10, p50:")
print(np.percentile(hard_mal_scores, [0.5, 1, 5, 10, 50]))

# Inspect top 20 validation benign URLs with highest scores (val false positives at low thresholds)
df_val_benign = pd.DataFrame({"url": [val_urls[i] for i in np.where(y_val == 0)[0]], "score": val_benign_scores})
print("\nTop 20 Validation Benign with highest scores:")
for _, r in df_val_benign.sort_values("score", ascending=False).head(20).iterrows():
    u = r["url"]
    print(f"Score={r['score']:.4f}: {u}")
