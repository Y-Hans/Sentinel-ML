import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, "scripts")
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit
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

ntr, ns = len(tr), len(v7_syn)
train_urls = clean.url.iloc[tr].tolist()
syn_urls = v7_syn.url.tolist()

all_urls = train_urls + syn_urls
X_all, feature_names = vectorize_v7(all_urls)
Xtr, Xs = X_all[:ntr], X_all[ntr:]

fit_X = np.vstack([Xtr, Xs])
fit_y = np.r_[y[tr], v7_syn.label.to_numpy()].astype(np.float32)

sample_weight = np.r_[np.where(y[tr]==1, 1.2, 1.0), np.full(ns, 1.0)]

et = ExtraTreesClassifier(n_estimators=70, max_depth=20, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
et.fit(fit_X, fit_y, sample_weight=sample_weight)

print("Top 15 ET Feature Importances:")
for n, imp in sorted(zip(feature_names, et.feature_importances_), key=lambda x: -x[1])[:15]:
    print(f"  {n:<45}: {imp:.4f}")
