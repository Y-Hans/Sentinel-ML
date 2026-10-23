import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
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

sample_weight = np.r_[np.where(y_tr==1, 1.2, 1.0), np.full(ns, 1.0)]

hgb = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=3.0, random_state=42)
hgb.fit(fit_X, fit_y, sample_weight=sample_weight)

et = ExtraTreesClassifier(n_estimators=60, max_depth=18, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
et.fit(fit_X, fit_y, sample_weight=sample_weight)

p_hgb_v = hgb.predict_proba(Xv)[:, 1]
p_hgb_t = hgb.predict_proba(Xt)[:, 1]
p_hgb_h = hgb.predict_proba(Xh)[:, 1]
p_hgb_a = hgb.predict_proba(Xa)[:, 1] if Xa is not None else None

p_et_v = et.predict_proba(Xv)[:, 1]
p_et_t = et.predict_proba(Xt)[:, 1]
p_et_h = et.predict_proba(Xh)[:, 1]
p_et_a = et.predict_proba(Xa)[:, 1] if Xa is not None else None

idx_safe_brand = feature_names.index("Safe_Brand_Domain")
idx_safe_clean = feature_names.index("Safe_Clean_Domain")
idx_brand_imp = feature_names.index("BrandImpersonationScore")
idx_susp_tld = feature_names.index("SuspiciousTLD")
idx_is_ip = feature_names.index("IsDomainIP")
idx_susp_ext = feature_names.index("PathSuspiciousExtension")
idx_redirect = feature_names.index("QueryRedirect")
idx_path_words = feature_names.index("PathSuspiciousWords")
idx_query_words = feature_names.index("QuerySuspiciousWords")
idx_double_enc = feature_names.index("PathDoubleEncoded")
idx_at = feature_names.index("HasAtSymbol")
idx_subdomain = feature_names.index("NoOfSubDomain")

def compute_gated(p1, p2, mat):
    has_threat = (
        (mat[:, idx_brand_imp] > 0) |
        (mat[:, idx_susp_tld] > 0) |
        (mat[:, idx_is_ip] > 0) |
        (mat[:, idx_susp_ext] > 0) |
        (mat[:, idx_redirect] > 0) |
        (mat[:, idx_path_words] > 0) |
        (mat[:, idx_query_words] > 0) |
        (mat[:, idx_double_enc] > 0) |
        (mat[:, idx_at] > 0) |
        (mat[:, idx_subdomain] >= 2)
    )
    is_safe_brand = (mat[:, idx_safe_brand] == 1.0) & (~has_threat)
    is_safe_clean = (mat[:, idx_safe_clean] == 1.0) & (~has_threat)
    
    p = np.copy(p1)
    p[is_safe_clean] = np.minimum(p1[is_safe_clean], p2[is_safe_clean])
    p[is_safe_brand] = 0.001
    return p

pv = compute_gated(p_hgb_v, p_et_v, Xv)
grid = np.linspace(0.0005, 0.9995, 2000)
b = np.sort(pv[y_val == 0])
m = np.sort(pv[y_val == 1])
f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
ok = np.flatnonzero(f <= 0.010)
t = float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])

ph = compute_gated(p_hgb_h, p_et_h, Xh)
hard_benign_mask = (y_hard == 0)
hard_fps = hard_benign_mask & (ph >= t)

df_hard = hard.copy()
df_hard["score"] = ph

print(f"Threshold: {t:.4f}")
print(f"Total Hard False Positives: {hard_fps.sum()} / {hard_benign_mask.sum()}")
print("\nAll False Positive URLs on Hard-Source:")
for idx, r in df_hard[hard_fps].sort_values("score", ascending=False).iterrows():
    u = r["url"]
    score = r["score"]
    active = {feature_names[i]: Xh[idx, i] for i in range(len(feature_names)) if Xh[idx, i] != 0 and feature_names[i] not in ("URLLength", "DomainLength", "PathLength")}
    print(f"URL: {u} (Score={score:.4f})")
    print(f"  Active: {list(active.items())[:6]}")
