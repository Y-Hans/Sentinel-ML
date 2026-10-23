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
from sklearn.ensemble import HistGradientBoostingClassifier

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
adv = pd.read_csv("reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")

ntr, ns, nv, nt, nh, na = len(tr), len(v7_syn), len(va), len(te), len(hard), len(adv)

train_urls = clean.url.iloc[tr].tolist()
syn_urls = v7_syn.url.tolist()
val_urls = clean.url.iloc[va].tolist()
test_urls = clean.url.iloc[te].tolist()
hard_urls = hard.url.tolist()
adv_urls = adv.url.tolist()

all_urls = train_urls + syn_urls + val_urls + test_urls + hard_urls + adv_urls
X_all, feature_names = vectorize_v7(all_urls)

cuts = np.cumsum([ntr, ns, nv, nt, nh])
Xtr, Xs, Xv, Xt, Xh, Xa = np.split(X_all, cuts)

y_tr = y[tr]
y_syn = v7_syn.label.to_numpy()
y_val = y[va]
y_test = y[te]
y_hard = hard.label.to_numpy()
y_adv = adv.label.to_numpy()

fit_X = np.vstack([Xtr, Xs])
fit_y = np.r_[y_tr, y_syn].astype(np.float32)

sample_weight = np.r_[np.where(y_tr==1, 1.30, 1.0), np.full(ns, 1.0)]

hgb = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=3.0, random_state=42)
hgb.fit(fit_X, fit_y, sample_weight=sample_weight)

p_hgb_v = hgb.predict_proba(Xv)[:, 1]
p_hgb_t = hgb.predict_proba(Xt)[:, 1]
p_hgb_h = hgb.predict_proba(Xh)[:, 1]
p_hgb_a = hgb.predict_proba(Xa)[:, 1]

idx_safe_brand = feature_names.index("Safe_Brand_Domain")
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
idx_puny = feature_names.index("HostPunycode")
idx_port = feature_names.index("HasPort")
idx_slashes = feature_names.index("PathConsecutiveSlashes")
idx_non_ascii = feature_names.index("HasNonAscii")

def compute_gated_prob(p_in, mat):
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
        (mat[:, idx_puny] > 0) |
        (mat[:, idx_port] > 0) |
        (mat[:, idx_slashes] > 0) |
        (mat[:, idx_non_ascii] > 0) |
        (mat[:, idx_subdomain] >= 2)
    )
    is_safe_brand = (mat[:, idx_safe_brand] == 1.0) & (~has_threat)
    p_final = np.copy(p_in)
    p_final[is_safe_brand] = 0.001
    return p_final

pv = compute_gated_prob(p_hgb_v, Xv)
grid = np.linspace(0.0005, 0.9995, 2000)
b = np.sort(pv[y_val == 0])
m = np.sort(pv[y_val == 1])
f = (b.size - np.searchsorted(b, grid, "left")) / max(1, b.size)
r = (m.size - np.searchsorted(m, grid, "left")) / max(1, m.size)
ok = np.flatnonzero(f <= 0.010)
t = float(grid[ok[np.lexsort((grid[ok], f[ok], -r[ok]))[0]]])

pa = compute_gated_prob(p_hgb_a, Xa)
adv["pred"] = (pa >= t).astype(int)

print(f"Validation Selected Threshold: {t:.4f}")
print("Adversarial Recall by Family:")
for fam, g in adv.groupby("attack_family"):
    rec = (g.pred == 1).mean()
    print(f"  {fam:<30}: {rec*100:.2f}% (Total: {len(g)})")
print(f"\nOverall Adversarial Recall: {(adv.pred == 1).mean()*100:.3f}%")
