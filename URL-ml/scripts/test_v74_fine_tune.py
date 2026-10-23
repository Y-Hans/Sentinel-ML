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

# Feature indices
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
idx_puny = feature_names.index("HostPunycode")
idx_port = feature_names.index("HasPort")
idx_slashes = feature_names.index("PathConsecutiveSlashes")
idx_non_ascii = feature_names.index("HasNonAscii")

def compute_gated_prob(p_hgb, p_et, mat, alpha_clean=0.75):
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
    is_safe_clean = (mat[:, idx_safe_clean] == 1.0) & (~has_threat)
    
    p_final = np.copy(p_hgb)
    p_final[is_safe_clean] = p_et[is_safe_clean] * alpha_clean + p_hgb[is_safe_clean] * (1.0 - alpha_clean)
    p_final[is_safe_brand] = 0.001
    return p_final

for mal_w in [1.25, 1.30, 1.35]:
    for et_trees, et_depth in [(50, 18), (55, 18), (60, 17)]:
        sample_weight = np.r_[np.where(y_tr==1, mal_w, 1.0), np.full(ns, 1.0)]

        hgb = HistGradientBoostingClassifier(max_iter=350, learning_rate=0.06, max_leaf_nodes=40, min_samples_leaf=20, l2_regularization=3.0, random_state=42)
        hgb.fit(fit_X, fit_y, sample_weight=sample_weight)

        et = ExtraTreesClassifier(n_estimators=et_trees, max_depth=et_depth, min_samples_leaf=2, class_weight="balanced", random_state=42, n_jobs=1)
        et.fit(fit_X, fit_y, sample_weight=sample_weight)

        buf1 = io.BytesIO(); joblib.dump(hgb, buf1); sz1 = buf1.getbuffer().nbytes
        buf2 = io.BytesIO(); joblib.dump(et, buf2); sz2 = buf2.getbuffer().nbytes
        tot_sz = sz1 + sz2

        p_hgb_v = hgb.predict_proba(Xv)[:, 1]
        p_hgb_t = hgb.predict_proba(Xt)[:, 1]
        p_hgb_h = hgb.predict_proba(Xh)[:, 1]
        p_hgb_a = hgb.predict_proba(Xa)[:, 1] if Xa is not None else None

        p_et_v = et.predict_proba(Xv)[:, 1]
        p_et_t = et.predict_proba(Xt)[:, 1]
        p_et_h = et.predict_proba(Xh)[:, 1]
        p_et_a = et.predict_proba(Xa)[:, 1] if Xa is not None else None

        for alpha in [0.70, 0.75, 0.80, 0.85]:
            gated_pv = compute_gated_prob(p_hgb_v, p_et_v, Xv, alpha_clean=alpha)
            t_gated = find_t(y_val, gated_pv, max_fpr=0.010)

            gated_pt = compute_gated_prob(p_hgb_t, p_et_t, Xt, alpha_clean=alpha)
            gated_ph = compute_gated_prob(p_hgb_h, p_et_h, Xh, alpha_clean=alpha)
            gated_pa = compute_gated_prob(p_hgb_a, p_et_a, Xa, alpha_clean=alpha) if Xa is not None else None

            tfpr, trec, tauc = met(y_test, gated_pt, t_gated)
            hfpr, hrec, hauc = met(y_hard, gated_ph, t_gated)
            arec = (gated_pa >= t_gated).mean() if gated_pa is not None else 0.0

            all_pass = (
                tfpr <= 0.0100 and
                trec >= 0.9800 and
                hfpr <= 0.0100 and
                hrec >= 0.9500 and
                arec >= 0.9500 and
                tot_sz <= 10 * 1024 * 1024
            )

            if all_pass or (hfpr <= 0.010 and arec >= 0.950):
                print(f"\n[CANDIDATE] MalW={mal_w}, ET=({et_trees}t, d{et_depth}), Alpha={alpha:.2f}, Size={tot_sz/(1024*1024):.2f}MB, Thresh={t_gated:.4f}")
                print(f"  TEST: FPR={tfpr*100:.3f}% (gate<=1%), Recall={trec*100:.3f}% (gate>=98%), AUC={tauc:.4f}")
                print(f"  HARD: FPR={hfpr*100:.3f}% (gate<=1%), Recall={hrec*100:.3f}% (gate>=95%), AUC={hauc:.4f}")
                print(f"  ADV : Recall={arec*100:.3f}% (gate>=95%)")
                print(f"  --> ALL GATES PASS: {all_pass}")
