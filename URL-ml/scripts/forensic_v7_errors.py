import joblib
import pandas as pd
import numpy as np
from pathlib import Path
import sys
sys.path.insert(0, "scripts")
from v7_features import vectorize_v7, V7_FEATURE_NAMES
import json

ROOT = Path(".")
DATA = ROOT / "data"

hard = pd.read_csv(DATA / "hard_dataset.csv")
Xh, names = vectorize_v7(hard.url.tolist())
yh = hard.label.to_numpy()

# Load models
m_et = joblib.load("model/challengers/v7_et_remed_w3/model.joblib")
meta_et = json.loads(Path("model/challengers/v7_et_remed_w3/metadata.json").read_text())
t_et = meta_et["threshold"]

m_hgb = joblib.load("model/challengers/v7_hgb_remed_w3/model.joblib")
meta_hgb = json.loads(Path("model/challengers/v7_hgb_remed_w3/metadata.json").read_text())
t_hgb = meta_hgb["threshold"]

p_et = m_et.predict_proba(Xh)[:, 1]
p_hgb = m_hgb.predict_proba(Xh)[:, 1]

benign_mask = (yh == 0)
fp_mask_et = benign_mask & (p_et >= t_et)
fp_mask_hgb = benign_mask & (p_hgb >= t_hgb)

print(f"Total Hard Benign URLs: {benign_mask.sum()}")
print(f"ET False Positives:  {fp_mask_et.sum()} ({fp_mask_et.mean()*100:.2f}%)")
print(f"HGB False Positives: {fp_mask_hgb.sum()} ({fp_mask_hgb.mean()*100:.2f}%)")

df_hard = hard.copy()
df_hard["score_et"] = p_et
df_hard["score_hgb"] = p_hgb

# Inspect top 25 ET false positives
print("\nTop 25 Hard Benign False Positives (ExtraTrees):")
for idx, r in df_hard[fp_mask_et].sort_values("score_et", ascending=False).head(25).iterrows():
    feat = {n: Xh[idx, names.index(n)] for n in names if Xh[idx, names.index(n)] != 0}
    print(f"URL: {r['url']}")
    print(f"  Score ET: {r['score_et']:.4f} (thresh={t_et:.4f}), Score HGB: {r['score_hgb']:.4f}")
    # Print non-zero features
    active_feats = [f"{k}={v}" for k, v in feat.items() if k not in ("URLLength", "DomainLength", "PathLength")]
    print(f"  Active features: {', '.join(active_feats[:8])}")

# Let's check feature importances of ExtraTrees
print("\nTop 15 Feature Importances in ExtraTrees (v7_et_remed_w3):")
for n, imp in sorted(zip(names, m_et.feature_importances_), key=lambda x: -x[1])[:15]:
    print(f"  {n:<40}: {imp:.4f}")
