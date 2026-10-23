"""Test impact of clean unknown domain dampening.

Tests:
1. Unknown domain neutrality
2. Test split FPR & Recall
3. Hard split FPR & Recall
4. Adversarial split Recall
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parents[1]
URL_ML = ROOT / "URL-ml"
SCRIPTS = URL_ML / "scripts"
MODELS = URL_ML / "models"
DATA = URL_ML / "data"
REPORTS = URL_ML / "reports"

import sys
sys.path.insert(0, str(SCRIPTS))
from v7_features import extract_v7_features, V7_FEATURE_NAMES
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url
from sklearn.metrics import confusion_matrix

v7_champ = joblib.load(MODELS / "v7_champion.joblib")
base_model = v7_champ.base_model

# Load hard and test datasets
hard_df = pd.read_csv(DATA / "hard_dataset.csv")
adv_df = pd.read_csv(REPORTS / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")

clean_df = pd.read_csv(DATA / "cleaned_dataset.csv", usecols=["url", "label"])
clean_df["label"] = 1 - clean_df.label.astype(int)
from url_features import domain_group
from sklearn.model_selection import GroupShuffleSplit
groups = clean_df.url.map(domain_group)
y = clean_df.label.to_numpy()
idx = np.arange(len(clean_df))
tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
te = rest[te_r]
test_urls = clean_df.url.iloc[te].tolist()
test_labels = y[te]

print("Data loaded.")

idx_safe_clean = V7_FEATURE_NAMES.index("Safe_Clean_Domain")
idx_path_words = V7_FEATURE_NAMES.index("PathSuspiciousWords")
idx_query_words = V7_FEATURE_NAMES.index("QuerySuspiciousWords")
idx_safe_brand = V7_FEATURE_NAMES.index("Safe_Brand_Domain")

# Test on HARD dataset
hard_urls = hard_df["url"].tolist()
hard_labels = hard_df["label"].to_numpy()

from v8_classifier import V8RelationalURLClassifier
v8_orig = V8RelationalURLClassifier(base_model, threshold=0.2800)

hard_preds_orig = []
hard_preds_damped = []

for u in hard_urls:
    feat = extract_v7_features(u)
    vec = np.array([feat[k] for k in V7_FEATURE_NAMES], dtype=np.float32)
    raw_p = float(base_model.predict_proba(vec[None, :])[0, 1])
    p_orig, pred_orig, _ = v8_orig.adjudicate_single(u, vec, raw_p)
    hard_preds_orig.append(pred_orig)

    # Check damped version
    # Only dampen if safe_clean == 1 and zero suspicious words and raw_p is not overwhelmingly malicious (< 0.70)
    p_damped = p_orig
    # If not brand impersonation and not susp tld and safe_clean and no words
    if p_orig >= 0.2800 and vec[idx_safe_clean] == 1.0 and vec[idx_path_words] == 0 and vec[idx_query_words] == 0:
        if raw_p < 0.70:
            p_damped = 0.05
    hard_preds_damped.append(1 if p_damped >= 0.2800 else 0)

hard_preds_orig = np.array(hard_preds_orig)
hard_preds_damped = np.array(hard_preds_damped)

tn, fp, fn, tp = confusion_matrix(hard_labels, hard_preds_orig, labels=[0, 1]).ravel()
print(f"HARD (ORIG):   FPR={fp/(tn+fp)*100:.3f}% ({fp}/{tn+fp}), Recall={tp/(tp+fn)*100:.3f}% ({tp}/{tp+fn})")

tn, fp, fn, tp = confusion_matrix(hard_labels, hard_preds_damped, labels=[0, 1]).ravel()
print(f"HARD (DAMPED): FPR={fp/(tn+fp)*100:.3f}% ({fp}/{tn+fp}), Recall={tp/(tp+fn)*100:.3f}% ({tp}/{tp+fn})")

