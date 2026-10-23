"""Formal V7 -> V8 Ablation Study.

Evaluates 5 distinct architectures under identical protocols:
1. V7 Baseline (Frozen champion: 67 features + V7 SafeBrand rule, tau=0.2259)
2. V7 + Parent Prior Only (Base model score shifted by Bayesian parent prior)
3. V7 + Relational Features Only (HistGradientBoosting trained with relational features, without rule overrides)
4. V7 + Parent Prior + Relational Features
5. Full V8 Principled Adjudication (Full production V8 architecture, tau=0.2800)

Evaluates on:
- TEST split (N = 50,511)
- HARD dataset (N = 2,800)
- ADVERSARIAL dataset (N = 3,900)
- Targeted Legitimate Sites (N = 32)
- Long URL Matched Pairs (N = 20)
- Sentinel.db Replay (N = 13)
- Trusted-Parent Attacks (N = 25)
- Parent Impersonation (N = 20)
"""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix
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
from v8_normalization import parse_v8_url
from v8_classifier import V8RelationalURLClassifier
from v8_benchmark_suite import get_all_benchmark_slices

# Load datasets
v7_champ = joblib.load(MODELS / "v7_champion.joblib")
base_model = v7_champ.base_model

# Load parent profiles for Bayesian prior
profiles_bundle = json.loads((MODELS / "v8_parent_profiles.json").read_text(encoding="utf-8"))
domain_profiles = profiles_bundle.get("domain_profiles", profiles_bundle)
global_prior = float(profiles_bundle.get("global_prior_malicious", 0.3210))

# Load Hard and Adv
hard_df = pd.read_csv(DATA / "hard_dataset.csv")
adv_df = pd.read_csv(REPORTS / "URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv")

# Load Test split
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

# Slices
bench_slices = get_all_benchmark_slices()

print("Ablation runner loaded. Ready to execute 5 configurations.")
