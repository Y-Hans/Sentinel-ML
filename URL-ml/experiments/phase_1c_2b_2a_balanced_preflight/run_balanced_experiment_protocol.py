"""
Phase 1C.2B-2A-S2: Balanced Bare-Apex Training Experiment Protocol (Unexecuted)

This script defines the exact, self-contained execution protocol for the balanced bare-apex
training experiment, to be executed ONLY upon explicit authorization.

Invariants:
- Fixed 67-feature vector (V7_FEATURE_NAMES).
- Fixed HistGradientBoostingClassifier hyperparameters (max_iter=350, max_depth=8, lr=0.08).
- Fixed threshold of 0.2800.
- Single variable change: addition of candidate_malicious_bare_apex_3k.csv to Candidate dataset.
- Entity dictionary expansion strictly excluded to preserve attribution.
"""

from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import HistGradientBoostingClassifier

# Directory paths
EXP_DIR = Path(__file__).resolve().parent
ROOT_DIR = EXP_DIR.parents[2]
DATA_DIR = ROOT_DIR / "data"
SCRIPT_DIR = ROOT_DIR / "scripts"

import sys
sys.path.insert(0, str(SCRIPT_DIR))
from v7_features import vectorize_v7, V7_FEATURE_NAMES
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url
from url_features import domain_group

def execute_balanced_experiment():
    print("=== EXECUTING PHASE 1C.2B-2A BALANCED BARE-APEX TRAINING EXPERIMENT ===")
    
    # 1. Load Data
    clean = pd.read_csv(DATA_DIR / "cleaned_dataset.csv", usecols=["url", "label"])
    clean["label"] = 1 - clean.label.astype(int)  # 1 = malicious, 0 = benign
    
    groups = clean.url.map(domain_group)
    y = clean.label.to_numpy()
    idx = np.arange(len(clean))
    
    # Splits: 60% Train, 20% Val, 20% Test
    tr, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42).split(idx, y, groups))
    vr, te_r = next(GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=43).split(rest, y[rest], groups.iloc[rest]))
    val_idx = rest[vr]
    test_idx = rest[te_r]
    
    # Structural benign augmentation
    v7_syn = pd.read_csv(DATA_DIR / "v7_structural_benign.csv")
    syn_urls = v7_syn.url.tolist()
    y_syn = np.zeros(len(syn_urls), dtype=np.float32)
    
    train_clean_urls = clean.url.iloc[tr].tolist()
    y_tr = y[tr]
    
    # Baseline Control Dataset (N = 189,468)
    ctrl_urls = train_clean_urls + syn_urls
    ctrl_y = np.r_[y_tr, y_syn].astype(np.float32)
    
    # Candidate Augmentations:
    # Benign Bare Apex (15,000)
    df_ben_apex = pd.read_csv(ROOT_DIR / "experiments" / "phase_1c_2b_prototypes" / "candidate_bare_apex_15k.csv")
    cand_ben_urls = df_ben_apex.url.tolist()
    cand_ben_y = np.zeros(len(cand_ben_urls), dtype=np.float32)
    
    # Malicious Bare Apex (3,000)
    df_mal_apex = pd.read_csv(EXP_DIR / "candidate_malicious_bare_apex_3k.csv")
    cand_mal_urls = df_mal_apex.url.tolist()
    cand_mal_y = np.ones(len(cand_mal_urls), dtype=np.float32)
    
    # Balanced Candidate Dataset (N = 207,468)
    cand_urls = ctrl_urls + cand_ben_urls + cand_mal_urls
    cand_y = np.r_[ctrl_y, cand_ben_y, cand_mal_y].astype(np.float32)
    
    print(f"Dataset Sizes: Control={len(ctrl_urls)}, Candidate Balanced={len(cand_urls)}")
    print(f"Candidate Composition: Baseline={len(ctrl_urls)}, +BenignApex={len(cand_ben_urls)}, +MaliciousApex={len(cand_mal_urls)}")
    
    # 2. Vectorize
    print("Vectorizing datasets...")
    X_ctrl, _ = vectorize_v7(ctrl_urls)
    X_cand, _ = vectorize_v7(cand_urls)
    
    # 3. Train Models
    def train_hgbm(X, y_train):
        n_pos = np.sum(y_train == 1)
        n_neg = np.sum(y_train == 0)
        sw = np.ones(len(y_train), dtype=np.float32)
        sw[y_train == 1] = float(len(y_train)) / (2.0 * n_pos)
        sw[y_train == 0] = float(len(y_train)) / (2.0 * n_neg)
        
        clf = HistGradientBoostingClassifier(
            max_iter=350, max_depth=8, min_samples_leaf=30,
            learning_rate=0.08, l2_regularization=0.1, random_state=42
        )
        clf.fit(X, y_train, sample_weight=sw)
        return V8RelationalURLClassifier(base_model=clf, threshold=0.28)
    
    print("Training Control Model...")
    ctrl_model = train_hgbm(X_ctrl, ctrl_y)
    print("Training Balanced Candidate Model...")
    cand_model = train_hgbm(X_cand, cand_y)
    
    # 4. Save Models
    joblib.dump(ctrl_model, EXP_DIR / "control_model_reproduced.joblib")
    joblib.dump(cand_model, EXP_DIR / "candidate_balanced_model.joblib")
    print("Models saved successfully.")

if __name__ == "__main__":
    print("Notice: Execution requires explicit authorization.")
