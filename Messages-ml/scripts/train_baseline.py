"""
Baseline model training and experiment tracking framework for Message ML.

Implements Model A (Logistic Regression) and Model B (Small MLP) with strict
reproducibility contracts, feature group selection, and artifact export.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector, get_feature_names


@dataclass
class ExperimentResult:
    experiment_id: str
    model_type: str
    feature_config: Dict[str, Any]
    feature_count: int
    dataset_fingerprint: str
    seed: int
    train_samples: int
    val_samples: int
    test_samples: int
    train_metrics: Dict[str, float]
    val_metrics: Dict[str, float]
    test_metrics: Dict[str, float]
    scaler_params: Dict[str, List[float]]
    software_versions: Dict[str, str]


def compute_dataset_fingerprint(records: List[Dict[str, Any]]) -> str:
    """Computes a deterministic SHA-256 fingerprint of input dataset records."""
    hasher = hashlib.sha256()
    for r in sorted(records, key=lambda x: str(x.get("message_id", ""))):
        hasher.update(str(r.get("message_id", "")).encode("utf-8"))
        hasher.update(str(r.get("raw_text", "")).encode("utf-8"))
        hasher.update(str(r.get("security_label", "")).encode("utf-8"))
    return hasher.hexdigest()[:16]


def prepare_feature_matrices(
    train_records: List[Dict[str, Any]],
    val_records: List[Dict[str, Any]],
    test_records: List[Dict[str, Any]],
    feature_cfg: FeatureConfig,
    label_mapping: Dict[str, int],
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler, List[str]]:
    """
    Extracts, orders, and standardizes feature matrices for train/val/test splits.
    """
    feature_names = get_feature_names(feature_cfg)

    def records_to_xy(recs):
        X_list = []
        y_list = []
        for r in recs:
            vec = extract_feature_vector(
                raw_text=r.get("raw_text", ""),
                sender_header=r.get("sender_header"),
                config=feature_cfg,
            )
            lbl = r.get("security_label", "BENIGN")
            X_list.append(vec)
            y_list.append(label_mapping.get(lbl, 0))
        return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32)

    X_train, y_train = records_to_xy(train_records)
    X_val, y_val = records_to_xy(val_records)
    X_test, y_test = records_to_xy(test_records)

    # Fit scaler strictly on Train split
    scaler = StandardScaler()
    if len(X_train) > 0:
        X_train_scaled = scaler.fit_transform(X_train)
        X_val_scaled = scaler.transform(X_val) if len(X_val) > 0 else X_val
        X_test_scaled = scaler.transform(X_test) if len(X_test) > 0 else X_test
    else:
        X_train_scaled = X_train
        X_val_scaled = X_val
        X_test_scaled = X_test

    return (
        X_train_scaled,
        y_train,
        X_val_scaled,
        y_val,
        X_test_scaled,
        y_test,
        scaler,
        feature_names,
    )


def train_candidate_model(
    model_type: str,
    train_records: List[Dict[str, Any]],
    val_records: List[Dict[str, Any]],
    test_records: List[Dict[str, Any]],
    feature_cfg: Optional[FeatureConfig] = None,
    seed: int = 42,
) -> Tuple[Any, ExperimentResult]:
    """
    Trains either 'LOGISTIC_REGRESSION' (Model A) or 'SMALL_MLP' (Model B)
    with full experiment metadata and performance logging.
    """
    cfg = feature_cfg or FeatureConfig()
    label_map = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}

    (
        X_train,
        y_train,
        X_val,
        y_val,
        X_test,
        y_test,
        scaler,
        feature_names,
    ) = prepare_feature_matrices(
        train_records, val_records, test_records, cfg, label_map
    )

    all_records = train_records + val_records + test_records
    dataset_fp = compute_dataset_fingerprint(all_records)

    if model_type == "LOGISTIC_REGRESSION":
        model = LogisticRegression(
            C=1.0,
            max_iter=500,
            random_state=seed,
            class_weight="balanced",
        )
    elif model_type == "SMALL_MLP":
        model = MLPClassifier(
            hidden_layer_sizes=(32, 16),
            activation="relu",
            max_iter=200,
            random_state=seed,
            early_stopping=True,
            validation_fraction=0.15,
        )
    else:
        raise ValueError(f"Unknown model_type '{model_type}'. Use 'LOGISTIC_REGRESSION' or 'SMALL_MLP'")

    if len(X_train) > 0:
        model.fit(X_train, y_train)

    def evaluate_split(X, y):
        if len(X) == 0:
            return {"precision": 0.0, "recall": 0.0, "f1_macro": 0.0}
        preds = model.predict(X)
        return {
            "precision": float(precision_score(y, preds, average="macro", zero_division=0)),
            "recall": float(recall_score(y, preds, average="macro", zero_division=0)),
            "f1_macro": float(f1_score(y, preds, average="macro", zero_division=0)),
        }

    train_m = evaluate_split(X_train, y_train)
    val_m = evaluate_split(X_val, y_val)
    test_m = evaluate_split(X_test, y_test)

    scaler_dict = {
        "mean": scaler.mean_.tolist() if hasattr(scaler, "mean_") and scaler.mean_ is not None else [],
        "scale": scaler.scale_.tolist() if hasattr(scaler, "scale_") and scaler.scale_ is not None else [],
    }

    import sklearn
    software_ver = {
        "python": sys.version.split()[0],
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
    }

    exp_res = ExperimentResult(
        experiment_id=f"EXP_{model_type}_{dataset_fp}_{seed}",
        model_type=model_type,
        feature_config=cfg.to_dict(),
        feature_count=len(feature_names),
        dataset_fingerprint=dataset_fp,
        seed=seed,
        train_samples=len(X_train),
        val_samples=len(X_val),
        test_samples=len(X_test),
        train_metrics=train_m,
        val_metrics=val_m,
        test_metrics=test_m,
        scaler_params=scaler_dict,
        software_versions=software_ver,
    )

    return model, exp_res
