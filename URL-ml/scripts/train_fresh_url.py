"""Train the single fresh URL HistGBM candidate from the frozen train split."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))

from fresh_url_features import (  # noqa: E402
    FEATURE_CONTRACT_ID,
    FEATURE_NAMES,
    FEATURE_NAMES_SHA256,
    vectorize_urls,
)
from fresh_url_schema import read_jsonl  # noqa: E402


def threshold_for_validation(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, dict]:
    best = None
    for threshold in np.linspace(0.05, 0.95, 901):
        predicted = scores >= threshold
        tp = int(((predicted == 1) & (y_true == 1)).sum())
        tn = int(((predicted == 0) & (y_true == 0)).sum())
        fp = int(((predicted == 1) & (y_true == 0)).sum())
        fn = int(((predicted == 0) & (y_true == 1)).sum())
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * recall / max(1e-12, precision + recall)
        # The validation constraint is explicit and test-independent.
        feasible = fpr <= 0.05
        key = (1 if feasible else 0, recall if feasible else -fpr, f1)
        candidate = (key, threshold, {"recall": recall, "fpr": fpr, "precision": precision, "f1": f1})
        if best is None or candidate[0] > best[0]:
            best = candidate
    assert best is not None
    return float(best[1]), best[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--model-out", type=Path, required=True)
    parser.add_argument("--metadata-out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20261024)
    args = parser.parse_args()

    train = read_jsonl(args.data_dir / "train.jsonl")
    validation = read_jsonl(args.data_dir / "validation.jsonl")
    if not train or not validation:
        raise SystemExit("train and validation splits are required")

    x_train = vectorize_urls([row["canonical_url"] for row in train])
    x_validation = vectorize_urls([row["canonical_url"] for row in validation])
    y_train = np.array([row["label"] == "MALICIOUS" for row in train], dtype=np.int8)
    y_validation = np.array([row["label"] == "MALICIOUS" for row in validation], dtype=np.int8)

    # Fresh data is intentionally source-skewed toward malicious URLs. Keep all
    # rows but prevent the majority class from dominating the fit.
    sample_weight = np.where(y_train == 0, 3.0, 1.0).astype(np.float64)
    model = HistGradientBoostingClassifier(
        loss="log_loss",
        learning_rate=0.03,
        max_iter=100,
        max_leaf_nodes=7,
        min_samples_leaf=100,
        l2_regularization=5.0,
        early_stopping=False,
        random_state=args.seed,
    )
    model.fit(x_train, y_train, sample_weight=sample_weight)
    validation_scores = model.predict_proba(x_validation)[:, 1]
    threshold, validation_metrics = threshold_for_validation(y_validation, validation_scores)

    args.model_out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model_out, compress=3)
    metadata = {
        "model_id": "SENTINEL_FRESH_URL_20261024",
        "version": "fresh_url_1.0.0",
        "feature_contract_id": FEATURE_CONTRACT_ID,
        "feature_names": FEATURE_NAMES,
        "feature_names_sha256": FEATURE_NAMES_SHA256,
        "model_type": "HistGradientBoostingClassifier",
        "hyperparameters": {
            "loss": "log_loss",
            "learning_rate": 0.03,
            "max_iter": 100,
            "max_leaf_nodes": 7,
            "min_samples_leaf": 100,
            "l2_regularization": 5.0,
            "early_stopping": False,
            "random_state": args.seed,
        },
        "decision_threshold": threshold,
        "threshold_selection": "validation_only; maximize recall subject to benign FPR <= 0.05",
        "training_rows": len(train),
        "validation_rows": len(validation),
        "training_class_counts": {
            "BENIGN": int((y_train == 0).sum()),
            "MALICIOUS": int((y_train == 1).sum()),
        },
        "validation_class_counts": {
            "BENIGN": int((y_validation == 0).sum()),
            "MALICIOUS": int((y_validation == 1).sum()),
        },
        "validation_metrics": validation_metrics,
        "validation_roc_auc": float(roc_auc_score(y_validation, validation_scores)),
        "dataset_manifest_sha256": hashlib.sha256((args.data_dir / "manifest.json").read_bytes()).hexdigest(),
        "joblib_sha256": hashlib.sha256(args.model_out.read_bytes()).hexdigest(),
        "portable_export_pending": True,
    }
    args.metadata_out.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
