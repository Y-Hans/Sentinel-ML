"""
CLI harness for executing reproducible baseline model experiments in Message ML.
"""

import json
from pathlib import Path
import sys
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evaluation"))

from feature_config import FeatureConfig
from leakage_analysis import partition_dataset_group_aware
from train_baseline import train_candidate_model


def run_baseline_experiment(
    data_file: Path,
    model_type: str = "LOGISTIC_REGRESSION",
    feature_config: FeatureConfig = None,
    seed: int = 42,
) -> Dict:
    """
    Loads dataset, creates group-aware partitions, trains candidate model,
    and returns reproducible experiment metadata and metrics.
    """
    records = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line.strip()))

    splits = partition_dataset_group_aware(
        records, train_ratio=0.60, val_ratio=0.20, test_ratio=0.20, seed=seed
    )

    model, exp_res = train_candidate_model(
        model_type=model_type,
        train_records=splits["TRAIN"],
        val_records=splits["VALIDATION"],
        test_records=splits["TEST"],
        feature_cfg=feature_config,
        seed=seed,
    )

    return {
        "experiment_id": exp_res.experiment_id,
        "model_type": exp_res.model_type,
        "dataset_fingerprint": exp_res.dataset_fingerprint,
        "train_samples": exp_res.train_samples,
        "val_samples": exp_res.val_samples,
        "test_samples": exp_res.test_samples,
        "train_metrics": exp_res.train_metrics,
        "val_metrics": exp_res.val_metrics,
        "test_metrics": exp_res.test_metrics,
        "feature_count": exp_res.feature_count,
        "active_groups": exp_res.feature_config["active_groups"],
        "software_versions": exp_res.software_versions,
    }


if __name__ == "__main__":
    fixtures_path = ROOT / "data" / "benchmarks" / "synthetic_pipeline_fixtures.jsonl"
    print("Running Baseline Model A (Logistic Regression)...")
    res_a = run_baseline_experiment(fixtures_path, model_type="LOGISTIC_REGRESSION")
    print(json.dumps(res_a, indent=2))

    print("\nRunning Baseline Model B (Small MLP)...")
    res_b = run_baseline_experiment(fixtures_path, model_type="SMALL_MLP")
    print(json.dumps(res_b, indent=2))
