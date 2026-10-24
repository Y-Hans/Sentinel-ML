"""Export the fresh HistGBM model in the existing pure-Kotlin tree format."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, default=None)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata_path = args.metadata or args.model.with_name("fresh_url_20261024_metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    model = joblib.load(args.model)

    trees = []
    for predictors in model._predictors:
        tree = predictors[0]
        nodes = []
        for node in tree.nodes:
            nodes.append(
                [
                    int(node["feature_idx"]),
                    int(node["bin_threshold"]),
                    int(node["left"]),
                    int(node["right"]),
                    float(node["value"]),
                    int(node["is_leaf"]),
                    int(node["missing_go_to_left"]),
                ]
            )
        trees.append(nodes)

    bundle = {
        "version": metadata["version"],
        "model_id": metadata["model_id"],
        "model_type": metadata["model_type"],
        "feature_contract_id": metadata["feature_contract_id"],
        "feature_names_sha256": metadata["feature_names_sha256"],
        "n_features": len(metadata["feature_names"]),
        "n_trees": len(trees),
        "learning_rate": float(model.learning_rate),
        "base_score": float(np.ravel(model._baseline_prediction)[0]),
        "decision_threshold": float(metadata["decision_threshold"]),
        "conf_bound": 0.80,
        "feature_names": metadata["feature_names"],
        "bin_thresholds": [arr.tolist() for arr in model._bin_mapper.bin_thresholds_],
        "trees": trees,
        "dataset_manifest_sha256": metadata["dataset_manifest_sha256"],
        "threshold_selection": metadata["threshold_selection"],
    }
    text = json.dumps(bundle, separators=(",", ":"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    metadata["portable_asset_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    metadata["portable_asset_size_bytes"] = len(text.encode())
    metadata["portable_export_pending"] = False
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "size_bytes": len(text.encode()),
                "n_features": len(metadata["feature_names"]),
                "n_trees": len(trees),
                "sha256": metadata["portable_asset_sha256"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
