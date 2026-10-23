"""Export V8 Champion to Portable JSON Bundle for Pure Kotlin / Android Runtime.

Produces:
- URL-ml/models/v8_champion_portable.json
- android-runtime/url/assets/v8_champion_portable.json

Leaves V7 assets completely untouched!
"""
from __future__ import annotations
import json
from pathlib import Path
import joblib
import numpy as np

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
ANDROID_ASSETS = ROOT.parent / "android-runtime" / "url" / "assets"

# Load base model
v7_model = joblib.load(MODELS / "v7_champion.joblib")
hgb = v7_model.base_model
feature_names = v7_model.feature_names
v8_threshold = 0.2800
conf_bound = 0.80

# Extract trees from HistGradientBoostingClassifier
trees_data = []
for iter_trees in hgb._predictors:
    tree = iter_trees[0]  # binary classification
    nodes_list = []
    for node in tree.nodes:
        # [feature_idx, bin_threshold, left, right, value, is_leaf, missing_go_to_left]
        nodes_list.append([
            int(node["feature_idx"]),
            int(node["bin_threshold"]),
            int(node["left"]),
            int(node["right"]),
            float(node["value"]),
            int(node["is_leaf"]),
            int(node["missing_go_to_left"]),
        ])
    trees_data.append(nodes_list)

export_bundle = {
    "version": "8.0.0",
    "model_type": "HistGradientBoostingClassifier",
    "n_trees": len(trees_data),
    "learning_rate": float(hgb.learning_rate),
    "base_score": float(np.ravel(hgb._baseline_prediction)[0]),
    "decision_threshold": v8_threshold,
    "conf_bound": conf_bound,
    "feature_names": feature_names,
    "bin_thresholds": [arr.tolist() for arr in hgb._bin_mapper.bin_thresholds_],
    "trees": trees_data,
}

json_payload = json.dumps(export_bundle, separators=(",", ":"))

target_files = [
    MODELS / "v8_champion_portable.json",
    ANDROID_ASSETS / "v8_champion_portable.json",
]

for tf in target_files:
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.write_text(json_payload, encoding="utf-8")
    print(f"Exported V8 portable bundle ({len(trees_data)} trees, {len(json_payload)/1024:.2f} KB) to {tf}")

if __name__ == "__main__":
    print("V8 portable export completed successfully.")
