"""Re-export the fitted scaler without losing feature-order metadata."""

import json
from pathlib import Path

import joblib

from train_tf_model import RISK_CENTER, RISK_LOGIT_SCALE
from url_features import FULL_FEATURES


root = Path(__file__).resolve().parents[1]
scaler = joblib.load(root / "model" / "scaler.pkl")
if len(scaler.mean_) != len(FULL_FEATURES):
    raise ValueError("Scaler size does not match the final feature set; retrain first")

scaler_data = {
    "feature_names": FULL_FEATURES,
    "mean": scaler.mean_.tolist(),
    "scale": scaler.scale_.tolist(),
    "risk_calibration": {"center": RISK_CENTER, "logit_scale": RISK_LOGIT_SCALE},
}
(root / "model" / "scaler.json").write_text(json.dumps(scaler_data, indent=2), encoding="utf-8")
print("scaler.json saved")
