"""Export V8 Champion Model to Joblib for Python Runtime.

Saves:
- URL-ml/models/v8_champion.joblib

Leaves V7 champion completely untouched.
"""
from __future__ import annotations
from pathlib import Path
import joblib
import numpy as np

from v7_features import V7_FEATURE_NAMES, extract_v7_features
from v8_classifier import V8RelationalURLClassifier

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
MODELS = ROOT / "models"

# Load frozen V7 model
v7_path = MODELS / "v7_champion.joblib"
v7_model = joblib.load(v7_path)

# Construct V8 Champion
v8_champion = V8RelationalURLClassifier(
    base_model=v7_model.base_model,
    feature_names=V7_FEATURE_NAMES,
    threshold=0.2800,
    conf_bound=0.80
)

# Export V8 model
v8_path = MODELS / "v8_champion.joblib"
joblib.dump(v8_champion, v8_path, compress=3)
print(f"Saved V8 Champion to {v8_path} ({v8_path.stat().st_size / 1024:.1f} KB)")

# Verification: Reload and test
loaded = joblib.load(v8_path)
test_url = "https://chessigma.com/"
feat = extract_v7_features(test_url)
vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
probs = loaded.predict_proba(vec, urls=[test_url])[0]
pred = loaded.predict(vec, urls=[test_url])[0]

print(f"Smoke Test [{test_url}]: P(Malicious)={probs[1]:.4f}, Pred={pred} (Expected: 0.0010, 0)")
assert probs[1] < 0.01, f"Expected benign probability, got {probs[1]}"
assert pred == 0, f"Expected 0, got {pred}"
print("V8 Champion Joblib verification PASSED!")
