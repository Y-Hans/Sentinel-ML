import json
from pathlib import Path

import numpy as np
import tensorflow as tf

# Import your feature function (adjust name if needed)
from url_features import extract_url_features

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "model" / "model.tflite"
SCALER_PATH = ROOT / "model" / "scaler.json"

# 🔒 MUST match training feature order EXACTLY
FEATURE_ORDER = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "IsHTTPS",
    "HasSuspiciousWords",
    "SpecialCharRatio",
    "DigitRatio",
    "HasAtSymbol",
    "SuspiciousTLD",
    "BrandImpersonationScore",
    "HyphenCount",
    "PathQueryLength",
    "KnownBrandDomain",
    "DomainVowelRatio"
]


# 📦 Load TFLite model
interpreter = tf.lite.Interpreter(model_path=str(MODEL_PATH))
interpreter.allocate_tensors()

input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()


# 📊 Load scaler
with open(SCALER_PATH, "r") as f:
    scaler = json.load(f)

mean = np.array(scaler["mean"], dtype=np.float32)
scale = np.array(scaler["scale"], dtype=np.float32)


def predict(url):
    try:
        # 🧠 Extract features (dict)
        feature_dict = extract_url_features(url)

        # 🔁 Convert to ordered array
        features = np.array(
            [feature_dict[f] for f in FEATURE_ORDER],
            dtype=np.float32
        )

        # 🧪 Normalize
        features = (features - mean) / scale

        # 🔁 Reshape for model
        features = features.reshape(1, -1).astype(np.float32)

        # 🧠 Run inference
        interpreter.set_tensor(input_details[0]['index'], features)
        interpreter.invoke()

        output = interpreter.get_tensor(output_details[0]['index'])[0][0]

        return float(output)

    except Exception as e:
        print(f"Error processing {url}: {e}")
        return None


# 🧪 TEST CASES
test_urls = [
    "https://google.com",
    "https://github.com",
    "https://shipaton.com",
    "http://secure-login-google.xyz",
    "https://paypa1-account-verification.top",
    "http://192.168.1.1/login",
    "http://example.com/login"
]


# 🚀 RUN TESTS
print("\n===== MODEL TEST RESULTS =====\n")

for url in test_urls:
    score = predict(url)

    if score is not None:
        print(f"{url} -> {score:.6f}")
    else:
        print(f"{url} -> ERROR")

print("\n==============================\n")