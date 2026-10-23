"""Train, evaluate, and export the lightweight phishing URL classifier."""

from __future__ import annotations

import argparse
import json
import os
import random
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, log_loss, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from url_features import FEATURE_SETS, domain_group, extract_url_features


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "final_dataset.csv"
MODEL_DIR = ROOT / "model"
MANUAL_URLS = [
    ("safe", "https://google.com"),
    ("safe", "https://github.com"),
    ("safe", "https://shipaton.com"),
    ("phishing", "http://secure-login-google.xyz"),
    ("phishing", "https://paypa1-account-verification.top"),
    ("phishing", "http://192.168.1.1/login"),
    ("suspicious", "http://example.com/login"),
]
RISK_CENTER = 0.43
RISK_LOGIT_SCALE = 1.50


def prediction_summary(name: str, values: np.ndarray) -> None:
    quantiles = np.quantile(values, [0, 0.01, 0.10, 0.25, 0.50, 0.75, 0.90, 0.99, 1])
    keys = ["min", "p01", "p10", "p25", "median", "p75", "p90", "p99", "max"]
    print(f"{name} quantiles:", {key: round(float(value), 4) for key, value in zip(keys, quantiles)})
    bins = np.histogram(values, bins=[0, 0.1, 0.2, 0.5, 0.6, 1.000001])[0]
    print(f"{name} bins [<.1, .1-.2, .2-.5, .5-.6, >=.6]: {bins.tolist()}")


def tflite_predict(model_path: Path, scaled_features: np.ndarray) -> np.ndarray:
    interpreter = tf.lite.Interpreter(model_path=str(model_path))
    interpreter.allocate_tensors()
    input_detail = interpreter.get_input_details()[0]
    output_detail = interpreter.get_output_details()[0]
    predictions = []
    for row in scaled_features.astype(np.float32):
        interpreter.set_tensor(input_detail["index"], row.reshape(1, -1))
        interpreter.invoke()
        predictions.append(float(interpreter.get_tensor(output_detail["index"]).reshape(-1)[0]))
    return np.asarray(predictions)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feature-set", choices=FEATURE_SETS, default="full")
    parser.add_argument("--epochs", type=int, choices=range(5, 11), default=8)
    parser.add_argument("--hard-weight", type=float, default=20.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)
    try:
        tf.config.experimental.enable_op_determinism()
    except Exception:
        pass

    feature_names = FEATURE_SETS[args.feature_set]
    data = pd.read_csv(DATA_PATH)
    missing_columns = [name for name in feature_names if name not in data.columns]
    if missing_columns:
        raise ValueError(f"Run merge_datasets.py --feature-set {args.feature_set}; missing {missing_columns}")
    if data[feature_names].isna().any().any():
        raise ValueError("Training data has missing feature values")
    if (data[feature_names].abs().sum(axis=1) == 0).any():
        raise ValueError("Training data has zero-only feature rows")

    X = data[feature_names].astype(np.float32)
    y = data["label"].astype(np.float32)
    groups = data["url"].map(domain_group)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=args.seed)
    train_idx, test_idx = next(splitter.split(X, y, groups))

    X_train_frame, X_test_frame = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_frame).astype(np.float32)
    X_test = scaler.transform(X_test_frame).astype(np.float32)
    sample_weight = np.where(
        data.iloc[train_idx]["DatasetSource"].to_numpy() == "hard", args.hard_weight, 1.0
    ).astype(np.float32)

    print(f"Feature list ({len(feature_names)}): {feature_names}")
    print(f"Train: {X_train.shape}; test: {X_test.shape}")
    print(f"Train hard rows: {int((data.iloc[train_idx]['DatasetSource'] == 'hard').sum()):,}; weight={args.hard_weight:g}")
    print(f"Test labels: {y_test.value_counts().sort_index().to_dict()}")

    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(len(feature_names),)),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(8, activation="relu"),
        tf.keras.layers.Dense(1),
    ])
    model.compile(
        optimizer="adam", loss=tf.keras.losses.BinaryCrossentropy(from_logits=True),
        metrics=[
            tf.keras.metrics.BinaryAccuracy(name="accuracy", threshold=0.0),
            tf.keras.metrics.AUC(name="auc", from_logits=True),
        ],
    )
    model.fit(
        X_train, y_train, sample_weight=sample_weight, epochs=args.epochs,
        batch_size=256, validation_data=(X_test, y_test), verbose=2, shuffle=True,
    )

    # Convert the learned logit into the requested risk bands inside the model.
    # This one-neuron transform is monotonic, so ranking/AUC is unchanged, while
    # moving confident safe/phishing cases away from the ambiguous middle.
    calibration = tf.keras.layers.Dense(1, activation="sigmoid", trainable=False, name="risk_calibration")
    export_input = tf.keras.Input(shape=(len(feature_names),), name="scaled_url_features")
    export_output = calibration(model(export_input, training=False))
    export_model = tf.keras.Model(export_input, export_output, name="phishing_url_risk")
    center_logit = np.log(RISK_CENTER / (1.0 - RISK_CENTER))
    calibration.set_weights([
        np.asarray([[RISK_LOGIT_SCALE]], dtype=np.float32),
        np.asarray([-RISK_LOGIT_SCALE * center_logit], dtype=np.float32),
    ])

    raw_logits = model.predict(X_test, batch_size=2048, verbose=0).reshape(-1)
    raw_test_scores = tf.math.sigmoid(raw_logits).numpy()
    test_scores = export_model.predict(X_test, batch_size=2048, verbose=0).reshape(-1)
    test_pred = (test_scores >= 0.5).astype(int)
    print("\nTest accuracy:", round(accuracy_score(y_test, test_pred), 6))
    print("Test ROC AUC:", round(roc_auc_score(y_test, test_scores), 6))
    print("Test log loss:", round(log_loss(y_test, test_scores), 6))
    print("Uncalibrated log loss:", round(log_loss(y_test, raw_test_scores), 6))
    print(f"Risk calibration: center={RISK_CENTER:.2f}, logit_scale={RISK_LOGIT_SCALE:.2f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:", confusion_matrix(y_test, test_pred).tolist())
    print(classification_report(y_test, test_pred, digits=4))
    prediction_summary("All test scores", test_scores)
    prediction_summary("Safe test scores", test_scores[y_test.to_numpy() == 0])
    prediction_summary("Phishing test scores", test_scores[y_test.to_numpy() == 1])

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    scaler_path = MODEL_DIR / "scaler.pkl"
    scaler_json_path = MODEL_DIR / "scaler.json"
    model_path = MODEL_DIR / "model.tflite"
    joblib.dump(scaler, scaler_path)
    scaler_json_path.write_text(
        json.dumps({
            "feature_names": feature_names,
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist(),
            "risk_calibration": {"center": RISK_CENTER, "logit_scale": RISK_LOGIT_SCALE},
        }, indent=2),
        encoding="utf-8",
    )

    # Keras 3 on native Windows can fail in ``from_keras_model`` while looking
    # up an internal call context. A concrete inference function avoids that
    # version-specific path and produces the same fixed-shape float model.
    inference = tf.function(lambda values: export_model(values, training=False))
    concrete = inference.get_concrete_function(
        tf.TensorSpec([1, len(feature_names)], tf.float32, name="url_features")
    )
    converter = tf.lite.TFLiteConverter.from_concrete_functions([concrete])
    model_path.write_bytes(converter.convert())

    manual_frame = pd.DataFrame(
        [extract_url_features(url, feature_names) for _, url in MANUAL_URLS], columns=feature_names
    )
    manual_scaled = scaler.transform(manual_frame).astype(np.float32)
    keras_manual = export_model.predict(manual_scaled, verbose=0).reshape(-1)
    tflite_manual = tflite_predict(model_path, manual_scaled)
    max_delta = float(np.max(np.abs(keras_manual - tflite_manual)))
    print("\nRaw TFLite manual predictions:")
    for (kind, url), score in zip(MANUAL_URLS, tflite_manual):
        print(f"{score:.6f}  [{kind:10}] {url}")
    print(f"Max Keras/TFLite prediction delta: {max_delta:.8f}")
    print(f"Saved {model_path}")
    print(f"Saved {scaler_json_path}")


if __name__ == "__main__":
    main()
