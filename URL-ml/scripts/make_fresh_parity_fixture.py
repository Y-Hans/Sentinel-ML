"""Generate Python reference records for the Android fresh-model parity test."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import numpy as np

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
from fresh_url_features import extract_fresh_features, vectorize_urls, FEATURE_NAMES  # noqa: E402


URLS = [
    "https://www.google.com/",
    "http://www.google.com/",
    "www.google.com",
    "//www.google.com/search?q=sentinel",
    "https://docs.python.org/3/library/urllib.parse.html#url-parsing",
    "account-verification.example.invalid/login?session=expired",
    "paypa1-security.example.invalid/verify/account",
    "download-center.example.invalid/update.apk",
    "portal.example.invalid/continue?url=https%3A%2F%2Fphish.example.invalid%2Flogin",
    "https://github.com/security-update/verify.apk",
    "bank-account.example.invalid/verify-card?otp=required",
    "https://192.0.2.10:8080/login",
    "https://example.com/path.",
    "https://example.com/path#fragment",
    "https://user:pass@example.com/path",
    "",
    "   ",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    model = joblib.load(args.model)
    metadata = json.loads(args.model.with_name("fresh_url_20261024_metadata.json").read_text())
    features = vectorize_urls(URLS)
    raw = model.predict_proba(features)[:, 1]
    records = []
    for index, (url, vector, probability) in enumerate(zip(URLS, features, raw)):
        records.append(
            {
                "id": f"fresh-parity-{index:03d}",
                "url": url,
                "features": [float(value) for value in vector],
                "raw_probability": float(probability),
                "final_probability": float(probability),
                "label": "MALICIOUS" if probability >= metadata["decision_threshold"] else "BENIGN",
                "decision_threshold": metadata["decision_threshold"],
                "feature_names": FEATURE_NAMES,
                "feature_contract_id": metadata["feature_contract_id"],
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
