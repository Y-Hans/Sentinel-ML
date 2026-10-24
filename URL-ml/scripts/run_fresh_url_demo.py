"""Run the model against newly authored presentation fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fresh_url_features import vectorize_urls  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    model = joblib.load(args.model)
    metadata = json.loads(args.model.with_name("fresh_url_20261024_metadata.json").read_text())
    fixtures = json.loads(args.fixtures.read_text())
    scores = model.predict_proba(vectorize_urls([fixture["url"] for fixture in fixtures]))[:, 1]
    output = []
    for fixture, score in zip(fixtures, scores):
        output.append(
            {
                **fixture,
                "raw_probability": float(score),
                "model_label": "MALICIOUS" if score >= metadata["decision_threshold"] else "BENIGN",
                "threshold": metadata["decision_threshold"],
            }
        )
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
