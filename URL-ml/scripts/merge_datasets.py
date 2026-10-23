"""Normalize labels, extract URL features for both sources, and merge them."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from url_features import FEATURE_SETS, extract_url_features


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def build_dataset(feature_set: str = "full") -> pd.DataFrame:
    feature_names = FEATURE_SETS[feature_set]
    original = pd.read_csv(DATA_DIR / "cleaned_dataset.csv", usecols=["url", "label"])
    hard = pd.read_csv(DATA_DIR / "hard_dataset.csv", usecols=["url", "label"])

    # The source dataset defines 1=legitimate; the curated hard set defines
    # 1=phishing. Normalize everything to 1=phishing (the model output meaning).
    original["label"] = 1 - original["label"].astype(int)
    original["DatasetSource"] = "original"
    hard["label"] = hard["label"].astype(int)
    hard["DatasetSource"] = "hard"

    combined = pd.concat([original, hard], ignore_index=True)
    conflicting = combined.groupby("url")["label"].nunique()
    if (conflicting > 1).any():
        examples = conflicting[conflicting > 1].index[:5].tolist()
        raise ValueError(f"Conflicting labels for URLs: {examples}")

    before = len(combined)
    combined["_source_order"] = combined["DatasetSource"].map({"original": 0, "hard": 1})
    combined = (
        combined.sort_values("_source_order")
        .drop_duplicates(subset="url", keep="last")
        .drop(columns="_source_order")
        .reset_index(drop=True)
    )

    feature_frame = pd.DataFrame(
        [extract_url_features(url, feature_names) for url in combined["url"]],
        columns=feature_names,
    )
    result = pd.concat([combined[["url"]], feature_frame, combined[["DatasetSource", "label"]]], axis=1)

    if result[feature_names].isna().any().any():
        raise ValueError("Feature extraction produced missing values")
    zero_rows = (result[feature_names].abs().sum(axis=1) == 0).sum()
    if zero_rows:
        raise ValueError(f"Feature extraction produced {zero_rows} zero-only rows")

    print(f"Original rows: {len(original):,}")
    print(f"Hard rows: {len(hard):,}")
    print(f"Removed same-label duplicate URLs: {before - len(result):,}")
    print(f"Merged rows: {len(result):,}")
    print(f"Labels (0=safe, 1=phishing): {result['label'].value_counts().sort_index().to_dict()}")
    print(f"Feature set ({len(feature_names)}): {feature_names}")
    print(f"Missing feature values: {int(result[feature_names].isna().sum().sum())}")
    print(f"Zero-only feature rows: {int(zero_rows)}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feature-set", choices=FEATURE_SETS, default="full")
    args = parser.parse_args()
    result = build_dataset(args.feature_set)
    output = DATA_DIR / "final_dataset.csv"
    result.to_csv(output, index=False)
    print(f"Saved {output}")


if __name__ == "__main__":
    main()
