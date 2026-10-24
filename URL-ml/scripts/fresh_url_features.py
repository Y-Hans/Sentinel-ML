"""Versioned feature contract for the fresh URL model.

The existing deterministic 67-feature implementation is used as an implementation
compatibility reference only. The new model never loads or reuses old model
weights, datasets, predictions, or fixtures.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))

from v7_features import (  # noqa: E402
    V7_FEATURE_NAMES,
    canonicalize_url,
    extract_v7_features,
)


FEATURE_CONTRACT_ID = "fresh_url_67_v1"
FEATURE_NAMES = list(V7_FEATURE_NAMES)
FEATURE_NAMES_SHA256 = hashlib.sha256(
    json.dumps(FEATURE_NAMES, separators=(",", ":")).encode("utf-8")
).hexdigest()


def extract_fresh_features(url: str) -> dict[str, float]:
    return extract_v7_features(url)


def vectorize_urls(urls: list[str]):
    import numpy as np

    matrix = np.empty((len(urls), len(FEATURE_NAMES)), dtype=np.float32)
    for index, url in enumerate(urls):
        features = extract_fresh_features(url)
        matrix[index] = [features[name] for name in FEATURE_NAMES]
    return matrix


__all__ = [
    "FEATURE_CONTRACT_ID",
    "FEATURE_NAMES",
    "FEATURE_NAMES_SHA256",
    "canonicalize_url",
    "extract_fresh_features",
    "vectorize_urls",
]
