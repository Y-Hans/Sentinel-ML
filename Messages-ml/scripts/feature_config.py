"""
Feature configuration and group definitions for Message ML.

Allows dynamic selection of feature subsets for empirical evaluation
and ensures reproducible feature ordering for model training and TFLite export.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set

ALL_FEATURE_GROUPS = [
    "STRUCTURAL",
    "URGENCY",
    "FEAR_THREAT",
    "AUTH",
    "OTP_INTENT",
    "FINANCIAL",
    "CTA",
    "SENDER",
    "NGRAM_HASH",
    "LEGIT_INTENT",
]

DEFAULT_ACTIVE_GROUPS = [
    "STRUCTURAL",
    "URGENCY",
    "FEAR_THREAT",
    "AUTH",
    "OTP_INTENT",
    "FINANCIAL",
    "CTA",
    "SENDER",
    "LEGIT_INTENT",
]


@dataclass
class FeatureConfig:
    active_groups: List[str] = field(default_factory=lambda: list(DEFAULT_ACTIVE_GROUPS))
    ngram_hash_bins: int = 16
    hash_seed: int = 42
    version: str = "1.0.0"

    def __post_init__(self):
        for grp in self.active_groups:
            if grp not in ALL_FEATURE_GROUPS:
                raise ValueError(f"Invalid feature group '{grp}'. Allowed: {ALL_FEATURE_GROUPS}")

    def to_dict(self) -> Dict:
        return {
            "version": self.version,
            "active_groups": self.active_groups,
            "ngram_hash_bins": self.ngram_hash_bins,
            "hash_seed": self.hash_seed,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "FeatureConfig":
        return cls(
            active_groups=data.get("active_groups", list(DEFAULT_ACTIVE_GROUPS)),
            ngram_hash_bins=data.get("ngram_hash_bins", 16),
            hash_seed=data.get("hash_seed", 42),
            version=data.get("version", "1.0.0"),
        )
