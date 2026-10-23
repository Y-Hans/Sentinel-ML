"""Sentinel-ML — Shared Data Contracts and Protocol Definitions.

This module defines the canonical data models, severity enumerations,
and classification result structures shared across URL-ML, Messages-ML,
and the Sentinel Risk Fusion Engine.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional


class EvidenceSeverity(Enum):
    """Hierarchical severity levels for threat evidence."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        levels = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return levels[self.value]

    def __ge__(self, other: "EvidenceSeverity") -> bool:
        if not isinstance(other, EvidenceSeverity):
            return NotImplemented
        return self.level >= other.level

    def __gt__(self, other: "EvidenceSeverity") -> bool:
        if not isinstance(other, EvidenceSeverity):
            return NotImplemented
        return self.level > other.level

    def __le__(self, other: "EvidenceSeverity") -> bool:
        if not isinstance(other, EvidenceSeverity):
            return NotImplemented
        return self.level <= other.level

    def __lt__(self, other: "EvidenceSeverity") -> bool:
        if not isinstance(other, EvidenceSeverity):
            return NotImplemented
        return self.level < other.level


class DecisionVerdict(Enum):
    """Final operational policy verdicts emitted by Sentinel."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class MessageThreatClass(Enum):
    """Three-class taxonomic labeling for message content."""
    BENIGN = "BENIGN"
    SPAM = "SPAM"
    MALICIOUS = "MALICIOUS"


class UrlThreatClass(Enum):
    """Binary threat categorization for URLs."""
    BENIGN = "BENIGN"
    MALICIOUS = "MALICIOUS"


@dataclass(frozen=True)
class UrlClassificationResult:
    """Standardized output from URL-ML classification and relational adjudication."""
    url: str
    predicted_class: UrlThreatClass
    raw_probability: float
    adjudicated_severity: EvidenceSeverity
    is_safe_brand_gated: bool = False
    has_threat_override: bool = False
    triggered_invariants: List[str] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MessageClassificationResult:
    """Standardized output from Messages-ML natural language analysis."""
    raw_text: str
    predicted_class: MessageThreatClass
    class_probabilities: Dict[str, float]
    adjudicated_severity: EvidenceSeverity
    extracted_urls: List[str] = field(default_factory=list)
    sender_header: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskFusionDecision:
    """Unified security verdict produced by the Risk Fusion Engine.
    
    Adheres strictly to the architectural invariant:
    `PAYLOAD OVERRIDES CONTEXT` — If max_payload_severity >= EvidenceSeverity.HIGH,
    verdict must be WARN or BLOCK regardless of message or group context.
    """
    verdict: DecisionVerdict
    highest_severity: EvidenceSeverity
    message_result: Optional[MessageClassificationResult] = None
    url_results: List[UrlClassificationResult] = field(default_factory=list)
    context_flags: Dict[str, bool] = field(default_factory=dict)
    rationale: str = ""
