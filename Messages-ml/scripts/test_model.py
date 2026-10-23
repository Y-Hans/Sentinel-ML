"""
CLI inference and rule inspection tester for Message ML.

Allows testing single SMS messages against normalization, sender parsing,
feature extraction, and deterministic security rules.
"""

import json
from pathlib import Path
import sys
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "evaluation"))

from feature_config import FeatureConfig
from feature_extraction import extract_message_features
from rules_engine import evaluate_rules
from sender_parser import parse_sender_header
from text_normalization import analyze_and_normalize


def inspect_message(raw_text: str, sender_header: Optional[str] = None):
    norm_res = analyze_and_normalize(raw_text)
    sender_res = parse_sender_header(sender_header)
    rule_signals = evaluate_rules(raw_text, sender_header)
    features = extract_message_features(raw_text, sender_header)

    report = {
        "input": {
            "raw_text": raw_text,
            "sender_header": sender_header,
        },
        "normalization": {
            "cleaned_text": norm_res.cleaned_text,
            "detected_script": norm_res.detected_script,
            "is_mixed_script": norm_res.is_mixed_script,
            "has_homoglyphs": norm_res.has_homoglyphs,
            "zero_width_count": norm_res.zero_width_count,
        },
        "sender_intelligence": {
            "sender_type": sender_res.sender_type,
            "has_dlt_structural_shape": sender_res.has_dlt_structural_shape,
            "dlt_prefix": sender_res.dlt_prefix,
            "dlt_entity_code": sender_res.dlt_entity_code,
            "dlt_suffix_category": sender_res.dlt_suffix_category,
            "is_domestic_phone": sender_res.is_domestic_phone,
            "known_entity_category": sender_res.known_entity_category,
        },
        "rule_signals": [
            {
                "rule_id": s.rule_id,
                "signal_type": s.signal_type,
                "severity": s.severity,
                "confidence": s.confidence,
                "evidence": s.evidence,
                "metadata": s.metadata,
            }
            for s in rule_signals
        ],
        "extracted_feature_summary": {
            "total_features": len(features),
            "otp_present": features.get("otp_present", 0.0),
            "otp_negation_warning": features.get("otp_negation_warning", 0.0),
            "otp_disclosure_request": features.get("otp_disclosure_request", 0.0),
            "delivery_otp_context": features.get("delivery_otp_context", 0.0),
            "high_pressure_score": features.get("high_pressure_score", 0.0),
            "total_fear_signals_count": features.get("total_fear_signals_count", 0.0),
            "url_count": features.get("url_count", 0.0),
            "has_shortener_url": features.get("has_shortener_url", 0.0),
        },
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = sys.argv[1]
        sender = sys.argv[2] if len(sys.argv) > 2 else None
        inspect_message(text, sender)
    else:
        sample_text = "Your OTP is 483921 for HDFC NetBanking login. Never share this OTP with anyone."
        sample_sender = "VK-HDFCBK"
        print("Running demo inspection on sample message:")
        inspect_message(sample_text, sample_sender)
