"""
Messages-ML Feature Extraction Engine V3.
Extends Champion V2's 70 deterministic features with contextual representation
and interaction features to resolve real-world behavioral false positives
(Hinglish team chat, delivery PINs, transactional OTPs) without degrading attack recall.
"""

from dataclasses import dataclass, field
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml")
sys.path.insert(0, str(ROOT / "Messages-ml" / "scripts"))

import feature_extraction as v2_fe
from feature_config import FeatureConfig
from text_normalization import analyze_and_normalize, TextNormalizationResult
from sender_parser import parse_sender_header

def extract_v3_contextual_features(features: Dict[str, float], raw_text: str) -> Dict[str, float]:
    t = raw_text.lower()
    
    # 1. Threat intent aggregator
    threat_signals = (
        features.get("account_blocked_signal", 0.0) +
        features.get("disconnection_signal", 0.0) +
        features.get("penalty_signal", 0.0) +
        features.get("legal_action_signal", 0.0) +
        features.get("unauthorized_activity_signal", 0.0) +
        features.get("otp_disclosure_request", 0.0) * 2.0
    )
    has_threat_intent = 1.0 if threat_signals > 0.0 else 0.0
    
    # 2. Delivery PIN / OTP context interaction
    delivery_ctx = features.get("delivery_otp_context", 0.0)
    pin_pres = features.get("pin_present", 0.0)
    otp_pres = features.get("otp_present", 0.0)
    delivery_x_pin = delivery_ctx * pin_pres
    delivery_x_otp = delivery_ctx * otp_pres
    
    # 3. URL context interaction
    url_cnt = features.get("url_count", 0.0)
    has_url = 1.0 if url_cnt > 0 else 0.0
    url_without_threat = has_url * (1.0 - has_threat_intent)
    coercive_threat_x_url = threat_signals * has_url
    
    # 4. Legit transactional OTP interaction
    legit_ctx = features.get("legit_context_score", 0.0)
    has_legit_inst = features.get("has_legit_institution", 0.0)
    otp_disc = features.get("otp_disclosure_request", 0.0)
    legit_otp_delivery = 1.0 if (legit_ctx > 0.0 or has_legit_inst > 0.0) and otp_pres > 0.0 and otp_disc == 0.0 else 0.0
    
    # 5. Conversational / Project Collaboration Signals
    conv_cues = ["haan", "bhej", "kare", "karte", "hum", "aap", "voh", "toh", "sahi", "dekh", "dekhte", "karo", "chalega", "baje", "subah", "raat", "kal", "shayad", "kaise", "hota"]
    conv_matches = sum(1 for c in conv_cues if re.search(r'\b' + c + r'\b', t))
    conversational_marker_count = float(conv_matches)
    is_conversational = 1.0 if conv_matches >= 2 else (0.5 if conv_matches == 1 else 0.0)
    
    dev_cues = ["github", "dataset", "simulink", "simulation", "prototype", "ppt", "segmentation", "severity", "repository", "colab", "jupyter"]
    dev_matches = sum(1 for d in dev_cues if d in t)
    dev_collab_count = float(dev_matches)
    is_dev_collab = 1.0 if dev_matches >= 1 else 0.0
    
    collab_score = min(1.0, is_conversational + is_dev_collab)
    conversational_x_url = collab_score * url_without_threat
    benign_collab_signal = 1.0 if (is_conversational > 0.0 or is_dev_collab > 0.0) and has_threat_intent == 0.0 and features.get("urgency_word_count", 0.0) == 0.0 else 0.0

    return {
        "v3_has_threat_intent": has_threat_intent,
        "v3_delivery_x_pin": delivery_x_pin,
        "v3_delivery_x_otp": delivery_x_otp,
        "v3_url_without_threat": url_without_threat,
        "v3_coercive_threat_x_url": coercive_threat_x_url,
        "v3_legit_otp_delivery": legit_otp_delivery,
        "v3_conversational_marker_count": conversational_marker_count,
        "v3_dev_collab_count": dev_collab_count,
        "v3_conversational_x_url": conversational_x_url,
        "v3_benign_collab_signal": benign_collab_signal,
    }


def extract_feature_vector_v3(
    raw_text: str,
    sender_header: Optional[str] = None,
    config: Optional[FeatureConfig] = None,
) -> List[float]:
    cfg = config or FeatureConfig()
    base_dict = v2_fe.extract_message_features(raw_text, sender_header, cfg)
    v3_dict = extract_v3_contextual_features(base_dict, raw_text)
    base_dict.update(v3_dict)
    names = sorted(list(base_dict.keys()))
    return [base_dict[k] for k in names]


def get_feature_names_v3(config: Optional[FeatureConfig] = None) -> List[str]:
    cfg = config or FeatureConfig()
    dummy_dict = v2_fe.extract_message_features("Sample text", "VK-SAMPLE", cfg)
    v3_dict = extract_v3_contextual_features(dummy_dict, "Sample text")
    dummy_dict.update(v3_dict)
    return sorted(list(dummy_dict.keys()))
