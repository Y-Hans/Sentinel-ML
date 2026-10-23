"""
Deterministic, lightweight feature extraction engine for Message ML.

Extracts modular feature groups (Structural, Urgency, Fear/Threat, Authentication,
OTP Intent, Financial, CTA, Sender, N-Gram Hashes) with strict portability to Android/Kotlin.
"""

from dataclasses import dataclass
import math
import re
from typing import Dict, List, Optional, Set, Tuple

from feature_config import DEFAULT_ACTIVE_GROUPS, FeatureConfig
from sender_parser import parse_sender_header, SenderParseResult
from text_normalization import analyze_and_normalize, TextNormalizationResult


# ============================================================================
# Pure Python 32-bit MurmurHash3 (x86 variant) for Bit-for-Bit Kotlin Parity
# ============================================================================

def murmur3_32(key: bytes, seed: int = 42) -> int:
    """
    Standard 32-bit MurmurHash3 implementation on byte strings.
    Matches standard Google Guava / Apache Commons / Kotlin implementations.
    """
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    r1 = 15
    r2 = 13
    m = 5
    n = 0xE6546B64

    length = len(key)
    h1 = seed & 0xFFFFFFFF
    nblocks = length // 4

    # Body
    for i in range(0, nblocks * 4, 4):
        k1 = (
            key[i]
            | (key[i + 1] << 8)
            | (key[i + 2] << 16)
            | (key[i + 3] << 24)
        ) & 0xFFFFFFFF

        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << r1) | (k1 >> (32 - r1))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << r2) | (h1 >> (32 - r2))) & 0xFFFFFFFF
        h1 = ((h1 * m) + n) & 0xFFFFFFFF

    # Tail
    tail = key[nblocks * 4 :]
    k1 = 0
    t_len = len(tail)
    if t_len >= 3:
        k1 ^= (tail[2] << 16) & 0xFFFFFFFF
    if t_len >= 2:
        k1 ^= (tail[1] << 8) & 0xFFFFFFFF
    if t_len >= 1:
        k1 ^= tail[0] & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << r1) | (k1 >> (32 - r1))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    # Finalization
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    return h1 & 0xFFFFFFFF


# ============================================================================
# Regex Patterns for Deterministic Signals
# ============================================================================

# Urgency and pressure terms
RE_URGENCY_WORDS = re.compile(
    r"\b(immediately|urgent|urgently|asap|hurry|rush|act\s+now|quick|instantly|fast|promptly)\b",
    re.IGNORECASE,
)
RE_DEADLINE_WORDS = re.compile(
    r"\b(today|tonight|within\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)|before\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?|expires?|deadline|last\s+date|last\s+day)\b",
    re.IGNORECASE,
)
RE_TIME_LIMIT = re.compile(
    r"\b(?:within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|in\s+\d+\s*(?:hours?|minutes?)|by\s+\d{1,2}\s*(?:pm|am))\b",
    re.IGNORECASE,
)

# Fear, Penalty, Disconnection, Suspension terms
RE_ACCOUNT_BLOCKED = re.compile(
    r"\b(blocked|deactivated|suspended|locked|restricted|freez(?:ed|e|ing)|disabled|inoperative)\b",
    re.IGNORECASE,
)
RE_PENALTY = re.compile(
    r"\b(penalty|fine|fined|charges|late\s+fee|dues|recovery|legal\s+notice)\b",
    re.IGNORECASE,
)
RE_LEGAL_ACTION = re.compile(
    r"\b(police|fir|court|arrest|warrant|advocate|legal\s+action|cbi|cyber\s+crime|trai\s+complaint)\b",
    re.IGNORECASE,
)
RE_DISCONNECTION = re.compile(
    r"\b(disconnect(?:ed|ion)?|power\s+cut|light\s+cut|bijli\s+cut|service\s+terminat(?:ed|ion))\b",
    re.IGNORECASE,
)
RE_UNAUTHORIZED_ACTIVITY = re.compile(
    r"\b(unauthorized|suspicious\s+login|fraudulent\s+transaction|security\s+alert|unrecognized\s+device)\b",
    re.IGNORECASE,
)
RE_KYC_PAN = re.compile(
    r"\b(kyc|pan\s*card|aadhaar|document\s+verification|yono|update\s+pan|pan\s+update|kyc\s+update)\b",
    re.IGNORECASE,
)

# Authentication & Credentials
RE_OTP_GENERIC = re.compile(
    r"\b(otp|one\s*time\s*password|verification\s*code|auth\s*code|security\s*code|login\s*pin|2fa)\b",
    re.IGNORECASE,
)
RE_PIN = re.compile(r"\b(upi\s*pin|atm\s*pin|mpin|secret\s*pin|passcode)\b", re.IGNORECASE)
RE_PASSWORD = re.compile(r"\b(password|netbanking\s*password|login\s*password)\b", re.IGNORECASE)
RE_NUMERIC_CODE = re.compile(r"\b\d{4,8}\b")

# OTP Intent: Legitimate Warnings vs Malicious Disclosure Requests vs Delivery OTP
RE_OTP_NEGATION_WARNING = re.compile(
    r"\b(never\s+share|do\s+not\s+(?:share|disclose|give|tell|forward)|bank\s+never\s+asks|keep\s+(?:it\s+)?confidential|strictly\s+confidential|don'?t\s+share)\b",
    re.IGNORECASE,
)
RE_OTP_DISCLOSURE_REQUEST = re.compile(
    r"\b(?:share|send|tell|forward|provide|give|reply\s+with|message)\s+(?:me\s+|us\s+|your\s+|the\s+)?(?:secret\s+)?(?:otp|code|pin|password|one\s*time\s*password)\b|"
    r"\b(?:otp|code|pin)\s+(?:to\s+(?:cancel|stop|verify|customer\s*care|support|executive|officer|manager|number))\b",
    re.IGNORECASE,
)
RE_DELIVERY_CONTEXT = re.compile(
    r"\b(delivery\s+agent|delivery\s+associate|delivery\s+partner|delivery\s+boy|courier\s+person|at\s+your\s+door|package\s+arrival|order\s+delivery)\b",
    re.IGNORECASE,
)

# Financial & Transactional
RE_DEBIT_CREDIT = re.compile(
    r"\b(debited\s+by|credited\s+with|withdrawn|transferred|txn|transaction|payment\s+of|refund\s+of)\b",
    re.IGNORECASE,
)
RE_CURRENCY_AMOUNT = re.compile(r"(?:₹|Rs\.?|INR)\s*[\d,]+(?:\.\d+)?", re.IGNORECASE)
RE_MASKED_ACCOUNT = re.compile(r"(?:[xX*]{2,}\d{3,4}|a/c\s*(?:no\.?)?\s*[xX*]*\d{3,4})", re.IGNORECASE)
RE_BALANCE = re.compile(r"\b(bal|balance|avl\s*bal|available\s*balance)\b", re.IGNORECASE)
RE_UPI_COLLECT = re.compile(
    r"\b(collect\s+request|upi\s+collect|approve\s+collect|enter\s+pin\s+to\s+receive)\b",
    re.IGNORECASE,
)
RE_LURE_PRIZE = re.compile(
    r"\b(lottery|won|winner|cashback|reward|bonus|lucky\s+draw|free\s+gift|claim\s+reward|earned\s+rs)\b",
    re.IGNORECASE,
)

# CTA & Routing
RE_URL = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
RE_SHORTENER = re.compile(r"\b(bit\.ly|tinyurl\.com|is\.gd|cutt\.ly|t\.co|rb\.gy|shorturl\.at|wa\.me)\b", re.IGNORECASE)
RE_RAW_IP = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE)
RE_APK = re.compile(r"(\.apk\b|download\s+(?:support|bank|update)\s+app)", re.IGNORECASE)
RE_PHONE = re.compile(r"(?:\+91|0)?[6-9]\d{9}")
RE_UPI_VPA = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|okicici|oksbi|paytm|ybl|apl|upi)\b", re.IGNORECASE)
RE_WHATSAPP_CTA = re.compile(r"\b(whatsapp|wa\.me|contact\s+on\s+whatsapp|telegram)\b", re.IGNORECASE)

# Legitimate Institutional & Protective Context
RE_LEGIT_INSTITUTION = re.compile(
    r"\b(income\s+tax|incometax|uidai|aadhaar|msedcl|mahavitaran|gov\.in|bank\s+of|hdfc|icici|sbi|axis\s+bank|kotak|pnb)\b",
    re.IGNORECASE,
)
RE_LEGIT_NOTICE = re.compile(
    r"\b(official\s+(?:portal|app|website)|never\s+ask|do\s+not\s+share|consumer\s+no|ay\s+\d{4}|section\s+\d+|dear\s+customer)\b",
    re.IGNORECASE,
)


# ============================================================================
# Modular Feature Extractors
# ============================================================================

def extract_structural_features(norm: TextNormalizationResult) -> Dict[str, float]:
    total_c = max(1, norm.total_chars)
    words = norm.cleaned_text.split()
    word_count = len(words)
    avg_word_len = sum(len(w) for w in words) / max(1, word_count)

    return {
        "message_length": float(norm.total_chars),
        "word_count": float(word_count),
        "avg_word_length": float(avg_word_len),
        "digit_count": float(norm.digit_count),
        "digit_ratio": float(norm.digit_count / total_c),
        "uppercase_count": float(norm.uppercase_count),
        "uppercase_ratio": float(norm.uppercase_count / total_c),
        "special_char_count": float(norm.punctuation_count),
        "special_char_ratio": float(norm.punctuation_count / total_c),
        "newline_count": float(norm.newline_count),
        "whitespace_count": float(norm.whitespace_count),
        "zero_width_count": float(norm.zero_width_count),
        "has_homoglyphs": 1.0 if norm.has_homoglyphs else 0.0,
        "is_mixed_script": 1.0 if norm.is_mixed_script else 0.0,
    }


def extract_urgency_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    urg_matches = len(RE_URGENCY_WORDS.findall(text))
    dl_matches = len(RE_DEADLINE_WORDS.findall(text))
    time_lim = 1.0 if RE_TIME_LIMIT.search(text) else 0.0

    return {
        "urgency_word_count": float(urg_matches),
        "deadline_word_count": float(dl_matches),
        "has_time_limit_pattern": time_lim,
        "high_pressure_score": float(urg_matches * 1.5 + dl_matches * 1.0 + time_lim * 2.0),
    }


def extract_fear_threat_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    blk = 1.0 if RE_ACCOUNT_BLOCKED.search(text) else 0.0
    pen = 1.0 if RE_PENALTY.search(text) else 0.0
    leg = 1.0 if RE_LEGAL_ACTION.search(text) else 0.0
    disc = 1.0 if RE_DISCONNECTION.search(text) else 0.0
    unauth = 1.0 if RE_UNAUTHORIZED_ACTIVITY.search(text) else 0.0
    kyc = 1.0 if RE_KYC_PAN.search(text) else 0.0

    total_signals = blk + pen + leg + disc + unauth + kyc

    return {
        "account_blocked_signal": blk,
        "penalty_signal": pen,
        "legal_action_signal": leg,
        "disconnection_signal": disc,
        "unauthorized_activity_signal": unauth,
        "kyc_pan_signal": kyc,
        "total_fear_signals_count": float(total_signals),
    }


def extract_auth_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    otp_gen = 1.0 if RE_OTP_GENERIC.search(text) else 0.0
    pin_pres = 1.0 if RE_PIN.search(text) else 0.0
    pass_pres = 1.0 if RE_PASSWORD.search(text) else 0.0
    num_codes = RE_NUMERIC_CODE.findall(text)
    has_code = 1.0 if len(num_codes) > 0 else 0.0
    max_code_len = float(max((len(c) for c in num_codes), default=0))

    return {
        "otp_generic_present": otp_gen,
        "pin_present": pin_pres,
        "password_present": pass_pres,
        "numeric_code_present": has_code,
        "numeric_code_length": max_code_len,
    }


def extract_otp_intent_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    otp_pres = 1.0 if (RE_OTP_GENERIC.search(text) or RE_NUMERIC_CODE.search(text)) else 0.0
    neg_warn = 1.0 if RE_OTP_NEGATION_WARNING.search(text) else 0.0
    disc_req = 1.0 if RE_OTP_DISCLOSURE_REQUEST.search(text) else 0.0
    deliv_ctx = 1.0 if RE_DELIVERY_CONTEXT.search(text) else 0.0

    # Intent score: positive implies attack/theft risk, negative implies benign protective warning
    intent_score = (disc_req * 3.0) - (neg_warn * 2.0) - (deliv_ctx * 1.5)

    return {
        "otp_present": otp_pres,
        "otp_negation_warning": neg_warn,
        "otp_disclosure_request": disc_req,
        "delivery_otp_context": deliv_ctx,
        "otp_intent_risk_score": float(intent_score),
    }


def extract_financial_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    dc_matches = len(RE_DEBIT_CREDIT.findall(text))
    amt = 1.0 if RE_CURRENCY_AMOUNT.search(text) else 0.0
    acct = 1.0 if RE_MASKED_ACCOUNT.search(text) else 0.0
    bal = 1.0 if RE_BALANCE.search(text) else 0.0
    upi_coll = 1.0 if RE_UPI_COLLECT.search(text) else 0.0
    lures = len(RE_LURE_PRIZE.findall(text))

    return {
        "debit_credit_count": float(dc_matches),
        "currency_amount_present": amt,
        "masked_account_present": acct,
        "balance_keyword_present": bal,
        "upi_collect_keyword_present": upi_coll,
        "prize_lure_count": float(lures),
    }


def extract_cta_features(norm: TextNormalizationResult) -> Dict[str, float]:
    raw = norm.raw_text
    urls = RE_URL.findall(raw)
    url_count = len(urls)
    has_short = 1.0 if RE_SHORTENER.search(raw) else 0.0
    has_ip = 1.0 if RE_RAW_IP.search(raw) else 0.0
    has_apk = 1.0 if RE_APK.search(raw) else 0.0
    phones = RE_PHONE.findall(raw)
    phone_count = len(phones)
    vpas = RE_UPI_VPA.findall(raw)
    vpa_count = len(vpas)
    has_wa = 1.0 if RE_WHATSAPP_CTA.search(raw) else 0.0

    return {
        "url_count": float(url_count),
        "has_shortener_url": has_short,
        "has_raw_ip_url": has_ip,
        "has_apk_reference": has_apk,
        "phone_number_count": float(phone_count),
        "upi_vpa_count": float(vpa_count),
        "whatsapp_cta_present": has_wa,
    }


def extract_sender_features(
    sender_res: SenderParseResult, norm: TextNormalizationResult
) -> Dict[str, float]:
    is_alpha = 1.0 if sender_res.sender_type == "ALPHANUMERIC_HEADER" else 0.0
    is_dlt = 1.0 if sender_res.has_dlt_structural_shape else 0.0
    is_phone = 1.0 if sender_res.sender_type == "PHONE_NUMBER" else 0.0
    is_short = 1.0 if sender_res.is_shortcode else 0.0
    has_bank = 1.0 if sender_res.known_entity_category == "BANK" else 0.0

    # Cross-consistency: phone sender sending banking/power cut threats
    body_has_bank = 1.0 if (RE_MASKED_ACCOUNT.search(norm.normalized_lowercase) or RE_KYC_PAN.search(norm.normalized_lowercase)) else 0.0
    body_has_disc = 1.0 if RE_DISCONNECTION.search(norm.normalized_lowercase) else 0.0
    phone_bank_mismatch = 1.0 if (is_phone and (body_has_bank or body_has_disc)) else 0.0

    return {
        "sender_is_alphanumeric": is_alpha,
        "sender_is_dlt_shape": is_dlt,
        "sender_is_phone_number": is_phone,
        "sender_is_shortcode": is_short,
        "sender_has_bank_match": has_bank,
        "sender_phone_with_banking_body": phone_bank_mismatch,
    }


def extract_legit_intent_features(norm: TextNormalizationResult) -> Dict[str, float]:
    text = norm.normalized_lowercase
    inst = len(RE_LEGIT_INSTITUTION.findall(text))
    notice = len(RE_LEGIT_NOTICE.findall(text))
    
    # Overlapping protective features
    has_inst = 1.0 if inst > 0 else 0.0
    has_notice = 1.0 if notice > 0 else 0.0
    
    return {
        "legit_institution_keyword_count": float(inst),
        "legit_notice_keyword_count": float(notice),
        "has_legit_institution": has_inst,
        "has_legit_notice": has_notice,
        "legit_context_score": float(inst * 1.0 + notice * 1.5)
    }

def extract_interaction_features(features: Dict[str, float]) -> Dict[str, float]:
    """Stage B: Explicit deterministic interaction features."""
    return {
        "urgency_x_legit_intent": features.get("urgency_word_count", 0.0) * features.get("legit_context_score", 0.0),
        "kyc_x_sender": features.get("kyc_pan_signal", 0.0) * features.get("sender_is_alphanumeric", 0.0),
        "otp_x_protective": features.get("otp_intent_signal", 0.0) * features.get("legit_notice_keyword_count", 0.0),
        "financial_x_credential": features.get("financial_keyword_count", 0.0) * features.get("credential_theft_signal", 0.0),
        "url_x_cta": features.get("has_url", 0.0) * features.get("has_cta_link", 0.0),
        "url_x_sender": features.get("has_url", 0.0) * features.get("sender_is_phone_number", 0.0),
        "institutional_x_url": features.get("legit_institution_keyword_count", 0.0) * features.get("has_url", 0.0),
        "suspension_x_protective": features.get("account_suspension_signal", 0.0) * features.get("legit_notice_keyword_count", 0.0),
        "banking_x_disclosure": features.get("banking_keyword_count", 0.0) * features.get("disclosure_request_signal", 0.0),
        "urgency_x_credential": features.get("urgency_word_count", 0.0) * features.get("credential_theft_signal", 0.0),
        "fear_x_cta": features.get("total_fear_signals_count", 0.0) * features.get("has_cta_link", 0.0)
    }

def extract_ngram_hash_features(
    norm: TextNormalizationResult, num_bins: int = 16, seed: int = 42
) -> Dict[str, float]:
    """
    Computes a fixed-length character 3-gram feature vector using MurmurHash3.
    Deterministic, vocabulary-free, and bit-for-bit reproducible in Kotlin.
    """
    bins = [0.0] * num_bins
    text = norm.normalized_lowercase
    t_len = len(text)

    if t_len < 3:
        return {f"ngram_hash_{i}": 0.0 for i in range(num_bins)}

    total_ngrams = t_len - 2
    for i in range(total_ngrams):
        ngram = text[i : i + 3].encode("utf-8")
        h = murmur3_32(ngram, seed=seed)
        bin_idx = h % num_bins
        bins[bin_idx] += 1.0

    # L2 Normalization
    norm_factor = math.sqrt(sum(b * b for b in bins))
    if norm_factor > 1e-6:
        bins = [b / norm_factor for b in bins]

    return {f"ngram_hash_{i}": bins[i] for i in range(num_bins)}


# ============================================================================
# Master Extraction Orchestrator
# ============================================================================

def extract_message_features(
    raw_text: str,
    sender_header: Optional[str] = None,
    config: Optional[FeatureConfig] = None,
) -> Dict[str, float]:
    """
    Extracts all active feature groups into a named dictionary.
    """
    cfg = config or FeatureConfig()
    norm_res = analyze_and_normalize(raw_text)
    sender_res = parse_sender_header(sender_header)

    features: Dict[str, float] = {}

    if "STRUCTURAL" in cfg.active_groups:
        features.update(extract_structural_features(norm_res))
    if "URGENCY" in cfg.active_groups:
        features.update(extract_urgency_features(norm_res))
    if "FEAR_THREAT" in cfg.active_groups:
        features.update(extract_fear_threat_features(norm_res))
    if "AUTH" in cfg.active_groups:
        features.update(extract_auth_features(norm_res))
    if "OTP_INTENT" in cfg.active_groups:
        features.update(extract_otp_intent_features(norm_res))
    if "FINANCIAL" in cfg.active_groups:
        features.update(extract_financial_features(norm_res))
    if "CTA" in cfg.active_groups:
        features.update(extract_cta_features(norm_res))
    if "SENDER" in cfg.active_groups:
        features.update(extract_sender_features(sender_res, norm_res))
    if "LEGIT_INTENT" in cfg.active_groups:
        features.update(extract_legit_intent_features(norm_res))
    if "NGRAM_HASH" in cfg.active_groups:
        features.update(
            extract_ngram_hash_features(
                norm_res, num_bins=cfg.ngram_hash_bins, seed=cfg.hash_seed
            )
        )
    # Apply Interactions
    features.update(extract_interaction_features(features))

    return features


def get_feature_names(config: Optional[FeatureConfig] = None) -> List[str]:
    """
    Returns the deterministic, ordered list of feature names for a given FeatureConfig.
    """
    dummy_feat = extract_message_features(
        raw_text="Sample text for feature order initialization",
        sender_header="VK-SAMPLE",
        config=config,
    )
    return sorted(list(dummy_feat.keys()))


def extract_feature_vector(
    raw_text: str,
    sender_header: Optional[str] = None,
    config: Optional[FeatureConfig] = None,
) -> List[float]:
    """
    Extracts ordered numerical feature vector matching get_feature_names().
    """
    feat_dict = extract_message_features(raw_text, sender_header, config)
    names = get_feature_names(config)
    return [feat_dict[k] for k in names]
