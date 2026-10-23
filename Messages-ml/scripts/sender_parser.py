"""
Sender intelligence and header parser for Message ML.

Extracts probabilistic structural signals from sender headers (e.g. DLT headers,
phone numbers, shortcodes) without treating headers as authentication or safety proofs.
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set

# Structural DLT pattern: 2-letter operator/circle code + separator + 6-alphanumeric entity + optional category
DLT_PATTERN = re.compile(r"^([A-Za-z]{2})[-_]([A-Za-z0-9]{6})(?:[-_]([A-Za-z0-9]+))?$")

# Standard standalone 6-character alphanumeric header
STANDALONE_ALPHA_PATTERN = re.compile(r"^[A-Za-z0-9]{3,9}$")

# Indian Domestic 10-digit phone number with optional +91 or 0 prefix
INDIAN_PHONE_PATTERN = re.compile(r"^(?:\+91|0)?([6-9]\d{9})$")

# General International Phone Number with country code
INTL_PHONE_PATTERN = re.compile(r"^\+?[1-9]\d{6,14}$")

# Numeric shortcode (3 to 6 digits)
SHORTCODE_PATTERN = re.compile(r"^\d{3,6}$")

# Known Indian Entity / Brand substrings for similarity reference
KNOWN_ENTITIES: Dict[str, str] = {
    "HDFCBK": "BANK",
    "HDFC": "BANK",
    "SBIINB": "BANK",
    "SBIPAY": "BANK",
    "SBICRD": "BANK",
    "SBI": "BANK",
    "ICICIB": "BANK",
    "ICICI": "BANK",
    "AXISBK": "BANK",
    "AXIS": "BANK",
    "KOTAKB": "BANK",
    "KOTAK": "BANK",
    "PNBSMS": "BANK",
    "PNB": "BANK",
    "BOBTXN": "BANK",
    "BOB": "BANK",
    "CANBNK": "BANK",
    "CANARA": "BANK",
    "AIRTEL": "TELECOM",
    "JIOINF": "TELECOM",
    "JIO": "TELECOM",
    "VIALRT": "TELECOM",
    "VIL": "TELECOM",
    "BSNL": "TELECOM",
    "ITDPRC": "GOVT",
    "UIDAI": "GOVT",
    "EPFOHO": "GOVT",
    "GSTIND": "GOVT",
    "VAAHAN": "GOVT",
    "AMAZON": "ECOMMERCE",
    "FLPKRT": "ECOMMERCE",
    "SWIGGY": "DELIVERY",
    "ZOMATO": "DELIVERY",
}


@dataclass
class SenderParseResult:
    raw_header: Optional[str]
    sender_type: str  # "ALPHANUMERIC_HEADER", "PHONE_NUMBER", "SHORTCODE", "UNKNOWN"
    has_dlt_structural_shape: bool
    dlt_prefix: Optional[str]
    dlt_entity_code: Optional[str]
    dlt_suffix_category: Optional[str]
    is_domestic_phone: bool
    is_international_phone: bool
    is_shortcode: bool
    known_entity_match: Optional[str]
    known_entity_category: Optional[str]
    header_length: int


def parse_sender_header(header: Optional[str]) -> SenderParseResult:
    """
    Parses sender string and extracts structural properties and probabilistic entity signals.
    Does NOT assert authentication or trustworthiness.
    """
    if header is None or not str(header).strip():
        return SenderParseResult(
            raw_header=None,
            sender_type="UNKNOWN",
            has_dlt_structural_shape=False,
            dlt_prefix=None,
            dlt_entity_code=None,
            dlt_suffix_category=None,
            is_domestic_phone=False,
            is_international_phone=False,
            is_shortcode=False,
            known_entity_match=None,
            known_entity_category=None,
            header_length=0,
        )

    clean_header = str(header).strip()
    h_len = len(clean_header)

    # 1. Test DLT Header Regex
    dlt_match = DLT_PATTERN.match(clean_header)
    if dlt_match:
        prefix = dlt_match.group(1).upper()
        entity = dlt_match.group(2).upper()
        suffix = dlt_match.group(3).upper() if dlt_match.group(3) else None

        # Check entity against known entity list
        matched_entity = None
        matched_category = None
        for known, cat in KNOWN_ENTITIES.items():
            if known in entity:
                matched_entity = known
                matched_category = cat
                break

        return SenderParseResult(
            raw_header=clean_header,
            sender_type="ALPHANUMERIC_HEADER",
            has_dlt_structural_shape=True,
            dlt_prefix=prefix,
            dlt_entity_code=entity,
            dlt_suffix_category=suffix,
            is_domestic_phone=False,
            is_international_phone=False,
            is_shortcode=False,
            known_entity_match=matched_entity,
            known_entity_category=matched_category,
            header_length=h_len,
        )

    # 2. Test Shortcode (numeric 3 to 6 digits)
    if SHORTCODE_PATTERN.match(clean_header):
        return SenderParseResult(
            raw_header=clean_header,
            sender_type="SHORTCODE",
            has_dlt_structural_shape=False,
            dlt_prefix=None,
            dlt_entity_code=None,
            dlt_suffix_category=None,
            is_domestic_phone=False,
            is_international_phone=False,
            is_shortcode=True,
            known_entity_match=None,
            known_entity_category=None,
            header_length=h_len,
        )

    # 3. Test Indian Domestic Phone Number
    dom_match = INDIAN_PHONE_PATTERN.match(clean_header)
    if dom_match:
        return SenderParseResult(
            raw_header=clean_header,
            sender_type="PHONE_NUMBER",
            has_dlt_structural_shape=False,
            dlt_prefix=None,
            dlt_entity_code=None,
            dlt_suffix_category=None,
            is_domestic_phone=True,
            is_international_phone=False,
            is_shortcode=False,
            known_entity_match=None,
            known_entity_category=None,
            header_length=h_len,
        )

    # 4. Test Standalone Alphanumeric Header (without operator prefix)
    if STANDALONE_ALPHA_PATTERN.match(clean_header) and not clean_header.isdigit():
        upper_header = clean_header.upper()
        matched_entity = None
        matched_category = None
        for known, cat in KNOWN_ENTITIES.items():
            if known in upper_header:
                matched_entity = known
                matched_category = cat
                break

        return SenderParseResult(
            raw_header=clean_header,
            sender_type="ALPHANUMERIC_HEADER",
            has_dlt_structural_shape=False,
            dlt_prefix=None,
            dlt_entity_code=upper_header,
            dlt_suffix_category=None,
            is_domestic_phone=False,
            is_international_phone=False,
            is_shortcode=False,
            known_entity_match=matched_entity,
            known_entity_category=matched_category,
            header_length=h_len,
        )

    # 5. Test General International Phone
    if INTL_PHONE_PATTERN.match(clean_header):
        return SenderParseResult(
            raw_header=clean_header,
            sender_type="PHONE_NUMBER",
            has_dlt_structural_shape=False,
            dlt_prefix=None,
            dlt_entity_code=None,
            dlt_suffix_category=None,
            is_domestic_phone=False,
            is_international_phone=True,
            is_shortcode=False,
            known_entity_match=None,
            known_entity_category=None,
            header_length=h_len,
        )

    # 6. Fallback Unknown
    return SenderParseResult(
        raw_header=clean_header,
        sender_type="UNKNOWN",
        has_dlt_structural_shape=False,
        dlt_prefix=None,
        dlt_entity_code=None,
        dlt_suffix_category=None,
        is_domestic_phone=False,
        is_international_phone=False,
        is_shortcode=False,
        known_entity_match=None,
        known_entity_category=None,
        header_length=h_len,
    )
