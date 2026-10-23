"""
Conservative text normalization and script analysis module for Message ML.

Preserves security-critical signals (e.g., zero-width characters, mixed scripts,
homoglyphs, casing metrics) while providing clean normalized text for feature extraction.
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Set, Tuple
import unicodedata

# Common zero-width and invisible control characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u00ad",  # Soft hyphen
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u202a",  # Left-to-right embedding
    "\u202b",  # Right-to-left embedding
    "\u202c",  # Pop directional formatting
    "\u202d",  # Left-to-right override
    "\u202e",  # Right-to-left override
}

# Common Cyrillic & Greek homoglyphs used in Latin-script phishing
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic small letter a
    "\u0410": "A",  # Cyrillic capital letter A
    "\u0435": "e",  # Cyrillic small letter ie
    "\u0415": "E",  # Cyrillic capital letter Ie
    "\u043e": "o",  # Cyrillic small letter o
    "\u041e": "O",  # Cyrillic capital letter O
    "\u0440": "p",  # Cyrillic small letter er
    "\u0420": "P",  # Cyrillic capital letter Er
    "\u0441": "c",  # Cyrillic small letter es
    "\u0421": "C",  # Cyrillic capital letter Es
    "\u0443": "y",  # Cyrillic small letter u
    "\u0445": "x",  # Cyrillic small letter ha
    "\u0425": "X",  # Cyrillic capital letter Ha
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0406": "I",  # Cyrillic capital letter Byelorussian-Ukrainian I
    "\u0458": "j",  # Cyrillic small letter je
    "\u0408": "J",  # Cyrillic capital letter Je
    # Greek lookalikes
    "\u03b1": "a",  # Greek small letter alpha
    "\u03bf": "o",  # Greek small letter omicron
    "\u039f": "O",  # Greek capital letter Omicron
    "\u03bd": "v",  # Greek small letter nu
}


@dataclass
class TextNormalizationResult:
    raw_text: str
    cleaned_text: str
    normalized_lowercase: str
    total_chars: int
    zero_width_count: int
    homoglyph_count: int
    latin_char_count: int
    devanagari_char_count: int
    digit_count: int
    uppercase_count: int
    lowercase_count: int
    punctuation_count: int
    whitespace_count: int
    newline_count: int
    other_unicode_count: int
    detected_script: str
    is_mixed_script: bool
    has_homoglyphs: bool


def analyze_and_normalize(raw_text: str) -> TextNormalizationResult:
    """
    Analyzes raw message text and produces a conservative normalized output
    along with detailed structural, script, and security anomaly metrics.
    """
    if raw_text is None:
        raw_text = ""

    total_chars = len(raw_text)
    if total_chars == 0:
        return TextNormalizationResult(
            raw_text="",
            cleaned_text="",
            normalized_lowercase="",
            total_chars=0,
            zero_width_count=0,
            homoglyph_count=0,
            latin_char_count=0,
            devanagari_char_count=0,
            digit_count=0,
            uppercase_count=0,
            lowercase_count=0,
            punctuation_count=0,
            whitespace_count=0,
            newline_count=0,
            other_unicode_count=0,
            detected_script="UNKNOWN",
            is_mixed_script=False,
            has_homoglyphs=False,
        )

    # 1. Structural and script counts on verbatim raw string
    zero_width_count = 0
    homoglyph_count = 0
    latin_count = 0
    devanagari_count = 0
    digit_count = 0
    upper_count = 0
    lower_count = 0
    punct_count = 0
    whitespace_count = 0
    newline_count = 0
    other_unicode_count = 0

    for ch in raw_text:
        if ch in ZERO_WIDTH_CHARS:
            zero_width_count += 1
            continue

        if ch in HOMOGLYPH_MAP:
            homoglyph_count += 1

        if ch == "\n" or ch == "\r":
            newline_count += 1

        if ch.isspace():
            whitespace_count += 1
            continue

        if ch.isdigit():
            digit_count += 1
            continue

        cat = unicodedata.category(ch)
        if cat.startswith("P") or cat.startswith("S"):
            punct_count += 1
            continue

        if ch.isupper():
            upper_count += 1
        elif ch.islower():
            lower_count += 1

        # Letter / Word Character Unicode block analysis
        cp = ord(ch)
        # Latin: Basic Latin (A-Z, a-z), Latin-1 Supplement, Latin Extended-A/B
        if (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A) or (0x00C0 <= cp <= 0x024F):
            latin_count += 1
        # Devanagari: 0x0900 - 0x097F
        elif 0x0900 <= cp <= 0x097F:
            devanagari_count += 1
        else:
            other_unicode_count += 1

    # 2. Determine Primary Script
    total_letters = latin_count + devanagari_count + other_unicode_count
    if total_letters == 0:
        detected_script = "LATIN" if digit_count > 0 else "UNKNOWN"
        is_mixed_script = False
    else:
        latin_ratio = latin_count / total_letters
        deva_ratio = devanagari_count / total_letters

        if latin_count > 0 and devanagari_count > 0:
            detected_script = "MIXED"
            is_mixed_script = True
        elif latin_ratio >= 0.85:
            detected_script = "LATIN"
            is_mixed_script = (other_unicode_count > 1)
        elif deva_ratio >= 0.85:
            detected_script = "DEVANAGARI"
            is_mixed_script = (other_unicode_count > 1)
        else:
            detected_script = "OTHER"
            is_mixed_script = (latin_count > 0 or devanagari_count > 0)

    # 3. Clean Text Construction (Conservative Normalization)
    stripped_text = "".join(ch for ch in raw_text if ch not in ZERO_WIDTH_CHARS)
    normalized_nfkd = unicodedata.normalize("NFKD", stripped_text)
    homoglyph_replaced = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in normalized_nfkd)

    cleaned_lines = []
    for line in homoglyph_replaced.splitlines():
        collapsed = re.sub(r"[ \t]+", " ", line).strip()
        if collapsed:
            cleaned_lines.append(collapsed)
    cleaned_text = "\n".join(cleaned_lines)
    normalized_lowercase = cleaned_text.lower()

    return TextNormalizationResult(
        raw_text=raw_text,
        cleaned_text=cleaned_text,
        normalized_lowercase=normalized_lowercase,
        total_chars=total_chars,
        zero_width_count=zero_width_count,
        homoglyph_count=homoglyph_count,
        latin_char_count=latin_count,
        devanagari_char_count=devanagari_count,
        digit_count=digit_count,
        uppercase_count=upper_count,
        lowercase_count=lower_count,
        punctuation_count=punct_count,
        whitespace_count=whitespace_count,
        newline_count=newline_count,
        other_unicode_count=other_unicode_count,
        detected_script=detected_script,
        is_mixed_script=is_mixed_script,
        has_homoglyphs=(homoglyph_count > 0),
    )


def mask_sensitive_patterns(text: str) -> str:
    """
    Replaces sensitive personal details (OTPs, phone numbers, card/account numbers,
    dates, UPI VPAs, URLs, numbers) with generic parameter tokens for template grouping.
    """
    if not text:
        return ""

    out = text

    # Mask URLs
    out = re.sub(r"https?://\S+|www\.\S+", "<URL>", out, flags=re.IGNORECASE)

    # Mask Indian Phone Numbers (10 digits starting with 6-9, with optional +91/0 prefix)
    out = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", out)

    # Mask UPI VPAs (e.g., name@okhdfcbank, user@paytm)
    out = re.sub(r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}", "<UPI_VPA>", out)

    # Mask Bank Account / Card numbers (e.g., XX1234, **5678, ending 9012, or 12-16 digits)
    out = re.sub(r"(?:[xX*]{2,}\d{3,4}|\b\d{12,16}\b)", "<ACCOUNT>", out)

    # Mask Currency Amounts (e.g., Rs. 500, INR 1,200.50, ₹4500)
    out = re.sub(r"(?:₹|Rs\.?|INR)\s*[\d,]+(?:\.\d+)?", "<AMOUNT>", out, flags=re.IGNORECASE)

    # Mask Dates (e.g. 24-AUG-26, 24/08/2026, 24-08-26)
    out = re.sub(r"\b\d{1,2}[-/](?:[A-Za-z]{3}|\d{1,2})[-/]\d{2,4}\b", "<DATE>", out, flags=re.IGNORECASE)

    # Mask Times (e.g. 9:30 PM, 10:00 AM, 18:45)
    out = re.sub(r"\b\d{1,2}:\d{2}(?:\s*(?:am|pm))?\b", "<TIME>", out, flags=re.IGNORECASE)

    # Mask isolated 4-8 digit numeric codes (OTPs / PINs)
    out = re.sub(r"\b\d{4,8}\b", "<NUM_CODE>", out)

    # Mask any remaining numbers
    out = re.sub(r"\b\d+\b", "<NUM>", out)

    return out
