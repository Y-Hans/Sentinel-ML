"""Lightweight, deterministic URL feature extraction shared by training and clients."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit


BASE_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "NoOfSubDomain", "IsHTTPS",
    "HasSuspiciousWords", "SpecialCharRatio", "DigitRatio", "HasAtSymbol",
]
CORE_FEATURES = BASE_FEATURES + [
    "SuspiciousTLD", "BrandImpersonationScore", "HyphenCount",
]
FULL_FEATURES = CORE_FEATURES + [
    "PathQueryLength", "KnownBrandDomain", "DomainVowelRatio",
]
FEATURE_SETS = {"base": BASE_FEATURES, "core": CORE_FEATURES, "full": FULL_FEATURES}

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "verification", "secure", "account",
    "password", "credential", "wallet", "update", "unlock",
)
SUSPICIOUS_TLDS = {
    "biz", "buzz", "cf", "click", "country", "download", "ga", "gq",
    "info", "loan", "ml", "online", "rest", "review", "ru", "stream",
    "support", "tk", "top", "work", "xyz",
}
COMMON_BRANDS = (
    "adobe", "amazon", "apple", "bankofamerica", "bbc", "chase", "cnn",
    "coinbase", "discord", "docker", "dropbox", "ebay", "facebook", "fedex",
    "forbes", "github", "google", "instagram", "linkedin", "microsoft",
    "mozilla", "netflix", "office", "openai", "outlook", "paypal", "reddit",
    "spotify", "stackoverflow", "telegram", "tiktok", "twitter", "ups",
    "walmart", "whatsapp", "wikipedia", "yahoo", "youtube",
)
TWO_LABEL_SUFFIXES = {
    "ac.in", "ac.jp", "ac.uk", "co.in", "co.jp", "co.nz", "co.uk",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "gov.in", "gov.uk",
    "net.au", "net.in", "org.au", "org.in", "org.uk",
}
LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})


def _parse(url: str):
    raw = str(url).strip()
    parsed = urlsplit(raw if "://" in raw else "//" + raw, scheme="http")
    return raw, parsed, (parsed.hostname or "").lower().rstrip(".")


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _suffix_size(labels: list[str]) -> int:
    return 2 if len(labels) >= 2 and ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 1


def _registrable_label(host: str) -> str:
    labels = [part for part in host.split(".") if part]
    if not labels or _is_ip(host):
        return host
    suffix_size = _suffix_size(labels)
    return labels[-(suffix_size + 1)] if len(labels) > suffix_size else labels[0]


def _subdomain_depth(host: str) -> int:
    labels = [part for part in host.split(".") if part]
    if _is_ip(host) or len(labels) <= 1:
        return 0
    return max(0, len(labels) - _suffix_size(labels) - 1)


def _has_suspicious_words(raw: str) -> int:
    lower = raw.lower()
    if any(word in lower for word in SUSPICIOUS_WORDS):
        return 1
    return int(bool(re.search(r"(?:^|[^a-z])bank(?:[^a-z]|$)", lower)))


def _brand_impersonation_score(host: str) -> float:
    if not host or _is_ip(host):
        return 0.0
    registered = re.sub(r"[^a-z0-9]", "", _registrable_label(host)).translate(LEET_TRANSLATION)
    if registered in COMMON_BRANDS:
        return 0.0

    candidates: list[str] = []
    for label in host.split("."):
        compact = re.sub(r"[^a-z0-9]", "", label).translate(LEET_TRANSLATION)
        if compact:
            candidates.append(compact)
        candidates.extend(
            token.translate(LEET_TRANSLATION)
            for token in re.split(r"[^a-z0-9]+", label)
            if len(token) >= 4
        )

    brand_set = set(COMMON_BRANDS)
    if any(candidate in brand_set for candidate in candidates):
        return 1.0

    best = 0.0
    for candidate in candidates:
        for brand in COMMON_BRANDS:
            if brand in candidate or candidate in brand:
                if min(len(candidate), len(brand)) >= 4:
                    best = max(best, min(len(candidate), len(brand)) / max(len(candidate), len(brand)))
            # Catch a single insertion, deletion, or substitution without the
            # cost/complexity of a general edit-distance library.
            if abs(len(candidate) - len(brand)) <= 1 and _one_edit_apart(candidate, brand):
                best = max(best, 0.85)
    return float(best if best >= 0.72 else 0.0)


def _one_edit_apart(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    i = j = differences = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
        else:
            differences += 1
            j += 1
            if differences > 1:
                return False
    return True


def _entropy(raw: str) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw.lower())
    length = len(raw)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _known_brand_domain(host: str) -> float:
    registered = re.sub(r"[^a-z0-9]", "", _registrable_label(host)).translate(LEET_TRANSLATION)
    return float(registered in COMMON_BRANDS)


def _domain_vowel_ratio(host: str) -> float:
    letters = [char for char in _registrable_label(host).lower() if char.isalpha()]
    return sum(char in "aeiou" for char in letters) / len(letters) if letters else 0.0


def extract_url_features(url: str, feature_names=FULL_FEATURES) -> dict[str, float]:
    """Return a fixed-order-compatible numeric feature mapping for one URL."""
    raw, parsed, host = _parse(url)
    length = max(1, len(raw))
    all_features = {
        "URLLength": float(len(raw)),
        "DomainLength": float(len(host)),
        "IsDomainIP": float(_is_ip(host)),
        "NoOfSubDomain": float(_subdomain_depth(host)),
        "IsHTTPS": float(parsed.scheme.lower() == "https"),
        "HasSuspiciousWords": float(_has_suspicious_words(raw)),
        "SpecialCharRatio": sum(not char.isalnum() for char in raw) / length,
        "DigitRatio": sum(char.isdigit() for char in raw) / length,
        "HasAtSymbol": float("@" in raw),
    }
    requested = set(feature_names)
    if "SuspiciousTLD" in requested:
        all_features["SuspiciousTLD"] = float(host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS if "." in host else 0)
    if "BrandImpersonationScore" in requested:
        all_features["BrandImpersonationScore"] = _brand_impersonation_score(host)
    if "HyphenCount" in requested:
        all_features["HyphenCount"] = float(host.count("-"))
    if "URLCharEntropy" in requested:
        all_features["URLCharEntropy"] = _entropy(raw)
    if "PathQueryLength" in requested:
        all_features["PathQueryLength"] = float(len(parsed.path) + len(parsed.query) + len(parsed.fragment))
    if "KnownBrandDomain" in requested:
        all_features["KnownBrandDomain"] = _known_brand_domain(host)
    if "DomainVowelRatio" in requested:
        all_features["DomainVowelRatio"] = _domain_vowel_ratio(host)
    return {name: all_features[name] for name in feature_names}


def domain_group(url: str) -> str:
    """Use the registrable host as a leakage-resistant split group."""
    _, _, host = _parse(url)
    if _is_ip(host):
        return host
    labels = [part for part in host.split(".") if part]
    suffix_size = _suffix_size(labels)
    return ".".join(labels[-(suffix_size + 1):]) if len(labels) > suffix_size else host
