"""Updated V7 Deterministic, domain-independent and context-aware URL feature representation (V7.5).

Refinements:
1. Adversarial resilience:
   - URLUppercaseRatio: detects case manipulation evasions.
   - HasNestedURL: detects nested protocol/URL embedding in paths or non-standard query parameters.
   - PathTraversalCount: detects ../ and /./ traversal evasions.
   - Normalized keyword matching: strips separators (l-o-g-i-n, s_i_g_n_i_n) to detect separator insertion evasions.
2. Robust multi-label public suffix and www prefix handling.
3. Expanded brand and institution registry.
"""
from __future__ import annotations
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit
import numpy as np

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "verification", "secure", "account",
    "password", "credential", "wallet", "update", "unlock", "billing",
    "checkout", "confirm", "session", "token", "recover", "authenticate",
    "banking", "oauth", "security", "support-desk", "helpdesk"
)

SUSPICIOUS_TLDS = {
    "biz", "buzz", "cf", "click", "country", "download", "ga", "gq",
    "info", "loan", "ml", "online", "rest", "review", "ru", "stream",
    "support", "tk", "top", "work", "xyz", "fit", "surf", "racing",
    "cam", "kim", "mom", "icu", "sbs", "cfd", "monster", "bar",
    "vip", "pw", "cc", "ws"
}

COMMON_BRANDS = {
    # Tech & OS & Cloud & Software
    "google", "apple", "microsoft", "amazon", "meta", "facebook", "instagram", "whatsapp",
    "twitter", "x", "linkedin", "tiktok", "snapchat", "telegram", "discord", "reddit",
    "spotify", "netflix", "youtube", "twitch", "vimeo", "hulu", "disney", "pinterest", "tumblr",
    "github", "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes", "npm", "pypi", "npmjs",
    "adobe", "dropbox", "box", "slack", "zoom", "salesforce", "oracle", "ibm", "cisco", "atlassian", "trello",
    "nvidia", "intel", "amd", "qualcomm", "samsung", "sony", "cloudflare", "fastly", "akamai",
    "aws", "azure", "digitalocean", "linode", "heroku", "vercel", "netlify", "notion", "figma",
    "mozilla", "blogger", "epicgames", "wordpress", "arstechnica", "canva", "medium", "substack",
    # Finance & Banking & Crypto
    "paypal", "stripe", "square", "shopify", "chase", "wellsfargo", "bankofamerica", "citibank",
    "capitalone", "barclays", "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard",
    "americanexpress", "discover", "mastercard", "visa", "binance", "coinbase", "kraken",
    "metamask", "gemini", "crypto", "blockchain",
    # Commerce & Travel & Delivery
    "ebay", "etsy", "walmart", "target", "costco", "bestbuy", "homedepot", "ikea", "nike",
    "adidas", "starbucks", "mcdonalds", "subway", "uber", "lyft", "airbnb", "booking",
    "expedia", "tripadvisor", "marriott", "hilton", "delta", "united", "americanairlines",
    "fedex", "ups", "usps", "dhl", "doordash", "grubhub", "instacart", "steam", "steamcommunity",
    # Media & News & Telecom
    "bbc", "cnn", "nytimes", "wsj", "washingtonpost", "forbes", "bloomberg", "reuters",
    "theguardian", "huffpost", "techcrunch", "theverge", "wired", "npr", "pbs",
    "att", "verizon", "tmobile", "vodafone", "orange",
    # Education & Knowledge & Public Institutions
    "wikipedia", "wikimedia", "archive", "coursera", "edx", "udemy", "khanacademy",
    "quora", "mit", "stanford", "harvard", "berkeley", "oxford", "cambridge",
    "cdc", "who", "nih", "nasa", "un", "europa", "gov", "irs", "usa", "uk"
}

TWO_LABEL_SUFFIXES = {
    "ac.in", "ac.jp", "ac.uk", "co.in", "co.jp", "co.nz", "co.uk",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "gov.in", "gov.uk",
    "net.au", "net.in", "org.au", "org.in", "org.uk", "edu.au", "edu.cn",
    "gob.es", "gob.mx", "gc.ca", "gouv.fr", "fed.us", "edu.in", "res.in"
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".zip", ".apk", ".vbs", ".bat", ".cmd",
    ".pif", ".hta", ".iso", ".php", ".jsp", ".cgi", ".sh", ".bin"
)

LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})

SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
TRAILING_DELIMS = ".,;:!?)]}\"'>" + "<"


def canonicalize_url(url: str) -> str:
    """Canonicalize URL matching Sentinel Android canonicalization contract.

    - Strips leading/trailing whitespace and trailing sentence/punctuation delimiters
    - Preserves explicit scheme (lowercasing scheme prefix e.g. HTTP:// -> http://)
    - Normalizes protocol-relative //example.com -> https://example.com
    - Prepends https:// to schemeless inputs (e.g. www.domain.com -> https://www.domain.com)
    - Returns empty string for empty/whitespace-only input
    """
    if not url:
        return ""
    trimmed = str(url).strip()
    while trimmed and trimmed[-1] in TRAILING_DELIMS:
        trimmed = trimmed[:-1].strip()
    if not trimmed:
        return ""
    m = SCHEME_PREFIX_RE.match(trimmed)
    if m:
        scheme = m.group(0).lower()
        return scheme + trimmed[len(m.group(0)):]
    if trimmed.startswith("//"):
        return f"https:{trimmed}"
    return f"https://{trimmed}"


def _safe_port(p):
    try:
        return p.port
    except (ValueError, TypeError):
        return None


def _parse(url: str):
    canonical = canonicalize_url(url)
    raw = canonical if canonical else str(url).strip()
    p = urlsplit(raw if "://" in raw else "//" + raw, scheme="https")
    try:
        host = (p.hostname or "").lower().rstrip(".")
    except (ValueError, TypeError):
        host = (p.netloc.split(":")[0] if p.netloc else "").lower().rstrip(".")
    path = p.path or ""
    query = p.query or ""
    return raw, p, host, path, query


def _is_ip(host: str) -> int:
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _is_ipv4(host: str) -> int:
    try:
        return int(isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address))
    except ValueError:
        return 0


def _suffix_size(labels: list[str]) -> int:
    return 2 if len(labels) >= 2 and ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES else 1


def _registrable_label(host: str) -> str:
    labels = [part for part in host.split(".") if part]
    if not labels or _is_ip(host):
        return host
    suffix_size = _suffix_size(labels)
    if len(labels) > suffix_size:
        cand = labels[-(suffix_size + 1)]
        if cand == "www" and len(labels) == suffix_size + 1:
            return labels[-suffix_size]
        return cand
    return labels[0]


def _subdomain_depth(host: str) -> int:
    labels = [part for part in host.split(".") if part]
    if _is_ip(host) or len(labels) <= 1:
        return 0
    return max(0, len(labels) - _suffix_size(labels) - 1)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return float(-sum((v / n) * math.log2(v / n) for v in c.values()))


def _one_edit_apart(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right)) == 1
    short, long = (left, right) if len(left) < len(right) else (right, left)
    i = j = diffs = 0
    while i < len(short) and j < len(long):
        if short[i] == long[j]:
            i += 1
            j += 1
        else:
            diffs += 1
            j += 1
            if diffs > 1:
                return False
    return True


def _brand_impersonation_score(host: str) -> float:
    if not host or _is_ip(host):
        return 0.0
    reg_clean = re.sub(r"[^a-z0-9]", "", _registrable_label(host)).translate(LEET_TRANSLATION)
    if reg_clean in COMMON_BRANDS:
        return 0.0

    candidates: list[str] = []
    labels = host.split(".")
    for label in labels:
        compact = re.sub(r"[^a-z0-9]", "", label).translate(LEET_TRANSLATION)
        if len(compact) >= 4:
            candidates.append(compact)
        for token in re.split(r"[^a-z0-9]+", label):
            token_clean = token.translate(LEET_TRANSLATION)
            if len(token_clean) >= 4:
                candidates.append(token_clean)

    for candidate in candidates:
        if candidate in COMMON_BRANDS and candidate != reg_clean:
            return 1.0

    best = 0.0
    for candidate in candidates:
        for brand in COMMON_BRANDS:
            if len(brand) < 5 or len(candidate) < 5:
                continue
            if brand in candidate or candidate in brand:
                score = min(len(candidate), len(brand)) / max(len(candidate), len(brand))
                if score >= 0.80:
                    best = max(best, score)
            if abs(len(candidate) - len(brand)) <= 1 and _one_edit_apart(candidate, brand):
                best = max(best, 0.85)

    return float(best if best >= 0.80 else 0.0)


def extract_v7_features(url: str) -> dict[str, float]:
    """Extract full V7.5 deterministic feature dictionary for a single URL."""
    raw, p, host, path, query = _parse(url)
    labels = [x for x in host.split(".") if x]
    seg = [x for x in path.split("/") if x]
    decoded_path = unquote(path)
    raw_len = max(1, len(raw))
    host_len = max(1, len(host))

    # Host features
    is_ip = _is_ip(host)
    is_ipv4 = _is_ipv4(host)
    tld = host.rsplit(".", 1)[-1] if "." in host and not is_ip else ""
    susp_tld = float(tld in SUSPICIOUS_TLDS)
    brand_impersonation = _brand_impersonation_score(host)
    reg_label = re.sub(r"[^a-z0-9]", "", _registrable_label(host)).translate(LEET_TRANSLATION)
    known_brand = float(reg_label in COMMON_BRANDS or _registrable_label(host) in COMMON_BRANDS)
    subdomain_depth = float(_subdomain_depth(host))
    host_hyphens = float(host.count("-"))
    host_underscores = float(host.count("_"))
    host_digits = float(sum(c.isdigit() for c in host))
    host_digit_ratio = host_digits / host_len
    host_entropy = _entropy(host)
    host_punycode = float("xn--" in host)
    host_hex_pattern = float(bool(re.search(r"[0-9a-fA-F]{8,}", host)))
    host_vowels = [c for c in reg_label if c.isalpha()]
    host_vowel_ratio = float(sum(c in "aeiou" for c in host_vowels) / max(1, len(host_vowels)))
    host_numeric_labels = float(sum(x.isdigit() for x in labels))

    # Scheme
    is_https = float(p.scheme.lower() == "https")
    port_val = _safe_port(p)
    has_port = float(bool(port_val and port_val not in (80, 443)))

    # Path features (normalized)
    clean_path_str = "/".join(seg)
    path_len = float(len(clean_path_str))
    path_depth = float(len(seg))
    path_consecutive_slashes = float(path.count("//"))
    path_traversal = float(path.count("..") + path.count("/."))
    path_entropy = _entropy(decoded_path) if clean_path_str else 0.0
    path_susp_ext = float(any(path.lower().endswith(x) for x in SUSPICIOUS_EXTENSIONS))
    path_encoded_count = float(len(re.findall(r"%[0-9a-fA-F]{2}", path)))
    path_double_encoded = float("%25" in path.lower())
    path_at_symbol = float("@" in path)
    path_digits = float(sum(c.isdigit() for c in clean_path_str))
    path_digit_ratio = path_digits / max(1, len(clean_path_str))
    path_hex_hash = float(bool(re.search(r"[0-9a-fA-F]{16,}", clean_path_str)))
    
    # Path keyword analysis (exact and normalized without separators)
    path_lower = clean_path_str.lower()
    path_compact = re.sub(r"[^a-z0-9]", "", path_lower).translate(LEET_TRANSLATION)
    path_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in path_lower or w in path_compact))
    
    # Query features
    query_len = float(len(query))
    params = query.split("&") if query else []
    query_param_count = float(len(params))
    query_encoded_count = float(len(re.findall(r"%[0-9a-fA-F]{2}", query)))
    query_at_symbol = float("@" in query)
    query_entropy = _entropy(query)
    
    # Open redirect / nested URL in query
    query_lower = query.lower()
    query_compact = re.sub(r"[^a-z0-9]", "", query_lower).translate(LEET_TRANSLATION)
    query_redirect = float(bool(re.search(r"(?:url|next|redirect|target|dest|return|r|link|uri)=(?:https?%3A%2F%2F|https?://)", query_lower)))
    query_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in query_lower or w in query_compact))
    query_hex_hash = float(bool(re.search(r"[0-9a-fA-F]{16,}", query)))
    query_max_val_len = float(max((len(x.split("=", 1)[1]) if "=" in x else 0 for x in params), default=0))
    query_long_val = float(query_max_val_len >= 64)

    # General URL features (excluding scheme)
    has_at_symbol = float("@" in raw)
    url_char_entropy = _entropy(raw)
    content_portion = host + ("/" + clean_path_str if clean_path_str else "") + ("?" + query if query else "")
    special_char_ratio = float(sum(not c.isalnum() for c in content_portion) / max(1, len(content_portion)))
    has_non_ascii = float(any(ord(c) > 127 for c in raw))
    url_upper_ratio = float(sum(c.isupper() for c in raw) / raw_len)
    
    # Nested URL check
    raw_lower = raw.lower()
    has_nested_url = float(("http://" in raw_lower[8:]) or ("https://" in raw_lower[8:]) or ("http%3a" in raw_lower) or ("https%3a" in raw_lower))

    # Threat Indicator Flag
    is_susp_host = (susp_tld > 0) or (brand_impersonation > 0) or (is_ip > 0) or (subdomain_depth >= 2) or (host_punycode > 0)

    # Contextual Threat Interaction Features (Zero on legitimate navigation paths!)
    risk_susp_word_susp_tld = (path_susp_words + query_susp_words) * susp_tld
    risk_susp_word_brand_imp = (path_susp_words + query_susp_words) * brand_impersonation
    risk_susp_word_ip = (path_susp_words + query_susp_words) * is_ip
    risk_susp_word_subdomain = (path_susp_words + query_susp_words) * float(subdomain_depth >= 2)
    risk_brand_imp_susp_tld = brand_impersonation * susp_tld
    risk_brand_imp_subdomain = brand_impersonation * float(subdomain_depth >= 1)
    risk_ip_with_path = is_ip * float(path_len > 0)
    risk_http_brand_imp = (1.0 - is_https) * brand_impersonation
    risk_http_susp_tld = (1.0 - is_https) * susp_tld
    risk_http_susp_words = (1.0 - is_https) * (path_susp_words + query_susp_words)
    risk_redirect_susp_host = query_redirect * float(is_susp_host)
    risk_susp_ext_susp_host = path_susp_ext * float(is_susp_host)

    # Contextual Path/Host digits & depth (active ONLY on suspicious host contexts)
    risk_path_digit_susp_host = path_digit_ratio * float(is_susp_host)
    risk_path_depth_susp_host = path_depth * float(is_susp_host)
    risk_path_entropy_susp_host = path_entropy * float(is_susp_host)

    # Host Anomaly Contextualization
    risk_hyphen_brand_imp = host_hyphens * brand_impersonation
    risk_hyphen_susp_tld = host_hyphens * susp_tld
    risk_hyphen_subdomain = host_hyphens * float(subdomain_depth >= 2)
    risk_digits_brand_imp = host_digit_ratio * brand_impersonation
    risk_digits_susp_tld = host_digit_ratio * susp_tld
    
    # Safe Domain Indicators
    safe_clean_domain = float(susp_tld == 0 and brand_impersonation == 0 and is_ip == 0 and subdomain_depth <= 1 and host_punycode == 0 and has_port == 0 and url_upper_ratio < 0.15 and not has_non_ascii)
    safe_brand_domain = float(known_brand == 1 and susp_tld == 0 and brand_impersonation == 0 and is_ip == 0 and subdomain_depth <= 1 and path_susp_ext == 0 and query_redirect == 0 and host_punycode == 0 and has_port == 0 and url_upper_ratio < 0.15 and not has_non_ascii and not has_nested_url)

    return {
        "URLLength": float(len(raw)),
        "DomainLength": float(len(host)),
        "IsDomainIP": float(is_ip),
        "IsIPv4": float(is_ipv4),
        "NoOfSubDomain": float(subdomain_depth),
        "IsHTTPS": float(is_https),
        "HasPort": float(has_port),
        "HasAtSymbol": float(has_at_symbol),
        "HasNonAscii": float(has_non_ascii),
        "HasNestedURL": float(has_nested_url),
        "URLUppercaseRatio": float(url_upper_ratio),
        "PathTraversalCount": float(path_traversal),
        "SpecialCharRatio": float(special_char_ratio),
        "URLCharEntropy": float(url_char_entropy),
        "SuspiciousTLD": float(susp_tld),
        "BrandImpersonationScore": float(brand_impersonation),
        "KnownBrandDomain": float(known_brand),
        "HostHyphenCount": float(host_hyphens),
        "HostUnderscoreCount": float(host_underscores),
        "HostDigitRatio": float(host_digit_ratio),
        "HostEntropy": float(host_entropy),
        "HostPunycode": float(host_punycode),
        "HostHexPattern": float(host_hex_pattern),
        "HostVowelRatio": float(host_vowel_ratio),
        "HostNumericLabels": float(host_numeric_labels),
        "PathLength": float(path_len),
        "PathDepth": float(path_depth),
        "PathConsecutiveSlashes": float(path_consecutive_slashes),
        "PathEntropy": float(path_entropy),
        "PathSuspiciousExtension": float(path_susp_ext),
        "PathSuspiciousWords": float(path_susp_words),
        "PathEncodedCount": float(path_encoded_count),
        "PathDoubleEncoded": float(path_double_encoded),
        "PathAtSymbol": float(path_at_symbol),
        "PathDigitRatio": float(path_digit_ratio),
        "PathHexHash": float(path_hex_hash),
        "QueryLength": float(query_len),
        "QueryParamCount": float(query_param_count),
        "QueryEncodedCount": float(query_encoded_count),
        "QueryRedirect": float(query_redirect),
        "QueryAtSymbol": float(query_at_symbol),
        "QueryLongValue": float(query_long_val),
        "QueryEntropy": float(query_entropy),
        "QuerySuspiciousWords": float(query_susp_words),
        "QueryHexHash": float(query_hex_hash),
        "Risk_SuspiciousWord_on_SuspiciousTLD": float(risk_susp_word_susp_tld),
        "Risk_SuspiciousWord_on_BrandImpersonation": float(risk_susp_word_brand_imp),
        "Risk_SuspiciousWord_on_IP": float(risk_susp_word_ip),
        "Risk_SuspiciousWord_on_Subdomain": float(risk_susp_word_subdomain),
        "Risk_BrandImpersonation_on_SuspiciousTLD": float(risk_brand_imp_susp_tld),
        "Risk_BrandImpersonation_on_Subdomain": float(risk_brand_imp_subdomain),
        "Risk_IP_with_Path": float(risk_ip_with_path),
        "Risk_HTTP_with_BrandImpersonation": float(risk_http_brand_imp),
        "Risk_HTTP_with_SuspiciousTLD": float(risk_http_susp_tld),
        "Risk_HTTP_with_SuspiciousWords": float(risk_http_susp_words),
        "Risk_Redirect_on_SuspiciousHost": float(risk_redirect_susp_host),
        "Risk_SuspiciousExt_on_SuspiciousHost": float(risk_susp_ext_susp_host),
        "Risk_PathDigit_on_SuspiciousHost": float(risk_path_digit_susp_host),
        "Risk_PathDepth_on_SuspiciousHost": float(risk_path_depth_susp_host),
        "Risk_PathEntropy_on_SuspiciousHost": float(risk_path_entropy_susp_host),
        "Risk_Hyphen_with_BrandImp": float(risk_hyphen_brand_imp),
        "Risk_Hyphen_with_SuspiciousTLD": float(risk_hyphen_susp_tld),
        "Risk_Hyphen_with_Subdomain": float(risk_hyphen_subdomain),
        "Risk_Digits_with_BrandImp": float(risk_digits_brand_imp),
        "Risk_Digits_with_SuspiciousTLD": float(risk_digits_susp_tld),
        "Safe_Clean_Domain": float(safe_clean_domain),
        "Safe_Brand_Domain": float(safe_brand_domain),
    }


V7_FEATURE_NAMES = sorted(extract_v7_features("https://example.com").keys())


def vectorize_v7(urls: list[str]) -> tuple[np.ndarray, list[str]]:
    """Vectorize a list of URLs into a float32 numpy matrix."""
    names = V7_FEATURE_NAMES
    matrix = np.empty((len(urls), len(names)), dtype=np.float32)
    for i, u in enumerate(urls):
        feat = extract_v7_features(u)
        matrix[i] = [feat[n] for n in names]
    return matrix, names
