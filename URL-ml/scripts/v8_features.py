"""V8 Deterministic, Context-Aware, and Relational Feature Representation.

Feature Space Architecture:
- Group A: 50 Absolute URL Features (Lexical, syntactic, structural, security indicators)
- Group B: 14 Parent / Site Features (Train-derived prior, frequency, domain category, morphology baseline)
- Group C: 16 Relational & Site-Relative Morphology Features (Deviations, site-specific anomalies, threat-parent interactions)

Total Feature Dimensions: 80 features.
"""
from __future__ import annotations
import math
import re
from collections import Counter
from urllib.parse import unquote
import numpy as np

from v8_normalization import parse_v8_url, ParsedV8URL, is_ip_host, is_ipv4_host
from v8_parent_profiler import V8ParentProfiler

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
    "google", "apple", "microsoft", "amazon", "meta", "facebook", "instagram", "whatsapp",
    "twitter", "x", "linkedin", "tiktok", "snapchat", "telegram", "discord", "reddit",
    "spotify", "netflix", "youtube", "twitch", "vimeo", "hulu", "disney", "pinterest", "tumblr",
    "github", "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes", "npm", "pypi", "npmjs",
    "adobe", "dropbox", "box", "slack", "zoom", "salesforce", "oracle", "ibm", "cisco", "atlassian", "trello",
    "nvidia", "intel", "amd", "qualcomm", "samsung", "sony", "cloudflare", "fastly", "akamai",
    "aws", "azure", "digitalocean", "linode", "heroku", "vercel", "netlify", "notion", "figma",
    "mozilla", "blogger", "epicgames", "wordpress", "arstechnica", "canva", "medium", "substack",
    "paypal", "stripe", "square", "shopify", "chase", "wellsfargo", "bankofamerica", "citibank",
    "capitalone", "barclays", "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard",
    "americanexpress", "discover", "mastercard", "visa", "binance", "coinbase", "kraken",
    "metamask", "gemini", "crypto", "blockchain",
    "ebay", "etsy", "walmart", "target", "costco", "bestbuy", "homedepot", "ikea", "nike",
    "adidas", "starbucks", "mcdonalds", "subway", "uber", "lyft", "airbnb", "booking",
    "expedia", "tripadvisor", "marriott", "hilton", "delta", "united", "americanairlines",
    "fedex", "ups", "usps", "dhl", "doordash", "grubhub", "instacart", "steam", "steamcommunity",
    "bbc", "cnn", "nytimes", "wsj", "washingtonpost", "forbes", "bloomberg", "reuters",
    "theguardian", "huffpost", "techcrunch", "theverge", "wired", "npr", "pbs",
    "att", "verizon", "tmobile", "vodafone", "orange",
    "wikipedia", "wikimedia", "archive", "coursera", "edx", "udemy", "khanacademy",
    "quora", "mit", "stanford", "harvard", "berkeley", "oxford", "cambridge",
    "cdc", "who", "nih", "nasa", "un", "europa", "gov", "irs", "usa", "uk",
    "crazygames", "codenames", "chessigma"
}

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".zip", ".apk", ".vbs", ".bat", ".cmd",
    ".pif", ".hta", ".iso", ".php", ".jsp", ".cgi", ".sh", ".bin"
)

LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return float(-sum((v / n) * math.log2(v / n) for v in c.values()))


def _brand_impersonation_score(host: str, parent_domain: str) -> float:
    if not host or is_ip_host(host):
        return 0.0
    reg_clean = re.sub(r"[^a-z0-9]", "", parent_domain.split(".")[0]).translate(LEET_TRANSLATION)
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

    return float(best if best >= 0.80 else 0.0)


SCHEME_PREFIX_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
TRAILING_DELIMS = ".,;:!?)]}\"'>" + "<"


def canonicalize_url(url: str) -> str:
    """Canonicalize URL to consistent scheme and formatting contract."""
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


def extract_v8_features(
    url: str,
    profiler: V8ParentProfiler,
    parsed: ParsedV8URL | None = None
) -> dict[str, float]:
    """Extract complete 80-dimensional V8 feature vector for a URL."""
    c_url = canonicalize_url(url) if parsed is None else url
    p = parsed if parsed is not None else parse_v8_url(c_url)
    raw = p.raw
    raw_len = max(1, len(raw))
    host = p.host
    host_len = max(1, len(host))
    parent = p.parent_domain
    clean_path = p.clean_path
    path_len = len(clean_path)
    path_depth = len(p.path_segments)
    query = p.query
    query_len = len(query)

    # ==========================================
    # GROUP A: ABSOLUTE URL FEATURES (50 features)
    # ==========================================
    is_ip = float(p.is_ip)
    is_ipv4 = float(is_ipv4_host(host))
    tld = host.rsplit(".", 1)[-1] if "." in host and not p.is_ip else ""
    susp_tld = float(tld in SUSPICIOUS_TLDS)
    brand_imp = _brand_impersonation_score(host, parent)
    subdomain_depth = float(p.subdomain_depth)
    
    is_https = float(p.scheme == "https")
    has_port = float(bool(p.port and p.port not in (80, 443)))
    has_at_symbol = float("@" in raw)
    has_non_ascii = float(any(ord(c) > 127 for c in raw))
    raw_lower = raw.lower()
    has_nested_url = float(("http://" in raw_lower[8:]) or ("https://" in raw_lower[8:]) or ("http%3a" in raw_lower) or ("https%3a" in raw_lower))
    url_upper_ratio = float(sum(c.isupper() for c in raw) / raw_len)
    
    path_traversal = float(p.path.count("..") + p.path.count("/."))
    content_portion = host + ("/" + clean_path if clean_path else "") + ("?" + query if query else "")
    special_char_ratio = float(sum(not c.isalnum() for c in content_portion) / max(1, len(content_portion)))
    url_char_entropy = _entropy(raw)
    
    host_hyphens = float(host.count("-"))
    host_underscores = float(host.count("_"))
    host_digits = float(sum(c.isdigit() for c in host))
    host_digit_ratio = host_digits / host_len
    host_entropy = _entropy(host)
    host_punycode = float("xn--" in host)
    host_hex_pattern = float(bool(re.search(r"[0-9a-fA-F]{8,}", host)))
    host_vowels = [c for c in parent if c.isalpha()]
    host_vowel_ratio = float(sum(c in "aeiou" for c in host_vowels) / max(1, len(host_vowels)))
    host_numeric_labels = float(sum(x.isdigit() for x in host.split(".") if x))

    path_consecutive_slashes = float(p.path.count("//"))
    decoded_path = unquote(p.path)
    path_entropy = _entropy(decoded_path) if clean_path else 0.0
    path_susp_ext = float(any(p.path.lower().endswith(x) for x in SUSPICIOUS_EXTENSIONS))
    path_encoded_count = float(len(re.findall(r"%[0-9a-fA-F]{2}", p.path)))
    path_double_encoded = float("%25" in p.path.lower())
    path_at_symbol = float("@" in p.path)
    path_digits = float(sum(c.isdigit() for c in clean_path))
    path_digit_ratio = path_digits / max(1, path_len)
    path_hex_hash = float(bool(re.search(r"[0-9a-fA-F]{16,}", clean_path)))

    path_lower = clean_path.lower()
    path_compact = re.sub(r"[^a-z0-9]", "", path_lower).translate(LEET_TRANSLATION)
    path_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in path_lower or w in path_compact))

    query_param_count = float(len(p.query_params))
    query_encoded_count = float(len(re.findall(r"%[0-9a-fA-F]{2}", query)))
    query_lower = query.lower()
    query_compact = re.sub(r"[^a-z0-9]", "", query_lower).translate(LEET_TRANSLATION)
    query_redirect = float(bool(re.search(r"(?:url|next|redirect|target|dest|return|r|link|uri)=(?:https?%3A%2F%2F|https?://)", query_lower)))
    query_at_symbol = float("@" in query)
    query_max_val_len = float(max((len(x.split("=", 1)[1]) if "=" in x else 0 for x in p.query_params), default=0))
    query_long_val = float(query_max_val_len >= 64)
    query_entropy = _entropy(query)
    query_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in query_lower or w in query_compact))
    query_hex_hash = float(bool(re.search(r"[0-9a-fA-F]{16,}", query)))

    is_susp_host = (susp_tld > 0) or (brand_imp > 0) or (is_ip > 0) or (subdomain_depth >= 2) or (host_punycode > 0)

    risk_susp_word_susp_tld = (path_susp_words + query_susp_words) * susp_tld
    risk_susp_word_brand_imp = (path_susp_words + query_susp_words) * brand_imp
    risk_susp_word_ip = (path_susp_words + query_susp_words) * is_ip
    risk_susp_word_subdomain = (path_susp_words + query_susp_words) * float(subdomain_depth >= 2)
    risk_brand_imp_susp_tld = brand_imp * susp_tld
    risk_brand_imp_subdomain = brand_imp * float(subdomain_depth >= 1)
    risk_ip_with_path = is_ip * float(path_len > 0)
    risk_http_brand_imp = (1.0 - is_https) * brand_imp
    risk_http_susp_tld = (1.0 - is_https) * susp_tld
    risk_http_susp_words = (1.0 - is_https) * (path_susp_words + query_susp_words)
    risk_redirect_susp_host = query_redirect * float(is_susp_host)
    risk_susp_ext_susp_host = path_susp_ext * float(is_susp_host)

    # ==========================================
    # GROUP B: PARENT / SITE FEATURES (14 features)
    # ==========================================
    p_feat = profiler.get_parent_features(parent)
    p_mal_prior = p_feat["Parent_MaliciousPrior"]
    p_p50_len = p_feat["Parent_P50Length"]
    p_p90_len = p_feat["Parent_P90Length"]
    p_p50_depth = p_feat["Parent_P50PathDepth"]
    p_p90_depth = p_feat["Parent_P90PathDepth"]
    p_p50_ql = p_feat["Parent_P50QueryLength"]
    p_hex_prev = p_feat["Parent_HexPrevalence"]
    is_financial = p_feat["Parent_IsFinancial"]
    is_dev = p_feat["Parent_IsDeveloper"]
    is_media = p_feat["Parent_IsMedia"]
    is_gaming = p_feat["Parent_IsGaming"]

    # ==========================================
    # GROUP C: RELATIONAL & MORPHOLOGY FEATURES (16 features)
    # ==========================================
    # 1. Relative length deviations from parent baseline
    rel_len_dev_p50 = (float(raw_len) - p_p50_len) / max(15.0, p_p50_len)
    rel_len_excess_p90 = max(0.0, float(raw_len) - p_p90_len) / max(15.0, p_p90_len)

    # 2. Relative path depth deviations from parent baseline
    rel_depth_dev_p50 = float(path_depth) - p_p50_depth
    rel_depth_excess_p90 = max(0.0, float(path_depth) - p_p90_depth)

    # 3. Relative query length deviation
    rel_query_dev_p50 = max(0.0, float(query_len) - p_p50_ql) / max(10.0, p_p50_ql + 1.0)

    # 4. Hex hash contextualization: on sites with high hex prevalence (e.g. GitHub commit SHAs), hex hash is normal
    rel_hex_anomaly = path_hex_hash * max(0.0, 1.0 - p_hex_prev * 3.0)

    # 5. Site-relative expected morphology
    # Developer repo patterns (e.g. user/repo, /commit/, /tree/, /blob/, /issues/)
    is_expected_dev = is_dev * float(
        path_depth >= 2 and any(k in path_lower for k in ("commit", "blob", "tree", "issues", "pull", "releases", "raw", "actions"))
    )
    # Media watch patterns (e.g. watch?v=, /channel/, /embed/)
    is_expected_media = is_media * float(
        ("watch" in path_lower and "v=" in query_lower) or any(k in path_lower for k in ("embed", "shorts", "channel", "playlist")) or (len(clean_path) <= 12 and path_depth == 1)
    )
    # Gaming room / game patterns (e.g. /game/, /room/, /play/)
    is_expected_gaming = is_gaming * float(
        any(k in path_lower for k in ("game", "room", "play", "app", "analysis", "table")) or path_depth <= 2
    )
    rel_morphology_expected = float(is_expected_dev > 0 or is_expected_media > 0 or is_expected_gaming > 0)

    # 6. Unambiguous strong malicious evidence in child
    has_strong_malicious_child = float(
        (path_susp_ext > 0) or
        (query_redirect > 0) or
        (path_double_encoded > 0) or
        (path_traversal > 0) or
        (has_nested_url > 0) or
        ((path_susp_words + query_susp_words >= 2) and (is_dev == 0))
    )

    # 7. CRITICAL SECURITY INVARIANT: Strong malicious child defeats parent trust
    threat_override_parent_trust = has_strong_malicious_child * max(0.0, 1.0 - p_mal_prior)

    # 8. SPECIAL FINANCIAL EXCEPTION: Sensitive action on financial domain retains full scrutiny
    is_sensitive_fin_action = is_financial * float(
        (path_susp_words + query_susp_words > 0) or
        any(k in path_lower for k in ("login", "signin", "verify", "otp", "auth", "account", "update", "kyc", "card"))
    )
    threat_financial_action_override = is_sensitive_fin_action * max(0.0, 1.0 - p_mal_prior)

    # 9. Child path complexity contextualized against parent
    # Long paths/tokens on dev/gaming sites are NOT penalized as generic threats
    rel_path_digit_anomaly = path_digit_ratio * float(is_dev == 0 and is_gaming == 0)
    rel_path_depth_anomaly = max(0.0, float(path_depth) - 3.0) * float(is_dev == 0)

    # Assemble complete dictionary
    feat_dict = {
        # Group A
        "URLLength": float(raw_len),
        "DomainLength": float(host_len),
        "IsDomainIP": is_ip,
        "IsIPv4": is_ipv4,
        "NoOfSubDomain": subdomain_depth,
        "IsHTTPS": is_https,
        "HasPort": has_port,
        "HasAtSymbol": has_at_symbol,
        "HasNonAscii": has_non_ascii,
        "HasNestedURL": has_nested_url,
        "URLUppercaseRatio": url_upper_ratio,
        "PathTraversalCount": path_traversal,
        "SpecialCharRatio": special_char_ratio,
        "URLCharEntropy": url_char_entropy,
        "SuspiciousTLD": susp_tld,
        "BrandImpersonationScore": brand_imp,
        "HostHyphenCount": host_hyphens,
        "HostUnderscoreCount": host_underscores,
        "HostDigitRatio": host_digit_ratio,
        "HostEntropy": host_entropy,
        "HostPunycode": host_punycode,
        "HostHexPattern": host_hex_pattern,
        "HostVowelRatio": host_vowel_ratio,
        "HostNumericLabels": host_numeric_labels,
        "PathLength": float(path_len),
        "PathDepth": float(path_depth),
        "PathConsecutiveSlashes": path_consecutive_slashes,
        "PathEntropy": path_entropy,
        "PathSuspiciousExtension": path_susp_ext,
        "PathSuspiciousWords": path_susp_words,
        "PathEncodedCount": path_encoded_count,
        "PathDoubleEncoded": path_double_encoded,
        "PathAtSymbol": path_at_symbol,
        "PathDigitRatio": path_digits / max(1, path_len),
        "PathHexHash": path_hex_hash,
        "QueryLength": float(query_len),
        "QueryParamCount": query_param_count,
        "QueryEncodedCount": query_encoded_count,
        "QueryRedirect": query_redirect,
        "QueryAtSymbol": query_at_symbol,
        "QueryLongValue": query_long_val,
        "QueryEntropy": query_entropy,
        "QuerySuspiciousWords": query_susp_words,
        "QueryHexHash": query_hex_hash,
        "Risk_SuspiciousWord_on_SuspiciousTLD": risk_susp_word_susp_tld,
        "Risk_SuspiciousWord_on_BrandImpersonation": risk_susp_word_brand_imp,
        "Risk_SuspiciousWord_on_IP": risk_susp_word_ip,
        "Risk_SuspiciousWord_on_Subdomain": risk_susp_word_subdomain,
        "Risk_BrandImpersonation_on_SuspiciousTLD": risk_brand_imp_susp_tld,
        "Risk_BrandImpersonation_on_Subdomain": risk_brand_imp_subdomain,
        "Risk_IP_with_Path": risk_ip_with_path,
        "Risk_HTTP_with_BrandImpersonation": risk_http_brand_imp,
        "Risk_HTTP_with_SuspiciousTLD": risk_http_susp_tld,
        "Risk_HTTP_with_SuspiciousWords": risk_http_susp_words,
        "Risk_Redirect_on_SuspiciousHost": risk_redirect_susp_host,
        "Risk_SuspiciousExt_on_SuspiciousHost": risk_susp_ext_susp_host,

        # Group B
        **p_feat,

        # Group C
        "Rel_Length_Dev_P50": rel_len_dev_p50,
        "Rel_Length_Excess_P90": rel_len_excess_p90,
        "Rel_PathDepth_Dev_P50": rel_depth_dev_p50,
        "Rel_PathDepth_Excess_P90": rel_depth_excess_p90,
        "Rel_QueryLength_Dev": rel_query_dev_p50,
        "Rel_HexHash_Anomaly": rel_hex_anomaly,
        "Rel_Morphology_Expected": rel_morphology_expected,
        "Rel_PathDigit_Anomaly": rel_path_digit_anomaly,
        "Rel_PathDepth_Anomaly": rel_path_depth_anomaly,
        "Threat_HasStrongMaliciousChild": has_strong_malicious_child,
        "Threat_ParentTrust_Bypass_Attempt": threat_override_parent_trust,
        "Threat_Financial_SensitiveAction": is_sensitive_fin_action,
        "Threat_Financial_NullifyTrust": threat_financial_action_override,
    }

    return feat_dict


# Generate sorted feature names
_dummy_profiler = V8ParentProfiler()
_dummy_profiler.global_prior_malicious = 0.12
V8_FEATURE_NAMES = sorted(extract_v8_features("https://example.com", _dummy_profiler).keys())


def vectorize_v8(
    urls: list[str],
    profiler: V8ParentProfiler
) -> tuple[np.ndarray, list[str]]:
    """Vectorize a list of URLs into a float32 matrix using V8 representation."""
    names = V8_FEATURE_NAMES
    n = len(urls)
    matrix = np.empty((n, len(names)), dtype=np.float32)
    for i, u in enumerate(urls):
        feat = extract_v8_features(u, profiler)
        matrix[i] = [feat[k] for k in names]
    return matrix, names
