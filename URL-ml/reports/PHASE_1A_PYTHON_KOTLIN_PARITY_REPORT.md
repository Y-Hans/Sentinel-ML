# SENTINEL — Phase 1A Python/Kotlin Canonicalization Parity Report
**Date:** October 21, 2026  
**Scope:** Phase 1A Completion — Schemeless URL Feature Extraction Parity Repair  
**Status:** COMPLETED & VERIFIED (Zero Git Staging, Zero Model Retraining, Zero Phase 2 Progression)

---

## 1. Executive Summary

This report establishes the forensic closure of the **Phase 1A schemeless URL feature discrepancy** identified between the Python training pipeline (`sentinel-ml/URL-ml/scripts/v7_features.py` / `v8_normalization.py`) and the Android Kotlin runtime (`com.sentinel.ai.core.ml.url.UrlFeatureExtractor`).

### The Defect
When evaluating schemeless inputs (e.g. `www.instagram.com`, `instagram.com`):
- **Android Kotlin (`UrlFeatureExtractor.kt`):** Canonicalized missing schemes by prepending `https://`, setting `IsHTTPS = 1.0f`, URLLength = 25, yielding `raw_p = 0.0019` and adjudicated verdict **BENIGN**.
- **Python Pipeline (`v7_features.py` prior to repair):** Handled missing schemes via `urlsplit(raw if "://" in raw else "//" + raw, scheme="http")`. In Python's `urlsplit`, inputs starting with `//` are treated as network-path references with an empty scheme (`p.scheme == ""`). Consequently, `p.scheme.lower() == "https"` evaluated to `0.0`. This penalized safe brands under insecure HTTP threat rules (`Risk_HTTP_with_BrandImpersonation = 1.0`), escalating `raw_p` to `0.9820` and falsely declaring `www.instagram.com` **MALICIOUS**.

### The Repair
A surgical, zero-weight, contract-aligned canonicalization implementation was deployed to `v7_features.py` and `v8_normalization.py`. The repair:
1. Implements the exact canonicalization logic matching Android `UrlFeatureExtractor.canonicalizeUrl`.
2. Preserves explicit `http://` as HTTP (`IsHTTPS = 0.0`) and preserves explicit `https://` (`IsHTTPS = 1.0`).
3. Normalizes schemeless and protocol-relative inputs to `https://` (`IsHTTPS = 1.0`).
4. Strips trailing delimiters (`.,;:!?)]}"'<>`).
5. Strictly maintains the frozen 67-feature vector dimension, feature naming, and alphabetical ordering.
6. Preserves the frozen production Champion V8 model weights and artifacts without modification.

---

## 2. Cryptographic Integrity & Ledger

Before and after the repair, SHA-256 hashes were computed to confirm zero tampering with frozen model artifacts and production Android code.

| Artifact / File | Pre-Repair SHA-256 | Post-Repair SHA-256 | Status |
| :--- | :--- | :--- | :--- |
| `v8_champion.joblib` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | **FROZEN UNTOUCHED** |
| `v8_champion_portable.json` | `e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870` | `e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870` | **FROZEN UNTOUCHED** |
| `UrlFeatureExtractor.kt` | `4c20aa3d10ec8ddc7510f0bb2e73ff4e43eb3c031781640d933e77782d006873` | `4c20aa3d10ec8ddc7510f0bb2e73ff4e43eb3c031781640d933e77782d006873` | **REFERENCE CONTRACT UNTOUCHED** |
| `v8_features.py` | `8c23202cf08888c5ba3ba5e4a1c03280a5b21d84a16a396c2241e66407956cb0` | `8c23202cf08888c5ba3ba5e4a1c03280a5b21d84a16a396c2241e66407956cb0` | **UNTOUCHED (Already Compliant)** |
| `v7_features.py` | `86cd3ba552efd1f3773d78f3e2d46b28752dc6a4166e58e6c5148c89f9952b3b` | `28bb05005281c2183c1996bcd91faac0d21a326295d783c742e60f931a13fac8` | **REPAIRED** |
| `v8_normalization.py` | `e252f727bf20ba9a51ef9e9e6371283d4772251ec1b31f65f0730a3aa61fa137` | `0d65648e8ba924ea4247fd5d73a9f307d6c50a952639fca1d8cf2891f294b5a9` | **REPAIRED** |
| `test_url_canonicalization_parity.py` | *(new file)* | `3fa3f631d1b107ace62a7c17c585c126ed1c98cb62fa3609cce953a5dd369ee9` | **NEW TEST SUITE** |

### Git State Preservation
- Repository: `sentinel-ai` (Git root)
- Branch: `reforge` at commit `85da31ca364b0a38c2265442d3919e11fc858390`
- Status: **Exactly 93 porcelain entries** (67 tracked modified/deleted, 26 untracked). Zero staged files, zero commits, zero stashes, zero clean operations.

---

## 3. Code Modifications

### 3.1 `sentinel-ml/URL-ml/scripts/v7_features.py`
Added `canonicalize_url(url: str) -> str` matching Kotlin `UrlFeatureExtractor.canonicalizeUrl`, and updated `_parse(url)`:

```python
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
```

### 3.2 `sentinel-ml/URL-ml/scripts/v8_normalization.py`
Updated `ParsedV8URL` to apply `canonicalize_url` on initialization:

```python
class ParsedV8URL:
    """Deterministic structured representation of a URL."""
    __slots__ = (
        "raw", "scheme", "host", "port", "parent_domain",
        "subdomain_labels", "subdomain_depth", "path", "path_segments",
        "clean_path", "query", "query_params", "fragment", "is_ip"
    )

    def __init__(self, raw: str):
        canonical = canonicalize_url(raw)
        raw_str = canonical if canonical else str(raw).strip()
        self.raw = raw_str
        
        # Scheme extraction
        p = urlsplit(raw_str if "://" in raw_str else "//" + raw_str, scheme="https")
        self.scheme = (p.scheme or "https").lower()
```

---

## 4. Test Verification & Parity Results

### 4.1 Python Regression & Parity Suite (`test_url_canonicalization_parity.py`)
Executed with Python 3 virtual environment (`sentinel-ml/URL-ml/venv/Scripts/python.exe -m unittest -v`):

```
test_feature_vector_dimension_and_order ... ok
test_is_https_feature_contract ... ok
test_schemeless_to_https_feature_invariance ... ok
test_all_174_golden_records ... ok
test_bare_apex_locked_policy_evaluation ... ok
test_explicit_http_penalized_as_malicious ... ok
test_irs_helpdesk_adjudication_parity ... ok
test_malformed_and_corner_cases_do_not_crash ... ok
test_safe_brand_schemeless_benign_parity ... ok
test_schemeless_ip_based_urls_detected ... ok
test_schemeless_malicious_attacks_detected ... ok
test_schemeless_suspicious_extensions_detected ... ok
test_canonicalize_empty_and_whitespace ... ok
test_canonicalize_explicit_schemes ... ok
test_canonicalize_preserves_paths_and_queries ... ok
test_canonicalize_protocol_relative ... ok
test_canonicalize_schemeless_and_bare_domains ... ok
test_canonicalize_trailing_delimiters ... ok

----------------------------------------------------------------------
Ran 18 tests in 12.333s
OK
```

### 4.2 Cross-Language Model Evaluation Comparison
Live comparison across Python and Android implementations on key reference inputs:

| Input URL | Canonical Form | Python `raw_p` | Android `raw_p` | Python `final_p` | Android `final_p` | Verdict | Parity Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `www.instagram.com` | `https://www.instagram.com` | 0.0019 | 0.0019 | 0.0010 | 0.0010 | **BENIGN** | **100% IDENTICAL** |
| `https://www.instagram.com` | `https://www.instagram.com` | 0.0019 | 0.0019 | 0.0010 | 0.0010 | **BENIGN** | **100% IDENTICAL** |
| `http://www.instagram.com` | `http://www.instagram.com` | 0.9696 | 0.9696 | 0.9696 | 0.9696 | **MALICIOUS** | **100% IDENTICAL** |
| `google.com` | `https://google.com` | 0.4676 | 0.4676 | 0.4676 | 0.4676 | **MALICIOUS** | **100% IDENTICAL** |
| `https://google.com` | `https://google.com` | 0.4676 | 0.4676 | 0.4676 | 0.4676 | **MALICIOUS** | **100% IDENTICAL** |
| `www.google.com` | `https://www.google.com` | 0.0018 | 0.0018 | 0.0010 | 0.0010 | **BENIGN** | **100% IDENTICAL** |
| `https://www.google.com` | `https://www.google.com` | 0.0018 | 0.0018 | 0.0010 | 0.0010 | **BENIGN** | **100% IDENTICAL** |
| `irs-helpdesk.win/reset-password` | `https://irs-helpdesk.win/reset-password` | 0.2160 | 0.2160 | 0.9500 | 0.9500 | **MALICIOUS** | **100% IDENTICAL** |
| `http://irs-helpdesk.win/reset-password` | `http://irs-helpdesk.win/reset-password` | 0.4817 | 0.4817 | 0.9500 | 0.9500 | **MALICIOUS** | **100% IDENTICAL** |
| `sbi-kyc-update.xyz/login` | `https://sbi-kyc-update.xyz/login` | 0.7873 | 0.7873 | 0.7873 | 0.7873 | **MALICIOUS** | **100% IDENTICAL** |
| `evil-download.com/update.apk` | `https://evil-download.com/update.apk` | 0.9996 | 0.9996 | 0.9996 | 0.9996 | **MALICIOUS** | **100% IDENTICAL** |
| `192.168.1.1/login` | `https://192.168.1.1/login` | 0.8940 | 0.8940 | 0.8940 | 0.8940 | **MALICIOUS** | **100% IDENTICAL** |

### 4.3 Android Core Test Suite
Executed via Gradle (`gradlew.bat :core:testDebugUnitTest --tests com.sentinel.ai.core.ml.url.*`):

| Test Suite | Test Count | Failures | Errors | Result |
| :--- | :--- | :--- | :--- | :--- |
| `SafeDomainAdjudicationTest` | 30 | 0 | 0 | **PASS** |
| `UrlCanonicalizationTest` | 10 | 0 | 0 | **PASS** |
| `UrlParityTest` | 6 | 0 | 0 | **PASS** |
| `UrlV8ParityTest` | 2 | 0 | 0 | **PASS** |
| **Total URL Unit Tests** | **48** | **0** | **0** | **100% PASS** |

### 4.4 Golden Corpus Parity
All 174 reference records in `golden_urls_v8.json` verified across Python and Android runtimes:
- Feature maximum absolute difference: `< 1e-4` (0.00000000)
- Raw tree probability maximum difference: `< 1e-4`
- Final adjudicated probability maximum difference: `< 1e-4`
- Decision label matches: **174 / 174 (100.0%)**

---

## 5. Phase 1A Closure Conclusion

1. **Defect Permanently Resolved:** Schemeless URLs follow the exact same canonicalization contract across Python and Kotlin.
2. **Zero Degradation:** Insecure HTTP inputs remain penalized; attack links, payload extensions, IP URLs, and phishing paths remain reliably detected as MALICIOUS.
3. **Model & Architecture Invariance:** The 67-feature vector dimension, ordering, tree bin thresholds, and frozen model weights remain 100% untouched.
4. **Boundary Compliance:** No Phase 2 tasks initiated. Git status preserved at exactly 93 entries with zero commits or stashes.
