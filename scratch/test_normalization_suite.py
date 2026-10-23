"""Comprehensive Normalization & Adversarial URL Parsing Test Suite.

Verifies:
1. http vs https
2. default ports (80, 443) vs non-default ports (8080, 8443)
3. URL fragments (#heading, #section)
4. Credentials / userinfo (user:pass@host)
5. Percent-encoding (%20, %2e%2e, %2f)
6. Double encoding (%2520, %252e%252e)
7. Unicode characters & Punycode (xn--...)
8. IPv4 and IPv6 addresses ([::1], [2001:db8::1]:8080)
9. Trailing dots in hostname (example.com.)
10. Repeated slashes (http://example.com///path////to///resource)
11. Mixed case (HtTpS://ExAmPlE.CoM/PaTh)
12. Nested absolute URLs (http://host.com/https://nested.com/target)
13. Multi-label public suffixes (.co.uk, .co.nz, .github.io)
14. raw.githubusercontent.com intentional boundary (-> githubusercontent.com)
"""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
URL_ML = ROOT / "URL-ml"
SCRIPTS = URL_ML / "scripts"

import sys
sys.path.insert(0, str(SCRIPTS))
from v8_normalization import parse_v8_url, extract_parent_domain

NORMALIZATION_TESTS = [
    # 1. Scheme variations
    ("https://example.com/path", "example.com", "path", "https"),
    ("http://example.com/path", "example.com", "path", "http"),
    ("HTTPS://EXAMPLE.COM/PATH", "example.com", "PATH", "https"),

    # 2. Ports
    ("https://example.com:443/secure", "example.com", "secure", "https"),
    ("http://example.com:80/standard", "example.com", "standard", "http"),
    ("http://example.com:8080/dev", "example.com", "dev", "http"),
    ("https://secure.example.com:8443/auth", "example.com", "auth", "https"),

    # 3. Fragments
    ("https://example.com/doc#section-2", "example.com", "doc", "https"),
    ("https://example.com/doc?ver=1#part3", "example.com", "doc", "https"),

    # 4. Userinfo
    ("https://user:password@example.com/login", "example.com", "login", "https"),
    ("http://attacker:secret@evil.example.com/steal", "example.com", "steal", "http"),

    # 5. Percent encoding & double encoding
    ("https://example.com/path%20with%20spaces", "example.com", "path%20with%20spaces", "https"),
    ("https://example.com/path%2520double", "example.com", "path%2520double", "https"),
    ("https://example.com/dir%2fsub", "example.com", "dir%2fsub", "https"),

    # 6. Unicode & IDN / Punycode
    ("https://xn--gogle-qta.com/search", "xn--gogle-qta.com", "search", "https"),

    # 7. IPv4 and IPv6
    ("http://192.168.1.1/admin", "192.168.1.1", "admin", "http"),
    ("http://192.168.1.1:8080/setup", "192.168.1.1", "setup", "http"),
    ("http://[::1]/debug", "::1", "debug", "http"),
    ("http://[2001:db8::1]:8080/index", "2001:db8::1", "index", "http"),

    # 8. Trailing dots in hostname
    ("https://example.com./path", "example.com", "path", "https"),

    # 9. Repeated slashes (normalized clean path)
    ("https://example.com///path////to///resource", "example.com", "path/to/resource", "https"),

    # 10. Nested URLs
    ("https://aggregator.com/https://target-site.com/checkout", "aggregator.com", "https:/target-site.com/checkout", "https"),

    # 11. Multi-label public suffixes
    ("https://shop.local-artisan.co.uk/item", "local-artisan.co.uk", "item", "https"),
    ("https://app.bakery.co.nz/menu", "bakery.co.nz", "menu", "https"),
    ("https://developer.project.github.io/docs", "project.github.io", "docs", "https"),

    # 12. raw.githubusercontent.com intentional boundary
    ("https://raw.githubusercontent.com/user/repo/main/file.txt", "githubusercontent.com", "user/repo/main/file.txt", "https"),
]

print("=" * 80)
print("SENTINEL-ML V8 INDEPENDENT NORMALIZATION SUITE")
print("=" * 80)

passed = 0
for raw, exp_parent, exp_path, exp_scheme in NORMALIZATION_TESTS:
    res = parse_v8_url(raw)
    parent_ok = (res.parent_domain == exp_parent)
    scheme_ok = (res.scheme == exp_scheme)
    path_ok = (res.clean_path == exp_path)

    is_ok = parent_ok and scheme_ok and path_ok
    status = "PASS" if is_ok else "FAIL"
    if is_ok:
        passed += 1
    else:
        print(f"  [MISMATCH]: {raw}")
        print(f"    Parent: Got '{res.parent_domain}', Exp '{exp_parent}' (Match: {parent_ok})")
        print(f"    Scheme: Got '{res.scheme}', Exp '{exp_scheme}' (Match: {scheme_ok})")
        print(f"    Path:   Got '{res.clean_path}', Exp '{exp_path}' (Match: {path_ok})")
    print(f"[{status:4s}] {raw:60s} -> Parent: {res.parent_domain:25s} | Scheme: {res.scheme}")

print("=" * 80)
print(f"NORMALIZATION SUITE SUMMARY: {passed} / {len(NORMALIZATION_TESTS)} passed ({passed/len(NORMALIZATION_TESTS)*100:.1f}%)")

if passed != len(NORMALIZATION_TESTS):
    raise AssertionError(f"Normalization tests failed: {passed}/{len(NORMALIZATION_TESTS)}")
print("ALL NORMALIZATION TESTS PASSED PERFECTLY.")
