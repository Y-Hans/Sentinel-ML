"""Write newly authored, non-training demo fixtures."""

from __future__ import annotations

import json
from pathlib import Path


FIXTURES = [
    {"id": "safe_ordinary", "category": "safe_ordinary", "url": "https://www.google.com/"},
    {
        "id": "safe_long_legitimate",
        "category": "safe_long_legitimate",
        "url": "https://docs.python.org/3/library/urllib.parse.html#url-parsing",
    },
    {
        "id": "phishing_lure",
        "category": "phishing",
        "url": "https://account-verification.example.invalid/login?session=expired",
    },
    {
        "id": "brand_impersonation",
        "category": "brand_impersonation",
        "url": "https://paypa1-security.example.invalid/verify/account",
    },
    {
        "id": "suspicious_executable",
        "category": "executable_payload",
        "url": "https://download-center.example.invalid/update.apk",
    },
    {
        "id": "redirect_url",
        "category": "redirect",
        "url": "https://portal.example.invalid/continue?url=https%3A%2F%2Fphish.example.invalid%2Flogin",
    },
    {
        "id": "trusted_host_malicious_path",
        "category": "trusted_host_malicious_path",
        "url": "https://github.com/security-update/verify.apk",
    },
    {
        "id": "financial_verification_lure",
        "category": "financial_verification",
        "url": "https://bank-account.example.invalid/verify-card?otp=required",
    },
]


def main() -> None:
    path = Path("URL-ml/reports/fresh_url_20261024_demo_fixtures.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(FIXTURES, indent=2) + "\n", encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
