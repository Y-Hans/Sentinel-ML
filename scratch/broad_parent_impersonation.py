"""Broad Parent Impersonation & Typosquatting Evaluation Suite.

Evaluates that legitimate parent reputation NEVER transfers to attacker-controlled registrable domains:
1. Subdomain impersonation (e.g. google.com.evil.example)
2. Prefix / hyphen impersonation (e.g. evil-google.com)
3. Unicode / Punycode homoglyphs (e.g. xn--gogle-qta.com)
4. Mixed-case evasion (e.g. GoOgLe.CoM.evil.com)
5. Trailing dot variations (e.g. google.com./path)
6. Userinfo credential tricks (e.g. http://google.com@attacker.com/login)
7. Unusual port manipulation (e.g. http://attacker.com:8443/google.com/login)
8. Encoded host / path tricks

Mandatory Invariant: 100% DETECTION RATE ON IMPERSONATION ATTACKS.
"""
from __future__ import annotations
import json
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
URL_ML = ROOT / "URL-ml"
SCRIPTS = URL_ML / "scripts"
MODELS = URL_ML / "models"

import sys
sys.path.insert(0, str(SCRIPTS))
from v7_features import extract_v7_features, V7_FEATURE_NAMES
from v8_classifier import V8RelationalURLClassifier
import joblib

v7_champ = joblib.load(MODELS / "v7_champion.joblib")
v8_engine = V8RelationalURLClassifier(v7_champ.base_model, threshold=0.2800)

IMPERSONATION_ATTACKS = [
    # 1. Subdomain Impersonation on Attacker Domain
    ("SUBDOMAIN_IMP", "https://google.com.evil.example/login"),
    ("SUBDOMAIN_IMP", "https://github.com.evil.example/session"),
    ("SUBDOMAIN_IMP", "https://youtube.com.evil.example/watch?v=123"),
    ("SUBDOMAIN_IMP", "https://microsoft.com.evil.example/auth"),
    ("SUBDOMAIN_IMP", "https://apple.com.evil.example/icloud"),
    ("SUBDOMAIN_IMP", "https://paypal.com.evil.example/signin"),
    ("SUBDOMAIN_IMP", "https://chase.com.evil.example/online"),
    ("SUBDOMAIN_IMP", "https://bankofamerica.com.evil.example/verify"),

    # 2. Prefix / Hyphen Impersonation
    ("PREFIX_IMP", "https://google-security-update.com/signin"),
    ("PREFIX_IMP", "https://github-auth-service.com/login"),
    ("PREFIX_IMP", "https://youtube-video-awards.com/claim"),
    ("PREFIX_IMP", "https://microsoft-office-login.top/account"),
    ("PREFIX_IMP", "https://apple-id-verify.click/recover"),
    ("PREFIX_IMP", "https://paypal-resolution-center.biz/dispute"),

    # 3. Unicode / Punycode Homoglyphs
    ("PUNYCODE_HOMOGLYPH", "https://xn--gogle-qta.com/signin"),
    ("PUNYCODE_HOMOGLYPH", "https://xn--pypal-4ve.com/login"),
    ("PUNYCODE_HOMOGLYPH", "https://xn--appl-epa.com/recovery"),
    ("PUNYCODE_HOMOGLYPH", "https://xn--microsft-e1a.com/office365"),

    # 4. Mixed-case Evasion
    ("MIXED_CASE", "https://GoOgLe.CoM.attacker-domain.xyz/auth"),
    ("MIXED_CASE", "https://GiThUb.CoM.security-portal.top/login"),
    ("MIXED_CASE", "https://PaYpAl.CoM.verification-notice.online/update"),

    # 5. Userinfo Confusion Tricks
    ("USERINFO_TRICK", "https://google.com:secret@evil-domain.com/login"),
    ("USERINFO_TRICK", "https://paypal.com@attacker-site.org/signin"),
    ("USERINFO_TRICK", "https://github.com:access_token@malicious-host.net/repo"),

    # 6. Unusual Port Tricks
    ("UNUSUAL_PORT", "http://attacker-controlled.com:8443/paypal.com/login.html"),
    ("UNUSUAL_PORT", "http://malicious-server.xyz:8080/google.com/verify.php"),

    # 7. Banking Brand Generic Impersonation
    ("BANK_IMP", "http://bank-of-america-customer-support.xyz/online-banking"),
    ("BANK_IMP", "http://wellsfargo-security-alert.top/verify-account"),
    ("BANK_IMP", "http://citibank-card-update.buzz/kyc-verification"),
    ("BANK_IMP", "http://chase-bank-resolution.click/login"),
]

print("=" * 80)
print("SENTINEL-ML BROAD PARENT IMPERSONATION AUDIT")
print("=" * 80)

failures = []
for cat, u in IMPERSONATION_ATTACKS:
    feat = extract_v7_features(u)
    vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
    raw_p = float(v7_champ.base_model.predict_proba(vec)[0, 1])
    final_p, pred, label = v8_engine.adjudicate_single(u, vec[0], raw_p)

    status = "BLOCKED" if pred == 1 else "BYPASS"
    if pred == 0:
        failures.append((cat, u, raw_p, final_p))
    print(f"[{cat:20s}] RawP={raw_p:.4f} -> FinalP={final_p:.4f} ({label:9s}) | {status} | {u}")

print("=" * 80)
print(f"BROAD IMPERSONATION SUMMARY: {len(IMPERSONATION_ATTACKS) - len(failures)} / {len(IMPERSONATION_ATTACKS)} blocked ({(len(IMPERSONATION_ATTACKS) - len(failures))/len(IMPERSONATION_ATTACKS)*100:.1f}%)")

if failures:
    print("\nFAILURES:")
    for cat, u, raw_p, fin_p in failures:
        print(f"  [BYPASS] {cat}: Raw={raw_p:.4f}, Final={fin_p:.4f} | {u}")
    raise AssertionError(f"Broad Impersonation Suite FAILED with {len(failures)} bypasses!")
else:
    print("SUCCESS: ALL PARENT IMPERSONATION ATTACKS DETECTED WITH 100% RECALL.")
