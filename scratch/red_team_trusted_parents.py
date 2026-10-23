"""Aggressive Red-Team Attack Suite Against Trusted-Parent Architecture.

Tests whether parent trust can ever suppress strong malicious child evidence:
1. Trusted parent + Executable / APK payload (.exe, .apk, .scr, .bat, .vbs)
2. Trusted parent + Open redirect (url=, target=, dest=, redirect parameters)
3. Trusted parent + Credential harvesting / Stealers / Token grabbers
4. Trusted parent + Brand impersonation on subdomains
5. Trusted parent + Obfuscated / Double-encoded payload
6. Trusted parent + Nested URL injection
7. Trusted parent + IP-based target
8. Trusted parent + Punycode / Homoglyph lookalikes

Mandatory Security Invariant: 0 BYPASSES PERMITTED (100% Detection Rate).
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

RED_TEAM_ATTACKS = [
    # Category 1: Executables & Malicious Binaries on Trusted Parents
    ("TRUSTED_EXE", "https://github.com/torvalds/linux/releases/download/v1.0/backdoor.exe"),
    ("TRUSTED_EXE", "https://github.com/apache/spark/archive/refs/tags/malware.apk"),
    ("TRUSTED_EXE", "https://github.com/tensorflow/tensorflow/files/stealer.scr"),
    ("TRUSTED_EXE", "https://github.com/kubernetes/kubernetes/releases/download/v1.20/trojan.bat"),
    ("TRUSTED_EXE", "https://github.com/golang/go/raw/master/src/exploit.vbs"),
    ("TRUSTED_EXE", "https://raw.githubusercontent.com/user/repo/main/agent.dll"),
    ("TRUSTED_EXE", "https://drive.google.com/uc?id=1AbCdEfGhIjKlMnOpQrStUvWxYz&export=download&file=payload.exe"),
    ("TRUSTED_EXE", "https://youtube.com/files/download/botnet.exe"),
    ("TRUSTED_EXE", "https://paypal.com/downloads/security_patch.apk"),
    ("TRUSTED_EXE", "https://microsoft.com/en-us/download/confirmation.aspx?id=54321&payload=ransomware.exe"),

    # Category 2: Open Redirects & Reflected Links on Trusted Parents
    ("TRUSTED_REDIRECT", "https://www.youtube.com/redirect?q=https%3A%2F%2Fsecure-phishing-portal.com%2Flogin"),
    ("TRUSTED_REDIRECT", "https://www.youtube.com/redirect?event=video_description&redir_token=XYZ&q=http%3A%2F%2Fphish-site.ru"),
    ("TRUSTED_REDIRECT", "https://www.google.com/url?q=https%3A%2F%2Fcredential-theft.com%2Fsignin&sa=D"),
    ("TRUSTED_REDIRECT", "https://google.com/url?target=http://malicious-login-portal.top/auth"),
    ("TRUSTED_REDIRECT", "https://github.com/login?return_to=https%3A%2F%2Fevil-attacker.com%2Fharvest"),
    ("TRUSTED_REDIRECT", "https://paypal.com/signin?dest=http%3A%2F%2Ffake-paypal-verify.xyz"),
    ("TRUSTED_REDIRECT", "https://bitbucket.org/account/signin/?next=https%3A%2F%2Fcredential-stealer.org"),
    ("TRUSTED_REDIRECT", "https://spotify.com/redirect?url=http://malware-drop.biz"),
    ("TRUSTED_REDIRECT", "https://vimeo.com/r?link=https%3A%2F%2Fphishing.example.com"),

    # Category 3: Credential Stealers / Token Grabbers on Trusted Platforms
    ("TRUSTED_STEALER", "https://github.com/attacker/discord_token_grabber/blob/main/grabber.py"),
    ("TRUSTED_STEALER", "https://github.com/dark-coder/discord_token_stealer_v2/releases"),
    ("TRUSTED_STEALER", "https://github.com/hacker/telegram_session_rat_and_stealer/archive/master.zip"),
    ("TRUSTED_STEALER", "https://raw.githubusercontent.com/crimelab/malware/master/credential_dump.txt"),
    ("TRUSTED_STEALER", "https://gitlab.com/blackhat/wallet_stealer_extension"),

    # Category 4: Brand Impersonation Spoofing Trusted Parents (Lookalikes / Subdomains)
    ("PARENT_IMPERSONATION", "https://youtube.com.evil-phish.com/watch?v=dQw4w9WgXcQ"),
    ("PARENT_IMPERSONATION", "https://github.com.account-recovery-portal.xyz/login"),
    ("PARENT_IMPERSONATION", "https://google.com.security-alert-verification.top/signin"),
    ("PARENT_IMPERSONATION", "https://paypal.com.verify-billing-info.click/update"),
    ("PARENT_IMPERSONATION", "https://apple.com.id-support-auth.live/recovery"),
    ("PARENT_IMPERSONATION", "https://microsoft.com.office365-password-reset.info/login"),
    ("PARENT_IMPERSONATION", "https://chase.com.onlinebanking-customer-care.xyz/auth"),
    ("PARENT_IMPERSONATION", "http://github-auth-verify.top/session"),
    ("PARENT_IMPERSONATION", "http://google-drive-shared-document.xyz/view"),
    ("PARENT_IMPERSONATION", "http://paypal-resolution-center.buzz/signin"),

    # Category 5: Obfuscated / Evasion / Double Encoding on Trusted Parents
    ("OBFUSCATED", "https://github.com/user/repo/blob/master/path%2520with%2520double%2520encoding"),
    ("OBFUSCATED", "https://google.com/search?q=%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
    ("OBFUSCATED", "https://youtube.com/watch?v=123%2526cmd%3Dwhoami"),

    # Category 6: Nested URL Injections
    ("NESTED_URL", "https://github.com/https://phishing-site.com/login"),
    ("NESTED_URL", "https://youtube.com/https://credential-trap.com/verify"),
    ("NESTED_URL", "https://google.com/http://attacker.com/payload.exe"),

    # Category 7: Typosquatting / Punycode of Trusted Parents
    ("PUNYCODE_TYPO", "https://xn--gogle-qta.com/search?q=login"),
    ("PUNYCODE_TYPO", "https://xn--pypal-4ve.com/signin"),
    ("PUNYCODE_TYPO", "https://xn--yutube-2ya.com/watch"),
    ("PUNYCODE_TYPO", "https://xn--appl-epa.com/icloud/auth"),
    ("PUNYCODE_TYPO", "https://g00gle.com/signin"),
    ("PUNYCODE_TYPO", "https://paypa1.com/cgi-bin/webscr"),
    ("PUNYCODE_TYPO", "https://g1thub.com/torvalds/linux"),

    # Category 8: Financial Attacks Spoofing Trusted Financial Parents
    ("FINANCIAL_ATTACK", "https://chase.com.security-login-card.xyz/verify"),
    ("FINANCIAL_ATTACK", "https://paypal.com.dispute-resolution-case982.top/confirm"),
    ("FINANCIAL_ATTACK", "https://hdfcbank.com.netbanking-kyc-update.online/pan"),
    ("FINANCIAL_ATTACK", "https://sbi.co.in.yono-customer-update.live/login.php"),
    ("FINANCIAL_ATTACK", "https://wellsfargo.com.account-suspension-warning.click/reactivate")
]

print("=" * 80)
print("SENTINEL-ML RED-TEAM TRUSTED-PARENT ATTACK SUITE")
print("=" * 80)
print(f"Total Aggressive Red-Team Attack URLs: {len(RED_TEAM_ATTACKS)}")

bypasses = []
results = []

for cat, u in RED_TEAM_ATTACKS:
    feat = extract_v7_features(u)
    vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
    raw_p = float(v7_champ.base_model.predict_proba(vec)[0, 1])
    final_p, pred_int, label = v8_engine.adjudicate_single(u, vec[0], raw_p)

    is_caught = (pred_int == 1)
    if not is_caught:
        bypasses.append((cat, u, raw_p, final_p))

    results.append({
        "category": cat,
        "url": u,
        "base_model_probability": raw_p,
        "final_adjudicated_probability": final_p,
        "label": label,
        "caught": is_caught
    })
    print(f"[{cat:20s}] RawP={raw_p:.4f} -> FinalP={final_p:.4f} ({label:9s}) | {u}")

print("=" * 80)
print(f"RED-TEAM RESULTS SUMMARY:")
print(f"  Total Attacks Evaluated: {len(RED_TEAM_ATTACKS)}")
print(f"  Attacks Caught (Blocked): {len(RED_TEAM_ATTACKS) - len(bypasses)} / {len(RED_TEAM_ATTACKS)} ({(len(RED_TEAM_ATTACKS) - len(bypasses))/len(RED_TEAM_ATTACKS)*100:.2f}%)")
print(f"  Bypasses (False Negatives): {len(bypasses)}")

if bypasses:
    print("\nCRITICAL SECURITY FAILURES (BYPASSES):")
    for cat, u, raw_p, fin_p in bypasses:
        print(f"  [BYPASS] {cat}: Raw={raw_p:.4f}, Final={fin_p:.4f} | {u}")
    raise AssertionError(f"Red-Team Trusted-Parent Suite FAILED with {len(bypasses)} bypasses!")
else:
    print("\nSUCCESS: 0 TRUSTED-PARENT BYPASSES OBSERVED. SECURITY INVARIANTS 100% INTACT.")
