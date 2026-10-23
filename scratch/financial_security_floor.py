"""Financial & Payment Security Floor Evaluation.

Verifies:
1. Legitimate banking logins on real financial parents are handled cleanly without false alarms.
2. Malicious financial attacks (fake KYC, OTP phishing, credential theft, account suspension) are blocked 100%.
3. Invariant 4: A benign-looking parent NEVER suppresses sensitive financial child operations (login, otp, kyc, verify).
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

FINANCIAL_CASES = [
    # Benign real financial sites
    ("BENIGN_BANK", "https://chase.com/personal/banking", 0),
    ("BENIGN_BANK", "https://www.paypal.com/us/home", 0),
    ("BENIGN_BANK", "https://www.bankofamerica.com/", 0),
    ("BENIGN_BANK", "https://www.wellsfargo.com/", 0),
    ("BENIGN_BANK", "https://www.fidelity.com/", 0),
    ("BENIGN_BANK", "https://www.hdfcbank.com/", 0),

    # Malicious financial phishing on attacker domains
    ("MALICIOUS_FIN", "http://chase-security-update.com/login", 1),
    ("MALICIOUS_FIN", "http://paypal-verification-center.xyz/signin", 1),
    ("MALICIOUS_FIN", "http://sbi-kyc-pan-update.online/auth", 1),
    ("MALICIOUS_FIN", "http://wellsfargo-account-reactivation.top/verify", 1),
    ("MALICIOUS_FIN", "http://bankofamerica-fraud-alert.buzz/session", 1),
    ("MALICIOUS_FIN", "http://hdfc-netbanking-password-reset.live/otp", 1),
    ("MALICIOUS_FIN", "http://citibank-card-verification.club/kyc", 1),
    ("MALICIOUS_FIN", "http://axis-bank-pan-link.info/document", 1),

    # Malicious financial child URLs on trusted cloud / hosting parents (Must NOT be suppressed!)
    ("HOSTED_FIN_PHISH", "https://github.com/phish-user/fake-paypal-login/releases/download/v1/login.php", 1),
    ("HOSTED_FIN_PHISH", "https://drive.google.com/uc?id=98765&export=download&file=sbi_kyc_app.apk", 1),
    ("HOSTED_FIN_PHISH", "https://youtube.com/redirect?q=https%3A%2F%2Fchase-online-verify.com%2Fotp", 1),
    ("HOSTED_FIN_PHISH", "https://storage.googleapis.com/phishing-bucket/hdfc_login_page.html", 1),
    ("HOSTED_FIN_PHISH", "https://firebaseapp.com/paypal-account-recovery/index.html", 1),
]

print("=" * 80)
print("FINANCIAL & PAYMENT SECURITY FLOOR AUDIT")
print("=" * 80)

failures = []
for cat, u, expected in FINANCIAL_CASES:
    feat = extract_v7_features(u)
    vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
    raw_p = float(v7_champ.base_model.predict_proba(vec)[0, 1])
    final_p, pred, label = v8_engine.adjudicate_single(u, vec[0], raw_p)

    is_correct = (pred == expected)
    status = "PASS" if is_correct else "FAIL"
    if not is_correct:
        failures.append((cat, u, raw_p, final_p, expected))

    print(f"[{cat:18s}] RawP={raw_p:.4f} -> FinalP={final_p:.4f} ({label:9s}) Exp={expected} | {status} | {u}")

print("=" * 80)
print(f"FINANCIAL FLOOR SUMMARY: {len(FINANCIAL_CASES) - len(failures)} / {len(FINANCIAL_CASES)} passed ({(len(FINANCIAL_CASES) - len(failures))/len(FINANCIAL_CASES)*100:.1f}%)")

if failures:
    print("\nFAILURES:")
    for cat, u, raw_p, fin_p, exp in failures:
        print(f"  [FAIL] {cat}: Raw={raw_p:.4f}, Final={fin_p:.4f}, Exp={exp} | {u}")
    raise AssertionError(f"Financial Security Floor FAILED with {len(failures)} failures!")
else:
    print("SUCCESS: FINANCIAL SECURITY FLOOR 100% VERIFIED. ZERO WEAKENING OBSERVED.")
