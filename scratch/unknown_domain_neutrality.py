"""Verify Unknown Domain Neutrality.

Tests that V8 behaves neutrally toward unseen / brand-new / zero-day domains:
1. Unknown != Malicious (Benign URLs on unknown domains are NOT flagged)
2. Complicated != Malicious (Long or structured benign URLs on unknown domains are NOT flagged)
3. Strong Malicious on unknown domain IS flagged.
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

UNKNOWN_CASES = [
    # 1. Simple Benign URLs on completely unknown / zero-day domains
    ("BENIGN_SIMPLE", "https://local-artisan-bakery.co.nz/menu", 0),
    ("BENIGN_SIMPLE", "https://melbourne-dental-clinic.com.au/about-us", 0),
    ("BENIGN_SIMPLE", "https://bristol-plumbing-services.co.uk/contact", 0),
    ("BENIGN_SIMPLE", "https://sunnyvale-community-library.org/hours", 0),
    ("BENIGN_SIMPLE", "https://osaka-ramen-guide.jp/locations", 0),

    # 2. Benign Long URLs on unknown domains
    ("BENIGN_LONG", "https://wellington-organic-coffee-roasters.co.nz/our-story-from-bean-to-cup-fair-trade-guarantee", 0),
    ("BENIGN_LONG", "https://seattle-neighborhood-farmers-markets.org/schedules-and-seasonal-produce-availability-guide", 0),

    # 3. Benign complex query on unknown domains
    ("BENIGN_QUERY", "https://toronto-real-estate-listings.ca/search?neighborhood=downtown&min_beds=2&max_price=850000&sort=date_desc", 0),
    ("BENIGN_QUERY", "https://auckland-used-bookstore.co.nz/catalog?category=science-fiction&year_min=1980&year_max=2000&in_stock=true", 0),

    # 4. Unknown domain + GitHub-like path (e.g. self-hosted Gitea/cgit)
    ("BENIGN_DEV_LIKE", "https://git.internal-university-lab.edu/cs101/homework-3/blob/main/solution.py", 0),
    ("BENIGN_DEV_LIKE", "https://code.robotics-research-consortium.org/navigation/commit/a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e", 0),

    # 5. Unknown domain + 40-character hex hash / session token
    ("BENIGN_HASH_PATH", "https://photo-sharing-portfolio.net/gallery/54b7ad52899dc6ae801334ee0ee693b4a20b0fa7/view", 0),

    # 6. Malicious URLs on unknown domains (Must still be caught!)
    ("MALICIOUS_PHISH", "http://secure-account-verification-portal.xyz/login.php", 1),
    ("MALICIOUS_IP", "http://185.220.101.5/payload/stealer.exe", 1),
    ("MALICIOUS_REDIRECT", "http://artisan-crafts-online.biz/click?dest=http%3A%2F%2Fbanking-phish.ru", 1),
    ("MALICIOUS_BRAND_SUB", "http://paypal.security-update.local-artisan-bakery.co.nz/auth", 1),
    ("MALICIOUS_EXE", "https://community-choir-notes.org/downloads/concert_program.exe", 1),
]

print("=" * 80)
print("UNKNOWN DOMAIN NEUTRALITY & ROBUSTNESS EVALUATION")
print("=" * 80)

correct = 0
for cat, u, expected in UNKNOWN_CASES:
    feat = extract_v7_features(u)
    vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
    raw_p = float(v7_champ.base_model.predict_proba(vec)[0, 1])
    final_p, pred, label = v8_engine.adjudicate_single(u, vec[0], raw_p)

    status = "CORRECT" if pred == expected else "INCORRECT"
    if pred == expected:
        correct += 1
    print(f"[{cat:18s}] RawP={raw_p:.4f} -> FinalP={final_p:.4f} ({label:9s}) Expected={expected} | {status} | {u}")

print("=" * 80)
print(f"UNKNOWN DOMAIN SUMMARY: {correct} / {len(UNKNOWN_CASES)} passed ({correct/len(UNKNOWN_CASES)*100:.1f}%)")
