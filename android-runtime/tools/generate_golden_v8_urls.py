"""Generate Golden Test Corpus for URL-ML V8 Cross-Language Parity Verification.

Generates:
- android-runtime/golden_test_data/golden_urls_v8.json

Covers diverse real-world, adversarial, and edge-case URLs:
- Legitimate problem URLs (Chessigma, CrazyGames, Codenames, YouTube, GitHub commits, deep paths)
- Long URL matched pairs
- Trusted-parent malicious URLs (malware downloads, open redirects, phishing)
- Parent impersonation & lookalikes
- Financial / payment sites
- Unknown domains
- Diverse test split and hard negative URLs
"""
from __future__ import annotations
import json
from pathlib import Path
import sys
import joblib
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
URL_ML = ROOT / "URL-ml"
DATA = URL_ML / "data"
MODELS = URL_ML / "models"
REPORTS = URL_ML / "reports"
GOLDEN_DIR = ROOT / "android-runtime" / "golden_test_data"
GOLDEN_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(URL_ML / "scripts"))
sys.path.insert(0, str(ROOT / "scratch"))

from v7_features import extract_v7_features, V7_FEATURE_NAMES, vectorize_v7
from v8_benchmark_suite import get_all_benchmark_slices
from v8_classifier import V8RelationalURLClassifier

# Load V7 model base
v7_champion = joblib.load(MODELS / "v7_champion.joblib")
base_model = v7_champion.base_model
v8_engine = V8RelationalURLClassifier(base_model, threshold=0.2800)

print("Compiling Golden URLs for V8 Parity Test...")

golden_urls = []

# 1. Add all benchmark items
slices = get_all_benchmark_slices()
for s_name, items in slices.items():
    for it in items:
        golden_urls.append((f"bench_{s_name}", it.url))

# 2. Add real-device sentinel.db URLs
with open(ROOT / "7sep_messages_v3" / "data" / "bench_sentinel_replay.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        if not line.strip(): continue
        rec = json.loads(line)
        text = rec.get("raw_text", "")
        import re
        for u in re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text):
            golden_urls.append(("sentinel_db", u))
        if rec.get("source") == "Intent (Link)":
            golden_urls.append(("sentinel_db", text.strip()))

# 3. Add sample from hard_dataset
hard_df = pd.read_csv(DATA / "hard_dataset.csv")
for _, row in hard_df.head(40).iterrows():
    golden_urls.append(("hard_dataset", row["url"]))

# 4. Add sample from test set
clean_df = pd.read_csv(DATA / "cleaned_dataset.csv")
for _, row in clean_df.head(50).iterrows():
    golden_urls.append(("cleaned_dataset", row["url"]))

# Deduplicate URLs
seen = set()
unique_golden = []
for cat, u in golden_urls:
    u_clean = u.strip()
    if u_clean and u_clean not in seen:
        seen.add(u_clean)
        unique_golden.append((cat, u_clean))

print(f"Total Unique Golden URLs: {len(unique_golden)}")

golden_records = []
for i, (cat, u) in enumerate(unique_golden):
    feat = extract_v7_features(u)
    vec = np.array([[feat[k] for k in V7_FEATURE_NAMES]], dtype=np.float32)
    raw_p = float(base_model.predict_proba(vec)[0, 1])
    final_p, pred_int, label = v8_engine.adjudicate_single(u, vec[0], raw_p)
    
    record = {
        "id": f"v8_gold_{i:04d}",
        "url": u,
        "category": cat,
        "features": [float(feat[k]) for k in V7_FEATURE_NAMES],
        "rawProbability": float(raw_p),
        "finalProbability": float(final_p),
        "isMalicious": bool(pred_int == 1),
        "label": label
    }
    golden_records.append(record)

out_file = GOLDEN_DIR / "golden_urls_v8.json"
out_file.write_text(json.dumps(golden_records, indent=2), encoding="utf-8")
print(f"Exported {len(golden_records)} records to {out_file} ({out_file.stat().st_size / 1024:.1f} KB)")

if __name__ == "__main__":
    print("Golden V8 corpus generation complete.")
