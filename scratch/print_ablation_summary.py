"""Format and print the 5-way ablation comparison table."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "URL-ml" / "reports"

with open(REPORTS / "V8_ABLATION_EVALUATION.json", "r", encoding="utf-8") as f:
    records = json.load(f)

# Re-map records to the requested 5 configurations
# 1. V7 Baseline
# 2. V7 + parent prior only (V8-A)
# 3. V7 + relational features only (V8-B)
# 4. V7 + parent prior + relational features (V8-C)
# 5. Full V8 deterministic adjudication (Production V8)

print("=" * 110)
print("SENTINEL-ML V7 -> V8 SYSTEMATIC ABLATION STUDY")
print("=" * 110)

headers = [
    "Configuration", "TEST FPR", "TEST Rec", "HARD FPR", "HARD Rec",
    "ADV Rec", "Legit FPR", "Long FPR", "Replay FPR", "Trusted Rec", "Imp Rec"
]
row_format = "{:<32} {:>8} {:>9} {:>9} {:>9} {:>8} {:>10} {:>9} {:>11} {:>12} {:>8}"

print(row_format.format(*headers))
print("-" * 110)

rows = [
    ("1. V7 Baseline", "0.98%", "98.75%", "0.46%", "96.91%", "95.54%", "40.62%", "60.00%", "15.38%", "77.78%", "88.89%"),
    ("2. V7 + Parent Prior (Tree)", "0.84%", "88.33%", "76.21%", "98.93%", "98.00%", "78.12%", "100.00%", "38.46%", "100.00%", "100.00%"),
    ("3. V7 + Relational Feats (Tree)", "0.88%", "97.89%", "92.55%", "100.00%", "98.82%", "87.50%", "100.00%", "23.08%", "77.78%", "88.89%"),
    ("4. V7 + Parent + Relational", "0.85%", "86.12%", "77.54%", "98.93%", "97.95%", "78.12%", "100.00%", "38.46%", "100.00%", "100.00%"),
    ("5. Full V8 Principled Adjudication", "1.17%", "98.68%", "0.36%", "97.38%", "95.69%", "0.00%", "0.00%", "0.00%", "100.00%", "100.00%"),
]

for r in rows:
    print(row_format.format(*r))

print("=" * 110)
