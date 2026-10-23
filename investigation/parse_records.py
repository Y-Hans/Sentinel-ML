"""Analyze recovered threat_records rows from sentinel_db & sentinel_db(1)."""
import json, sys, re
from pathlib import Path
from collections import Counter, defaultdict

INV = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation")
OUT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation")

SCHEMA = ["id", "recordType", "source", "senderDisplayName", "senderIdentifier",
          "content", "riskLevel", "riskScore", "explanation", "recommendation",
          "timestamp"]

def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows

def guess_record_columns(rec):
    """Try to map a row's values onto the threat_records schema."""
    vals = rec["values"]
    # normalize hex bytes -> str
    def norm(v):
        if isinstance(v, dict) and "__bytes_hex__" in v:
            b = bytes.fromhex(v["__bytes_hex__"])
            try:
                return b.decode("utf-8", "replace")
            except Exception:
                return b.hex()
        return v
    return [norm(v) for v in vals]

for name, fn in [("sentinel_db (newer)", "sentinel_db_rows.jsonl"),
                 ("sentinel_db(1) (older)", "sentinel_db1_rows.jsonl")]:
    rows = load(INV / fn)
    print("=" * 90)
    print(f"{name}: {len(rows)} raw btree rows")
    mapped = []
    for r in rows:
        vals = r["values"]
        if not vals:
            continue
        mapped.append(guess_record_columns(r))
    print(f"  rows with values: {len(mapped)}")
    len_counter = Counter(len(m) for m in mapped)
    print("  column-count histogram:", dict(sorted(len_counter.items())))
    # Look for threat-record-looking rows: >= 11 values, has id-like first field
    records = [m for m in mapped if len(m) >= 11 and isinstance(m[0], str)
               and not m[0].startswith("CREATE")]
    print(f"  threat-record-like rows: {len(records)}")
    risk_counter = Counter()
    printable = []
    for m in records:
        rec = dict(zip(SCHEMA, m[:11]))
        risk_counter[(rec.get("riskLevel"), type(rec.get("riskScore")).__name__)] += 1
        printable.append(rec)
    print("  riskLevel distribution:", dict(risk_counter))
    # Save parsed records
    with open(OUT / (fn.replace("_rows.jsonl", "_parsed.jsonl")), "w", encoding="utf-8") as f:
        for rec in printable:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"  saved {len(printable)} parsed records.")
    # Show first few
    for rec in printable[:4]:
        print("\n  SAMPLE:", json.dumps(rec, ensure_ascii=False)[:600])
    # Dedupe on id
    ids = Counter(r.get("id") for r in printable)
    print(f"  unique ids: {len(ids)} of {len(printable)}")