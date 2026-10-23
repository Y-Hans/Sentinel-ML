"""Extract rows from the corrupted-but-recoverable sentinel databases.

Use the manual b-tree leaf scanner, write rows to JSONL with safe handling.
"""
import sys, os, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scratch"))
from salvage_db import scan_leaf_pages, varint, decode_record  # reuse parser

INV = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation")
SOURCES = [
    ("sentinel_db.recovered.db", "sentinel_db_rows.jsonl"),
    ("sentinel_db(1).recovered.db", "sentinel_db1_rows.jsonl"),
]

def to_json_safe(v):
    if isinstance(v, bytes):
        return {"__bytes_hex__": v.hex()}
    if isinstance(v, str):
        return v
    return v

for src, outp in SOURCES:
    p = INV / src
    if not p.exists():
        print(f"skip {src}")
        continue
    raw = scan_leaf_pages(p)
    print(f"{src}: {len(raw)} rows")
    cols = {}
    for pno, rowid, vals in raw:
        n = len(vals)
        cols[n] = cols.get(n, 0) + 1
    print("  value-count histogram:", dict(sorted(cols.items())))
    with open(INV / outp, "w", encoding="utf-8") as f:
        for pno, rowid, vals in raw:
            rec = {"page": pno, "rowid": rowid, "ncols": len(vals),
                   "values": [to_json_safe(v) for v in vals]}
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    print(f"  wrote {outp}")

    # Try to print page-1 (sqlite_master) rows verbatim
    print("  page 1 rows:")
    for pno, rowid, vals in raw:
        if pno in (0, 1):
            print("   ", pno, rowid, [str(v)[:200] for v in vals])