"""Summarize extracted rows from recovered sentinel DBs: schema + samples."""
import json, sys, re
from pathlib import Path

INV = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation")

def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            rows.append(r)
    return rows

for name, fn in [("sentinel_db (newer)", "sentinel_db_rows.jsonl"),
                 ("sentinel_db(1) (older)", "sentinel_db1_rows.jsonl")]:
    fp = INV / fn
    if not fp.exists():
        print(f"== {name}: {fn} MISSING")
        continue
    rows = load(fp)
    print("=" * 80)
    print(f"{name}: {len(rows)} rows extracted")
    # Find sqlite_master-like records (strings containing CREATE)
    creates = []
    for r in rows:
        strs = [v for v in r.get("values", []) if isinstance(v, str)]
        for s in strs:
            if "CREATE" in s:
                creates.append(s)
    print(f"  CREATE-statement candidates found in {len(creates)} values")
    # Try extracting the SQL segments
    table_defs = []
    for s in creates:
        for m in re.finditer(r"CREATE(?: UNIQUE)? INDEX[^;]*;|CREATE TABLE [^;]*;", s):
            table_defs.append(m.group(0))
    for td in sorted(set(table_defs)):
        print("\n  SQL:", td[:400])
    # Describe the value-count structure of non-empty rows
    empty = sum(1 for r in rows if not r["values"])
    print(f"\n  rows with empty values: {empty}")
    lens = {}
    for r in rows:
        n = len([v for v in r["values"] if v is not None])
        lens[r["ncols"]] = lens.get(r["ncols"], 0) + 1
    print("  ncols histogram:", dict(sorted(lens.items())))