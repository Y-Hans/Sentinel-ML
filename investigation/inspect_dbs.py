"""Phase 1 investigation: inventory every message database in the repo."""
import sqlite3, os, json, sys, hashlib

BASE = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml"
DBS = [
    os.path.join(BASE, "sentinel_db"),
    os.path.join(BASE, "sentinel_db(1)"),
    os.path.join(BASE, "sentinel_reconstructed.db"),
    os.path.join(BASE, "test_fixed.db"),
    os.path.join(BASE, "scratch", "sentinel_db_newer.db"),
]

def file_hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

for p in DBS:
    print("=" * 90)
    if not os.path.exists(p):
        print(f"MISSING: {p}")
        continue
    size = os.path.getsize(p)
    print(f"DB: {p}")
    print(f"  size={size} bytes  sha256={file_hash(p)}")
    try:
        con = sqlite3.connect(p)
        cur = con.cursor()
        tabs = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        print(f"  tables: {tabs}")
        for t in tabs:
            try:
                cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                schema = cur.execute(f'PRAGMA table_info("{t}")').fetchall()
                print(f"\n  TABLE {t} rows={cnt}")
                for col in schema:
                    print(f"    - {col[1]} ({col[2]})")
            except Exception as e:
                print(f"    ERROR reading {t}: {e}")
        con.close()
    except Exception as e:
        print(f"  ERROR opening: {e}")