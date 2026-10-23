import sqlite3
from pathlib import Path

SRC = Path(r"C:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml")

for name in ["sentinel_reconstructed.db", "test_fixed.db"]:
    p = SRC / name
    try:
        con = sqlite3.connect(str(p))
        tables = con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
        print("===", name)
        for t, s in tables:
            n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
            print(f"-- {t} ({n} rows)")
            print((s or "")[:600])
        con.close()
    except Exception as e:
        print("===", name, "ERROR:", e)

# Also try .recover-style salvage on the decoded UTF-16 conversions
for out in ["sentinel_db_newer.db", "sentinel_db_older.db"]:
    p = SRC / "scratch" / out
    if not p.exists():
        continue
    try:
        con = sqlite3.connect(str(p))
        tables = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        print("=== decoded", out, "->", [t[0] for t in tables])
        con.close()
    except Exception as e:
        print("=== decoded", out, "ERROR:", e)
