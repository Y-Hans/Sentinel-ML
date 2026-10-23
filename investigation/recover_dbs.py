"""Recover original SQLite files from UTF-16LE-corrupted copies.

Hypothesis: sentinel_db / sentinel_db(1) are SQLite files that were opened in a
text editor and saved as Unicode (UTF-16 LE), mapping each original byte to one
UTF-16 code unit. Reversing: read file text (utf-16-le), encode latin-1 -> bytes.
"""
import os, sqlite3, hashlib

BASE = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml"
OUT = os.path.join(BASE, "investigation")

def recover(src):
    with open(src, "rb") as f:
        raw = f.read()
    # strip BOM if present
    if raw[:2] == b"\xff\xfe":
        raw = raw[2:]
    text = raw.decode("utf-16-le", errors="replace")
    # Any replacement char indicates a lossy conversion already occurred upstream.
    n_repl = text.count("\ufffd")
    data = text.encode("latin-1", errors="replace")
    return data, n_repl

for name in ["sentinel_db", "sentinel_db(1)"]:
    src = os.path.join(BASE, name)
    data, n_repl = recover(src)
    print(f"{name}: recovered {len(data)} bytes, replacements={n_repl}, "
          f"header={data[:16]!r}")
    if data[:16] == b"SQLite format 3\x00":
        out_path = os.path.join(OUT, name + ".recovered.db")
        with open(out_path, "wb") as f:
            f.write(data)
        h = hashlib.sha256(data).hexdigest()
        print(f"  wrote {out_path} sha256={h}")
        try:
            con = sqlite3.connect(out_path)
            tabs = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
            print(f"  VALID SQLite! tables: {tabs}")
            for t in tabs:
                n = con.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                print(f"    {t}: {n} rows")
            con.close()
        except Exception as e:
            print(f"  still malformed: {e}")
    else:
        print("  NOT SQLite after recovery")