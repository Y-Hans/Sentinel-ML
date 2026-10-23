"""Salvage records from malformed SQLite files by scanning for table b-tree leaf pages.

Simpler approach: use SQLite's deserialize + recover via the C API is not exposed.
Instead we parse the file manually enough to extract rows: walk sqlite_master if intact;
otherwise scan all pages for leaf-table b-tree pages (type 0x0D) and decode records.
"""
import sqlite3, struct, sys
from pathlib import Path

SRC = Path(r"C:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml")

def varint(b, i):
    r = 0
    for k in range(9):
        v = b[i + k]
        if k == 8:
            r = (r << 8) | v
            return r, i + 9
        r = (r << 7) | (v & 0x7F)
        if not (v & 0x80):
            return r, i + k + 1

def decode_record(b, i, page_end):
    """Decode a record at offset i. Returns (values, next_i) or None."""
    hdr_len, j = varint(b, i)
    hdr_end = i + hdr_len
    if hdr_end > page_end:
        return None
    serials = []
    while j < hdr_end:
        s, j = varint(b, j)
        serials.append(s)
    vals = []
    d = hdr_end
    for s in serials:
        if s == 0:
            vals.append(None)
        elif s <= 6:
            n = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}[s]
            vals.append(int.from_bytes(b[d:d+n], "big", signed=True))
            d += n
        elif s == 7:
            vals.append(struct.unpack(">d", b[d:d+8])[0]); d += 8
        elif s == 8:
            vals.append(0)
        elif s == 9:
            vals.append(1)
        elif s >= 13 and s % 2 == 1:
            n = (s - 13) // 2
            vals.append(b[d:d+n].decode("utf-8", "replace")); d += n
        elif s >= 12 and s % 2 == 0:
            n = (s - 12) // 2
            vals.append(b[d:d+n]); d += n
        else:
            return None
    return vals, d

def scan_leaf_pages(path):
    data = path.read_bytes()
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1:
        page_size = 65536
    rows = []
    npages = len(data) // page_size
    for pno in range(npages):
        base = pno * page_size
        off = base + (100 if pno == 0 else 0)
        if data[off] != 0x0D:  # leaf table b-tree page
            continue
        ncell = int.from_bytes(data[off+3:off+5], "big")
        cell_ptr_arr = off + 8
        for c in range(ncell):
            ptr = int.from_bytes(data[cell_ptr_arr+2*c:cell_ptr_arr+2*c+2], "big")
            ci = off + ptr
            if ci + 2 > base + page_size:
                continue
            try:
                payload_len, ci = varint(data, ci)
                rowid, ci = varint(data, ci)
                r = decode_record(data, ci, base + page_size)
                if r:
                    rows.append((pno, rowid, r[0]))
            except Exception:
                continue
    return rows

if __name__ == "__main__":
    target = sys.argv[1]
    p = SRC / target
    rows = scan_leaf_pages(p)
    print(target, "->", len(rows), "rows salvaged")
    out = SRC / "scratch" / (target.replace("(", "_").replace(")", "_") + ".rows.txt")
    with open(out, "w", encoding="utf-8") as f:
        for pno, rowid, vals in rows:
            f.write(f"page={pno} rowid={rowid} :: {vals!r}\n")
    print("wrote", out)
