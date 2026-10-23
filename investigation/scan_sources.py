"""Scan sentinel-ml sources (excluding data blobs) for champion_v2 / s22 producers."""
import os, re, io
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
_log = io.open(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation\scan_sources_result.txt", "w", encoding="utf-8")
def print(*a, **k):
    _log.write(" ".join(str(x) for x in a) + "\n")

ROOT = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml"
SKIP_DIRS = {"data", ".git", "__pycache__", "node_modules", ".gradle", "build"}
p_champ = re.compile(r"champion_v2", re.I)
p_s22 = re.compile(r"\bs22\b", re.I)
p_dump = re.compile(r"(pickle\.dump|joblib\.dump)")

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        if os.path.splitext(fn)[1].lower() not in (".py", ".md", ".json", ".kt", ".txt", ".yaml", ".yml"):
            continue
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, ROOT)
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        c, s = bool(p_champ.search(txt)), bool(p_s22.search(txt))
        if not (c or s):
            continue
        lines = txt.splitlines()
        marks = []
        for i, line in enumerate(lines, 1):
            if p_champ.search(line) or p_s22.search(line):
                tag = "DUMP" if p_dump.search(line) else ""
                marks.append(f"    {i}{':' + tag if tag else ':'} {line.strip()[:120]}")
        print(f"\n### {rel}  (champ={c} s22={s})  hits={len(marks)}")
        for m in marks[:12]:
            print(m)