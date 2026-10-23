"""Search both repos for key patterns; write results to a file."""
import os, re

ROOTS = [
    r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml",
    r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ai",
]
PATTERNS = {
    "INSTITUTIONAL_DAMPENING": None,
    "institutional_keywords": None,
    "instKeywords": None,
    "reUrgentThreatOverride": None,
    "institutional_": None,
}
EXCLUDE_DIRS = {".git", ".gradle", "build", "caches", "node_modules", "__pycache__",
                ".android-home", "gradle-home-codex", ".kilo", ".idea"}
EXTS = {".kt", ".py", ".md", ".json", ".java", ".xml", ".kts"}

hits = []
for root in ROOTS:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in EXTS:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception:
                continue
            for pat in PATTERNS:
                idxs = [m.start() for m in re.finditer(pat, content)]
                if idxs:
                    hits.append((pat, fp, len(idxs)))

out = os.path.join(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation", "pattern_hits.txt")
with open(out, "w", encoding="utf-8") as f:
    for pat, fp, n in sorted(hits):
        f.write(f"{pat} | {n} | {fp}\n")
print(f"{len(hits)} hits written to {out}")