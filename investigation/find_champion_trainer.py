"""Find which trainer script produced champion_v2 (s22) and which dataset it used."""
import os, re

MT = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml\model_training"
pats = {
    "champion_v2_model": re.compile(r"champion_v2_model", re.I),
    "s22": re.compile(r"\bs22\b"),
    "train_v8": re.compile(r"train_expanded_v8", re.I),
    "to_pickle": re.compile(r"(pickle\.dump|joblib\.dump)"),
    "threshold_0.704": re.compile(r"0\.704"),
}
hits = {}
for fn in sorted(os.listdir(MT)):
    if not fn.endswith(".py"):
        continue
    p = os.path.join(MT, fn)
    try:
        txt = open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    row = [k for k, rx in pats.items() if rx.search(txt)]
    if row:
        hits[fn] = row
for fn, row in sorted(hits.items()):
    print(f"{fn:42s} {', '.join(row)}")

print("\n--- dump sites detail ---")
for fn, row in sorted(hits.items()):
    if "champion_v2_model" not in row:
        continue
    p = os.path.join(MT, fn)
    txt = open(p, encoding="utf-8", errors="replace").read()
    print(f"\n### {fn}")
    for i, line in enumerate(txt.splitlines(), 1):
        if "champion_v2_model" in line or "load_dataset(" in line or "s22" in line.lower():
            print(f"  {i}: {line.strip()[:130]}")