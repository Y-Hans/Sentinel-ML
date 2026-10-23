"""Summarize v2_forensic_detail.jsonl into per-slice tables."""
import json, os, sys

INV = r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\investigation"
out = []
emit = out.append

rows = [json.loads(l) for l in open(os.path.join(INV, "v2_forensic_detail.jsonl"), encoding="utf-8") if l.strip()]

emit("=== HP VARIANTS ===")
for r in rows:
    if r["tag"].startswith("HP_ANNOUNCEMENT"):
        emit(f"{(r['note'] or 'HP'):22s} p_nb={r['p_nb']:.4f} {r['label']}")

inst_b = [r for r in rows if r["tag"].startswith("INSTITUTIONAL_") and r["tag"].endswith("_BENIGN")]
inst_m = [r for r in rows if r["tag"].startswith("INSTITUTIONAL_") and not r["tag"].endswith("_BENIGN")]

emit("\n=== INSTITUTIONAL BENIGN (16) — FP if label != BENIGN ===")
for r in inst_b:
    mark = "FP  " if r["label"] != "BENIGN" else "ok  "
    emit(f"{mark} p_nb={r['p_nb']:.4f} {r['text'][:95]!r}")

emit("\n=== INSTITUTIONAL MALICIOUS — TP if label != BENIGN ===")
for r in inst_m:
    mark = "TP  " if r["label"] != "BENIGN" else "MISS"
    emit(f"{mark} p_nb={r['p_nb']:.4f} {r['text'][:95]!r}")

sim = [r for r in rows if r["tag"] == "SIMULATION"]
sim_benign = [r for r in sim if str(r.get("gt", "")).startswith("BENIGN")]
sim_fp = [r for r in sim_benign if r["label"] != "BENIGN"]

emit("\n=== SIMULATION REAL-HISTORY FPs (benign ground truth, p_nb >= 0.704) ===")
for r in sorted(sim_fp, key=lambda x: -x["p_nb"]):
    outcome = r["note"].split("|")[-1]
    emit(f"p_nb={r['p_nb']:.4f} outcome={outcome:22s} sender={(r['sender'] or '')[:35]!r} text={r['text'][:80]!r}")

amb = [r for r in sim if r.get("gt", "") == "AMBIGUOUS_CONVERSATIONAL" and r["label"] != "BENIGN"]
emit("\n=== SIMULATION AMBIGUOUS flagged (44 total) ===")
for r in sorted(amb, key=lambda x: -x["p_nb"]):
    emit(f"p_nb={r['p_nb']:.4f} text={r['text'][:80]!r}")

emit("\n=== SIMULATION MALICIOUS (3 TRUE_POSITIVE_MALICIOUS_URL) ===")
for r in sim:
    if r.get("gt", "") == "TRUE_POSITIVE_MALICIOUS_URL":
        emit(f"p_nb={r['p_nb']:.4f} label={r['label']:9s} text={r['text'][:100]!r}")

emit("\n=== LEGACY 6sep FP CLASSES ===")
for r in rows:
    if r["tag"].startswith(("CLASS_", "REPLAY_", "HELLO")):
        emit(f"{r['tag']:26s} p_nb={r['p_nb']:.4f} {r['label']}")

nb = lambda r: r["label"] != "BENIGN"
emit("\n=== COUNTS (frozen V2, tau=0.704, no context) ===")
emit(f"institutional benign FPR : {sum(map(nb, inst_b))}/{len(inst_b)} = {sum(map(nb, inst_b))/max(1,len(inst_b)):.2%}")
emit(f"institutional mal recall : {sum(map(nb, inst_m))}/{len(inst_m)} = {sum(map(nb, inst_m))/max(1,len(inst_m)):.2%}")
emit(f"real-history benign FPR  : {len(sim_fp)}/{len(sim_benign)} = {len(sim_fp)/max(1,len(sim_benign)):.2%}")

with open(os.path.join(INV, "v2_summary.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("written", len(out), "lines")