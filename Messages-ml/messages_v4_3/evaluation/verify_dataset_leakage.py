"""
Deep Dataset and Leakage Verification for Sentinel Messages V4.3.
"""
import json
import re
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]

def normalize_text(text: str) -> str:
    t = text.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t

def get_tokens(text: str) -> set:
    return set(normalize_text(text).split())

def jaccard(s1: set, s2: set) -> float:
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)

def main():
    train_path = ROOT / "messages_v4_3/data/train_v4_3.jsonl"
    manifest_path = ROOT / "messages_v4_3/data/dataset_manifest_v4_3.json"

    print("=== 1. VERIFYING DATASET PROPERTIES ===")
    train_rows = [json.loads(line) for line in open(train_path, encoding="utf-8") if line.strip()]
    print(f"Exact training count: {len(train_rows)}")

    label_counts = Counter(r.get("security_label") for r in train_rows)
    print("Exact label distribution:", dict(label_counts))

    source_counts = Counter(r.get("source_dataset", "unknown") for r in train_rows)
    print("Exact source distribution:")
    for s, c in source_counts.most_common():
        print(f"  {s:<35s}: {c:6d}")

    # Hinglish detection (records marked with language: hinglish or from hinglish sources)
    hinglish_records = [
        r for r in train_rows 
        if r.get("language") == "hinglish" or "hinglish" in r.get("source_dataset", "").lower()
    ]
    print(f"Exact Hinglish count (tagged/source): {len(hinglish_records)}")

    # Raw duplicates
    raw_texts = [r.get("raw_text", "") for r in train_rows]
    raw_counter = Counter(raw_texts)
    raw_dups = sum(c - 1 for c in raw_counter.values() if c > 1)
    unique_raw = len(raw_counter)
    print(f"Raw unique texts: {unique_raw} | Raw duplicates: {raw_dups}")

    # Normalized duplicates
    norm_texts = [normalize_text(t) for t in raw_texts]
    norm_counter = Counter(norm_texts)
    norm_dups = sum(c - 1 for c in norm_counter.values() if c > 1)
    unique_norm = len(norm_counter)
    print(f"Normalized unique texts: {unique_norm} | Normalized duplicates: {norm_dups}")

    print("\n=== 2. DEEP DATA LEAKAGE VERIFICATION ===")
    # Collect all protected evaluation sets
    eval_files = [
        ("Test Split", ROOT / "data/processed/test.jsonl"),
        ("OOD Split", ROOT / "data/processed/ood.jsonl"),
    ]
    eval_files += [(p.stem, p) for p in (ROOT / "data/benchmarks").glob("*.jsonl")]
    eval_files += [(p.stem, p) for p in (ROOT.parent / "7sep_messages_v3/data").glob("bench_*.jsonl")]

    total_eval_records = 0
    eval_exact_texts = {}
    eval_norm_texts = {}
    eval_ids = set()

    for name, ep in eval_files:
        if not ep.exists(): continue
        rows = [json.loads(x) for x in open(ep, encoding="utf-8") if x.strip()]
        total_eval_records += len(rows)
        for idx, r in enumerate(rows):
            eid = r.get("id") or r.get("message_id") or f"{name}_{idx}"
            eval_ids.add(eid)
            txt = r.get("raw_text", "")
            eval_exact_texts[txt] = (name, eid)
            eval_norm_texts[normalize_text(txt)] = (name, eid, txt)

    print(f"Total protected evaluation records gathered: {total_eval_records}")
    print(f"Total unique protected exact texts:        {len(eval_exact_texts)}")
    print(f"Total unique protected normalized texts:   {len(eval_norm_texts)}")

    # Check Exact Overlap
    exact_leakage = []
    for r in train_rows:
        t = r.get("raw_text", "")
        if t in eval_exact_texts:
            exact_leakage.append((r.get("id"), eval_exact_texts[t], t))

    print(f"\nExact Text Overlap Violations: {len(exact_leakage)}")
    if exact_leakage:
        print("  SAMPLE EXACT LEAKS:", exact_leakage[:3])

    # Check ID Overlap
    train_ids = set(r.get("id") for r in train_rows if r.get("id"))
    id_leakage = train_ids & eval_ids
    print(f"Message ID Collision Violations: {len(id_leakage)}")
    if id_leakage:
        print("  SAMPLE ID COLLISIONS:", list(id_leakage)[:3])

    # Check Normalized Text Overlap
    norm_leakage = []
    for r in train_rows:
        nt = normalize_text(r.get("raw_text", ""))
        if nt in eval_norm_texts:
            # Check if this was an actual exact overlap or a template collapse
            norm_leakage.append((r.get("id"), eval_norm_texts[nt][0], r.get("raw_text"), eval_norm_texts[nt][2]))

    print(f"Normalized Text Overlap Count: {len(norm_leakage)}")
    if norm_leakage:
        print(f"  Sample Normalized Matches (e.g. template collisions like OTP or numbers replaced by <NUM>):")
        for tid, sname, t_train, t_eval in norm_leakage[:5]:
            print(f"    Train [{tid}]: {t_train[:60]}...")
            print(f"    Eval  [{sname}]: {t_eval[:60]}...")

    # Near-Duplicate Risk: High Jaccard similarity (> 0.85 token overlap) on hard challenge benchmarks
    print("\n=== 3. NEAR-DUPLICATE RISK ON CHALLENGE BENCHMARKS ===")
    challenge_benchmarks = ["bench_hinglish_robustness", "bench_adversarial_semantic_pairs", "bench_sentinel_replay"]
    high_sim_pairs = []

    train_tokens = [(r.get("id"), get_tokens(r.get("raw_text", "")), r.get("raw_text", "")) for r in train_rows[:5000]] # sample 5k train
    for name, ep in eval_files:
        if name not in challenge_benchmarks: continue
        rows = [json.loads(x) for x in open(ep, encoding="utf-8") if x.strip()]
        for r in rows:
            etok = get_tokens(r.get("raw_text", ""))
            if len(etok) < 4: continue
            for tid, ttok, t_raw in train_tokens:
                j = jaccard(ttok, etok)
                if j >= 0.85:
                    high_sim_pairs.append((name, r.get("raw_text"), tid, t_raw, j))

    print(f"High-similarity pairs found against sample train (Jaccard >= 0.85): {len(high_sim_pairs)}")
    if high_sim_pairs:
        for bname, eraw, tid, traw, j in high_sim_pairs[:3]:
            print(f"  [{bname}] Jaccard={j:.2f}:")
            print(f"    Eval:  {eraw}")
            print(f"    Train: {traw}")

if __name__ == "__main__":
    main()
