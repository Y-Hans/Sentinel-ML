import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
EXP_DIR = ROOT / "messages_v4_5/experiments/next_architecture"
DATA_DIR = EXP_DIR / "data"

def norm_case_ws(s: str) -> str:
    return " ".join(s.lower().split())

def norm_url(s: str) -> str:
    t = s.lower()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    return " ".join(t.split())

def norm_aggressive(s: str) -> str:
    t = s.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return " ".join(t.split())

def tokenize(s: str) -> set:
    return set(re.findall(r"\b\w+\b", s.lower()))

def jaccard(s1: set, s2: set) -> float:
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)

def get_text(r: dict) -> str:
    return (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()

print("=" * 80)
print("BUILDING CONTROLLED INDEPENDENT VALIDATION SET")
print("=" * 80)

# Step 1: Index all protected datasets
print("1. Indexing all protected evaluation suites and auxiliary training data...")
protected_paths = [
    ROOT / "data/processed/test.jsonl",
    ROOT / "data/processed/ood.jsonl",
    ROOT / "data/processed/val.jsonl",
    ROOT / "data/processed/train.jsonl",
    DATA_DIR / "auxiliary_train.jsonl",
]
protected_paths += list((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))
protected_paths += list((ROOT / "data/benchmarks").glob("*.jsonl"))
sim_path = ROOT.parent / "6sep/simulation/SIMULATION_CASES.jsonl"
if sim_path.exists():
    protected_paths.append(sim_path)

prot_exact = set()
prot_case_ws = set()
prot_url_norm = set()
prot_aggr = set()
prot_ids = set()
prot_tokens = [] # list of (id, text, set_of_tokens)

# Inverted index for fast Jaccard >= 0.70 checking
inverted_index = defaultdict(list)

for p in protected_paths:
    if not p.exists(): continue
    for line in open(p, "r", encoding="utf-8", errors="ignore"):
        if not line.strip(): continue
        r = json.loads(line)
        t = get_text(r)
        if not t: continue
        mid = str(r.get("message_id") or r.get("id") or r.get("original_id") or "")
        if mid:
            prot_ids.add(mid)
        prot_exact.add(t)
        prot_case_ws.add(norm_case_ws(t))
        prot_url_norm.add(norm_url(t))
        aggr = norm_aggressive(t)
        prot_aggr.add(aggr)
        toks = tokenize(aggr)
        if toks:
            idx = len(prot_tokens)
            prot_tokens.append((mid, t, toks))
            for tok in toks:
                inverted_index[tok].append(idx)

print(f"Total protected records indexed: {len(prot_tokens)}")
print(f"Unique exact: {len(prot_exact)}, Unique aggressive: {len(prot_aggr)}, Unique IDs: {len(prot_ids)}")

def check_isolation(text: str, mid: str = ""):
    """Returns (is_clean, failure_reason)"""
    if not text:
        return False, "EMPTY_TEXT"
    if mid and mid in prot_ids:
        return False, f"ID_COLLISION: {mid}"
    if text in prot_exact:
        return False, "EXACT_COLLISION"
    if norm_case_ws(text) in prot_case_ws:
        return False, "CASE_WS_COLLISION"
    if norm_url(text) in prot_url_norm:
        return False, "URL_NORM_COLLISION"
    aggr = norm_aggressive(text)
    if aggr in prot_aggr:
        return False, "AGGRESSIVE_NORM_COLLISION"
    
    # Check Jaccard >= 0.70 using inverted index
    toks = tokenize(aggr)
    if not toks:
        return False, "NO_TOKENS"
    
    candidate_indices = set()
    for tok in toks:
        candidate_indices.update(inverted_index.get(tok, []))
    
    len_cand = len(toks)
    min_len = int(len_cand * 0.70)
    max_len = int(len_cand / 0.70) + 1
    
    for c_idx in candidate_indices:
        _, p_text, p_toks = prot_tokens[c_idx]
        if min_len <= len(p_toks) <= max_len:
            j = len(toks & p_toks) / len(toks | p_toks)
            if j >= 0.70:
                return False, f"JACCARD_COLLISION ({j:.3f}): '{p_text[:60]}...'"
                
    return True, "CLEAN"

print("\nIsolation checker initialized and verified.")
