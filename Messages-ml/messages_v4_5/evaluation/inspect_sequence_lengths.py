import json
from pathlib import Path
from transformers import AutoTokenizer
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")

def read_texts(p: Path):
    texts = []
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                t = (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()
                texts.append(t)
    return texts

def main():
    tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/all-MiniLM-L6-v2", local_files_only=True)

    files = [
        ("Train (train_v4_4_b)", ROOT / "messages_v4_4/data/train_v4_4_b.jsonl"),
        ("Validation", ROOT / "data/processed/val.jsonl"),
        ("Primary TEST", ROOT / "data/processed/test.jsonl"),
        ("Primary OOD", ROOT / "data/processed/ood.jsonl"),
    ]
    for p in sorted((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl")):
        files.append((f"Holdout: {p.stem}", p))

    stats = {}
    print(f"{'Split / Dataset':<35} | {'Count':<6} | {'Max':<5} | {'p50':<4} | {'p90':<4} | {'p95':<4} | {'p99':<4} | {'>128 (%)':<8}")
    print("-" * 85)

    all_texts = []
    for name, p in files:
        if not p.exists():
            continue
        texts = read_texts(p)
        all_texts.extend(texts)
        lens = [len(tokenizer.encode(t, truncation=False)) for t in texts]
        arr = np.array(lens)
        pct_trunc = float(np.mean(arr > 128) * 100)
        stats[name] = {
            "count": len(texts),
            "max": int(np.max(arr)),
            "p50": float(np.percentile(arr, 50)),
            "p90": float(np.percentile(arr, 90)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
            "pct_gt_128": pct_trunc,
        }
        print(f"{name:<35} | {len(texts):<6} | {int(np.max(arr)):<5} | {int(np.percentile(arr, 50)):<4} | {int(np.percentile(arr, 90)):<4} | {int(np.percentile(arr, 95)):<4} | {int(np.percentile(arr, 99)):<4} | {pct_trunc:<8.2f}%")

    all_arr = np.array([len(tokenizer.encode(t, truncation=False)) for t in all_texts])
    print("-" * 85)
    print(f"{'OVERALL COMBINED':<35} | {len(all_texts):<6} | {int(np.max(all_arr)):<5} | {int(np.percentile(all_arr, 50)):<4} | {int(np.percentile(all_arr, 90)):<4} | {int(np.percentile(all_arr, 95)):<4} | {int(np.percentile(all_arr, 99)):<4} | {float(np.mean(all_arr > 128)*100):<8.2f}%")

    with open(ROOT / "messages_v4_5/reports/sequence_length_audit.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

if __name__ == "__main__":
    main()
