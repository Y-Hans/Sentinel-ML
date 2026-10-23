"""
Universal evaluation suite for Sentinel Messages V4.3 candidates.
Reports exact counts, denominators, recalls, and FPRs across all evaluation splits and benchmark suites.
"""
import json
from pathlib import Path
from typing import Callable, Dict, List, Tuple
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score

ROOT = Path(__file__).resolve().parents[2]
LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
REV_LABELS = {0: "BENIGN", 1: "SUSPICIOUS_SPAM", 2: "MALICIOUS"}

def read_jsonl(p: Path) -> List[Dict]:
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

def get_benchmark_paths() -> List[Path]:
    p1 = list((ROOT / "data/benchmarks").glob("*.jsonl"))
    p2 = list((ROOT.parent / "7sep_messages_v3/data").glob("bench_*.jsonl"))
    return sorted(p1 + p2, key=lambda x: x.name)

def compute_detailed_metrics(rows: List[Dict], probs: np.ndarray, threshold: float) -> Dict:
    y_true = np.array([LABELS.get(r.get("security_label"), 0) for r in rows], dtype=np.int32)
    p_nonbenign = probs[:, 1] + probs[:, 2]
    # Prediction policy: if P(non-benign) >= threshold -> max(SUSPICIOUS, MALICIOUS), else BENIGN
    y_pred = np.where(p_nonbenign >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

    n_total = len(rows)
    mal_mask = (y_true == 2)
    ben_mask = (y_true == 0)
    susp_mask = (y_true == 1)

    n_mal = int(mal_mask.sum())
    n_ben = int(ben_mask.sum())
    n_susp = int(susp_mask.sum())

    # Malicious detection
    mal_correct = int((y_pred[mal_mask] == 2).sum())
    mal_missed = n_mal - mal_correct
    mal_recall = float(mal_correct / n_mal) if n_mal > 0 else None

    # Non-benign detection (catches either suspicious or malicious)
    nonben_mask = (y_true != 0)
    n_nonben = int(nonben_mask.sum())
    nonben_correct = int((y_pred[nonben_mask] != 0).sum())
    nonben_recall = float(nonben_correct / n_nonben) if n_nonben > 0 else None

    # Benign false positives
    ben_fp = int((y_pred[ben_mask] != 0).sum())
    ben_clean = n_ben - ben_fp
    ben_fpr = float(ben_fp / n_ben) if n_ben > 0 else None

    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist()

    return {
        "n_total": n_total,
        "n_malicious": n_mal,
        "malicious_correct": mal_correct,
        "malicious_missed": mal_missed,
        "malicious_recall": mal_recall,
        "n_benign": n_ben,
        "benign_fp": ben_fp,
        "benign_clean": ben_clean,
        "benign_fpr": ben_fpr,
        "n_nonbenign": n_nonben,
        "nonbenign_correct": nonben_correct,
        "nonbenign_recall": nonben_recall,
        "macro_f1": macro_f1,
        "confusion_matrix": cm,
        "threshold": threshold,
    }

def select_threshold_on_validation(val_rows: List[Dict], val_probs: np.ndarray, max_fpr: float = 0.02) -> float:
    best_t = 0.70
    best_recall = -1.0
    best_f1 = -1.0
    
    for t in np.arange(0.30, 0.95, 0.01):
        t_val = float(round(t, 2))
        m = compute_detailed_metrics(val_rows, val_probs, t_val)
        fpr = m["benign_fpr"] if m["benign_fpr"] is not None else 0.0
        rec = m["malicious_recall"] if m["malicious_recall"] is not None else 0.0
        f1 = m["macro_f1"]
        
        if fpr <= max_fpr:
            if rec > best_recall or (rec == best_recall and f1 > best_f1):
                best_recall = rec
                best_f1 = f1
                best_t = t_val

    return best_t

def run_full_evaluation(predict_proba_fn: Callable[[List[str]], np.ndarray], threshold: float = None) -> Dict:
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
    test_rows = read_jsonl(ROOT / "data/processed/test.jsonl")
    ood_rows = read_jsonl(ROOT / "data/processed/ood.jsonl")

    val_texts = [r.get("raw_text", "") for r in val_rows]
    val_probs = predict_proba_fn(val_texts)

    if threshold is None:
        threshold = select_threshold_on_validation(val_rows, val_probs, max_fpr=0.02)

    val_metrics = compute_detailed_metrics(val_rows, val_probs, threshold)

    test_texts = [r.get("raw_text", "") for r in test_rows]
    test_probs = predict_proba_fn(test_texts)
    test_metrics = compute_detailed_metrics(test_rows, test_probs, threshold)

    ood_texts = [r.get("raw_text", "") for r in ood_rows]
    ood_probs = predict_proba_fn(ood_texts)
    ood_metrics = compute_detailed_metrics(ood_rows, ood_probs, threshold)

    bench_results = {}
    for bp in get_benchmark_paths():
        rows = read_jsonl(bp)
        if not rows:
            continue
        texts = [r.get("raw_text", "") for r in rows]
        probs = predict_proba_fn(texts)
        bench_results[bp.name] = compute_detailed_metrics(rows, probs, threshold)

    return {
        "threshold": threshold,
        "validation": val_metrics,
        "test": test_metrics,
        "ood": ood_metrics,
        "benchmarks": bench_results,
    }
