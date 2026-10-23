"""
Candidate A: Multilingual MiniLM embeddings + Calibrated Classifier.
Uses sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 to encode semantic representations.
"""
import json
import pickle
import time
from pathlib import Path
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV

ROOT = Path(__file__).resolve().parents[2]
sys_eval = str(ROOT / "messages_v4_3/evaluation")
import sys
sys.path.insert(0, sys_eval)
from eval_suite import run_full_evaluation, read_jsonl, LABELS

OUT = ROOT / "messages_v4_3"

def run_candidate_a():
    print("--- Candidate A: Multilingual MiniLM Semantic Embeddings ---")
    t0 = time.time()
    model_name = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
    print(f"Loading encoder: {model_name}...")
    encoder = SentenceTransformer(model_name)
    
    train_path = OUT / "data/train_v4_3.jsonl"
    print(f"Loading training data from {train_path}...")
    train_rows = read_jsonl(train_path)
    print(f"Total training rows: {len(train_rows)}")

    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)

    print("Encoding training texts into dense semantic vectors (batch_size=64)...")
    t_enc = time.time()
    # Cache embeddings to disk to speed up subsequent experimentation
    cache_path = OUT / "data/train_v4_3_minilm_embs.npy"
    if cache_path.exists():
        print(f"Loading cached embeddings from {cache_path}...")
        X_train = np.load(cache_path)
    else:
        X_train = encoder.encode(train_texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
        np.save(cache_path, X_train)
    print(f"Encoded {len(train_texts)} texts in {time.time()-t_enc:.1f}s. Shape: {X_train.shape}")

    print("Training calibrated classifier on semantic embeddings...")
    base_clf = LogisticRegression(max_iter=1000, class_weight="balanced", C=1.0, random_state=42)
    base_clf.fit(X_train, y_train)

    # Prediction wrapper for eval_suite
    def predict_proba_fn(texts):
        embs = encoder.encode(texts, batch_size=64, show_progress_bar=False, normalize_embeddings=True)
        return base_clf.predict_proba(embs)

    print("Running universal evaluation suite across all 19 benchmark suites & splits...")
    res = run_full_evaluation(predict_proba_fn, threshold=None)
    
    threshold = res["threshold"]
    print(f"\nLocked Validation Threshold: {threshold}")
    val = res["validation"]
    print(f"Validation: Malicious {val['malicious_correct']}/{val['n_malicious']} ({val['malicious_recall']:.4f}), Benign FP {val['benign_fp']}/{val['n_benign']} ({val['benign_fpr']:.4f})")
    test = res["test"]
    print(f"Test:       Malicious {test['malicious_correct']}/{test['n_malicious']} ({test['malicious_recall']:.4f}), Benign FP {test['benign_fp']}/{test['n_benign']} ({test['benign_fpr']:.4f})")
    ood = res["ood"]
    print(f"OOD:        Malicious {ood['malicious_correct']}/{ood['n_malicious']} ({ood['malicious_recall']:.4f}), Benign FP {ood['benign_fp']}/{ood['n_benign']} ({ood['benign_fpr']:.4f})")

    print("\n--- Benchmark Slices ---")
    for bname, bm in res["benchmarks"].items():
        mal_str = f"{bm['malicious_correct']}/{bm['n_malicious']}" if bm['n_malicious'] > 0 else "N/A"
        ben_str = f"{bm['benign_fp']}/{bm['n_benign']}" if bm['n_benign'] > 0 else "N/A"
        rec_str = f"{bm['malicious_recall']:.4f}" if bm['malicious_recall'] is not None else "N/A"
        fpr_str = f"{bm['benign_fpr']:.4f}" if bm['benign_fpr'] is not None else "N/A"
        print(f"{bname:38s} | Malicious: {mal_str:>7s} ({rec_str:>6s}) | Benign FP: {ben_str:>7s} ({fpr_str:>6s})")

    res["model_name"] = "Candidate_A_Multilingual_MiniLM"
    res["encoder"] = model_name
    res["training_time_s"] = time.time() - t0

    out_metrics = OUT / "reports/candidate_a_metrics.json"
    with open(out_metrics, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved Candidate A results to {out_metrics}")

if __name__ == "__main__":
    run_candidate_a()
