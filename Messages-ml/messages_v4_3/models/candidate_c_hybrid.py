"""
Candidate C: Hybrid Subword Morphemes + Lightweight Intent Signals + Dense MiniLM Semantic Projection.
Combines subword char/word TFIDF with 16-dim MiniLM intent projection + 14 core structural signals.
"""
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import json
import pickle
import time
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sentence_transformers import SentenceTransformer
from sklearn.decomposition import TruncatedSVD

ROOT = Path(__file__).resolve().parents[2]
sys_eval = str(ROOT / "messages_v4_3/evaluation")
sys_scripts = str(ROOT / "scripts")
import sys
sys.path.insert(0, sys_eval)
sys.path.insert(0, sys_scripts)
from eval_suite import run_full_evaluation, read_jsonl, LABELS
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector

OUT = ROOT / "messages_v4_3"

def run_candidate_c():
    print("--- Candidate C: Hybrid Subword + Intent Projection Architecture ---", flush=True)
    t0 = time.time()

    train_path = OUT / "data/train_v4_3.jsonl"
    print(f"Loading training data from {train_path}...", flush=True)
    train_rows = read_jsonl(train_path)
    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)
    print(f"Total training rows: {len(train_rows)}", flush=True)

    # 1. Subword representations
    print("Fitting subword char-wb (1500 dims) and word (1000 dims) vectorizers...", flush=True)
    word_vec = TfidfVectorizer(max_features=1000, ngram_range=(1, 2), sublinear_tf=True)
    char_vec = TfidfVectorizer(max_features=1500, analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
    X_word = word_vec.fit_transform(train_texts).toarray()
    X_char = char_vec.fit_transform(train_texts).toarray()

    # 2. Dense Semantic Embeddings + TruncatedSVD projection to 32 dimensions
    print("Loading MiniLM encoder and computing semantic projection...", flush=True)
    encoder = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
    cache_path = OUT / "data/train_v4_3_minilm_embs.npy"
    if cache_path.exists():
        print(f"Loading cached embeddings from {cache_path}...", flush=True)
        raw_embs = np.load(cache_path)
    else:
        raw_embs = encoder.encode(train_texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
        np.save(cache_path, raw_embs)
    
    print("Fitting TruncatedSVD (32 components) on semantic embeddings...", flush=True)
    svd = TruncatedSVD(n_components=32, random_state=42)
    X_sem = svd.fit_transform(raw_embs)
    print(f"Semantic projection shape: {X_sem.shape}", flush=True)

    # 3. Deterministic 70-feature vector
    print("Extracting deterministic tabular features...", flush=True)
    fconfig = FeatureConfig()
    X_det = np.asarray([extract_feature_vector(t, None, fconfig) for t in train_texts], dtype=np.float32)

    # 4. Concatenate: [70 det, 1000 word, 1500 char, 32 semantic] = 2602 dimensions
    X_train = np.hstack([X_det, X_word, X_char, X_sem]).astype(np.float32)
    print(f"Full feature matrix shape: {X_train.shape}", flush=True)

    print("Fitting standard scaler...", flush=True)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("Training HistGradientBoostingClassifier...", flush=True)
    clf = HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.08,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        class_weight="balanced",
        random_state=20260914,
    )
    clf.fit(X_train_scaled, y_train)
    print(f"Model fitted in {time.time()-t0:.1f}s", flush=True)

    def predict_proba_fn(texts):
        det = np.asarray([extract_feature_vector(t, None, fconfig) for t in texts], dtype=np.float32)
        w = word_vec.transform(texts).toarray()
        c = char_vec.transform(texts).toarray()
        e = encoder.encode(texts, batch_size=64, show_progress_bar=False, normalize_embeddings=True)
        s = svd.transform(e)
        X = np.hstack([det, w, c, s]).astype(np.float32)
        return clf.predict_proba(scaler.transform(X))

    print("Running universal evaluation suite across all 19 benchmark suites & splits...", flush=True)
    res = run_full_evaluation(predict_proba_fn, threshold=None)

    threshold = res["threshold"]
    print(f"\nLocked Validation Threshold: {threshold}", flush=True)
    val = res["validation"]
    print(f"Validation: Malicious {val['malicious_correct']}/{val['n_malicious']} ({val['malicious_recall']:.4f}), Benign FP {val['benign_fp']}/{val['n_benign']} ({val['benign_fpr']:.4f})", flush=True)
    test = res["test"]
    print(f"Test:       Malicious {test['malicious_correct']}/{test['n_malicious']} ({test['malicious_recall']:.4f}), Benign FP {test['benign_fp']}/{test['n_benign']} ({test['benign_fpr']:.4f})", flush=True)
    ood = res["ood"]
    print(f"OOD:        Malicious {ood['malicious_correct']}/{ood['n_malicious']} ({ood['malicious_recall']:.4f}), Benign FP {ood['benign_fp']}/{ood['n_benign']} ({ood['benign_fpr']:.4f})", flush=True)

    print("\n--- Benchmark Slices ---", flush=True)
    for bname, bm in res["benchmarks"].items():
        mal_str = f"{bm['malicious_correct']}/{bm['n_malicious']}" if bm['n_malicious'] > 0 else "N/A"
        ben_str = f"{bm['benign_fp']}/{bm['n_benign']}" if bm['n_benign'] > 0 else "N/A"
        rec_str = f"{bm['malicious_recall']:.4f}" if bm['malicious_recall'] is not None else "N/A"
        fpr_str = f"{bm['benign_fpr']:.4f}" if bm['benign_fpr'] is not None else "N/A"
        print(f"{bname:38s} | Malicious: {mal_str:>7s} ({rec_str:>6s}) | Benign FP: {ben_str:>7s} ({fpr_str:>6s})", flush=True)

    res["model_name"] = "Candidate_C_Hybrid_Subword_Semantic_Trees"
    res["training_time_s"] = time.time() - t0

    out_metrics = OUT / "reports/candidate_c_metrics.json"
    with open(out_metrics, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved Candidate C results to {out_metrics}", flush=True)

    # Save artifacts
    model_dir = OUT / "models/candidate_c"
    model_dir.mkdir(parents=True, exist_ok=True)
    with open(model_dir / "model.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open(model_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(model_dir / "word_vec.pkl", "wb") as f:
        pickle.dump(word_vec, f)
    with open(model_dir / "char_vec.pkl", "wb") as f:
        pickle.dump(char_vec, f)
    with open(model_dir / "svd.pkl", "wb") as f:
        pickle.dump(svd, f)
    print(f"Artifacts saved to {model_dir}", flush=True)

if __name__ == "__main__":
    run_candidate_c()
