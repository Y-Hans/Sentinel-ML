"""
Candidate D: Sentinel Messages V4.3 Primary Release Architecture.
High-capacity Subword Morphemes (char_wb 2-5, 2500) + Word (1-2, 1500) + 15 Structural Non-Lexical Signals.
Trained on the 19,070-record contrastive and Hinglish dataset with HistGradientBoostingClassifier.
"""
import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

import json
import pickle
import re
import time
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[2]
sys_eval = str(ROOT / "messages_v4_3/evaluation")
import sys
sys.path.insert(0, sys_eval)
from eval_suite import run_full_evaluation, read_jsonl, LABELS

OUT = ROOT / "messages_v4_3"

RE_URL = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
RE_PHONE = re.compile(r"(?:\+91|0)?[6-9]\d{9}")

def extract_structural_signals(text: str) -> np.ndarray:
    """Extracts 18 non-lexical, language-independent structural signals."""
    t = text.strip()
    length = max(1, len(t))
    words = t.split()
    w_count = len(words)
    avg_w_len = sum(len(w) for w in words) / max(1, w_count)

    digits = sum(c.isdigit() for c in t)
    uppers = sum(c.isupper() for c in t)
    specials = sum(not c.isalnum() and not c.isspace() for c in t)

    urls = RE_URL.findall(t)
    url_count = len(urls)
    has_url = 1.0 if url_count > 0 else 0.0

    phones = RE_PHONE.findall(t)
    phone_count = len(phones)
    has_phone = 1.0 if phone_count > 0 else 0.0

    text_no_url = RE_URL.sub("", t)
    is_question = 1.0 if "?" in text_no_url else 0.0
    is_short = 1.0 if w_count <= 8 else 0.0

    is_naked_url = 1.0 if (has_url and (w_count <= 2 or len(urls[0]) >= 0.7 * length)) else 0.0
    has_suspicious_tld = 1.0 if re.search(r"\.(?:cc|xyz|top|live|click|site|club|buzz|info|tk|ml|ga|cf|gq|su|work|shop|vip)(?:/|\?|:|$)", t, re.I) else 0.0
    has_hex_or_ip_url = 1.0 if (re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", t) or re.search(r"[a-f0-9]{16,}", t, re.I) or "::" in t) else 0.0
    is_suspicious_naked_url = 1.0 if (is_naked_url and (has_suspicious_tld or has_hex_or_ip_url)) else 0.0

    digit_ratio = digits / length
    upper_ratio = uppers / length
    special_ratio = specials / length

    return np.array([
        float(length),
        float(w_count),
        float(avg_w_len),
        float(digits),
        float(digit_ratio),
        float(uppers),
        float(upper_ratio),
        float(specials),
        float(special_ratio),
        float(url_count),
        has_url,
        float(phone_count),
        has_phone,
        is_question,
        is_short,
        is_naked_url,
        has_suspicious_tld,
        has_hex_or_ip_url,
        is_suspicious_naked_url,
    ], dtype=np.float32)

def run_candidate_d():
    print("--- Candidate D: Sentinel Messages V4.3 Primary Release Architecture ---", flush=True)
    t0 = time.time()
    train_path = OUT / "data/train_v4_3.jsonl"
    print(f"Loading training data from {train_path}...", flush=True)
    train_rows = read_jsonl(train_path)
    train_texts = [r.get("raw_text", "") for r in train_rows]
    y_train = np.array([LABELS.get(r.get("security_label"), 0) for r in train_rows], dtype=np.int32)
    print(f"Total training rows: {len(train_rows)}", flush=True)

    print("Fitting subword char-wb vectorizer (char_wb 2-5, 2500 dims) and word vectorizer (1-2 ngrams, 1500 dims)...", flush=True)
    word_vec = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), sublinear_tf=True)
    char_vec = TfidfVectorizer(max_features=2500, analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)

    X_word = word_vec.fit_transform(train_texts).toarray()
    X_char = char_vec.fit_transform(train_texts).toarray()
    X_struct = np.asarray([extract_structural_signals(t) for t in train_texts], dtype=np.float32)

    X_train = np.hstack([X_struct, X_word, X_char]).astype(np.float32)
    print(f"Full feature matrix shape: {X_train.shape} (19 structural + 1500 word + 2500 char = 4019 dims)", flush=True)

    print("Fitting standard scaler...", flush=True)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print("Training HistGradientBoostingClassifier (max_iter=300, learning_rate=0.08)...", flush=True)
    clf = HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.08,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        class_weight={0: 1.5, 1: 1.0, 2: 1.0},
        random_state=20260914,
    )
    clf.fit(X_train_scaled, y_train)
    print(f"Model fitted in {time.time()-t0:.1f}s", flush=True)

    def predict_proba_fn(texts):
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        w = word_vec.transform(texts).toarray()
        c = char_vec.transform(texts).toarray()
        X = np.hstack([st, w, c]).astype(np.float32)
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

    res["model_name"] = "Candidate_D_V4_3_Release"
    res["training_time_s"] = time.time() - t0

    out_metrics = OUT / "reports/candidate_d_metrics.json"
    with open(out_metrics, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved Candidate D results to {out_metrics}", flush=True)

    # Save artifacts
    model_dir = OUT / "models/candidate_d"
    model_dir.mkdir(parents=True, exist_ok=True)
    with open(model_dir / "model.pkl", "wb") as f:
        pickle.dump(clf, f)
    with open(model_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(model_dir / "word_vec.pkl", "wb") as f:
        pickle.dump(word_vec, f)
    with open(model_dir / "char_vec.pkl", "wb") as f:
        pickle.dump(char_vec, f)
    print(f"Artifacts saved to {model_dir}", flush=True)

if __name__ == "__main__":
    run_candidate_d()
