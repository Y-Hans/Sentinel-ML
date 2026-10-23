"""
Diagnosis of Institutional Regression for Sentinel Messages V4.4 RC2 - Experiment 3.
"""
import json
import pickle
import sys
from pathlib import Path
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from candidate_d_v4_3 import extract_structural_signals

def main():
    print("=" * 80)
    print("DIAGNOSIS: INSTITUTIONAL REGRESSION MECHANISM")
    print("=" * 80)

    # 1. Load Exp2 model
    exp2_dir = ROOT / "messages_v4_4/models/rc2_experiment_2"
    with open(exp2_dir / "model.pkl", "rb") as f: m = pickle.load(f)
    with open(exp2_dir / "scaler.pkl", "rb") as f: s = pickle.load(f)
    with open(exp2_dir / "word_vec.pkl", "rb") as f: w = pickle.load(f)
    with open(exp2_dir / "char_vec.pkl", "rb") as f: c = pickle.load(f)

    # 2. Check training data for institutional terms
    train_path = ROOT / "messages_v4_4/data/train_v4_4_rc2_exp2.jsonl"
    rows = [json.loads(line) for line in open(train_path, encoding="utf-8") if line.strip()]
    
    terms = [
        "share otp", "do not share otp", "never share otp", "share your otp", "send otp",
        "google workspace", "workspace", "procured", "faculty", "announcement", "announcements",
        "student discount", "internship", "scholarship", "placement", "corporate partnership",
        "campus wi-fi", "processing fee", "enter cvv", "upi transfer required", "account suspended"
    ]

    print("\nTERM FREQUENCIES IN TRAINING SET (train_v4_4_rc2_exp2.jsonl):")
    print(f"{'Term':<26} | {'BENIGN':<8} | {'SPAM':<8} | {'MALICIOUS':<10}")
    print("-" * 60)
    for term in terms:
        cnts = {"BENIGN": 0, "SUSPICIOUS_SPAM": 0, "MALICIOUS": 0}
        for r in rows:
            txt = (r.get("raw_text") or r.get("text") or "").lower()
            lbl = r.get("security_label") or r.get("label")
            if term in txt and lbl in cnts:
                cnts[lbl] += 1
        print(f"{term:<26} | {cnts['BENIGN']:<8} | {cnts['SUSPICIOUS_SPAM']:<8} | {cnts['MALICIOUS']:<10}")

    # 3. Analyze the 7 failed institutional malicious records
    bench_path = ROOT / "data/benchmarks/slice_institutional_partnerships.jsonl"
    bench_rows = [json.loads(line) for line in open(bench_path, encoding="utf-8") if line.strip()]
    mal_bench = [r for r in bench_rows if r.get("security_label") == "MALICIOUS"]

    def score_text(txt):
        st = np.asarray([extract_structural_signals(txt)], dtype=np.float32)
        wv = w.transform([txt]).toarray()
        cv = c.transform([txt]).toarray()
        X = np.hstack([st, wv, cv]).astype(np.float32)
        probs = m.predict_proba(s.transform(X))[0]
        return probs

    print("\nDETAILED ANALYSIS OF 16 BENCHMARK MALICIOUS SAMPLES:")
    print(f"{'ID':<3} | {'P(MAL)':<8} | {'P(MAL+SPAM)':<12} | {'Active Word Feats':<40} | Text")
    print("-" * 120)
    for i, r in enumerate(mal_bench):
        txt = r["raw_text"]
        probs = score_text(txt)
        p_nb = probs[1] + probs[2]
        
        wv = w.transform([txt]).toarray()[0]
        w_names = np.array(w.get_feature_names_out())
        active = list(w_names[wv > 0])
        
        print(f"{i:2d}  | {probs[2]:<8.4f} | {p_nb:<12.4f} | {str(active[:5]):<40} | {txt}")

if __name__ == "__main__":
    main()
