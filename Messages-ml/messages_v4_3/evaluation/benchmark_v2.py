"""
Benchmark frozen Champion V2 baseline using eval_suite.
"""
import pickle
import sys
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/evaluation"))
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from eval_suite import run_full_evaluation

with open(ROOT / "champion_v2_model.pkl", "rb") as f:
    model = pickle.load(f)
with open(ROOT / "champion_v2_scaler.pkl", "rb") as f:
    scaler = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_word.pkl", "rb") as f:
    word = pickle.load(f)
with open(ROOT / "champion_v2_tfidf_char.pkl", "rb") as f:
    char = pickle.load(f)

def v2_predict_proba(texts):
    det = np.asarray([extract_feature_vector(t, None, FeatureConfig()) for t in texts], dtype=np.float32)
    w = word.transform(texts).toarray()
    c = char.transform(texts).toarray()
    X = np.hstack([det, w, c])
    return model.predict_proba(scaler.transform(X))

if __name__ == "__main__":
    res = run_full_evaluation(v2_predict_proba, threshold=0.704)
    print(f"V2 Threshold: {res['threshold']}")
    val = res['validation']
    print(f"V2 Val: Malicious {val['malicious_correct']}/{val['n_malicious']} ({val['malicious_recall']:.4f}), Benign FP {val['benign_fp']}/{val['n_benign']} ({val['benign_fpr']:.4f})")
    test = res['test']
    print(f"V2 Test: Malicious {test['malicious_correct']}/{test['n_malicious']} ({test['malicious_recall']:.4f}), Benign FP {test['benign_fp']}/{test['n_benign']} ({test['benign_fpr']:.4f})")
    ood = res['ood']
    print(f"V2 OOD: Malicious {ood['malicious_correct']}/{ood['n_malicious']} ({ood['malicious_recall']:.4f}), Benign FP {ood['benign_fp']}/{ood['n_benign']} ({ood['benign_fpr']:.4f})")
    
    print("\n--- Benchmark Suites ---")
    for bname, bm in res["benchmarks"].items():
        mal_str = f"{bm['malicious_correct']}/{bm['n_malicious']}" if bm['n_malicious'] > 0 else "N/A"
        ben_str = f"{bm['benign_fp']}/{bm['n_benign']}" if bm['n_benign'] > 0 else "N/A"
        rec_str = f"{bm['malicious_recall']:.4f}" if bm['malicious_recall'] is not None else "N/A"
        fpr_str = f"{bm['benign_fpr']:.4f}" if bm['benign_fpr'] is not None else "N/A"
        print(f"{bname:38s} | Malicious: {mal_str:>7s} ({rec_str:>6s}) | Benign FP: {ben_str:>7s} ({fpr_str:>6s})")

    # Save baseline metrics
    import json
    out_path = ROOT / "messages_v4_3/evaluation/v2_baseline_metrics.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved V2 baseline metrics to {out_path}")
