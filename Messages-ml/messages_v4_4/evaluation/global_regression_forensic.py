import os
import sys
import json
import pickle
import numpy as np
from pathlib import Path
import re

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
THRESHOLDS = {
    "v43": 0.610,
    "rc1": 0.630,
    "exp1": 0.680,
    "exp2": 0.680,
    "exp3": 0.740
}

def read_jsonl(p):
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]

def get_signals(text):
    t_lower = text.lower()
    return {
        "URL": bool(re.search(r"https?://\S+|www\.\S+", t_lower)),
        "Phone": bool(re.search(r"(?:\+91|0)?[6-9]\d{9}", t_lower)),
        "OTP": bool(re.search(r"\b(otp|code|pin)\b", t_lower)),
        "APK": bool(re.search(r"\.apk\b", t_lower)),
        "Institutional": bool(re.search(r"\b(bank|hdfc|sbi|icici|axis|account|dear customer)\b", t_lower)),
        "Electricity": bool(re.search(r"\b(power|electricity|bill|disconnect|update|kyc)\b", t_lower)),
        "Conversational": bool(re.search(r"\b(hello|hi|hey|how are you|good morning)\b", t_lower))
    }

def main():
    # Load models
    models = {}
    paths = {
        "v43": ROOT / "messages_v4_3/models/candidate_d",
        "rc1": ROOT / "messages_v4_4/models/candidate_b_refined",
        "exp1": ROOT / "messages_v4_4/models/rc2_experiment_1",
        "exp2": ROOT / "messages_v4_4/models/rc2_experiment_2",
        "exp3": ROOT / "messages_v4_4/models/rc2_experiment_3",
    }
    for name, path in paths.items():
        with open(path / "model.pkl", "rb") as f: m = pickle.load(f)
        with open(path / "scaler.pkl", "rb") as f: s = pickle.load(f)
        with open(path / "word_vec.pkl", "rb") as f: w = pickle.load(f)
        with open(path / "char_vec.pkl", "rb") as f: c = pickle.load(f)
        models[name] = (m, s, w, c)
        if name == "exp3":
            with open(path / "config.json", "r") as f: cfg = json.load(f)
            THRESHOLDS["exp3"] = cfg.get("validation_threshold", 0.74)
            print("Exp3 Threshold:", THRESHOLDS["exp3"])

    def predict(texts, name):
        m, s, w, c = models[name]
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        X = np.hstack([st, w.transform(texts).toarray(), c.transform(texts).toarray()]).astype(np.float32)
        probs = m.predict_proba(s.transform(X))
        p_nb = probs[:, 1] + probs[:, 2]
        is_mal = probs[:, 2] >= probs[:, 1]
        return p_nb, is_mal

    test_rows = read_jsonl(ROOT / "data/processed/test.jsonl")
    val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")

    # Get predictions for all models
    test_texts = [r.get("text") or r.get("raw_text") for r in test_rows]
    val_texts = [r.get("text") or r.get("raw_text") for r in val_rows]
    
    test_probs = {name: predict(test_texts, name) for name in models}
    val_probs = {name: predict(val_texts, name) for name in models}

    results = {"malicious_missed_newly": [], "malicious_caught_newly": [], "benign_fp_newly": [], "benign_tn_newly": []}
    
    for i, r in enumerate(test_rows):
        label_str = r.get("security_label") or r.get("label")
        y_true = LABELS.get(label_str, 0)
        
        p_v43, is_mal_v43 = test_probs["v43"][0][i], test_probs["v43"][1][i]
        p_rc1, is_mal_rc1 = test_probs["rc1"][0][i], test_probs["rc1"][1][i]
        p_exp1, is_mal_exp1 = test_probs["exp1"][0][i], test_probs["exp1"][1][i]
        p_exp2, is_mal_exp2 = test_probs["exp2"][0][i], test_probs["exp2"][1][i]
        p_exp3, is_mal_exp3 = test_probs["exp3"][0][i], test_probs["exp3"][1][i]

        pred_rc1 = (p_rc1 >= THRESHOLDS["rc1"]) and is_mal_rc1
        pred_exp3 = (p_exp3 >= THRESHOLDS["exp3"]) and is_mal_exp3

        t_text = r.get("text") or r.get("raw_text")
        rec = {
            "id": r.get("message_id", f"test_{i}"),
            "text": t_text,
            "probs": {"v43": float(p_v43), "rc1": float(p_rc1), "exp1": float(p_exp1), "exp2": float(p_exp2), "exp3": float(p_exp3)},
            "labels": label_str,
            "structural_features": [float(x) for x in extract_structural_signals(t_text)],
            "signals": get_signals(t_text)
        }

        if y_true == 2: # Malicious
            if pred_rc1 and not pred_exp3:
                results["malicious_missed_newly"].append(rec)
            elif not pred_rc1 and pred_exp3:
                results["malicious_caught_newly"].append(rec)
        elif y_true == 0: # Benign
            if not pred_rc1 and pred_exp3:
                results["benign_fp_newly"].append(rec)
            elif pred_rc1 and not pred_exp3:
                results["benign_tn_newly"].append(rec)

    with open(ROOT / "messages_v4_4/evaluation/forensic_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"Malicious newly missed (RC1=True, Exp3=False): {len(results['malicious_missed_newly'])}")
    print(f"Malicious newly caught (RC1=False, Exp3=True): {len(results['malicious_caught_newly'])}")
    print(f"Benign newly FP (RC1=False, Exp3=True): {len(results['benign_fp_newly'])}")
    print(f"Benign newly TN (RC1=True, Exp3=False): {len(results['benign_tn_newly'])}")

    # Distributions for Val
    val_stats = {}
    for name in models:
        stats = {"benign": [], "malicious": []}
        for i, r in enumerate(val_rows):
            y_true = LABELS.get(r.get("security_label") or r.get("label"), 0)
            if y_true == 0:
                stats["benign"].append(float(val_probs[name][0][i]))
            elif y_true == 2:
                stats["malicious"].append(float(val_probs[name][0][i]))
        
        val_stats[name] = {
            "benign": {
                "mean": float(np.mean(stats["benign"])),
                "std": float(np.std(stats["benign"])),
                "p90": float(np.percentile(stats["benign"], 90)),
                "p95": float(np.percentile(stats["benign"], 95)),
                "p98": float(np.percentile(stats["benign"], 98)),
                "p99": float(np.percentile(stats["benign"], 99)),
                "max": float(np.max(stats["benign"]))
            },
            "malicious": {
                "mean": float(np.mean(stats["malicious"])),
                "std": float(np.std(stats["malicious"])),
                "p10": float(np.percentile(stats["malicious"], 10)),
                "p05": float(np.percentile(stats["malicious"], 5)),
                "p02": float(np.percentile(stats["malicious"], 2)),
                "p01": float(np.percentile(stats["malicious"], 1)),
                "min": float(np.min(stats["malicious"]))
            }
        }

    with open(ROOT / "messages_v4_4/evaluation/forensic_val_stats.json", "w") as f:
        json.dump(val_stats, f, indent=2)

if __name__ == "__main__":
    main()
