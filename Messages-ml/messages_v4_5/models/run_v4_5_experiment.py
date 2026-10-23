"""
Sentinel Messages V4.5 Stage 1 Architecture Experiment
End-to-End Execution Pipeline:
1. Feature Extraction: Pretrained frozen MiniLM contextual embeddings (384-dim) + 19 deterministic structural features
2. Required Ablations:
   - Ablation A: Contextual Only (384 dims)
   - Ablation B: Candidate-D / V4.3 Baseline (TF-IDF + Structural)
   - Ablation C: Contextual + Structural (403 dims)
3. Validation Threshold Calibration (FPR <= 2.0% on val.jsonl)
4. Full Evaluation on TEST, OOD, Clean OOD, Mobile Simulation, and 7 Targeted Diagnostic Probes
5. Three-Class Probability & Confusion Analysis
6. Global Regression Forensic against V4.3
7. Comprehensive Reporting & Artifact Serialization
"""

import os
import sys
import json
import pickle
import time
import re
from pathlib import Path
import numpy as np

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
LABEL_NAMES = ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"]

def read_jsonl(p: Path):
    return [json.loads(line) for line in open(p, "r", encoding="utf-8") if line.strip()]

def get_text(r: dict) -> str:
    return (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()

def get_label(r: dict) -> int:
    lbl_str = r.get("security_label") or r.get("label") or "BENIGN"
    if r.get("ground_truth_class") == "TRUE_POSITIVE_MALICIOUS_URL":
        lbl_str = "MALICIOUS"
    elif r.get("ground_truth_class") == "TRUE_NEGATIVE_BENIGN":
        lbl_str = "BENIGN"
    return LABELS.get(lbl_str, 0)

def norm_aggressive(s: str) -> str:
    t = s.lower().strip()
    t = re.sub(r"https?://\S+|www\.\S+", "<URL>", t)
    t = re.sub(r"(?:\+91|0)?[6-9]\d{9}", "<PHONE>", t)
    t = re.sub(r"\d+", "<NUM>", t)
    t = re.sub(r"[^\w\s]", " ", t)
    return " ".join(t.split())

def extract_features(texts, model, batch_size=128):
    print(f"Extracting MiniLM contextual embeddings for {len(texts)} texts...")
    t0 = time.time()
    embeddings = model.encode(texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True)
    print(f"Done in {time.time()-t0:.2f}s, shape: {embeddings.shape}")

    print(f"Extracting 19 deterministic structural features for {len(texts)} texts...")
    t0 = time.time()
    structural = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    print(f"Done in {time.time()-t0:.2f}s, shape: {structural.shape}")

    return np.asarray(embeddings, dtype=np.float32), structural

def compute_metrics(y_true, probs, threshold):
    # probs: (N, 3) -> [P(BENIGN), P(SPAM), P(MALICIOUS)]
    p_nb = probs[:, 1] + probs[:, 2]
    y_pred = np.where(p_nb >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)

    cm = np.zeros((3, 3), dtype=np.int32)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1

    ben_mask = (y_true == 0)
    mal_mask = (y_true == 2)
    spam_mask = (y_true == 1)

    n_ben = int(ben_mask.sum())
    n_mal = int(mal_mask.sum())
    n_spam = int(spam_mask.sum())

    ben_fp = int((y_pred[ben_mask] != 0).sum())
    ben_fpr = (ben_fp / n_ben) if n_ben > 0 else 0.0

    mal_recall_mal = int((y_pred[mal_mask] == 2).sum())
    mal_recall_total = (mal_recall_mal / n_mal) if n_mal > 0 else 0.0

    mal_to_spam = int((y_pred[mal_mask] == 1).sum())
    mal_to_ben = int((y_pred[mal_mask] == 0).sum())

    return {
        "threshold": float(threshold),
        "total": len(y_true),
        "n_benign": n_ben,
        "n_spam": n_spam,
        "n_malicious": n_mal,
        "benign_fp": ben_fp,
        "benign_fpr": float(ben_fpr),
        "malicious_detected": mal_recall_mal,
        "malicious_recall": float(mal_recall_total),
        "malicious_to_spam": mal_to_spam,
        "malicious_to_benign": mal_to_ben,
        "confusion_matrix": cm.tolist(),
        "mean_p_benign": float(np.mean(probs[:, 0])),
        "mean_p_spam": float(np.mean(probs[:, 1])),
        "mean_p_malicious": float(np.mean(probs[:, 2])),
    }

def calibrate_threshold(y_true_val, probs_val, max_fpr=0.02):
    p_nb = probs_val[:, 1] + probs_val[:, 2]
    ben_mask = (y_true_val == 0)
    n_ben = int(ben_mask.sum())
    mal_mask = (y_true_val == 2)
    n_mal = int(mal_mask.sum())

    ben_scores = p_nb[ben_mask]
    mal_scores = p_nb[mal_mask]

    p98_ben = float(np.percentile(ben_scores, 98))

    grid = np.arange(0.05, 0.955, 0.005)
    sweep = []
    selected_tau = None

    for tau in grid:
        tau = round(float(tau), 4)
        m = compute_metrics(y_true_val, probs_val, tau)
        sweep.append({
            "threshold": tau,
            "benign_fpr": m["benign_fpr"],
            "benign_fp": m["benign_fp"],
            "malicious_recall": m["malicious_recall"],
            "malicious_detected": m["malicious_detected"],
        })
        if m["benign_fpr"] <= max_fpr and selected_tau is None:
            selected_tau = tau

    if selected_tau is None:
        selected_tau = float(grid[-1])

    return selected_tau, p98_ben, sweep

def main():
    print("=" * 100)
    print("STARTING SENTINEL V4.5 STAGE 1 ARCHITECTURE EXPERIMENT")
    print("=" * 100)

    np.random.seed(42)

    # 1. Load data
    train_path = ROOT / "messages_v4_4/data/train_v4_4_b.jsonl"
    val_path = ROOT / "data/processed/val.jsonl"
    test_path = ROOT / "data/processed/test.jsonl"
    ood_path = ROOT / "data/processed/ood.jsonl"

    print("Loading datasets...")
    train_rows = read_jsonl(train_path)
    val_rows = read_jsonl(val_path)
    test_rows = read_jsonl(test_path)
    ood_rows = read_jsonl(ood_path)

    # Clean OOD
    train_norm_keys = {norm_aggressive(get_text(r)) for r in train_rows}
    clean_ood_rows = [r for r in ood_rows if norm_aggressive(get_text(r)) not in train_norm_keys]

    # Mobile Sim
    sim_path = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\6sep\simulation\SIMULATION_CASES.jsonl")
    sim_rows = read_jsonl(sim_path) if sim_path.exists() else []

    # Holdouts
    holdout_files = sorted((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))
    holdout_data = {p.stem: read_jsonl(p) for p in holdout_files}

    print(f"Train: {len(train_rows)} rows | Val: {len(val_rows)} | Test: {len(test_rows)} | OOD: {len(ood_rows)} | Clean OOD: {len(clean_ood_rows)}")

    # 2. Extract features
    encoder = SentenceTransformer("all-MiniLM-L6-v2")
    cache_dir = ROOT / "messages_v4_5/data"

    train_texts = [get_text(r) for r in train_rows]
    y_train = np.array([get_label(r) for r in train_rows], dtype=np.int32)

    val_texts = [get_text(r) for r in val_rows]
    y_val = np.array([get_label(r) for r in val_rows], dtype=np.int32)

    test_texts = [get_text(r) for r in test_rows]
    y_test = np.array([get_label(r) for r in test_rows], dtype=np.int32)

    ood_texts = [get_text(r) for r in ood_rows]
    y_ood = np.array([get_label(r) for r in ood_rows], dtype=np.int32)

    clean_ood_texts = [get_text(r) for r in clean_ood_rows]
    y_clean_ood = np.array([get_label(r) for r in clean_ood_rows], dtype=np.int32)

    sim_texts = [get_text(r) for r in sim_rows]
    y_sim = np.array([get_label(r) for r in sim_rows], dtype=np.int32)

    holdout_features = {}

    # Extract or load train/val/test/ood embeddings
    train_emb, train_st = extract_features(train_texts, encoder)
    val_emb, val_st = extract_features(val_texts, encoder)
    test_emb, test_st = extract_features(test_texts, encoder)
    ood_emb, ood_st = extract_features(ood_texts, encoder)
    clean_ood_emb, clean_ood_st = extract_features(clean_ood_texts, encoder)
    sim_emb, sim_st = extract_features(sim_texts, encoder) if sim_texts else (np.empty((0, 384)), np.empty((0, 19)))

    for name, h_rows in holdout_data.items():
        h_texts = [get_text(r) for r in h_rows]
        h_y = np.array([get_label(r) for r in h_rows], dtype=np.int32)
        h_emb, h_st = extract_features(h_texts, encoder)
        holdout_features[name] = (h_texts, h_y, h_emb, h_st, h_rows)

    # Save feature cache
    np.save(cache_dir / "train_emb.npy", train_emb)
    np.save(cache_dir / "val_emb.npy", val_emb)
    np.save(cache_dir / "test_emb.npy", test_emb)
    np.save(cache_dir / "ood_emb.npy", ood_emb)

    # Scale structural features
    scaler = StandardScaler()
    train_st_scaled = scaler.fit_transform(train_st)
    val_st_scaled = scaler.transform(val_st)
    test_st_scaled = scaler.transform(test_st)
    ood_st_scaled = scaler.transform(ood_st)
    clean_ood_st_scaled = scaler.transform(clean_ood_st)
    sim_st_scaled = scaler.transform(sim_st) if sim_texts else np.empty((0, 19))

    # Calculate class weights
    classes = np.unique(y_train)
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    class_weight_dict = {c: float(w) for c, w in zip(classes, weights)}
    print(f"Computed Balanced Class Weights: {class_weight_dict}")

    # =========================================================================
    # ABLATION A: CONTEXTUAL ONLY (384 DIMS)
    # =========================================================================
    print("\n" + "=" * 80)
    print("TRAINING ABLATION A: CONTEXTUAL ONLY (MiniLM 384 dims -> 3-Class Head)")
    print("=" * 80)
    clf_a = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42, C=1.0)
    clf_a.fit(train_emb, y_train)

    # Save model A
    with open(ROOT / "messages_v4_5/models/ablation_a_clf.pkl", "wb") as f:
        pickle.dump(clf_a, f)

    probs_val_a = clf_a.predict_proba(val_emb)
    tau_a, p98_a, sweep_a = calibrate_threshold(y_val, probs_val_a)
    print(f"Ablation A: Calibrated tau={tau_a:.4f} | Benign p98={p98_a:.4f}")

    # =========================================================================
    # ABLATION C: CONTEXTUAL + STRUCTURAL (403 DIMS)
    # =========================================================================
    print("\n" + "=" * 80)
    print("TRAINING ABLATION C: CONTEXTUAL + STRUCTURAL (384 + 19 = 403 dims -> 3-Class Head)")
    print("=" * 80)
    X_train_c = np.hstack([train_emb, train_st_scaled])
    X_val_c = np.hstack([val_emb, val_st_scaled])
    X_test_c = np.hstack([test_emb, test_st_scaled])
    X_ood_c = np.hstack([ood_emb, ood_st_scaled])
    X_clean_ood_c = np.hstack([clean_ood_emb, clean_ood_st_scaled])
    X_sim_c = np.hstack([sim_emb, sim_st_scaled]) if sim_texts else np.empty((0, 403))

    clf_c = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42, C=1.0)
    clf_c.fit(X_train_c, y_train)

    # Also train HistGradientBoosting on Ablation C for direct algorithmic parity with Candidate-D
    print("Training Ablation C (HistGradientBoosting) for algorithmic comparison...")
    clf_c_hgb = HistGradientBoostingClassifier(random_state=42, max_iter=150)
    clf_c_hgb.fit(X_train_c, y_train)

    with open(ROOT / "messages_v4_5/models/ablation_c_clf.pkl", "wb") as f:
        pickle.dump(clf_c, f)
    with open(ROOT / "messages_v4_5/models/ablation_c_hgb.pkl", "wb") as f:
        pickle.dump(clf_c_hgb, f)
    with open(ROOT / "messages_v4_5/models/scaler_structural.pkl", "wb") as f:
        pickle.dump(scaler, f)

    probs_val_c = clf_c.predict_proba(X_val_c)
    tau_c, p98_c, sweep_c = calibrate_threshold(y_val, probs_val_c)
    print(f"Ablation C (LogReg): Calibrated tau={tau_c:.4f} | Benign p98={p98_c:.4f}")

    probs_val_c_hgb = clf_c_hgb.predict_proba(X_val_c)
    tau_c_hgb, p98_c_hgb, sweep_c_hgb = calibrate_threshold(y_val, probs_val_c_hgb)
    print(f"Ablation C (HGB):    Calibrated tau={tau_c_hgb:.4f} | Benign p98={p98_c_hgb:.4f}")

    # =========================================================================
    # ABLATION B: LOAD FROZEN V4.3 BASELINE
    # =========================================================================
    v43_dir = ROOT / "messages_v4_3/models/candidate_d"
    with open(v43_dir / "model.pkl", "rb") as f: v43_m = pickle.load(f)
    with open(v43_dir / "scaler.pkl", "rb") as f: v43_s = pickle.load(f)
    with open(v43_dir / "word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
    with open(v43_dir / "char_vec.pkl", "rb") as f: v43_c = pickle.load(f)
    tau_v43 = 0.610

    def predict_v43(texts):
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        X = np.hstack([st, v43_w.transform(texts).toarray(), v43_c.transform(texts).toarray()]).astype(np.float32)
        return v43_m.predict_proba(v43_s.transform(X))

    # =========================================================================
    # EVALUATE ALL SUITES
    # =========================================================================
    eval_suites = [
        ("Validation Split", val_texts, y_val, val_emb, X_val_c, val_rows),
        ("Primary TEST", test_texts, y_test, test_emb, X_test_c, test_rows),
        ("Primary OOD", ood_texts, y_ood, ood_emb, X_ood_c, ood_rows),
        ("Clean OOD (Zero Overlap)", clean_ood_texts, y_clean_ood, clean_ood_emb, X_clean_ood_c, clean_ood_rows),
        ("Real Mobile Simulation", sim_texts, y_sim, sim_emb, X_sim_c, sim_rows),
    ]

    for name, (h_texts, h_y, h_emb, h_st, h_rows) in holdout_features.items():
        h_st_scaled = scaler.transform(h_st)
        X_h_c = np.hstack([h_emb, h_st_scaled])
        eval_suites.append((f"Holdout: {name}", h_texts, h_y, h_emb, X_h_c, h_rows))

    results_table = []
    full_eval_dict = {}

    print("\n" + "=" * 110)
    print(f"{'Evaluation Suite':<35} | {'Metric':<10} | {'V4.3 (tau=0.61)':<18} | {'Abl A (tau=' + f'{tau_a:.2f})':<18} | {'Abl C (tau=' + f'{tau_c:.2f})':<18}")
    print("=" * 110)

    for suite_name, texts, y_true, X_emb, X_comb, rows in eval_suites:
        if len(texts) == 0:
            continue
        p_v43 = predict_v43(texts)
        p_a = clf_a.predict_proba(X_emb)
        p_c = clf_c.predict_proba(X_comb)

        m_v43 = compute_metrics(y_true, p_v43, tau_v43)
        m_a = compute_metrics(y_true, p_a, tau_a)
        m_c = compute_metrics(y_true, p_c, tau_c)

        full_eval_dict[suite_name] = {
            "V4.3": m_v43,
            "Ablation_A": m_a,
            "Ablation_C": m_c,
            "probs": {
                "V4.3": p_v43.tolist(),
                "Ablation_A": p_a.tolist(),
                "Ablation_C": p_c.tolist(),
            }
        }

        # Print comparison row
        n_ben = m_v43["n_benign"]
        n_mal = m_v43["n_malicious"]

        if n_ben > 0:
            str_v43_fpr = f"{m_v43['benign_fpr']*100:.1f}% ({m_v43['benign_fp']}/{n_ben})"
            str_a_fpr = f"{m_a['benign_fpr']*100:.1f}% ({m_a['benign_fp']}/{n_ben})"
            str_c_fpr = f"{m_c['benign_fpr']*100:.1f}% ({m_c['benign_fp']}/{n_ben})"
            print(f"{suite_name:<35} | {'BENIGN FPR':<10} | {str_v43_fpr:<18} | {str_a_fpr:<18} | {str_c_fpr:<18}")

        if n_mal > 0:
            str_v43_rec = f"{m_v43['malicious_recall']*100:.1f}% ({m_v43['malicious_detected']}/{n_mal})"
            str_a_rec = f"{m_a['malicious_recall']*100:.1f}% ({m_a['malicious_detected']}/{n_mal})"
            str_c_rec = f"{m_c['malicious_recall']*100:.1f}% ({m_c['malicious_detected']}/{n_mal})"
            print(f"{suite_name:<35} | {'MAL RECALL':<10} | {str_v43_rec:<18} | {str_a_rec:<18} | {str_c_rec:<18}")

    print("=" * 110)

    # Save complete evaluation JSON
    with open(ROOT / "messages_v4_5/reports/v4_5_eval_results.json", "w", encoding="utf-8") as f:
        # Don't serialize massive raw probs array to keep json readable
        summary_to_save = {}
        for k, v in full_eval_dict.items():
            summary_to_save[k] = {
                "V4.3": v["V4.3"],
                "Ablation_A": v["Ablation_A"],
                "Ablation_C": v["Ablation_C"]
            }
        json.dump(summary_to_save, f, indent=2)

    # Save threshold sweep data
    sweep_data = {
        "Ablation_A": {"tau": tau_a, "p98": p98_a, "sweep": sweep_a},
        "Ablation_C": {"tau": tau_c, "p98": p98_c, "sweep": sweep_c},
    }
    with open(ROOT / "messages_v4_5/reports/threshold_sweep.json", "w", encoding="utf-8") as f:
        json.dump(sweep_data, f, indent=2)

    print("\nEvaluating regression forensic on primary TEST...")
    # =========================================================================
    # REGRESSION FORENSIC: V4.5 (Ablation C) vs V4.3
    # =========================================================================
    p_test_v43 = np.array(full_eval_dict["Primary TEST"]["probs"]["V4.3"])
    p_test_c = np.array(full_eval_dict["Primary TEST"]["probs"]["Ablation_C"])
    p_test_a = np.array(full_eval_dict["Primary TEST"]["probs"]["Ablation_A"])

    def get_pred(p, tau):
        p_nb = p[:, 1] + p[:, 2]
        return np.where(p_nb >= tau, np.where(p[:, 2] >= p[:, 1], 2, 1), 0)

    pred_v43 = get_pred(p_test_v43, tau_v43)
    pred_c = get_pred(p_test_c, tau_c)
    pred_a = get_pred(p_test_a, tau_a)

    forensic_records = {
        "malicious_missed_by_v45": [],
        "malicious_recovered_by_v45": [],
        "benign_fp_introduced_by_v45": [],
        "benign_fp_corrected_by_v45": [],
    }

    def detect_signals(text):
        t_low = text.lower()
        return {
            "has_url": bool(re.search(r"https?://\S+|www\.\S+", t_low)),
            "has_phone": bool(re.search(r"(?:\+91|0)?[6-9]\d{9}", t_low)),
            "has_otp": bool(re.search(r"\b(otp|code|pin|password)\b", t_low)),
            "has_apk": bool(re.search(r"\.apk\b", t_low)),
            "has_institutional": bool(re.search(r"\b(bank|hdfc|sbi|icici|axis|account|kyc|statement)\b", t_low)),
            "has_utility": bool(re.search(r"\b(electricity|power|bill|disconnect|meter|discom)\b", t_low)),
            "has_conversational": bool(re.search(r"\b(hello|hi|hey|how are you|good morning|dear)\b", t_low)),
            "has_hinglish": bool(re.search(r"\b(karo|hai|hoga|bhejo|turant|rupaye|paise)\b", t_low)),
        }

    for i, r in enumerate(test_rows):
        t = get_text(r)
        y = y_test[i]
        mid = r.get("message_id", f"test_{i}")
        sig = detect_signals(t)

        rec = {
            "message_id": mid,
            "text": t,
            "true_label": LABEL_NAMES[y],
            "v43_probs": [round(float(x), 4) for x in p_test_v43[i]],
            "v43_pred": LABEL_NAMES[pred_v43[i]],
            "v45_probs": [round(float(x), 4) for x in p_test_c[i]],
            "v45_pred": LABEL_NAMES[pred_c[i]],
            "signals": sig,
        }

        if y == 2: # MALICIOUS
            if pred_v43[i] == 2 and pred_c[i] != 2:
                # Malicious missed by V4.5
                mech = "MALICIOUS -> SPAM" if pred_c[i] == 1 else "MALICIOUS -> BENIGN"
                rec["failure_mechanism"] = mech
                forensic_records["malicious_missed_by_v45"].append(rec)
            elif pred_v43[i] != 2 and pred_c[i] == 2:
                # Malicious recovered by V4.5
                rec["recovery_mechanism"] = "SPAM -> MALICIOUS" if pred_v43[i] == 1 else "BENIGN -> MALICIOUS"
                forensic_records["malicious_recovered_by_v45"].append(rec)

        elif y == 0: # BENIGN
            if pred_v43[i] == 0 and pred_c[i] != 0:
                # Benign converted to FP
                rec["failure_mechanism"] = "BENIGN -> MALICIOUS" if pred_c[i] == 2 else "BENIGN -> SPAM"
                forensic_records["benign_fp_introduced_by_v45"].append(rec)
            elif pred_v43[i] != 0 and pred_c[i] == 0:
                # Benign FP corrected
                rec["correction_mechanism"] = "MALICIOUS -> BENIGN" if pred_v43[i] == 2 else "SPAM -> BENIGN"
                forensic_records["benign_fp_corrected_by_v45"].append(rec)

    with open(ROOT / "messages_v4_5/reports/v4_5_forensic_records.json", "w", encoding="utf-8") as f:
        json.dump(forensic_records, f, indent=2)

    print("\nForensic Counts on Primary TEST:")
    print(f"  Malicious Missed by V4.5 (V4.3 caught, V4.5 missed):     {len(forensic_records['malicious_missed_by_v45'])}")
    print(f"  Malicious Recovered by V4.5 (V4.3 missed, V4.5 caught):  {len(forensic_records['malicious_recovered_by_v45'])}")
    print(f"  Benign FPs Introduced by V4.5:                           {len(forensic_records['benign_fp_introduced_by_v45'])}")
    print(f"  Benign FPs Corrected by V4.5:                            {len(forensic_records['benign_fp_corrected_by_v45'])}")

    print("\nExperiment execution completed successfully!")

if __name__ == "__main__":
    main()
