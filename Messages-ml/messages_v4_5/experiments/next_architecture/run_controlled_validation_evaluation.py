import json
import pickle
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
from sentence_transformers import SentenceTransformer

# Force UTF-8 stdout
sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml")
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))

from candidate_d_v4_3 import extract_structural_signals

EXP_DIR = ROOT / "messages_v4_5/experiments/next_architecture"
DATA_DIR = EXP_DIR / "data"
MODELS_DIR = EXP_DIR / "models"
REPORTS_DIR = ROOT / "messages_v4_5/reports"

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
LABEL_NAMES = ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"]

def read_jsonl(p: Path):
    if not p.exists(): return []
    return [json.loads(line) for line in open(p, "r", encoding="utf-8", errors="ignore") if line.strip()]

def get_text(r: dict) -> str:
    return (r.get("raw_text") or r.get("text") or r.get("cleaned_text") or r.get("content") or "").strip()

def get_label(r: dict) -> int:
    lbl_str = r.get("security_label") or r.get("label") or "BENIGN"
    return LABELS.get(lbl_str, 0)

print("=" * 80)
print("1. LOADING FROZEN DETECTOR ARTIFACTS")
print("=" * 80)

# 1. Load Primary V4.3 Candidate-D
v43_dir = ROOT / "messages_v4_3/models/candidate_d"
with open(v43_dir / "model.pkl", "rb") as f: v43_m = pickle.load(f)
with open(v43_dir / "scaler.pkl", "rb") as f: v43_s = pickle.load(f)
with open(v43_dir / "word_vec.pkl", "rb") as f: v43_w = pickle.load(f)
with open(v43_dir / "char_vec.pkl", "rb") as f: v43_c = pickle.load(f)
tau_v43 = 0.610

def predict_v43(texts):
    if not texts:
        return np.empty((0, 3)), np.empty((0,), dtype=int)
    st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    X = np.hstack([st, v43_w.transform(texts).toarray(), v43_c.transform(texts).toarray()]).astype(np.float32)
    probs = v43_m.predict_proba(v43_s.transform(X))
    p_nb = probs[:, 1] + probs[:, 2]
    preds = np.where(p_nb >= tau_v43, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)
    return probs, preds

print("Primary V4.3 Candidate-D loaded. tau = 0.610")

# 2. Load Auxiliary Semantic Model
aux_model_path = MODELS_DIR / "auxiliary_semantic_model.pkl"
with open(aux_model_path, "rb") as f: aux_clf = pickle.load(f)
print(f"Auxiliary model loaded from: {aux_model_path}")

# 3. Load SentenceTransformer Encoder
encoder = SentenceTransformer("all-MiniLM-L6-v2")
print("SentenceTransformer all-MiniLM-L6-v2 loaded.")

def predict_aux(texts):
    embeddings = encoder.encode(texts, batch_size=128, show_progress_bar=False, normalize_embeddings=True)
    embeddings = np.asarray(embeddings, dtype=np.float32)
    probs = aux_clf.predict_proba(embeddings)
    sorted_probs = np.sort(probs, axis=1)
    margin = sorted_probs[:, -1] - sorted_probs[:, -2]
    return probs, margin, embeddings

# Attack Vector Checker for Downgrade
re_apk = re.compile(r"\.apk\b", re.I)

def check_no_vectors(text):
    has_url = bool(re.search(r"https?://\S+|www\.\S+|<URL>", text, re.I))
    has_phone = bool(re.search(r"(?:\+91|0)?[6-9]\d{9}|<PHONE>|<PHONE_NUMBER>", text))
    has_susp = bool(re.search(r"\.(?:cc|xyz|top|live|click|site|club|buzz|info|tk|ml|ga|cf|gq|su|work|shop|vip)(?:/|\?|:|$)", text, re.I))
    has_hex = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9]{16,}", text, re.I))
    has_apk = bool(re_apk.search(text))
    return {
        "no_vectors": (not has_url) and (not has_phone) and (not has_susp) and (not has_hex) and (not has_apk),
        "has_url": has_url,
        "has_phone": has_phone,
        "has_suspicious_tld": has_susp,
        "has_hex_or_ip": has_hex,
        "has_apk": has_apk
    }

print("\n" + "=" * 80)
print("2. LOADING CONTROLLED INDEPENDENT VALIDATION SET")
print("=" * 80)

val_file = DATA_DIR / "controlled_validation_set.jsonl"
val_records = read_jsonl(val_file)
print(f"Loaded {len(val_records)} independent validation records from: {val_file}")

texts = [get_text(r) for r in val_records]
y_true = np.array([get_label(r) for r in val_records], dtype=np.int32)
print("Ground truth distribution:", dict(Counter([LABEL_NAMES[y] for y in y_true])))

# 3. Model Inference
print("\n" + "=" * 80)
print("3. EXECUTING INFERENCE (FROZEN V4.3 BASELINE & AUXILIARY MODEL)")
print("=" * 80)

t0 = time.time()
v43_probs, v43_preds = predict_v43(texts)
print(f"V4.3 inference complete in {time.time()-t0:.2f}s.")

t0 = time.time()
aux_probs, aux_margins, embeddings = predict_aux(texts)
print(f"Auxiliary inference complete in {time.time()-t0:.2f}s.")

# 4. Arbitration: Variant B (Upgrade Only) & Variant C (Gated Downgrade)
# Thresholds:
theta_up = 0.95
margin_up = 0.40
theta_down = 0.95
aux_p_mal_down_ceiling = 0.05
v43_p_mal_down_ceiling = 0.70
margin_down = 0.50

var_b_preds = np.copy(v43_preds)
var_c_preds = np.copy(v43_preds)

upgraded_flags = []
downgraded_flags = []
downgrade_audits = []

for i in range(len(val_records)):
    t = texts[i]
    v_pred = v43_preds[i]
    v_prob = v43_probs[i]
    a_prob = aux_probs[i]
    a_mrg = aux_margins[i]
    vec_info = check_no_vectors(t)
    
    # Variant B upgrade logic
    is_upgraded = False
    if v_pred != 2 and a_prob[2] >= theta_up and a_mrg >= margin_up:
        var_b_preds[i] = 2
        var_c_preds[i] = 2
        is_upgraded = True
    upgraded_flags.append(is_upgraded)
    
    # Variant C downgrade logic
    is_downgraded = False
    cond_1 = (v_prob[2] < v43_p_mal_down_ceiling)
    cond_2 = vec_info["no_vectors"]
    cond_3 = (a_prob[0] >= theta_down)
    cond_4 = (a_prob[2] <= aux_p_mal_down_ceiling)
    cond_5 = (a_mrg >= margin_down)
    
    all_down_conditions = (v_pred == 2) and cond_1 and cond_2 and cond_3 and cond_4 and cond_5
    
    if all_down_conditions:
        var_c_preds[i] = 0
        is_downgraded = True
        downgrade_audits.append({
            "index": i,
            "message_id": val_records[i]["message_id"],
            "text": t,
            "ground_truth": LABEL_NAMES[y_true[i]],
            "v43_probs": [float(p) for p in v_prob],
            "aux_probs": [float(p) for p in a_prob],
            "aux_margin": float(a_mrg),
            "cond_1_v43_p_mal_lt_0_70": bool(cond_1),
            "cond_2_no_attack_vectors": bool(cond_2),
            "cond_3_aux_p_ben_ge_0_95": bool(cond_3),
            "cond_4_aux_p_mal_le_0_05": bool(cond_4),
            "cond_5_aux_margin_ge_0_50": bool(cond_5),
            "vector_details": vec_info,
            "safety_verdict": "SAFE" if y_true[i] != 2 else "FAILED_MALICIOUS_DOWNGRADE"
        })
    downgraded_flags.append(is_downgraded)

print("Decision arbitration complete.")

# 5. Compute Comprehensive Metrics
def compute_metrics(preds, y_true):
    n_ben = int((y_true == 0).sum())
    n_spm = int((y_true == 1).sum())
    n_mal = int((y_true == 2).sum())
    
    mal_det = int((preds[y_true == 2] == 2).sum())
    mal_fn = n_mal - mal_det
    mal_rec = mal_det / n_mal if n_mal > 0 else 0.0
    
    ben_fp = int((preds[y_true == 0] != 0).sum())
    ben_fpr = ben_fp / n_ben if n_ben > 0 else 0.0
    
    spm_mal = int((preds[y_true == 1] == 2).sum())
    spm_mal_rate = spm_mal / n_spm if n_spm > 0 else 0.0
    
    return {
        "n_benign": n_ben, "benign_fp": ben_fp, "benign_fpr": ben_fpr,
        "n_malicious": n_mal, "malicious_detected": mal_det, "malicious_fn": mal_fn, "malicious_recall": mal_rec,
        "n_spam": n_spm, "spam_to_malicious": spm_mal, "spam_to_malicious_rate": spm_mal_rate
    }

m_v43 = compute_metrics(v43_preds, y_true)
m_var_b = compute_metrics(var_b_preds, y_true)
m_var_c = compute_metrics(var_c_preds, y_true)

# Four-way Matrix on Malicious Subset (N = 101)
mal_mask = (y_true == 2)
v_mal_corr = (v43_preds[mal_mask] == 2)
c_mal_corr = (var_c_preds[mal_mask] == 2)

cat_a = int((v_mal_corr & c_mal_corr).sum()) # Both Correct
cat_b = int((v_mal_corr & ~c_mal_corr).sum()) # Regression (V4.3 correct, Variant wrong)
cat_c = int((~v_mal_corr & c_mal_corr).sum()) # Recovery (V4.3 wrong, Variant correct)
cat_d = int((~v_mal_corr & ~c_mal_corr).sum()) # Both wrong

four_way = {
    "cat_a_both_correct": cat_a,
    "cat_b_regressions": cat_b,
    "cat_c_recoveries": cat_c,
    "cat_d_both_wrong": cat_d,
    "total_malicious": int(mal_mask.sum())
}

print("\n" + "=" * 80)
print("EVALUATION RESULTS OVERVIEW")
print("=" * 80)
print(f"Total Validation Samples: {len(val_records)}")
print(f"V4.3 Baseline:  Mal Recall: {m_v43['malicious_detected']}/{m_v43['n_malicious']} ({m_v43['malicious_recall']*100:.2f}%) | Benign FP: {m_v43['benign_fp']}/{m_v43['n_benign']} ({m_v43['benign_fpr']*100:.2f}%) | Spam->Mal: {m_v43['spam_to_malicious']}/{m_v43['n_spam']} ({m_v43['spam_to_malicious_rate']*100:.2f}%)")
print(f"Variant B (Up): Mal Recall: {m_var_b['malicious_detected']}/{m_var_b['n_malicious']} ({m_var_b['malicious_recall']*100:.2f}%) | Benign FP: {m_var_b['benign_fp']}/{m_var_b['n_benign']} ({m_var_b['benign_fpr']*100:.2f}%) | Spam->Mal: {m_var_b['spam_to_malicious']}/{m_var_b['n_spam']} ({m_var_b['spam_to_malicious_rate']*100:.2f}%)")
print(f"Variant C (All):Mal Recall: {m_var_c['malicious_detected']}/{m_var_c['n_malicious']} ({m_var_c['malicious_recall']*100:.2f}%) | Benign FP: {m_var_c['benign_fp']}/{m_var_c['n_benign']} ({m_var_c['benign_fpr']*100:.2f}%) | Spam->Mal: {m_var_c['spam_to_malicious']}/{m_var_c['n_spam']} ({m_var_c['spam_to_malicious_rate']*100:.2f}%)")
print(f"\nFour-Way Malicious Matrix: A(Both Correct)={cat_a}, B(Regression)={cat_b}, C(Recovery)={cat_c}, D(Both Missed)={cat_d}")

CATEGORIES = {
    "A": "URL-less account/security deception",
    "B": "Electricity / utility messages",
    "C": "Institutional / campus messages",
    "D": "Conversational social engineering",
    "E": "Greetings and short openers",
    "F": "Legitimate security notifications",
    "G": "Legitimate utility notifications",
    "H": "Legitimate banking / OTP notifications",
    "I": "Legitimate technical / IT communication",
    "J": "APK / software references",
    "K": "Phone / callback messages",
    "L": "Hinglish / Indian English",
    "M": "Ordinary promotional spam"
}

# 6. Detailed Category Breakdown
print("\n" + "=" * 80)
print("CATEGORY-BY-CATEGORY BREAKDOWN (13 SEMANTIC CATEGORIES)")
print("=" * 80)
cat_metrics = {}
for cat_k in sorted(CATEGORIES.keys()):
    indices = [i for i, r in enumerate(val_records) if r["category"] == cat_k]
    y_sub = y_true[indices]
    v_sub = v43_preds[indices]
    b_sub = var_b_preds[indices]
    c_sub = var_c_preds[indices]
    
    sub_v43 = compute_metrics(v_sub, y_sub)
    sub_c = compute_metrics(c_sub, y_sub)
    
    # 4-way for this category
    sub_mal = (y_sub == 2)
    s_a = int(((v_sub[sub_mal] == 2) & (c_sub[sub_mal] == 2)).sum())
    s_b = int(((v_sub[sub_mal] == 2) & (c_sub[sub_mal] != 2)).sum())
    s_c = int(((v_sub[sub_mal] != 2) & (c_sub[sub_mal] == 2)).sum())
    s_d = int(((v_sub[sub_mal] != 2) & (c_sub[sub_mal] != 2)).sum())
    
    cat_metrics[cat_k] = {
        "name": CATEGORIES[cat_k],
        "n_samples": len(indices),
        "v43": sub_v43,
        "variant_c": sub_c,
        "four_way": {"A": s_a, "B": s_b, "C": s_c, "D": s_d}
    }
    print(f"Cat {cat_k:1s} ({CATEGORIES[cat_k][:32]:32s}) | Total: {len(indices):2d} | V4.3 Mal: {sub_v43['malicious_detected']:2d}/{sub_v43['n_malicious']:2d} | VarC Mal: {sub_c['malicious_detected']:2d}/{sub_c['n_malicious']:2d} | Ben FP: V4.3={sub_v43['benign_fp']}/{sub_v43['n_benign']}, VarC={sub_c['benign_fp']}/{sub_c['n_benign']} | 4-Way: A={s_a} B={s_b} C={s_c} D={s_d}")

# 7. Forensic Inspection
print("\n" + "=" * 80)
print("DEEP FORENSIC INSPECTION")
print("=" * 80)

# 7.1 Category C Recovered Threats (V4.3 missed, Variant C caught)
recovered_threats = []
for i in range(len(val_records)):
    if y_true[i] == 2 and v43_preds[i] != 2 and var_c_preds[i] == 2:
        recovered_threats.append({
            "index": i,
            "message_id": val_records[i]["message_id"],
            "original_id": val_records[i]["original_id"],
            "source": val_records[i]["source"],
            "source_family": val_records[i]["source_family"],
            "category": val_records[i]["category"],
            "text": texts[i],
            "v43_probs": [float(p) for p in v43_probs[i]],
            "v43_pred": LABEL_NAMES[v43_preds[i]],
            "aux_probs": [float(p) for p in aux_probs[i]],
            "aux_margin": float(aux_margins[i]),
            "final_pred": LABEL_NAMES[var_c_preds[i]],
            "annotation_rationale": val_records[i]["annotation_rationale"]
        })

print(f"\nTotal Category C Recovered Threats: {len(recovered_threats)}")
for r in recovered_threats:
    print(f"  * [{r['message_id']}] Cat {r['category']} ({r['source_family']}): '{r['text'][:80]}...'")
    print(f"    V4.3 P(M)={r['v43_probs'][2]:.4f} -> Pred={r['v43_pred']} | Aux P(M)={r['aux_probs'][2]:.4f} Margin={r['aux_margin']:.4f}")

# 7.2 Category B Regressions (V4.3 caught, Variant C missed)
regressed_threats = []
for i in range(len(val_records)):
    if y_true[i] == 2 and v43_preds[i] == 2 and var_c_preds[i] != 2:
        regressed_threats.append({
            "index": i,
            "message_id": val_records[i]["message_id"],
            "text": texts[i],
            "v43_probs": [float(p) for p in v43_probs[i]],
            "aux_probs": [float(p) for p in aux_probs[i]],
            "final_pred": LABEL_NAMES[var_c_preds[i]]
        })
print(f"\nTotal Category B Regressions: {len(regressed_threats)}")

# 7.3 New Benign False Alarms
new_benign_fps = []
for i in range(len(val_records)):
    if y_true[i] == 0 and v43_preds[i] == 0 and var_c_preds[i] != 0:
        new_benign_fps.append({
            "index": i,
            "message_id": val_records[i]["message_id"],
            "category": val_records[i]["category"],
            "text": texts[i],
            "v43_probs": [float(p) for p in v43_probs[i]],
            "aux_probs": [float(p) for p in aux_probs[i]],
            "aux_margin": float(aux_margins[i]),
            "final_pred": LABEL_NAMES[var_c_preds[i]]
        })
print(f"Total New Benign False Alarms: {len(new_benign_fps)}")
for fp in new_benign_fps:
    print(f"  * [{fp['message_id']}] Cat {fp['category']}: '{fp['text'][:80]}...' | Aux P(M)={fp['aux_probs'][2]:.4f}")

# 7.4 Spam Escalations (Spam -> Malicious)
spam_escalations = []
for i in range(len(val_records)):
    if y_true[i] == 1 and v43_preds[i] != 2 and var_c_preds[i] == 2:
        spam_escalations.append({
            "index": i,
            "message_id": val_records[i]["message_id"],
            "text": texts[i],
            "v43_probs": [float(p) for p in v43_probs[i]],
            "aux_probs": [float(p) for p in aux_probs[i]],
            "final_pred": LABEL_NAMES[var_c_preds[i]]
        })
print(f"Total Spam Escalations to Malicious: {len(spam_escalations)}")

# 7.5 Downgrade Safety Audit Verification
print(f"\nTotal Gated Downgrades Executed: {len(downgrade_audits)}")
downgrade_mal_violations = [d for d in downgrade_audits if d["safety_verdict"] == "FAILED_MALICIOUS_DOWNGRADE"]
print(f"Malicious Downgrade Safety Violations: {len(downgrade_mal_violations)}")
downgrade_path_verdict = "PASSED_ZERO_LEAKAGE" if len(downgrade_mal_violations) == 0 else "FAILED"
print(f"Downgrade Path Safety Verdict: {downgrade_path_verdict}")

# 8. Paired Record-Level Output
record_level_comparisons = []
for i in range(len(val_records)):
    record_level_comparisons.append({
        "message_id": val_records[i]["message_id"],
        "original_id": val_records[i]["original_id"],
        "source": val_records[i]["source"],
        "source_family": val_records[i]["source_family"],
        "category": val_records[i]["category"],
        "category_name": val_records[i]["category_name"],
        "text": texts[i],
        "ground_truth": LABEL_NAMES[y_true[i]],
        "v43_prediction": LABEL_NAMES[v43_preds[i]],
        "v43_p_benign": float(v43_probs[i][0]),
        "v43_p_spam": float(v43_probs[i][1]),
        "v43_p_malicious": float(v43_probs[i][2]),
        "aux_p_benign": float(aux_probs[i][0]),
        "aux_p_spam": float(aux_probs[i][1]),
        "aux_p_malicious": float(aux_probs[i][2]),
        "aux_margin": float(aux_margins[i]),
        "upgraded": bool(upgraded_flags[i]),
        "downgraded": bool(downgraded_flags[i]),
        "final_prediction": LABEL_NAMES[var_c_preds[i]]
    })

# Save results
eval_results = {
    "dataset": str(val_file),
    "dataset_sha256": "11a930e230f956f346e92544ff6986b79e847fa0ee5f7f6bff8756a5db410ca2",
    "total_records": len(val_records),
    "v43_metrics": m_v43,
    "variant_b_metrics": m_var_b,
    "variant_c_metrics": m_var_c,
    "four_way_matrix": four_way,
    "category_metrics": cat_metrics,
    "downgrade_safety_audit": {
        "total_downgrades": len(downgrade_audits),
        "malicious_violations": len(downgrade_mal_violations),
        "verdict": downgrade_path_verdict,
        "downgrade_records": downgrade_audits
    },
    "recovered_threats": recovered_threats,
    "regressed_threats": regressed_threats,
    "new_benign_fps": new_benign_fps,
    "spam_escalations": spam_escalations,
    "paired_records": record_level_comparisons
}

with open(EXP_DIR / "controlled_validation_results.json", "w", encoding="utf-8") as f:
    json.dump(eval_results, f, indent=2, ensure_ascii=False)

print(f"\nSaved complete validation results to: {EXP_DIR / 'controlled_validation_results.json'}")
