import os
import sys
import json
import pickle
import time
import re
from pathlib import Path
from collections import Counter, defaultdict
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

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

# 1. LOAD PRIMARY DETECTOR: FROZEN V4.3 CANDIDATE-D
print("=" * 80)
print("1. LOADING PRIMARY DETECTOR: SENTINEL MESSAGES V4.3 CANDIDATE-D (FROZEN)")
print("=" * 80)
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

print("V4.3 Candidate-D loaded successfully. Tau = 0.610")

# 2. LOAD AUDITED AUXILIARY TRAINING DATA
print("\n" + "=" * 80)
print("2. LOADING AUDITED AUXILIARY TRAINING CORPUS")
print("=" * 80)
aux_train_path = DATA_DIR / "auxiliary_train.jsonl"
aux_train_rows = read_jsonl(aux_train_path)
print(f"Loaded {len(aux_train_rows)} clean audited auxiliary training samples.")
aux_train_texts = [get_text(r) for r in aux_train_rows]
y_aux_train = np.array([get_label(r) for r in aux_train_rows], dtype=np.int32)
print("Label distribution in auxiliary training set:", dict(Counter([LABEL_NAMES[y] for y in y_aux_train])))

# 3. CONTEXTUAL FEATURE EXTRACTION (MiniLM)
print("\n" + "=" * 80)
print("3. EXTRACTING CONTEXTUAL EMBEDDINGS (SentenceTransformer: all-MiniLM-L6-v2)")
print("=" * 80)
encoder = SentenceTransformer("all-MiniLM-L6-v2")

aux_emb_cache = DATA_DIR / "auxiliary_train_emb.npy"
if aux_emb_cache.exists():
    print(f"Loading cached auxiliary embeddings from {aux_emb_cache}...")
    X_aux_train = np.load(aux_emb_cache)
else:
    print(f"Encoding {len(aux_train_texts)} auxiliary training samples...")
    t0 = time.time()
    X_aux_train = encoder.encode(aux_train_texts, batch_size=128, show_progress_bar=False, normalize_embeddings=True)
    X_aux_train = np.asarray(X_aux_train, dtype=np.float32)
    np.save(aux_emb_cache, X_aux_train)
    print(f"Encoded in {time.time()-t0:.2f}s, shape: {X_aux_train.shape}")

# 4. TRAIN AUXILIARY CONTEXTUAL EVIDENCE MODEL
print("\n" + "=" * 80)
print("4. TRAINING AUXILIARY CONTEXTUAL EVIDENCE MODEL")
print("=" * 80)
aux_clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=20260925, C=1.0)
t0 = time.time()
aux_clf.fit(X_aux_train, y_aux_train)
print(f"Auxiliary classifier trained in {time.time()-t0:.2f}s.")

# Save auxiliary model
with open(MODELS_DIR / "auxiliary_semantic_model.pkl", "wb") as f:
    pickle.dump(aux_clf, f)
print(f"Saved auxiliary model to: {MODELS_DIR / 'auxiliary_semantic_model.pkl'}")

def predict_aux(texts, embeddings=None):
    if embeddings is None:
        embeddings = encoder.encode(texts, batch_size=128, show_progress_bar=False, normalize_embeddings=True)
        embeddings = np.asarray(embeddings, dtype=np.float32)
    probs = aux_clf.predict_proba(embeddings)
    # Abstention / Margin calculation
    sorted_probs = np.sort(probs, axis=1)
    margin = sorted_probs[:, -1] - sorted_probs[:, -2]
    return probs, margin, embeddings

# 5. VALIDATION CALIBRATION (Strictly on val.jsonl)
print("\n" + "=" * 80)
print("5. CALIBRATING GATING THRESHOLDS ON VALIDATION SPLIT (val.jsonl)")
print("=" * 80)
val_rows = read_jsonl(ROOT / "data/processed/val.jsonl")
val_texts = [get_text(r) for r in val_rows]
y_val = np.array([get_label(r) for r in val_rows], dtype=np.int32)
val_cache_emb = ROOT / "messages_v4_5/data/val_emb.npy"
val_emb = np.load(val_cache_emb) if val_cache_emb.exists() else None

v43_val_probs, v43_val_preds = predict_v43(val_texts)
aux_val_probs, aux_val_margin, val_emb = predict_aux(val_texts, val_emb)

# Evaluation on Validation for V4.3 Baseline
v43_val_ben_fp = int((v43_val_preds[y_val == 0] != 0).sum())
v43_val_ben_fpr = v43_val_ben_fp / int((y_val == 0).sum())
v43_val_mal_det = int((v43_val_preds[y_val == 2] == 2).sum())
v43_val_mal_rec = v43_val_mal_det / int((y_val == 2).sum())
print(f"V4.3 Validation Baseline: Malicious Recall = {v43_val_mal_det}/{int((y_val==2).sum())} ({v43_val_mal_rec*100:.2f}%) | Benign FPR = {v43_val_ben_fp}/{int((y_val==0).sum())} ({v43_val_ben_fpr*100:.2f}%)")

# Calibrate Variant B Upgrade Threshold:
# Find threshold theta_up on P_aux(M) that maximizes validation malicious recoveries without increasing benign FP
best_theta_up = 0.85
best_val_b_rec = v43_val_mal_rec
best_val_b_fpr = v43_val_ben_fpr

for th in [0.70, 0.75, 0.80, 0.85, 0.90, 0.92, 0.95]:
    # Variant B upgrade: if v43 != 2 and P_aux(M) >= th -> upgrade to 2
    b_preds = np.copy(v43_val_preds)
    upgrade_mask = (v43_val_preds != 2) & (aux_val_probs[:, 2] >= th) & (aux_val_margin >= 0.40)
    b_preds[upgrade_mask] = 2
    
    ben_fp = int((b_preds[y_val == 0] != 0).sum())
    ben_fpr = ben_fp / int((y_val == 0).sum())
    mal_det = int((b_preds[y_val == 2] == 2).sum())
    mal_rec = mal_det / int((y_val == 2).sum())
    
    # We require benign FPR <= 2.0%
    if ben_fpr <= 0.020:
        if mal_rec >= best_val_b_rec:
            best_theta_up = th
            best_val_b_rec = mal_rec
            best_val_b_fpr = ben_fpr

print(f"Calibrated Variant B Upgrade Threshold: theta_up = {best_theta_up:.2f} (Val Rec: {best_val_b_rec*100:.2f}%, Val FPR: {best_val_b_fpr*100:.2f}%)")

# Calibrate Variant C Downgrade Threshold:
# Conditions: P_v43(M) < 0.70 AND no attack vectors AND P_aux(B) >= theta_down AND P_aux(M) <= 0.05 AND margin >= 0.50
re_apk = re.compile(r"\.apk\b", re.I)

def check_no_vectors(text):
    has_url = bool(re.search(r"https?://\S+|www\.\S+|<URL>", text, re.I))
    has_phone = bool(re.search(r"(?:\+91|0)?[6-9]\d{9}|<PHONE>|<PHONE_NUMBER>", text))
    has_susp = bool(re.search(r"\.(?:cc|xyz|top|live|click|site|club|buzz|info|tk|ml|ga|cf|gq|su|work|shop|vip)(?:/|\?|:|$)", text, re.I))
    has_hex = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9]{16,}", text, re.I))
    has_apk = bool(re_apk.search(text))
    return (not has_url) and (not has_phone) and (not has_susp) and (not has_hex) and (not has_apk)

val_no_vectors = np.array([check_no_vectors(t) for t in val_texts])

best_theta_down = 0.90
best_val_c_rec = 0.0
best_val_c_fpr = 1.0

for th_down in [0.80, 0.85, 0.90, 0.92, 0.95]:
    c_preds = np.copy(v43_val_preds)
    # Apply upgrade
    up_mask = (v43_val_preds != 2) & (aux_val_probs[:, 2] >= best_theta_up) & (aux_val_margin >= 0.40)
    c_preds[up_mask] = 2
    
    # Apply gated downgrade
    down_mask = (
        (v43_val_preds == 2) &
        (v43_val_probs[:, 2] < 0.70) &
        val_no_vectors &
        (aux_val_probs[:, 0] >= th_down) &
        (aux_val_probs[:, 2] <= 0.05) &
        (aux_val_margin >= 0.50)
    )
    c_preds[down_mask] = 0
    
    ben_fp = int((c_preds[y_val == 0] != 0).sum())
    ben_fpr = ben_fp / int((y_val == 0).sum())
    mal_det = int((c_preds[y_val == 2] == 2).sum())
    mal_rec = mal_det / int((y_val == 2).sum())
    
    # Check if any ground-truth malicious was downgraded on val
    downgraded_mal = int(((v43_val_preds == 2) & (y_val == 2) & down_mask).sum())
    print(f"  Sweep th_down={th_down:.2f}: Downgraded Malicious={downgraded_mal}, Val Rec={mal_rec*100:.2f}%, Val FPR={ben_fpr*100:.2f}%")
    if downgraded_mal == 0:
        best_theta_down = th_down
        best_val_c_rec = mal_rec
        best_val_c_fpr = ben_fpr

print(f"Calibrated Variant C Downgrade Threshold: theta_down = {best_theta_down:.2f}")

config = {
    "primary_model": "Sentinel Messages V4.3 Candidate-D",
    "primary_tau": 0.610,
    "auxiliary_model": "SentenceTransformer all-MiniLM-L6-v2 + LogisticRegression",
    "auxiliary_train_size": len(aux_train_rows),
    "theta_upgrade": best_theta_up,
    "upgrade_margin_min": 0.40,
    "theta_downgrade_benign": best_theta_down,
    "downgrade_v43_p_mal_ceiling": 0.70,
    "downgrade_aux_p_mal_ceiling": 0.05,
    "downgrade_margin_min": 0.50,
}
with open(EXP_DIR / "config.json", "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

# 6. EVALUATION SUITES EXECUTION
print("\n" + "=" * 80)
print("6. FULL EVALUATION ACROSS ALL BENCHMARK & HOLDOUT SUITES")
print("=" * 80)

# Load test, ood, clean ood
test_rows = read_jsonl(ROOT / "data/processed/test.jsonl")
ood_rows = read_jsonl(ROOT / "data/processed/ood.jsonl")
train_v44_rows = read_jsonl(ROOT / "messages_v4_4/data/train_v4_4_rc2_exp3.jsonl")
train_norm_keys = {norm_aggressive(get_text(r)) for r in train_v44_rows}
clean_ood_rows = [r for r in ood_rows if norm_aggressive(get_text(r)) not in train_norm_keys]

# Load simulation and benchmarks
sim_path = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\6sep\simulation\SIMULATION_CASES.jsonl")
sim_rows = read_jsonl(sim_path) if sim_path.exists() else []

bench_files = {p.stem: read_jsonl(p) for p in sorted((ROOT / "data/benchmarks").glob("*.jsonl"))}
holdout_files = {p.stem: read_jsonl(p) for p in sorted((ROOT / "messages_v4_4/evaluation/holdouts").glob("*.jsonl"))}

# Pre-cached embeddings
test_cache_emb = ROOT / "messages_v4_5/data/test_emb.npy"
ood_cache_emb = ROOT / "messages_v4_5/data/ood_emb.npy"
test_emb = np.load(test_cache_emb) if test_cache_emb.exists() else None
ood_emb = np.load(ood_cache_emb) if ood_cache_emb.exists() else None

suites = [
    ("Primary TEST", test_rows, test_emb),
    ("Primary OOD", ood_rows, ood_emb),
    ("Clean OOD", clean_ood_rows, None),
    ("Real Mobile Simulation", sim_rows, None),
]
for k, v in bench_files.items():
    suites.append((f"Benchmark: {k}", v, None))
for k, v in holdout_files.items():
    suites.append((f"Holdout: {k}", v, None))

results_by_suite = {}
four_way_test_details = []

for suite_name, rows, cached_emb in suites:
    if not rows: continue
    texts = [get_text(r) for r in rows]
    y_true = np.array([get_label(r) for r in rows], dtype=np.int32)
    no_vecs = np.array([check_no_vectors(t) for t in texts])
    
    # 1. Primary predictions
    v43_probs, v43_preds = predict_v43(texts)
    
    # 2. Auxiliary predictions
    aux_probs, aux_margins, _ = predict_aux(texts, cached_emb)
    
    # 3. Form Variant B (No Downgrade)
    var_b_preds = np.copy(v43_preds)
    b_up_mask = (v43_preds != 2) & (aux_probs[:, 2] >= best_theta_up) & (aux_margins >= 0.40)
    var_b_preds[b_up_mask] = 2
    
    # 4. Form Variant C (Tightly Gated Downgrade)
    var_c_preds = np.copy(v43_preds)
    var_c_preds[b_up_mask] = 2
    c_down_mask = (
        (v43_preds == 2) &
        (v43_probs[:, 2] < 0.70) &
        no_vecs &
        (aux_probs[:, 0] >= best_theta_down) &
        (aux_probs[:, 2] <= 0.05) &
        (aux_margins >= 0.50)
    )
    var_c_preds[c_down_mask] = 0
    
    # Calculate metrics
    def calc_suite_metrics(y_p, y_t):
        n_ben = int((y_t == 0).sum())
        n_spam = int((y_t == 1).sum())
        n_mal = int((y_t == 2).sum())
        
        ben_fp = int((y_p[y_t == 0] != 0).sum())
        ben_fpr = ben_fp / n_ben if n_ben > 0 else 0.0
        
        mal_det = int((y_p[y_t == 2] == 2).sum())
        mal_rec = mal_det / n_mal if n_mal > 0 else 0.0
        
        spam_to_mal = int((y_p[y_t == 1] == 2).sum())
        spam_to_mal_rate = spam_to_mal / n_spam if n_spam > 0 else 0.0
        
        return {
            "n_total": len(y_t),
            "n_benign": n_ben,
            "n_spam": n_spam,
            "n_malicious": n_mal,
            "benign_fp": ben_fp,
            "benign_fpr": float(ben_fpr),
            "malicious_detected": mal_det,
            "malicious_recall": float(mal_rec),
            "spam_to_malicious": spam_to_mal,
            "spam_to_malicious_rate": float(spam_to_mal_rate),
        }
        
    m_v43 = calc_suite_metrics(v43_preds, y_true)
    m_var_b = calc_suite_metrics(var_b_preds, y_true)
    m_var_c = calc_suite_metrics(var_c_preds, y_true)
    
    # Upgrades / downgrades count
    upgrades_b_to_m = int(((v43_preds != 2) & (var_c_preds == 2) & (y_true == 0)).sum())
    upgrades_s_to_m = int(((v43_preds != 2) & (var_c_preds == 2) & (y_true == 1)).sum())
    downgrades_m_to_b = int(((v43_preds == 2) & (var_c_preds == 0) & (y_true == 2)).sum())
    downgrades_fp_to_b = int(((v43_preds == 2) & (var_c_preds == 0) & (y_true == 0)).sum())
    
    results_by_suite[suite_name] = {
        "variant_a_v43": m_v43,
        "variant_b_no_downgrade": m_var_b,
        "variant_c_gated_downgrade": m_var_c,
        "upgraded_benign_to_mal": upgrades_b_to_m,
        "upgraded_spam_to_mal": upgrades_s_to_m,
        "downgraded_mal_to_ben": downgrades_m_to_b,
        "downgraded_fp_to_ben": downgrades_fp_to_b,
    }
    
    # If Primary TEST: perform four-way analysis
    if suite_name == "Primary TEST":
        for i, (r, t, yt, vp, cp, pr_v, pr_a) in enumerate(zip(rows, texts, y_true, v43_preds, var_c_preds, v43_probs, aux_probs)):
            if yt == 2: # Malicious record
                cat = None
                if vp == 2 and cp == 2:
                    cat = "A" # Both correct
                elif vp == 2 and cp != 2:
                    cat = "B" # V4.3 correct, New wrong (Regression)
                elif vp != 2 and cp == 2:
                    cat = "C" # V4.3 wrong, New correct (Recovery)
                else:
                    cat = "D" # Both wrong
                four_way_test_details.append({
                    "index": i,
                    "id": r.get("message_id") or r.get("id"),
                    "text": t,
                    "category": cat,
                    "v43_pred": LABEL_NAMES[vp],
                    "new_pred": LABEL_NAMES[cp],
                    "p_v43_b": float(pr_v[0]),
                    "p_v43_s": float(pr_v[1]),
                    "p_v43_m": float(pr_v[2]),
                    "p_aux_b": float(pr_a[0]),
                    "p_aux_s": float(pr_a[1]),
                    "p_aux_m": float(pr_a[2]),
                })

# Print Results Table
print("\n" + "=" * 110)
print(f"{'SUITE':<35} | {'V4.3 Mal':<12} | {'V4.3 FPR':<9} | {'Var B Mal':<12} | {'Var B FPR':<9} | {'Var C Mal':<12} | {'Var C FPR':<9}")
print("=" * 110)
for s, res in results_by_suite.items():
    va = res["variant_a_v43"]
    vb = res["variant_b_no_downgrade"]
    vc = res["variant_c_gated_downgrade"]
    
    m_va = f"{va['malicious_detected']}/{va['n_malicious']}"
    f_va = f"{va['benign_fpr']*100:.2f}%"
    m_vb = f"{vb['malicious_detected']}/{vb['n_malicious']}"
    f_vb = f"{vb['benign_fpr']*100:.2f}%"
    m_vc = f"{vc['malicious_detected']}/{vc['n_malicious']}"
    f_vc = f"{vc['benign_fpr']*100:.2f}%"
    
    print(f"{s:<35} | {m_va:<12} | {f_va:<9} | {m_vb:<12} | {f_vb:<9} | {m_vc:<12} | {f_vc:<9}")

# Four-way analysis counts on Primary TEST
fw_counts = Counter([d["category"] for d in four_way_test_details])
print("\n" + "=" * 80)
print("PRIMARY TEST FOUR-WAY MALICIOUS MATRIX (N=1,556):")
print(f"  Category A (Both Correct)            : {fw_counts['A']} ({fw_counts['A']/1556*100:.2f}%)")
print(f"  Category B (V4.3 Correct, New Wrong) : {fw_counts['B']} ({fw_counts['B']/1556*100:.2f}%) [REGRESSION]")
print(f"  Category C (V4.3 Wrong, New Correct) : {fw_counts['C']} ({fw_counts['C']/1556*100:.2f}%) [RECOVERED]")
print(f"  Category D (Both Wrong)              : {fw_counts['D']} ({fw_counts['D']/1556*100:.2f}%) [MISSED BY BOTH]")
print("=" * 80)

# Save evaluation JSON
with open(EXP_DIR / "evaluation_results.json", "w", encoding="utf-8") as f:
    json.dump({
        "config": config,
        "results_by_suite": results_by_suite,
        "four_way_summary": dict(fw_counts)
    }, f, indent=2)

# Save regression forensic JSON
with open(EXP_DIR / "regression_forensic.json", "w", encoding="utf-8") as f:
    json.dump({
        "four_way_test_details": four_way_test_details,
        "recovered_cases_category_c": [d for d in four_way_test_details if d["category"] == "C"],
        "regression_cases_category_b": [d for d in four_way_test_details if d["category"] == "B"],
    }, f, indent=2)

# Save training manifest and artifact manifest
training_manifest = {
    "training_corpus": str(aux_train_path),
    "training_records": len(aux_train_rows),
    "provenance_audit_file": str(DATA_DIR / "PROVENANCE_AUDIT.json"),
    "embedding_model": "all-MiniLM-L6-v2",
    "embedding_dimensions": 384,
    "classifier": "LogisticRegression(C=1.0, class_weight='balanced')",
    "random_seed": 20260925,
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
}
with open(EXP_DIR / "training_manifest.json", "w", encoding="utf-8") as f:
    json.dump(training_manifest, f, indent=2)

artifact_manifest = {
    "model_file": str(MODELS_DIR / "auxiliary_semantic_model.pkl"),
    "embedding_cache": str(aux_emb_cache),
    "config_file": str(EXP_DIR / "config.json"),
    "evaluation_file": str(EXP_DIR / "evaluation_results.json"),
    "regression_forensic_file": str(EXP_DIR / "regression_forensic.json")
}
with open(EXP_DIR / "artifact_manifest.json", "w", encoding="utf-8") as f:
    json.dump(artifact_manifest, f, indent=2)

print("Experiment execution and artifact generation complete.")
