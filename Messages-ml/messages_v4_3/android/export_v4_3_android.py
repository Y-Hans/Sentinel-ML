"""
Export Sentinel Messages V4.3 model, scaler, vectorizers, and golden parity fixtures
to Android portable JSON assets.
"""
from __future__ import annotations
import json
import pickle
import sys
from pathlib import Path
import numpy as np
import joblib

HERE = Path(__file__).resolve()
V4_3_DIR = HERE.parent.parent
ROOT = V4_3_DIR.parents[2]
MODELS_DIR = V4_3_DIR / "models" / "candidate_d"
REPORTS_DIR = V4_3_DIR / "reports"
ANDROID_OUT = V4_3_DIR / "android"
ANDROID_CORE_ASSETS = ROOT / "sentinel-ai" / "android-app" / "core" / "src" / "main" / "assets"
ANDROID_APP_ASSETS = ROOT / "sentinel-ai" / "android-app" / "app" / "src" / "main" / "assets"
ANDROID_TEST_RES = ROOT / "sentinel-ai" / "android-app" / "core" / "src" / "test" / "resources"

sys.path.insert(0, str(V4_3_DIR / "models"))
from candidate_d_v4_3 import extract_structural_signals

def export_v4_3(copy_to_android: bool = True):
    print("Loading Candidate D V4.3 artifacts...")
    tw = joblib.load(MODELS_DIR / "word_vec.pkl")
    tc = joblib.load(MODELS_DIR / "char_vec.pkl")
    sc = joblib.load(MODELS_DIR / "scaler.pkl")
    clf = joblib.load(MODELS_DIR / "model.pkl")

    # Load locked decision threshold
    metrics_path = REPORTS_DIR / "candidate_d_metrics.json"
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f:
            m_data = json.load(f)
        threshold = float(m_data.get("threshold", 0.704))
    else:
        threshold = 0.704
    print(f"Locked decision threshold: {threshold}")

    ANDROID_OUT.mkdir(parents=True, exist_ok=True)

    # 1. Word TF-IDF bundle
    stop_words_list = sorted(list(tw.get_stop_words())) if tw.get_stop_words() else []
    word_bundle = {
        "version": "4.3.0",
        "n_features": len(tw.vocabulary_),
        "ngram_range": list(tw.ngram_range),
        "stop_words": stop_words_list,
        "token_pattern": "(?u)\\b\\w\\w+\\b",
        "norm": tw.norm,
        "sublinear_tf": bool(tw.sublinear_tf),
        "vocabulary": {k: int(v) for k, v in tw.vocabulary_.items()},
        "idf": tw.idf_.tolist(),
    }
    w_json = json.dumps(word_bundle, separators=(",", ":"))
    w_path = ANDROID_OUT / "messages_v4_3_word_vocab_idf.json"
    w_path.write_text(w_json, encoding="utf-8")
    print(f"Exported Word TF-IDF: {w_path} ({len(w_json)/1024:.2f} KB, {len(tw.vocabulary_)} tokens)")

    # 2. Char TF-IDF bundle
    char_bundle = {
        "version": "4.3.0",
        "n_features": len(tc.vocabulary_),
        "analyzer": tc.analyzer,
        "ngram_range": list(tc.ngram_range),
        "norm": tc.norm,
        "sublinear_tf": bool(tc.sublinear_tf),
        "vocabulary": {k: int(v) for k, v in tc.vocabulary_.items()},
        "idf": tc.idf_.tolist(),
    }
    c_json = json.dumps(char_bundle, separators=(",", ":"))
    c_path = ANDROID_OUT / "messages_v4_3_char_vocab_idf.json"
    c_path.write_text(c_json, encoding="utf-8")
    print(f"Exported Char TF-IDF: {c_path} ({len(c_json)/1024:.2f} KB, {len(tc.vocabulary_)} n-grams)")

    # 3. Scaler bundle
    scaler_bundle = {
        "version": "4.3.0",
        "n_features": int(sc.n_features_in_),
        "mean": sc.mean_.tolist(),
        "scale": sc.scale_.tolist(),
        "var": sc.var_.tolist(),
    }
    s_json = json.dumps(scaler_bundle, separators=(",", ":"))
    s_path = ANDROID_OUT / "messages_v4_3_scaler.json"
    s_path.write_text(s_json, encoding="utf-8")
    print(f"Exported Scaler: {s_path} ({len(s_json)/1024:.2f} KB, {sc.n_features_in_} features)")

    # 4. Trees bundle
    trees_data = []
    for iter_idx in range(len(clf._predictors)):
        iter_classes = []
        for k in range(3):
            tree = clf._predictors[iter_idx][k]
            nodes_list = []
            for node in tree.nodes:
                nodes_list.append([
                    int(node["feature_idx"]),
                    int(node["bin_threshold"]),
                    int(node["left"]),
                    int(node["right"]),
                    float(node["value"]),
                    int(node["is_leaf"]),
                    int(node["missing_go_to_left"]),
                ])
            iter_classes.append(nodes_list)
        trees_data.append(iter_classes)

    tree_bundle = {
        "version": "4.3.0",
        "model_type": "HistGradientBoostingClassifier",
        "n_classes": 3,
        "n_iterations": len(trees_data),
        "n_trees_total": len(trees_data) * 3,
        "learning_rate": float(clf.learning_rate),
        "baseline_prediction": clf._baseline_prediction.tolist(),
        "decision_threshold": threshold,
        "class_labels": ["BENIGN", "SUSPICIOUS_SPAM", "MALICIOUS"],
        "n_features": int(sc.n_features_in_),
        "bin_thresholds": [arr.tolist() for arr in clf._bin_mapper.bin_thresholds_],
        "trees": trees_data,
    }
    t_json = json.dumps(tree_bundle, separators=(",", ":"))
    t_path = ANDROID_OUT / "messages_v4_3_trees.json"
    t_path.write_text(t_json, encoding="utf-8")
    print(f"Exported Trees: {t_path} ({len(t_json)/1024:.2f} KB, {len(trees_data)*3} trees)")

    total_kb = (len(w_json) + len(c_json) + len(s_json) + len(t_json)) / 1024
    print(f"=== Total V4.3 Android Assets: {total_kb:.2f} KB ({total_kb/1024:.2f} MB) ===")

    # 5. Generate Golden Parity Fixtures (115 diverse evaluation messages)
    print("Generating golden parity records...")
    bench_dir = ROOT / "sentinel-ml" / "7sep_messages_v3" / "data"
    test_path = ROOT / "sentinel-ml" / "Messages-ml" / "data" / "processed" / "test.jsonl"
    
    golden_texts = []
    if test_path.exists():
        with open(test_path, encoding="utf-8") as f:
            test_lines = [json.loads(line) for line in f if line.strip()]
        for r in test_lines[:40]:
            golden_texts.append((r.get("raw_text", ""), r.get("sender_header"), "TEST_SPLIT", r.get("security_label", "BENIGN")))

    for bname in ["bench_adversarial_semantic_pairs.jsonl", "bench_hinglish_robustness.jsonl", "bench_sentinel_replay.jsonl"]:
        bp = bench_dir / bname
        if bp.exists():
            with open(bp, encoding="utf-8") as f:
                b_lines = [json.loads(line) for line in f if line.strip()]
            for r in b_lines[:25]:
                golden_texts.append((r.get("raw_text", ""), r.get("sender_header"), bname, r.get("security_label", "BENIGN")))

    golden_records = []
    for idx, (txt, sender, cat, exp_label) in enumerate(golden_texts):
        st = extract_structural_signals(txt)
        w = tw.transform([txt]).toarray()
        c = tc.transform([txt]).toarray()
        X = np.hstack([[st], w, c]).astype(np.float32)
        X_scaled = sc.transform(X)
        probs = clf.predict_proba(X_scaled)[0]
        p_nonbenign = float(probs[1] + probs[2])
        pred_class = 2 if (p_nonbenign >= threshold and probs[2] >= probs[1]) else (1 if p_nonbenign >= threshold else 0)
        label_map = {0: "BENIGN", 1: "SUSPICIOUS_SPAM", 2: "MALICIOUS"}

        golden_records.append({
            "id": f"GOLDEN_V4_3_{idx:03d}",
            "text": txt,
            "sender": sender,
            "category": cat,
            "structural_features": [float(v) for v in st],
            "probabilities": [float(p) for p in probs],
            "predicted_class": int(pred_class),
            "label": label_map[pred_class],
            "expected_label": exp_label,
        })

    g_path = ANDROID_OUT / "golden_messages_v4_3.json"
    g_json = json.dumps(golden_records, indent=2, ensure_ascii=False)
    g_path.write_text(g_json, encoding="utf-8")
    print(f"Exported {len(golden_records)} golden records to {g_path} ({len(g_json)/1024:.2f} KB)")

    if copy_to_android:
        print("\nCopying V4.3 assets to Android runtime directories...")
        for target_dir in [ANDROID_CORE_ASSETS, ANDROID_APP_ASSETS, ANDROID_TEST_RES]:
            target_dir.mkdir(parents=True, exist_ok=True)
            for fname in ["messages_v4_3_word_vocab_idf.json", "messages_v4_3_char_vocab_idf.json", "messages_v4_3_scaler.json", "messages_v4_3_trees.json"]:
                dst = target_dir / fname
                dst.write_bytes((ANDROID_OUT / fname).read_bytes())
                print(f"  Copied {fname} -> {dst}")

        ANDROID_TEST_RES.mkdir(parents=True, exist_ok=True)
        dst_g = ANDROID_TEST_RES / "golden_messages_v4_3.json"
        dst_g.write_bytes(g_path.read_bytes())
        print(f"  Copied golden_messages_v4_3.json -> {dst_g}")

if __name__ == "__main__":
    export_v4_3()
