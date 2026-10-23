"""
Export Sentinel Messages V4.4 Candidate B to Android JSON assets and golden fixtures.
"""
from __future__ import annotations
import hashlib
import json
import pickle
import sys
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve()
V4_4_DIR = HERE.parent.parent
MESSAGES_ML = V4_4_DIR.parent
ROOT = MESSAGES_ML.parents[1]
MODELS_DIR = V4_4_DIR / "models/candidate_b_refined"
ANDROID_OUT = V4_4_DIR / "android"
ANDROID_CORE_ASSETS = ROOT / "sentinel-ai/android-app/core/src/main/assets"
ANDROID_APP_ASSETS = ROOT / "sentinel-ai/android-app/app/src/main/assets"
ANDROID_TEST_RES = ROOT / "sentinel-ai/android-app/core/src/test/resources"

sys.path.insert(0, str(MESSAGES_ML / "scripts"))
sys.path.insert(0, str(MESSAGES_ML / "messages_v4_3/models"))
from candidate_d_v4_3 import extract_structural_signals

def export_v4_4(copy_to_android: bool = True):
    print("Loading Candidate B V4.4 artifacts...")
    with open(MODELS_DIR / "word_vec.pkl", "rb") as f: tw = pickle.load(f)
    with open(MODELS_DIR / "char_vec.pkl", "rb") as f: tc = pickle.load(f)
    with open(MODELS_DIR / "scaler.pkl", "rb") as f: sc = pickle.load(f)
    with open(MODELS_DIR / "model.pkl", "rb") as f: clf = pickle.load(f)

    with open(MODELS_DIR / "config.json", "r", encoding="utf-8") as f:
        cfg = json.load(f)
    threshold = float(cfg["threshold"])
    print(f"Locked decision threshold for V4.4: {threshold}")

    ANDROID_OUT.mkdir(parents=True, exist_ok=True)

    # 1. Word TF-IDF bundle
    stop_words_list = sorted(list(tw.get_stop_words())) if tw.get_stop_words() else []
    word_bundle = {
        "version": "4.4.0",
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
    w_path = ANDROID_OUT / "messages_v4_4_word_vocab_idf.json"
    w_path.write_text(w_json, encoding="utf-8")
    print(f"Exported Word TF-IDF: {w_path} ({len(w_json)/1024:.2f} KB, {len(tw.vocabulary_)} tokens)")

    # 2. Char TF-IDF bundle
    char_bundle = {
        "version": "4.4.0",
        "n_features": len(tc.vocabulary_),
        "analyzer": tc.analyzer,
        "ngram_range": list(tc.ngram_range),
        "norm": tc.norm,
        "sublinear_tf": bool(tc.sublinear_tf),
        "vocabulary": {k: int(v) for k, v in tc.vocabulary_.items()},
        "idf": tc.idf_.tolist(),
    }
    c_json = json.dumps(char_bundle, separators=(",", ":"))
    c_path = ANDROID_OUT / "messages_v4_4_char_vocab_idf.json"
    c_path.write_text(c_json, encoding="utf-8")
    print(f"Exported Char TF-IDF: {c_path} ({len(c_json)/1024:.2f} KB, {len(tc.vocabulary_)} n-grams)")

    # 3. Scaler bundle
    scaler_bundle = {
        "version": "4.4.0",
        "n_features": int(sc.n_features_in_),
        "mean": sc.mean_.tolist(),
        "scale": sc.scale_.tolist(),
        "var": sc.var_.tolist(),
    }
    s_json = json.dumps(scaler_bundle, separators=(",", ":"))
    s_path = ANDROID_OUT / "messages_v4_4_scaler.json"
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
        "version": "4.4.0",
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
    t_path = ANDROID_OUT / "messages_v4_4_trees.json"
    t_path.write_text(t_json, encoding="utf-8")
    print(f"Exported Trees: {t_path} ({len(t_json)/1024:.2f} KB, {len(trees_data)*3} trees)")

    total_kb = (len(w_json) + len(c_json) + len(s_json) + len(t_json)) / 1024
    print(f"=== Total V4.4 Android Assets: {total_kb:.2f} KB ({total_kb/1024:.2f} MB) ===")

    # 5. Generate Golden Parity Fixtures (125 diverse evaluation messages)
    print("Generating golden parity records...")
    bench_dir = ROOT / "sentinel-ml/7sep_messages_v3/data"
    test_path = ROOT / "sentinel-ml/Messages-ml/data/processed/test.jsonl"
    holdout_dir = V4_4_DIR / "evaluation/holdouts"

    golden_texts = []
    if test_path.exists():
        with open(test_path, encoding="utf-8") as f:
            test_lines = [json.loads(line) for line in f if line.strip()]
        for r in test_lines[:40]:
            golden_texts.append((r.get("raw_text", ""), r.get("sender_header"), "TEST_SPLIT", r.get("security_label", "BENIGN")))

    for bname in ["bench_adversarial_semantic_pairs.jsonl", "bench_hinglish_robustness.jsonl", "bench_sentinel_replay.jsonl", "bench_system_notifications.jsonl"]:
        bp = bench_dir / bname
        if bp.exists():
            with open(bp, encoding="utf-8") as f:
                b_lines = [json.loads(line) for line in f if line.strip()]
            for r in b_lines[:15]:
                golden_texts.append((r.get("raw_text", ""), r.get("sender_header"), bname, r.get("security_label", "BENIGN")))

    for hname in ["holdout_electricity.jsonl", "holdout_conversational_social_eng.jsonl", "holdout_apk_payload.jsonl"]:
        hp = holdout_dir / hname
        if hp.exists():
            with open(hp, encoding="utf-8") as f:
                h_lines = [json.loads(line) for line in f if line.strip()]
            for r in h_lines[:10]:
                golden_texts.append((r.get("raw_text", ""), r.get("sender_header"), hname, r.get("security_label", "BENIGN")))

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
            "id": f"GOLDEN_V4_4_{idx:03d}",
            "text": txt,
            "sender": sender,
            "category": cat,
            "structural_features": [float(v) for v in st],
            "probabilities": [float(p) for p in probs],
            "predicted_class": int(pred_class),
            "label": label_map[pred_class],
            "expected_label": exp_label,
        })

    g_path = ANDROID_OUT / "golden_messages_v4_4.json"
    g_json = json.dumps(golden_records, indent=2, ensure_ascii=False)
    g_path.write_text(g_json, encoding="utf-8")
    print(f"Exported {len(golden_records)} golden records to {g_path} ({len(g_json)/1024:.2f} KB)")

    if copy_to_android:
        print("\nCopying V4.4 assets to Android runtime directories...")
        for target_dir in [ANDROID_CORE_ASSETS, ANDROID_APP_ASSETS, ANDROID_TEST_RES]:
            target_dir.mkdir(parents=True, exist_ok=True)
            for fname in ["messages_v4_4_word_vocab_idf.json", "messages_v4_4_char_vocab_idf.json", "messages_v4_4_scaler.json", "messages_v4_4_trees.json"]:
                dst = target_dir / fname
                dst.write_bytes((ANDROID_OUT / fname).read_bytes())
                print(f"  Copied {fname} -> {dst}")

        ANDROID_TEST_RES.mkdir(parents=True, exist_ok=True)
        dst_g = ANDROID_TEST_RES / "golden_messages_v4_4.json"
        dst_g.write_bytes(g_path.read_bytes())
        print(f"  Copied golden_messages_v4_4.json -> {dst_g}")

    # Compute SHA256 hashes of all exported artifacts
    hashes = {}
    for p in [w_path, c_path, s_path, t_path, g_path]:
        hashes[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()

    h_path = ANDROID_OUT / "android_asset_hashes.json"
    h_path.write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    print("\nAndroid Asset Hashes:")
    for k, v in hashes.items():
        print(f"  {k:<35s}: {v}")

if __name__ == "__main__":
    export_v4_4()
