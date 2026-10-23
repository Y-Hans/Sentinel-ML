"""Reproducible Messages V4 build, experiment, and Android-export pipeline.

V4 deliberately keeps the portable V2 feature shape so a candidate can be
exported through the existing Android TF-IDF/tree runtime.  The experiment
compares full features with a deterministic-field ablation.
"""
from __future__ import annotations

import hashlib
import json
import os
import pickle
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
# The desktop sandbox blocks creation of Windows multiprocessing pipes.  HistGBM
# remains deterministic and fully functional with a single OpenMP worker.
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "1")
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "messages_v4"
sys.path.insert(0, str(ROOT / "scripts"))
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector

SEED = 20260914
LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}


def read_jsonl(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows), encoding="utf-8")


def synthetic_pairs(version=1):
    """Controlled contrastive augmentation. No protected benchmark text is reused."""
    services = [
        ("electricity account", "provider app"), ("banking profile", "official mobile app"),
        ("delivery order", "order details in the app"), ("university account", "campus portal"),
        ("telecom connection", "provider self-care app"), ("tax filing", "government portal"),
    ]
    actions = ["review the notice", "check the status", "complete the scheduled update", "contact official support"]
    rows = []
    for i, (thing, official) in enumerate(services):
        for j, action in enumerate(actions):
            benign = f"Service notice: your {thing} has an update. Please {action} using the {official}. Never share an OTP, PIN, or password with anyone."
            malicious = f"Urgent {thing} alert: your service will be blocked today. Open http://secure-update-{i}{j}.example and enter your OTP and password immediately to restore it."
            for text, label, typ in ((benign, "BENIGN", "LEGITIMATE_LOOKALIKE"), (malicious, "MALICIOUS", "SOCIAL_ENGINEERING")):
                digest = hashlib.sha256((typ + text).encode()).hexdigest()
                rows.append({"message_id": "V4_SYN_" + digest[:24], "raw_text": text,
                             "security_label": label, "source_id": "SRC_V4_CONTROLLED_CONTRASTIVE_V1",
                             "source_type": "SYNTHETIC", "split": "TRAIN", "language": "en",
                             "primary_type": typ, "provenance": "controlled contrastive augmentation; not evaluation-derived"})
    hinglish = [
        ("Aapka order kal deliver hoga. Delivery ke time OTP sirf doorstep par agent ko batayein.", "BENIGN"),
        ("Bank alert: OTP kisi ko mat batana. Agar doubt ho to official app se support contact karein.", "BENIGN"),
        ("College portal maintenance kal subah hogi, login ke liye official website use karein.", "BENIGN"),
        ("Aapka bijli bill generate ho gaya hai. Payment provider app mein due date se pehle karein.", "BENIGN"),
        ("Aapka bank account band ho jayega. Abhi link kholkar OTP aur PIN bhejo: http://verify-now.example", "MALICIOUS"),
        ("Bijli aaj raat cut hogi. Turant is link par payment karo aur card details do: http://pay-fast.example", "MALICIOUS"),
        ("Courier rok diya gaya hai, delivery ke liye OTP is number par reply karo warna parcel return hoga.", "MALICIOUS"),
        ("KYC abhi update karo, WhatsApp support ko password bhejo warna account freeze hoga.", "MALICIOUS"),
    ]
    for i, (text, label) in enumerate(hinglish):
        for variant in range(8):
            rendered = text + (" Please verify details in the app." if variant % 2 else "")
            rows.append({"message_id": f"V4_HI_{i}_{variant}", "raw_text": rendered, "security_label": label,
                         "source_id": "SRC_V4_CONTROLLED_HINGLISH_V1", "source_type": "SYNTHETIC",
                         "split": "TRAIN", "language": "hinglish", "primary_type": "CONTROLLED_HINGLISH",
                         "provenance": "controlled Hinglish augmentation; not evaluation-derived"})
    if version == 1:
        return rows
    # V4-B uses compositional contrasts: topic is held constant while the action
    # changes from official-channel information to coercive secret disclosure.
    entities = ["electricity service", "bank account", "parcel delivery", "student portal", "mobile connection", "tax return", "UPI payment", "social account"]
    consequences = ["will be interrupted", "will be locked", "will be returned", "will be disabled"]
    official = ["the official app", "the provider website you normally use", "your saved account dashboard", "the service help centre"]
    channels = ["this web link", "a WhatsApp agent", "a number in this message", "a Telegram support account"]
    secrets = ["OTP", "UPI PIN", "password", "card number and CVV"]
    for i, entity in enumerate(entities):
        for j, consequence in enumerate(consequences):
            for k, secret in enumerate(secrets):
                benign = f"Notification: your {entity} has a scheduled update. Review it in {official[(i+j+k)%len(official)]}. Support will never request your {secret} in a message."
                attack = f"Urgent alert: your {entity} {consequence} today. Reply to {channels[(i+j+k)%len(channels)]} with your {secret} now to prevent the action."
                for repeat in range(3):
                    for text, label in ((benign, "BENIGN"), (attack, "MALICIOUS")):
                        rows.append({"message_id": f"V4B_EN_{i}_{j}_{k}_{repeat}_{label}", "raw_text": text, "security_label": label, "source_id": "SRC_V4_COMPOSITIONAL_CONTRASTIVE_V2", "source_type": "SYNTHETIC", "split": "TRAIN", "language": "en", "primary_type": "COMPOSITIONAL_CONTRASTIVE", "provenance": "controlled compositional augmentation; not evaluation-derived"})
    hindi_entities = ["bijli connection", "bank account", "courier parcel", "college account", "UPI payment"]
    for i, entity in enumerate(hindi_entities):
        for secret in ("OTP", "PIN", "password"):
            benign = f"Update: aapke {entity} ka notice available hai. Details {official[i % len(official)]} mein check karein. {secret} kisi ko share mat karein."
            attack = f"Urgent: aapka {entity} aaj block hoga. {channels[i % len(channels)]} par abhi {secret} bhejo warna service band ho jayegi."
            for repeat in range(12):
                for text, label in ((benign, "BENIGN"), (attack, "MALICIOUS")):
                    rows.append({"message_id": f"V4B_HI_{i}_{secret}_{repeat}_{label}", "raw_text": text, "security_label": label, "source_id": "SRC_V4_COMPOSITIONAL_HINGLISH_V2", "source_type": "SYNTHETIC", "split": "TRAIN", "language": "hinglish", "primary_type": "COMPOSITIONAL_HINGLISH", "provenance": "controlled Hinglish augmentation; not evaluation-derived"})
    return rows


def build_dataset(version=1):
    base = read_jsonl(ROOT / "data" / "processed" / "train_expanded_v5.jsonl")
    synth = synthetic_pairs(version)
    ids = {r.get("message_id") for r in base}
    synth = [r for r in synth if r["message_id"] not in ids]
    rows = base + synth
    write_jsonl(OUT / "data" / f"train_v4_{version}.jsonl", rows)
    manifest = {"version": "messages_v4_dataset_1", "created_utc": datetime.now(timezone.utc).isoformat(),
                "base": "data/processed/train_expanded_v5.jsonl", "base_records": len(base),
                "controlled_synthetic_records": len(synth), "total_records": len(rows),
                "label_counts": Counter(r.get("security_label") for r in rows),
                "source_counts": Counter(r.get("source_id") for r in rows),
                "sha256": hashlib.sha256((OUT / "data" / f"train_v4_{version}.jsonl").read_bytes()).hexdigest(),
                "protected_evaluation_inputs": ["val.jsonl", "test.jsonl", "ood.jsonl", "data/benchmarks/*", "7sep_messages_v3/data/bench_*.jsonl"],
                "policy": "Protected evaluation text was not copied or paraphrased into V4 training."}
    (OUT / f"dataset_manifest_v4_{version}.json").write_text(json.dumps(manifest, indent=2, default=lambda x: dict(x)), encoding="utf-8")
    return rows


def fit_vectorizers(rows):
    text = [r.get("raw_text", "") for r in rows]
    word = TfidfVectorizer(max_features=1500, ngram_range=(1, 2), stop_words="english", sublinear_tf=True)
    char = TfidfVectorizer(max_features=500, analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True)
    return word, char, word.fit_transform(text).toarray(), char.fit_transform(text).toarray()


def matrix(rows, word, char, deterministic):
    text = [r.get("raw_text", "") for r in rows]
    w, c = word.transform(text).toarray(), char.transform(text).toarray()
    if deterministic:
        det = np.asarray([extract_feature_vector(r.get("raw_text", ""), r.get("sender_header"), FeatureConfig()) for r in rows], dtype=np.float32)
    else:
        # Deliberate V4 representation: no surface-rule or sender-trust fields.
        det = np.zeros((len(rows), 70), dtype=np.float32)
    return np.hstack((det, w, c)).astype(np.float32)


def labels(rows): return np.asarray([LABELS.get(r.get("security_label"), 0) for r in rows], dtype=np.int32)


def predictions(probs, threshold):
    pnon = probs[:, 1] + probs[:, 2]
    return np.where(pnon >= threshold, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)


def metrics(rows, probs, threshold):
    y, pred = labels(rows), predictions(probs, threshold)
    cm = confusion_matrix(y, pred, labels=[0, 1, 2])
    benign = max(1, int(cm[0].sum())); mal = max(1, int(cm[2].sum()))
    return {"n": len(rows), "threshold": threshold, "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
            "benign_nonbenign_fpr": float((cm[0,1]+cm[0,2])/benign), "malicious_recall": float(cm[2,2]/mal),
            "nonbenign_recall": float(((pred[y != 0] != 0).sum()) / max(1, (y != 0).sum())), "confusion_matrix": cm.tolist()}


def choose_threshold(val, probs):
    # Locked on validation: maximize recall under a conservative benign FPR cap.
    frontier = []
    for t in np.arange(.50, .951, .01):
        m = metrics(val, probs, float(round(t, 3))); frontier.append(m)
    feasible = [m for m in frontier if m["benign_nonbenign_fpr"] <= .02]
    best = max(feasible or frontier, key=lambda m: (m["malicious_recall"], m["macro_f1"]))
    return best["threshold"], frontier


def run(version=1):
    global OUT
    # Each run is immutable; do not overwrite earlier candidate artifacts.
    OUT = ROOT / "messages_v4" / f"experiment_{version}"
    OUT.mkdir(exist_ok=True)
    train = build_dataset(version)
    val, test, ood = (read_jsonl(ROOT / "data" / "processed" / f"{n}.jsonl") for n in ("val", "test", "ood"))
    word, char, _, _ = fit_vectorizers(train)
    ytr = labels(train)
    results, candidates = {}, {}
    for name, det in (("full_features", True), ("text_only", False)):
        started = time.time(); xtr = matrix(train, word, char, det); scaler = StandardScaler().fit(xtr); xtr = scaler.transform(xtr)
        model = HistGradientBoostingClassifier(max_iter=300, max_leaf_nodes=31, l2_regularization=1.0,
                                               learning_rate=.08, random_state=SEED, class_weight="balanced").fit(xtr, ytr)
        pval = model.predict_proba(scaler.transform(matrix(val, word, char, det)))
        threshold, frontier = choose_threshold(val, pval)
        candidates[name] = {"deterministic_features": det, "training_seconds": time.time()-started,
                            "threshold": threshold, "validation": metrics(val,pval,threshold), "frontier": frontier}
        results[name] = (model, scaler, threshold, det)
    # Selection is validation-only and documented before reading TEST/OOD metrics.
    selected = max(candidates, key=lambda k: (candidates[k]["validation"]["malicious_recall"], -candidates[k]["validation"]["benign_nonbenign_fpr"], candidates[k]["validation"]["macro_f1"]))
    model, scaler, threshold, det = results[selected]
    evaluation = {"selected": selected, "candidates": candidates, "threshold_locked_from": "validation"}
    for name, rows in (("validation", val), ("test", test), ("ood", ood)):
        evaluation[name] = metrics(rows, model.predict_proba(scaler.transform(matrix(rows, word, char, det))), threshold)
    benchmark_files = list((ROOT / "data" / "benchmarks").glob("*.jsonl")) + list((ROOT.parent / "7sep_messages_v3" / "data").glob("bench_*.jsonl"))
    evaluation["benchmarks"] = {}
    for p in benchmark_files:
        rows = read_jsonl(p)
        if rows and all(r.get("security_label") in LABELS for r in rows):
            evaluation["benchmarks"][p.name] = metrics(rows, model.predict_proba(scaler.transform(matrix(rows, word, char, det))), threshold)
    artifacts = OUT / "artifacts"; artifacts.mkdir(exist_ok=True)
    for name, obj in (("messages_v4_model.pkl", model), ("messages_v4_scaler.pkl", scaler), ("messages_v4_tfidf_word.pkl", word), ("messages_v4_tfidf_char.pkl", char)):
        with (artifacts / name).open("wb") as f: pickle.dump(obj, f)
    config = {"version":"Messages V4", "architecture":f"HistGradientBoostingClassifier ({'full deterministic + text' if det else 'text-only; deterministic inputs hard-zeroed'})", "feature_dimensions":2070,
              "word_features":1500,"char_features":500,"deterministic_features_used":70 if det else 0,"seed":SEED,"selected_candidate":selected,
              "model_params":model.get_params(),"dataset_manifest":"../dataset_manifest.json"}
    (artifacts / "messages_v4_config.json").write_text(json.dumps(config, indent=2, default=str), encoding="utf-8")
    (artifacts / "messages_v4_threshold.json").write_text(json.dumps({"nonbenign_threshold":threshold,"selection_split":"validation","policy":"max malicious recall subject to benign FPR <= 2%"},indent=2), encoding="utf-8")
    # Histogram models are already probabilistic; calibration is measured, not invented.
    (artifacts / "messages_v4_calibration.json").write_text(json.dumps({"method":"native HistGradientBoosting probabilities", "note":"No post-hoc calibration fitted: validation was used exclusively for threshold selection."},indent=2), encoding="utf-8")
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts.iterdir() if p.is_file()}
    evaluation["artifact_hashes"] = hashes
    (OUT / "evaluation.json").write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
    export_android(model, scaler, word, char, threshold, artifacts, hashes, det)
    return evaluation


def export_android(clf, scaler, word, char, threshold, artifacts, hashes, deterministic_used):
    assets = OUT / "android_assets"; assets.mkdir(exist_ok=True)
    def dump(n, data): (assets/n).write_text(json.dumps(data, separators=(",", ":"), default=lambda x: int(x) if isinstance(x, np.integer) else float(x)), encoding="utf-8")
    dump("messages_v4_word_vocab_idf.json", {"version":"4.0.0","n_features":1500,"ngram_range":list(word.ngram_range),"stop_words":sorted(word.get_stop_words()),"token_pattern":"(?u)\\b\\w\\w+\\b","norm":word.norm,"sublinear_tf":word.sublinear_tf,"vocabulary":word.vocabulary_,"idf":word.idf_.tolist()})
    dump("messages_v4_char_vocab_idf.json", {"version":"4.0.0","n_features":500,"analyzer":char.analyzer,"ngram_range":list(char.ngram_range),"norm":char.norm,"sublinear_tf":char.sublinear_tf,"vocabulary":char.vocabulary_,"idf":char.idf_.tolist()})
    dump("messages_v4_scaler.json", {"version":"4.0.0","n_features":2070,"mean":scaler.mean_.tolist(),"scale":scaler.scale_.tolist(),"var":scaler.var_.tolist()})
    trees=[]
    for iteration in clf._predictors:
        trees.append([[[int(n['feature_idx']),int(n['bin_threshold']),int(n['left']),int(n['right']),float(n['value']),int(n['is_leaf']),int(n['missing_go_to_left'])] for n in tree.nodes] for tree in iteration])
    dump("messages_v4_trees.json", {"version":"4.0.0","model_type":"HistGradientBoostingClassifier","n_classes":3,"n_iterations":len(trees),"n_trees_total":len(trees)*3,"learning_rate":float(clf.learning_rate),"baseline_prediction":clf._baseline_prediction.tolist(),"decision_threshold":threshold,"class_labels":["BENIGN","SUSPICIOUS_SPAM","MALICIOUS"],"deterministic_features_used":70 if deterministic_used else 0,"bin_thresholds":[x.tolist() for x in clf._bin_mapper.bin_thresholds_],"trees":trees})
    manifest={"version":"Messages V4","threshold":threshold,"assets":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.iterdir()},"python_artifacts":hashes}
    (assets/"messages_v4_android_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
