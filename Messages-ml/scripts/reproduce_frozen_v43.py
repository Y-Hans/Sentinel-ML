"""Read-only reproduction and record-level forensic export for frozen V4.3.

Writes only to messages_v4_3/evaluation/reproduction_20260930/.
"""
import hashlib
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "messages_v4_3" / "models"))
from candidate_d_v4_3 import extract_structural_signals  # noqa: E402

ART = ROOT / "messages_v4_3" / "models" / "candidate_d"
OUT = ROOT / "messages_v4_3" / "evaluation" / "reproduction_20260930"
LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
REV = {v: k for k, v in LABELS.items()}
TAU = 0.61


def read_rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    model, scaler, word, char = [pickle.load(open(ART / n, "rb")) for n in
                                 ("model.pkl", "scaler.pkl", "word_vec.pkl", "char_vec.pkl")]
    artifact_meta = {
        "sha256": {p.name: sha256(p) for p in sorted(ART.glob("*.pkl"))},
        "classes_": [int(x) for x in model.classes_],
        "n_features_in_": int(model.n_features_in_),
        "n_iter_": int(model.n_iter_),
        "max_iter": model.max_iter,
        "early_stopping": model.early_stopping,
        "validation_fraction": model.validation_fraction,
        "n_iter_no_change": model.n_iter_no_change,
        "tol": model.tol,
        "learning_rate": model.learning_rate,
        "max_leaf_nodes": model.max_leaf_nodes,
        "l2_regularization": model.l2_regularization,
        "class_weight": model.class_weight,
        "word_features": len(word.vocabulary_),
        "word_config": {k: getattr(word, k) for k in ("ngram_range", "max_features", "sublinear_tf", "lowercase", "strip_accents")},
        "char_features": len(char.vocabulary_),
        "char_config": {k: getattr(char, k) for k in ("analyzer", "ngram_range", "max_features", "sublinear_tf", "lowercase", "strip_accents")},
        "scaler_features": int(scaler.n_features_in_),
    }
    results = {"artifacts": artifact_meta, "splits": {}}
    for split in ("val", "test", "ood"):
        path = ROOT / "data" / "processed" / f"{split}.jsonl"
        rows = read_rows(path)
        texts = [r.get("raw_text", "") for r in rows]
        st = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
        X = np.hstack([st, word.transform(texts).toarray(), char.transform(texts).toarray()]).astype(np.float32)
        probs = model.predict_proba(scaler.transform(X))
        y = np.array([LABELS.get(r.get("security_label"), 0) for r in rows])
        pnb = probs[:, 1] + probs[:, 2]
        pred = np.where(pnb >= TAU, np.where(probs[:, 2] >= probs[:, 1], 2, 1), 0)
        cm = [[int(((y == a) & (pred == b)).sum()) for b in range(3)] for a in range(3)]
        false = []
        for i, (row, pp, yh) in enumerate(zip(rows, probs, pred)):
            if yh == y[i]:
                continue
            # Per-record active word/character TF-IDF entries with strongest values.
            wrow = word.transform([texts[i]]).tocsr()
            crow = char.transform([texts[i]]).tocsr()
            wi = sorted(zip(wrow.indices, wrow.data), key=lambda x: -x[1])[:25]
            ci = sorted(zip(crow.indices, crow.data), key=lambda x: -x[1])[:25]
            wnames = {v: k for k, v in word.vocabulary_.items()}
            cnames = {v: k for k, v in char.vocabulary_.items()}
            false.append({
                "row_index": i, "message_id": row.get("message_id"), "source_id": row.get("source_id"),
                "source_type": row.get("source_type"), "category": row.get("primary_type"), "language": row.get("language"),
                "true_label": REV[int(y[i])], "predicted_label": REV[int(yh)], "probabilities": {REV[j]: float(pp[j]) for j in range(3)},
                "p_nonbenign": float(pnb[i]), "raw_text": texts[i], "structural": [float(x) for x in st[i]],
                "length": len(texts[i]), "url_present": bool(st[i][10]), "phone_present": bool(st[i][12]),
                "top_word_features": [[wnames[idx], float(val)] for idx, val in wi],
                "top_char_features": [[cnames[idx], float(val)] for idx, val in ci],
            })
        nben = int((y == 0).sum()); nmal = int((y == 2).sum())
        met = {"n": len(rows), "label_counts": {REV[i]: int((y == i).sum()) for i in range(3)},
               "confusion_matrix_true_by_pred_benign_spam_malicious": cm,
               "malicious_recall": float(((y == 2) & (pred == 2)).sum() / nmal),
               "malicious_correct": int(((y == 2) & (pred == 2)).sum()), "malicious_fn": int(((y == 2) & (pred != 2)).sum()),
               "benign_fpr": float(((y == 0) & (pred != 0)).sum() / nben),
               "benign_fp": int(((y == 0) & (pred != 0)).sum()),
               "spam_to_malicious": int(((y == 1) & (pred == 2)).sum()),
               "malicious_to_spam": int(((y == 2) & (pred == 1)).sum()),
               "p_nonbenign_quantiles": {str(q): float(np.quantile(pnb, q)) for q in (0, .25, .5, .75, .9, .95, .99, 1)},
               }
        # Useful class-conditional score summaries without fragile empty comprehensions.
        met["mean_probabilities_by_true_label"] = {REV[k]: [float(x) for x in probs[y == k].mean(axis=0)] for k in range(3)}
        results["splits"][split] = met
        (OUT / f"{split}_errors.json").write_text(json.dumps(false, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "reproduction.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
