"""Evaluate the fresh URL model, including required final-test slices."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent))
from fresh_url_features import extract_fresh_features, vectorize_urls  # noqa: E402
from fresh_url_schema import read_jsonl  # noqa: E402


def metrics(y_true, scores, threshold):
    y_pred = (scores >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "malicious_recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "benign_false_positive_rate": float(fp / max(1, fp + tn)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "row_count": int(len(y_true)),
    }


def slice_metrics(rows, scores, threshold):
    y = np.array([row["label"] == "MALICIOUS" for row in rows], dtype=np.int8)
    output = {}
    buckets = {
        "short_url": lambda row: len(row["canonical_url"]) <= 75,
        "long_url": lambda row: len(row["canonical_url"]) >= 200,
        "brand_impersonation": lambda row: extract_fresh_features(row["canonical_url"])["BrandImpersonationScore"] > 0,
        "ip_based_url": lambda row: extract_fresh_features(row["canonical_url"])["IsDomainIP"] > 0,
        "redirect_style_url": lambda row: extract_fresh_features(row["canonical_url"])["QueryRedirect"] > 0,
        "executable_payload_path": lambda row: extract_fresh_features(row["canonical_url"])["PathSuspiciousExtension"] > 0,
        "financial_login_verification": lambda row: (
            extract_fresh_features(row["canonical_url"])["PathSuspiciousWords"] > 0
            or extract_fresh_features(row["canonical_url"])["QuerySuspiciousWords"] > 0
        ),
        "legitimate_developer_media_documentation": lambda row: row["label"] == "BENIGN",
    }
    for name, predicate in buckets.items():
        selected = [index for index, row in enumerate(rows) if predicate(row)]
        if selected:
            output[name] = metrics(y[selected], scores[selected], threshold)
    by_source = {}
    for source in sorted({row["source_name"] for row in rows}):
        selected = [index for index, row in enumerate(rows) if row["source_name"] == source]
        by_source[source] = metrics(y[selected], scores[selected], threshold)
    by_domain = {}
    for domain in sorted({row["registrable_domain"] for row in rows}):
        selected = [index for index, row in enumerate(rows) if row["registrable_domain"] == domain]
        by_domain[domain] = metrics(y[selected], scores[selected], threshold)
    return {"slices": output, "per_source": by_source, "per_domain_group": by_domain}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--report-json", type=Path, required=True)
    parser.add_argument("--report-md", type=Path, required=True)
    args = parser.parse_args()
    rows = read_jsonl(args.data_dir / "final_test.jsonl")
    manifest = json.loads((args.data_dir / "manifest.json").read_text(encoding="utf-8"))
    model = joblib.load(args.model)
    x = vectorize_urls([row["canonical_url"] for row in rows])
    y = np.array([row["label"] == "MALICIOUS" for row in rows], dtype=np.int8)
    scores = model.predict_proba(x)[:, 1]
    metadata_path = args.model.with_name("fresh_url_20261024_metadata.json")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    threshold = float(metadata["decision_threshold"])
    measured = metrics(y, scores, threshold)
    measured.update(slice_metrics(rows, scores, threshold))

    start = time.perf_counter()
    for _ in range(10):
        model.predict_proba(x)
    elapsed_ms = (time.perf_counter() - start) * 1000 / max(1, 10 * len(rows))
    report = {
        "model_id": metadata["model_id"],
        "dataset_id": manifest["dataset_id"],
        "final_test_sha256": manifest["final_test_sha256"],
        "final_test_untouched_check": hashlib.sha256(
            (args.data_dir / "final_test.jsonl").read_bytes()
        ).hexdigest(),
        "threshold": threshold,
        "metrics": measured,
        "unknown_or_unresolved_excluded_from_final_test": sum(
            row["label"] == "UNKNOWN" or row.get("status") in {"UNKNOWN", "UNRESOLVED"}
            for row in rows
        ),
        "python_mean_batch_inference_ms_per_url": elapsed_ms,
        "portable_asset_size_bytes": (
            args.model.with_name("fresh_url_20261024_portable.json").stat().st_size
            if args.model.with_name("fresh_url_20261024_portable.json").exists()
            else None
        ),
        "limitations": [
            "URL-only evidence; no page fetch, DNS resolution, redirect following, or payload inspection.",
            "Benign labels are source-adjudicated and not a proof that a destination is always safe.",
        ],
    }
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Sentinel Fresh URL Model Evaluation",
        "",
        f"- Model: `{report['model_id']}`",
        f"- Final-test SHA-256: `{report['final_test_sha256']}`",
        f"- Threshold: `{threshold:.6f}` (selected on validation only)",
        f"- Malicious recall: `{measured['malicious_recall']:.4f}`",
        f"- Benign false-positive rate: `{measured['benign_false_positive_rate']:.4f}`",
        f"- Precision: `{measured['precision']:.4f}`",
        f"- F1: `{measured['f1']:.4f}`",
        f"- Confusion matrix: `{measured['confusion_matrix']}`",
        f"- Python inference: `{elapsed_ms:.6f} ms/url` averaged over repeated final-test batches",
        "",
        "## Slices",
        "",
    ]
    for name, result in measured["slices"].items():
        lines.append(f"- **{name}**: {result}")
    lines.extend(["", "## Per source", ""])
    for name, result in measured["per_source"].items():
        lines.append(f"- **{name}**: {result}")
    args.report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
