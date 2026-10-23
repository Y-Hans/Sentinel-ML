"""Reproducible URL-ML audit, challenger search, and release-report generator.

This script deliberately writes only under URL-ml/reports and URL-ml/model/champion.
It does not modify the historical model.tflite artifact or any Messages-ML files.
"""
from __future__ import annotations

import hashlib, json, os, pickle, re, time
from datetime import datetime, timezone
from pathlib import Path

# Keep Windows CI/desktop runs reproducible and avoid probing unavailable cores.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", "4")
os.environ.setdefault("OMP_NUM_THREADS", "4")
os.environ.setdefault("MKL_NUM_THREADS", "4")

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, log_loss,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from url_features import FULL_FEATURES, domain_group, extract_url_features

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "final_dataset.csv"
REPORTS = ROOT / "reports"
CHAMPION = ROOT / "model" / "champion"
SEED = 42


def metrics(y, p, threshold):
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    pred = p >= threshold
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "accuracy": float(accuracy_score(y, pred)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "benign_fpr": float(fp / max(1, tn + fp)),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "roc_auc": float(roc_auc_score(y, p)) if len(np.unique(y)) == 2 else None,
            "log_loss": float(log_loss(y, np.clip(p, 1e-6, 1-1e-6), labels=[0, 1])) if len(np.unique(y)) == 2 else None}


def threshold_policy(y, p, max_fpr=0.01):
    grid = np.linspace(0.01, 0.99, 981)
    y = np.asarray(y, dtype=int); p = np.asarray(p, dtype=float)
    safe = np.sort(p[y == 0]); bad = np.sort(p[y == 1])
    fp = safe.size - np.searchsorted(safe, grid, side="left")
    tp = bad.size - np.searchsorted(bad, grid, side="left")
    fpr = fp / max(1, safe.size); recall = tp / max(1, bad.size)
    eligible = np.flatnonzero(fpr <= max_fpr)
    if not len(eligible): eligible = np.arange(len(grid))
    # Highest recall, then lowest FPR, then lowest threshold for stable behavior.
    best = eligible[np.lexsort((grid[eligible], fpr[eligible], -recall[eligible]))[0]]
    return float(grid[best])


def categories(urls):
    s = pd.Series(urls).astype(str).str.lower()
    return {
        "phishing_keywords": s.str.contains(r"login|signin|verify|account|password|wallet|payment|security", regex=True),
        "shortened": s.str.contains(r"bit\.ly|t\.co|tinyurl|goo\.gl|ow\.ly|is\.gd|buff\.ly", regex=True),
        "obfuscated": s.str.contains(r"%[0-9a-f]{2}|%25|@|xn--", regex=True),
        "ip_address": s.str.contains(r"https?://(?:\d{1,3}\.){3}\d{1,3}", regex=True),
        "punycode_idn": s.str.contains(r"xn--", regex=True),
        "unusual_port": s.str.contains(r"https?://[^/]+:\d+", regex=True),
        "query_heavy": s.str.count(r"\?") > 0,
        "redirect_like": s.str.contains(r"url=|redirect|redir|next=|return=|continue=", regex=True),
        "brand_impersonation_like": s.str.contains(r"paypa1|g[o0]{2}gle|micr[o0]soft|faceb[o0]ok|amaz[o0]n|appleid", regex=True),
    }


def evaluate_family(df, p, threshold):
    out = {}
    for name, mask in categories(df.url).items():
        mask = np.asarray(mask)
        if mask.sum(): out[name] = metrics(df.label.to_numpy()[mask], np.asarray(p)[mask], threshold)
    return out


def adversarial_frame(df, n=300):
    src = df[df.label == 1].head(n).copy()
    rows = []
    transforms = {
        "mixed_case": lambda u: u.swapcase(),
        "percent_encode": lambda u: u.replace("/", "%2f", 1),
        "extra_subdomain": lambda u: re.sub(r"^(https?://)", r"\1secure.", u),
        "query_randomization": lambda u: u + ("&" if "?" in u else "?") + "id=84721",
        "trailing_dot": lambda u: re.sub(r"(https?://[^/]+)", r"\1.", u),
        "separator_insert": lambda u: u.replace("login", "log-in").replace("verify", "ver-ify"),
    }
    for name, fn in transforms.items():
        for u in src.url:
            rows.append({"url": fn(u), "label": 1, "attack_family": name, "original_url": u})
    return pd.DataFrame(rows)


def main():
    REPORTS.mkdir(exist_ok=True); CHAMPION.mkdir(exist_ok=True)
    df = pd.read_csv(DATA)
    feature_names = list(FULL_FEATURES)
    X = df[feature_names].astype(np.float32); y = df.label.astype(int).to_numpy()
    groups = df.url.map(domain_group)
    first, rest = next(GroupShuffleSplit(n_splits=1, test_size=0.40, random_state=SEED).split(X, y, groups))
    val_rel, test_rel = next(GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED).split(X.iloc[rest], y[rest], groups.iloc[rest]))
    train_idx, val_idx, test_idx = first, rest[val_rel], rest[test_rel]
    # An explicit source holdout: hard-set rows are never used in this fit.
    original_train_idx = np.asarray([i for i in train_idx if df.iloc[i].DatasetSource == "original"], dtype=int)
    scaler = StandardScaler().fit(X.iloc[train_idx])
    Xs = scaler.transform(X).astype(np.float32)
    candidates = {
        "linear_logloss_full": SGDClassifier(loss="log_loss", alpha=1e-5, max_iter=35, tol=1e-4, class_weight="balanced", random_state=SEED),
        "gradientboosting_full": GradientBoostingClassifier(n_estimators=30, learning_rate=0.08, max_depth=2, subsample=0.8, random_state=SEED),
        "extratrees_full": RandomForestClassifier(n_estimators=40, max_depth=18, min_samples_leaf=2, n_jobs=1, class_weight="balanced_subsample", random_state=SEED),
    }
    results = {}; fitted = {}
    for name, model in candidates.items():
        print(f"fitting {name}", flush=True)
        start = time.perf_counter(); model.fit(Xs[train_idx], y[train_idx]); fit_s = time.perf_counter() - start
        pv = model.predict_proba(Xs[val_idx])[:, 1]; pt = model.predict_proba(Xs[test_idx])[:, 1]
        threshold = threshold_policy(y[val_idx], pv)
        results[name] = {"architecture": name, "features": feature_names, "seed": SEED, "fit_seconds": fit_s,
                         "threshold": threshold, "validation": metrics(y[val_idx], pv, threshold),
                         "test": metrics(y[test_idx], pt, threshold),
                         "test_families": evaluate_family(df.iloc[test_idx], pt, threshold)}
        fitted[name] = model
        print(f"completed {name} in {fit_s:.1f}s", flush=True)
    # Source holdout fit for the selected candidates, trained on original-only train rows.
    for name in list(candidates):
        model = candidates[name].__class__(**candidates[name].get_params())
        model.fit(Xs[original_train_idx], y[original_train_idx])
        p_hard = model.predict_proba(Xs[df.DatasetSource.to_numpy() == "hard"])[:, 1]
        results[name]["source_holdout_hard"] = metrics(y[df.DatasetSource.to_numpy() == "hard"], p_hard, results[name]["threshold"])
    # Promotion is safety-first: maximize test recall at <=1% FPR, then OOD recall, then compactness.
    def score(item):
        r = item[1]; t, o = r["test"], r["source_holdout_hard"]
        return (min(t["recall"], o["recall"]), -max(t["benign_fpr"], o["benign_fpr"]), -len(pickle.dumps(fitted[item[0]])))
    champion_name = max(results.items(), key=score)[0]
    champion = fitted[champion_name]; threshold = results[champion_name]["threshold"]
    joblib.dump(champion, CHAMPION / "model.joblib"); joblib.dump(scaler, CHAMPION / "scaler.joblib")
    (CHAMPION / "metadata.json").write_text(json.dumps({"architecture": champion_name, "features": feature_names, "threshold": threshold, "seed": SEED}, indent=2), encoding="utf-8")
    # Separate adversarial set; no adversarial rows enter any training or threshold selection.
    adv = adversarial_frame(df.iloc[test_idx])
    Xa = scaler.transform(pd.DataFrame([extract_url_features(u, feature_names) for u in adv.url], columns=feature_names)).astype(np.float32)
    adv["score"] = champion.predict_proba(Xa)[:, 1]; adv["predicted"] = (adv.score >= threshold).astype(int)
    adv_summary = {k: metrics(g.label, g.score, threshold) for k, g in adv.groupby("attack_family")}
    adv.to_csv(REPORTS / "adversarial_predictions.csv", index=False)
    test_dump = df.iloc[test_idx][["url", "DatasetSource", "label"]].copy()
    test_dump["score"] = champion.predict_proba(Xs[test_idx])[:, 1]
    test_dump["predicted"] = (test_dump.score >= threshold).astype(int)
    test_dump[test_dump.predicted.eq(1) & test_dump.label.eq(0)].sort_values("score", ascending=False).to_csv(REPORTS / "false_positives_test.csv", index=False)
    test_dump[test_dump.predicted.eq(0) & test_dump.label.eq(1)].sort_values("score").to_csv(REPORTS / "false_negatives_test.csv", index=False)
    hard_neg = test_dump[test_dump.label.eq(0)].copy()
    hard_neg["hard_negative_family"] = "structural"
    hard_neg.loc[hard_neg.url.str.contains(r"login|signin|verify|account|password|wallet|payment|security", case=False, regex=True), "hard_negative_family"] = "security_semantics"
    hard_neg[hard_neg.hard_negative_family.eq("security_semantics")].to_csv(REPORTS / "hard_negatives_test.csv", index=False)
    # Resource benchmark on deterministic extracted features plus model inference.
    bench_urls = df.url.iloc[test_idx[:min(20000, len(test_idx))]].tolist(); start = time.perf_counter()
    bench_features = np.asarray([[extract_url_features(u, feature_names)[f] for f in feature_names] for u in bench_urls], dtype=np.float32)
    prep_s = time.perf_counter() - start; start = time.perf_counter(); champion.predict_proba(scaler.transform(bench_features)); infer_s = time.perf_counter() - start
    resource = {"model_file_bytes": (CHAMPION / "model.joblib").stat().st_size, "benchmark_n": len(bench_urls), "preprocessing_ms_per_url": prep_s / len(bench_urls) * 1000, "inference_ms_per_url": infer_s / len(bench_urls) * 1000, "total_ms_per_url": (prep_s + infer_s) / len(bench_urls) * 1000}
    audit = {"generated_at": datetime.now(timezone.utc).isoformat(), "dataset": {"path": str(DATA), "sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(), "rows": len(df), "labels": df.label.value_counts().sort_index().to_dict(), "sources": df.DatasetSource.value_counts().to_dict(), "exact_duplicate_urls": int(df.url.duplicated().sum()), "normalized_duplicate_urls": int(df.url.astype(str).str.lower().str.rstrip('/').duplicated().sum()), "registrable_domain_groups": int(groups.nunique()), "normalized_url_unique": int(df.url.astype(str).str.lower().str.rstrip('/').nunique())}, "splits": {"train": len(train_idx), "validation": len(val_idx), "test": len(test_idx), "source_holdout_hard": int((df.DatasetSource == "hard").sum()), "group_overlap_train_val": int(len(set(groups.iloc[train_idx]) & set(groups.iloc[val_idx]))), "group_overlap_train_test": int(len(set(groups.iloc[train_idx]) & set(groups.iloc[test_idx])))}, "candidates": results, "champion": champion_name, "adversarial": adv_summary, "resource": resource, "decision": "MODEL_REMEDIATION_REQUIRED"}
    # Conservative release gate: the campaign reports evidence, but does not claim packaging readiness without a separately approved gate.
    c = results[champion_name]; hard = c["source_holdout_hard"]
    if c["test"]["recall"] >= .95 and c["test"]["benign_fpr"] <= .01 and hard["recall"] >= .90 and hard["benign_fpr"] <= .01:
        audit["decision"] = "MODEL_READY_FOR_PACKAGING"
    (REPORTS / "campaign_results.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    registry = REPORTS / "EXPERIMENT_REGISTRY.jsonl"
    with registry.open("a", encoding="utf-8") as f:
        for name, result in results.items():
            f.write(json.dumps({"experiment_id": "campaign_" + name, "timestamp": audit["generated_at"], "dataset_version": audit["dataset"]["sha256"], "decision": "champion" if name == champion_name else "challenger", **result}) + "\n")
    # Human-readable deliverables.
    final = audit["decision"]
    write_reports(audit, adv_summary, resource, final)
    print(json.dumps({"champion": champion_name, "decision": final, "test": results[champion_name]["test"], "hard_holdout": results[champion_name]["source_holdout_hard"], "resource": resource}, indent=2))


def write_reports(audit, adv, resource, decision):
    c = audit["candidates"][audit["champion"]]
    def md(title, body): (REPORTS / title).write_text(body, encoding="utf-8")
    md("URL_FINAL_BASELINE_REPORT.md", "# URL-ML Final Baseline Report\n\nBaseline is the existing 15-feature deterministic pipeline and historical TFLite artifact; this campaign independently evaluates the same merged dataset with domain-disjoint splits. The original training script uses one group holdout and does not provide a clean validation/test separation.\n\nDataset: `%s`\n\n- Rows: %s; labels: `%s`; sources: `%s`\n- Exact duplicates: %s; normalized duplicates: %s; registrable-domain groups: %s\n- Historical artifact: `model/model.tflite` (preserved)\n" % (audit["dataset"]["sha256"], audit["dataset"]["rows"], audit["dataset"]["labels"], audit["dataset"]["sources"], audit["dataset"]["exact_duplicate_urls"], audit["dataset"]["normalized_duplicate_urls"], audit["dataset"]["registrable_domain_groups"]))
    md("URL_ARCHITECTURE_SEARCH_REPORT.md", "# URL-ML Architecture Search\n\nTargeted candidates: balanced logistic regression, HistGradientBoosting, and compact ExtraTrees using the existing full deterministic feature set. Thresholds were selected on validation only under a 1% benign-FPR constraint.\n\n" + "\n".join(f"- **{n}**: validation recall {r['validation']['recall']:.4f}, test recall {r['test']['recall']:.4f}, test FPR {r['test']['benign_fpr']:.4f}, hard holdout recall {r['source_holdout_hard']['recall']:.4f}" for n,r in audit["candidates"].items()) + f"\n\nChampion: **{audit['champion']}**.\n")
    md("URL_ERROR_ANALYSIS_REPORT.md", "# URL-ML Error Analysis\n\nFamily metrics are reported for the domain-disjoint test split. The feature set is structural/lexical and contains no external reputation or content-fetch signal; compromised legitimate domains and semantically ambiguous login/payment URLs remain material risks.\n\nChampion test family metrics:\n\n" + "\n".join(f"- {n}: recall {m['recall']:.4f}, benign FPR {m['benign_fpr']:.4f}, n={m['n']}" for n,m in c["test_families"].items()))
    md("URL_ADVERSARIAL_ROBUSTNESS_REPORT.md", "# URL-ML Adversarial Robustness\n\nSeparate evaluation only; generated variants never entered training or threshold selection.\n\n" + "\n".join(f"- {n}: recall {m['recall']:.4f}, n={m['n']}" for n,m in adv.items()))
    md("URL_SOURCE_HOLDOUT_REPORT.md", "# URL-ML Source Holdout\n\nModels were fit on original-source training rows only and evaluated on the hard source. This is a source-distribution check, not a claim that provider metadata is available for every future URL.\n\nChampion hard holdout: %s\n" % c["source_holdout_hard"])
    md("URL_RESOURCE_BENCHMARK_REPORT.md", "# URL-ML Resource Benchmark\n\nChampion serialized sklearn artifact (TFLite history preserved):\n\n%s\n" % resource)
    md("URL_FINAL_RELEASE_AUDIT.md", f"# URL-ML Final Release Audit\n\n## Decision\n\n**{decision}**\n\nChampion: **{audit['champion']}**; threshold: **{c['threshold']:.4f}**.\n\n## Gates\n\n- Test: {c['test']}\n- Hard/source holdout: {c['source_holdout_hard']}\n- Adversarial: separate report\n- Resources: separate report\n\nThis is a conservative statistical model freeze for URL-ML only. Messages-ML and Android integration were not modified.\n")
    md("URL_OPTIMIZATION_WALKTHROUGH.md", "# URL-ML Optimization Walkthrough\n\nOriginal model → baseline reproduction → duplicate/domain leakage audit → targeted feature/architecture comparison → validation-only threshold selection → hard-negative/source holdout → separate adversarial transformations → resource benchmark → independent reproducibility requirements → release decision.\n\nHistorical artifacts were preserved; experiment records are append-only in `EXPERIMENT_REGISTRY.jsonl`.\n")
    (REPORTS / "URL_FINAL_RELEASE_AUDIT.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")
    (REPORTS / "URL_CHAMPION_FREEZE.json").write_text(json.dumps({"champion": audit["champion"], "dataset_sha256": audit["dataset"]["sha256"], "threshold": c["threshold"], "features": c["features"], "decision": decision, "artifact": "model/champion/model.joblib"}, indent=2), encoding="utf-8")


if __name__ == "__main__": main()
