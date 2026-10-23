"""
Sentinel Phase 1D.1-B1: Isolated 16-Token Threat-Dictionary Evaluation
Author: Sentinel AI ML Engineering Team
Status: AUTHORIZED ISOLATED EVALUATION STAGE 2 (B1)

Scope & Safeguards:
1. Operates exclusively on frozen V8 champion binary (hash: 073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58).
2. Zero model retraining. Zero production code edits (Python or Kotlin). Zero Git mutations.
3. Evaluates 16 Phase 1C.2B-2A-S1 tokens strictly as a candidate threat-detection dictionary (NOT a safe whitelist).
4. Evaluates all 16 tokens individually and as a fixed combined set.
5. Evaluates across 6 independent corpora:
   - Clean Test Split (N = 50,511)
   - Diagnostic Benchmark v1.0 (N = 500)
   - Remediation Adversarial Split (N = 3,900)
   - Android Golden Fixtures (N = 174)
   - Independent Benign Bare-Apex (N = 15,000)
   - Repaired Malicious Bare-Apex (N = 2,843)
6. Separates Mode 1 (Threat Adjudication-Only, raw probs identical to A0) from Mode 2 (Feature-level extraction).
7. Evaluates against all seven pre-registered gates with explicit PASS / WARNING / HARD_FAIL boundaries.
"""

from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import sys
import time
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

# Path configuration
EXP_DIR = Path(__file__).resolve().parent
URL_ML_DIR = EXP_DIR.parents[1]
DATA_DIR = URL_ML_DIR / "data"
MODELS_DIR = URL_ML_DIR / "models"
REPORTS_DIR = URL_ML_DIR / "reports"
SCRIPTS_DIR = URL_ML_DIR / "scripts"
PROJECT_ROOT = EXP_DIR.parents[3]
ANDROID_RES_DIR = PROJECT_ROOT / "sentinel-ai" / "android-app" / "core" / "src" / "test" / "resources"

sys.path.insert(0, str(SCRIPTS_DIR))

from v7_features import (
    vectorize_v7,
    V7_FEATURE_NAMES,
    SUSPICIOUS_TLDS,
    COMMON_BRANDS,
    LEET_TRANSLATION,
    _parse,
    _registrable_label,
    _one_edit_apart,
    _is_ip
)
from v8_classifier import V8RelationalURLClassifier
from v8_normalization import parse_v8_url

EXPECTED_V8_CHAMPION_HASH = "073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58"
EXPECTED_DICT_HASH = "f2a32b58f62307e886e0f761f12d2ccbeb6d127eed9f3b56a8ab77c7ab4a9651"


def get_file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float, float]:
    """Calculate score and Wilson score interval for a binomial proportion."""
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    z = 1.959963984540054
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / denom
    spread = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * n)) / n) / denom
    lower = max(0.0, centre - spread)
    upper = min(1.0, centre + spread)
    return float(p), float(lower), float(upper)


def compute_binary_metrics(y_true: np.ndarray, preds: np.ndarray, probs: np.ndarray) -> Dict[str, Any]:
    """Compute detailed binary classification metrics."""
    n = len(y_true)
    y_true_bin = (y_true == 1).astype(int)
    preds_bin = (preds == 1).astype(int)

    tp = int(np.sum((preds_bin == 1) & (y_true_bin == 1)))
    fp = int(np.sum((preds_bin == 1) & (y_true_bin == 0)))
    fn = int(np.sum((preds_bin == 0) & (y_true_bin == 1)))
    tn = int(np.sum((preds_bin == 0) & (y_true_bin == 0)))

    n_pos = tp + fn
    n_neg = tn + fp

    rec, rec_lo, rec_hi = wilson_ci(tp, n_pos) if n_pos > 0 else (0.0, 0.0, 0.0)
    fpr, fpr_lo, fpr_hi = wilson_ci(fp, n_neg) if n_neg > 0 else (0.0, 0.0, 0.0)
    prec, prec_lo, prec_hi = wilson_ci(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0, 0.0)

    return {
        "n_total": n,
        "n_pos": n_pos,
        "n_neg": n_neg,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "recall": rec,
        "recall_95ci": [rec_lo, rec_hi],
        "fpr": fpr,
        "fpr_95ci": [fpr_lo, fpr_hi],
        "precision": prec,
        "precision_95ci": [prec_lo, prec_hi],
        "mean_prob": float(np.mean(probs)) if n > 0 else 0.0
    }


def brand_imp_score(host: str, brand_set: set[str]) -> float:
    """Deterministic brand impersonation score evaluating a specific brand set."""
    if not host or _is_ip(host):
        return 0.0
    reg_clean = re.sub(r"[^a-z0-9]", "", _registrable_label(host)).translate(LEET_TRANSLATION)
    if reg_clean in brand_set:
        return 0.0

    candidates: list[str] = []
    labels = host.split(".")
    for label in labels:
        compact = re.sub(r"[^a-z0-9]", "", label).translate(LEET_TRANSLATION)
        if len(compact) >= 4:
            candidates.append(compact)
        for token in re.split(r"[^a-z0-9]+", label):
            token_clean = token.translate(LEET_TRANSLATION)
            if len(token_clean) >= 4:
                candidates.append(token_clean)

    for candidate in candidates:
        if candidate in brand_set and candidate != reg_clean:
            return 1.0

    best = 0.0
    for candidate in candidates:
        for brand in brand_set:
            if len(brand) < 5 or len(candidate) < 5:
                continue
            if brand in candidate or candidate in brand:
                score = min(len(candidate), len(brand)) / max(len(candidate), len(brand))
                if score >= 0.80:
                    best = max(best, score)
            if abs(len(candidate) - len(brand)) <= 1 and _one_edit_apart(candidate, brand):
                best = max(best, 0.85)

    return float(best if best >= 0.80 else 0.0)


def is_brand_typosquat(host: str, brand_set: set[str]) -> bool:
    """Deterministic brand typosquatting detection evaluating a specific brand set."""
    reg_clean = re.sub(r"[^a-z0-9]", "", _registrable_label(host))
    reg_trans = reg_clean.translate(LEET_TRANSLATION)
    return bool(reg_trans in brand_set and reg_clean != reg_trans and any(c.isdigit() for c in reg_clean))


def is_threat_match(host: str, threat_tokens: set[str], baseline_brands: set[str] = COMMON_BRANDS) -> Tuple[bool, float, str]:
    """
    Evaluate candidate threat tokens as a threat-detection dictionary.
    Returns (is_match, score, match_type).
    """
    if not host or _is_ip(host):
        return False, 0.0, "none"

    combined_brands = baseline_brands.union(threat_tokens)
    base_score = brand_imp_score(host, baseline_brands)
    exp_score = brand_imp_score(host, combined_brands)
    base_typo = is_brand_typosquat(host, baseline_brands)
    exp_typo = is_brand_typosquat(host, combined_brands)

    if exp_score > base_score:
        return True, exp_score, "impersonation_score"
    if exp_typo and not base_typo:
        return True, 0.95, "typosquat"

    return False, 0.0, "none"


def verify_gate_policy(results: Dict[str, Any]) -> Dict[str, Any]:
    """Verify all 7 pre-registered gates under the 3-tier PASS / WARNING / HARD_FAIL policy."""
    gates = {}

    # Gate 1: Clean Test Malicious Recall (N = 23,158)
    g1_rec = results["clean_test"]["recall"]
    if g1_rec >= 0.98600:
        g1_stat = "PASS"
    elif g1_rec >= 0.98400:
        g1_stat = "WARNING_REVIEW"
    else:
        g1_stat = "HARD_FAIL"
    gates["Gate_1_Clean_Test_Recall"] = {
        "target": ">= 0.98600", "warning_range": "[0.98400, 0.98600)", "hard_fail": "< 0.98400",
        "value": float(g1_rec), "tp": int(results["clean_test"]["tp"]),
        "n": int(results["clean_test"]["n_pos"]), "status": g1_stat
    }

    # Gate 2: Clean Test Benign FPR (N = 27,353)
    g2_fpr = results["clean_test"]["fpr"]
    if g2_fpr <= 0.00962:
        g2_stat = "PASS"
    elif g2_fpr <= 0.01000:
        g2_stat = "WARNING_REVIEW"
    else:
        g2_stat = "HARD_FAIL"
    gates["Gate_2_Clean_Test_FPR"] = {
        "target": "<= 0.00962", "warning_range": "(0.00962, 0.01000]", "hard_fail": "> 0.01000",
        "value": float(g2_fpr), "fp": int(results["clean_test"]["fp"]),
        "n": int(results["clean_test"]["n_neg"]), "status": g2_stat
    }

    # Gate 3: Benchmark Bare-Apex FPR (N = 200, Category 1)
    g3_fpr = results["benchmark_bare_apex"]["fpr"]
    if g3_fpr <= 0.1000:
        g3_stat = "PASS"
    elif g3_fpr <= 0.1500:
        g3_stat = "WARNING_REVIEW"
    else:
        g3_stat = "HARD_FAIL"
    gates["Gate_3_Benchmark_Bare_Apex_FPR"] = {
        "target": "<= 0.1000", "warning_range": "(0.1000, 0.1500]", "hard_fail": "> 0.1500",
        "value": float(g3_fpr), "fp": int(results["benchmark_bare_apex"]["fp"]),
        "n": int(results["benchmark_bare_apex"]["n_neg"]), "status": g3_stat
    }

    # Gate 4: Benchmark Overall FPR (N = 500)
    g4_fpr = results["benchmark_overall"]["fpr"]
    if g4_fpr <= 0.4500:
        g4_stat = "PASS"
    elif g4_fpr <= 0.5000:
        g4_stat = "WARNING_REVIEW"
    else:
        g4_stat = "HARD_FAIL"
    gates["Gate_4_Benchmark_Overall_FPR"] = {
        "target": "<= 0.4500", "warning_range": "(0.4500, 0.5000]", "hard_fail": "> 0.5000",
        "value": float(g4_fpr), "fp": int(results["benchmark_overall"]["fp"]),
        "n": int(results["benchmark_overall"]["n_neg"]), "status": g4_stat
    }

    # Gate 5: Clean Test Phishing Bare-Apex Recall (N = 4,254)
    g5_rec = results["test_phishing_bare_apex"]["recall"]
    if g5_rec >= 0.98000:
        g5_stat = "PASS"
    elif g5_rec >= 0.97500:
        g5_stat = "WARNING_REVIEW"
    else:
        g5_stat = "HARD_FAIL"
    gates["Gate_5_Clean_Test_Phishing_Bare_Apex_Recall"] = {
        "target": ">= 0.98000", "warning_range": "[0.97500, 0.98000)", "hard_fail": "< 0.97500",
        "value": float(g5_rec), "tp": int(results["test_phishing_bare_apex"]["tp"]),
        "n": int(results["test_phishing_bare_apex"]["n_pos"]), "status": g5_stat
    }

    # Gate 6: Remediation Adversarial Recall (N = 1,950)
    g6_rec = results["adversarial_split"]["recall"]
    if g6_rec >= 0.98000:
        g6_stat = "PASS"
    elif g6_rec >= 0.97000:
        g6_stat = "WARNING_REVIEW"
    else:
        g6_stat = "HARD_FAIL"
    gates["Gate_6_Adversarial_Recall"] = {
        "target": ">= 0.98000", "warning_range": "[0.97000, 0.98000)", "hard_fail": "< 0.97000",
        "value": float(g6_rec), "tp": int(results["adversarial_split"]["tp"]),
        "n": int(results["adversarial_split"]["n_pos"]), "status": g6_stat
    }

    # Gate 7: Android Golden Fixtures Regressions (N = 174, Target = 0 regressions)
    g7_reg = results["golden_fixtures"]["n_regressions"]
    g7_stat = "PASS" if g7_reg == 0 else "HARD_FAIL"
    gates["Gate_7_Golden_Fixtures_Regressions"] = {
        "target": "== 0 regressions", "value": int(g7_reg), "status": g7_stat
    }

    return gates


def main():
    start_time = time.time()
    print("=" * 80)
    print("Sentinel Phase 1D.1-B1: Isolated 16-Token Threat-Dictionary Evaluation")
    print("=" * 80)

    # 1. Provenance Invariant Verification
    champ_model_path = MODELS_DIR / "v8_champion.joblib"
    dict_manifest_path = EXP_DIR / "candidate_threat_tokens_b1.json"

    obs_champ_hash = get_file_sha256(champ_model_path)
    obs_dict_hash = get_file_sha256(dict_manifest_path)

    print(f"V8 Champion Binary: {champ_model_path}")
    print(f"  Observed SHA-256: {obs_champ_hash}")
    assert obs_champ_hash == EXPECTED_V8_CHAMPION_HASH, f"CHAMPION HASH MISMATCH: {obs_champ_hash}"
    print("  [OK] Champion model hash verified bit-for-bit.")

    print(f"Candidate Threat Tokens: {dict_manifest_path}")
    print(f"  Observed SHA-256: {obs_dict_hash}")
    assert obs_dict_hash == EXPECTED_DICT_HASH, f"DICT HASH MISMATCH: {obs_dict_hash}"
    print("  [OK] Candidate threat tokens hash verified bit-for-bit.")

    with open(dict_manifest_path, "r", encoding="utf-8") as f:
        threat_manifest = json.load(f)
    threat_tokens_list = [item["token"] for item in threat_manifest]
    threat_tokens_set = set(threat_tokens_list)
    print(f"Loaded {len(threat_tokens_list)} threat tokens: {threat_tokens_list}\n")

    # 2. Load Frozen Corpora
    print("Loading Frozen Evaluation Corpora...")
    df_test = pd.read_csv(EXP_DIR / "clean_test_predictions_v8.csv")
    df_bench = pd.read_csv(EXP_DIR / "benchmark_predictions_v8.csv")
    df_adv = pd.read_csv(EXP_DIR / "adversarial_predictions_v8.csv")
    df_gold = pd.read_csv(EXP_DIR / "golden_predictions_v8.csv")

    p_15k = URL_ML_DIR / "experiments" / "phase_1c_2b_prototypes" / "candidate_bare_apex_15k.csv"
    p_2843 = URL_ML_DIR / "experiments" / "phase_1c_2b_2a_s2_f" / "candidate_malicious_bare_apex_repaired_2843.csv"
    df_15k = pd.read_csv(p_15k)
    df_2843 = pd.read_csv(p_2843)

    print(f"  Clean Test: {len(df_test):,} URLs")
    print(f"  Diagnostic Benchmark: {len(df_bench):,} URLs")
    print(f"  Adversarial: {len(df_adv):,} URLs")
    print(f"  Golden Fixtures: {len(df_gold):,} URLs")
    print(f"  Candidate Benign Apex 15k: {len(df_15k):,} URLs")
    print(f"  Repaired Malicious Apex 2843: {len(df_2843):,} URLs")

    # Score 15k and 2843 with frozen V8 champion to get baseline A0 probabilities
    print("\nScoring un-precalculated cohorts with frozen V8 champion (A0 baseline)...")
    champ_model = joblib.load(champ_model_path)

    t0 = time.time()
    X_15k, _ = vectorize_v7(df_15k["url"].tolist())
    raw_15k = champ_model.base_model.predict_proba(X_15k)[:, 1]
    adj_15k = champ_model.predict_proba(X_15k, urls=df_15k["url"].tolist())[:, 1]
    print(f"  Benign 15k scored in {time.time()-t0:.2f}s (mean raw: {np.mean(raw_15k):.4f}, mean adj: {np.mean(adj_15k):.4f})")

    t0 = time.time()
    X_2843, _ = vectorize_v7(df_2843["url"].tolist())
    raw_2843 = champ_model.base_model.predict_proba(X_2843)[:, 1]
    adj_2843 = champ_model.predict_proba(X_2843, urls=df_2843["url"].tolist())[:, 1]
    print(f"  Repaired 2843 scored in {time.time()-t0:.2f}s (mean raw: {np.mean(raw_2843):.4f}, mean adj: {np.mean(adj_2843):.4f})")

    # Assemble structured corpus dictionary
    corpora = {
        "clean_test": {
            "urls": df_test["url"].tolist(),
            "y_true": df_test["y_true"].to_numpy(dtype=int),
            "raw_probs": df_test["raw_prob"].to_numpy(dtype=float),
            "a0_adj_probs": df_test["v8_adj_prob"].to_numpy(dtype=float),
            "a0_preds": (df_test["v8_adj_prob"].to_numpy(dtype=float) >= 0.2800).astype(int)
        },
        "benchmark_overall": {
            "urls": df_bench["url"].tolist(),
            "y_true": df_bench["y_true"].to_numpy(dtype=int),
            "raw_probs": df_bench["raw_prob"].to_numpy(dtype=float),
            "a0_adj_probs": df_bench["v8_adj_prob"].to_numpy(dtype=float),
            "a0_preds": (df_bench["v8_adj_prob"].to_numpy(dtype=float) >= 0.2800).astype(int),
            "categories": df_bench["category"].tolist()
        },
        "adversarial_split": {
            "urls": df_adv["url"].tolist(),
            "y_true": df_adv["y_true"].to_numpy(dtype=int),
            "raw_probs": df_adv["raw_prob"].to_numpy(dtype=float),
            "a0_adj_probs": df_adv["v8_adj_prob"].to_numpy(dtype=float),
            "a0_preds": (df_adv["v8_adj_prob"].to_numpy(dtype=float) >= 0.2800).astype(int)
        },
        "golden_fixtures": {
            "urls": df_gold["url"].tolist(),
            "y_true": df_gold["isMalicious"].to_numpy(dtype=int),
            "raw_probs": df_gold["raw_prob"].to_numpy(dtype=float),
            "a0_adj_probs": df_gold["v8_adj_prob"].to_numpy(dtype=float),
            "a0_preds": (df_gold["v8_adj_prob"].to_numpy(dtype=float) >= 0.2800).astype(int),
            "ids": df_gold["id"].tolist()
        },
        "candidate_benign_15k": {
            "urls": df_15k["url"].tolist(),
            "y_true": np.zeros(len(df_15k), dtype=int),
            "raw_probs": raw_15k,
            "a0_adj_probs": adj_15k,
            "a0_preds": (adj_15k >= 0.2800).astype(int)
        },
        "candidate_malicious_2843": {
            "urls": df_2843["url"].tolist(),
            "y_true": np.ones(len(df_2843), dtype=int),
            "raw_probs": raw_2843,
            "a0_adj_probs": adj_2843,
            "a0_preds": (adj_2843 >= 0.2800).astype(int)
        }
    }

    # Pre-parse hosts for all corpora
    print("\nPre-parsing hostnames across all corpora...")
    for cname, cdata in corpora.items():
        hosts = []
        for u in cdata["urls"]:
            _, _, h, _, _ = _parse(u)
            hosts.append(h)
        cdata["hosts"] = hosts

    # 3. Part B: Per-Token Evaluation
    print("\n" + "=" * 80)
    print("Part B: Per-Token Evaluation (16 Tokens Evaluated Individually)")
    print("=" * 80)

    per_token_results = {}
    for tok_meta in threat_manifest:
        t = tok_meta["token"]
        t_set = {t}
        per_token_results[t] = {
            "token": t,
            "category": tok_meta["category"],
            "target": tok_meta["target"],
            "length": tok_meta["length"],
            "corpora": {}
        }
        for cname, cdata in corpora.items():
            n = len(cdata["urls"])
            n_match = 0
            tp = 0
            fp = 0
            fn_miss = 0
            tn_clean = 0
            flipped_to_mal = 0
            matched_urls = []

            for i in range(n):
                h = cdata["hosts"][i]
                is_hit, score, mtype = is_threat_match(h, t_set)
                y = cdata["y_true"][i]
                a0_pred = cdata["a0_preds"][i]

                if is_hit:
                    n_match += 1
                    if y == 1:
                        tp += 1
                    else:
                        fp += 1
                    if a0_pred == 0:
                        flipped_to_mal += 1
                    matched_urls.append({
                        "url": cdata["urls"][i],
                        "y_true": int(y),
                        "a0_pred": int(a0_pred),
                        "score": float(score),
                        "match_type": mtype
                    })
                else:
                    if y == 1:
                        fn_miss += 1
                    else:
                        tn_clean += 1

            per_token_results[t]["corpora"][cname] = {
                "n_total": n,
                "n_pos": int(np.sum(cdata["y_true"] == 1)),
                "n_neg": int(np.sum(cdata["y_true"] == 0)),
                "matches": n_match,
                "tp": tp,
                "fp": fp,
                "fn_miss": fn_miss,
                "tn_clean": tn_clean,
                "precision": float(tp / (tp + fp)) if (tp + fp) > 0 else 1.0,
                "net_flipped_to_malicious": flipped_to_mal,
                "matched_urls": matched_urls
            }

        ct_matches = per_token_results[t]["corpora"]["clean_test"]["matches"]
        ct_tps = per_token_results[t]["corpora"]["clean_test"]["tp"]
        ct_fps = per_token_results[t]["corpora"]["clean_test"]["fp"]
        r2843_matches = per_token_results[t]["corpora"]["candidate_malicious_2843"]["matches"]
        b15k_fps = per_token_results[t]["corpora"]["candidate_benign_15k"]["fp"]
        print(f"  Token {t:12s} (len {tok_meta['length']:2d}, {tok_meta['category']:14s}): "
              f"CleanTest Hits={ct_matches:2d} (TP={ct_tps:2d}, FP={ct_fps:1d}), "
              f"Repaired2843 Hits={r2843_matches:1d}, Benign15k FPs={b15k_fps:1d}")

    # 4. Part C: Combined 16-Token Threat Dictionary Evaluation (Mode 1: Adjudication-Only)
    print("\n" + "=" * 80)
    print("Part C: Combined 16-Token Threat Dictionary Evaluation (Mode 1: Adjudication-Only)")
    print("=" * 80)

    combined_results = {}
    decision_changes = []

    for cname, cdata in corpora.items():
        n = len(cdata["urls"])
        y_true = cdata["y_true"]
        raw_probs = cdata["raw_probs"]
        a0_adj = cdata["a0_adj_probs"]
        a0_preds = cdata["a0_preds"]

        b1_adj = np.copy(a0_adj)
        b1_preds = np.copy(a0_preds)
        match_flags = np.zeros(n, dtype=bool)
        match_scores = np.zeros(n, dtype=float)

        for i in range(n):
            h = cdata["hosts"][i]
            is_hit, score, mtype = is_threat_match(h, threat_tokens_set)
            if is_hit:
                match_flags[i] = True
                match_scores[i] = score
                # Tier 1 Active Threat Override: force final probability >= 0.9500
                b1_adj[i] = max(b1_adj[i], 0.9500)
                b1_preds[i] = 1

                if b1_preds[i] != a0_preds[i]:
                    decision_changes.append({
                        "corpus": cname,
                        "url": cdata["urls"][i],
                        "y_true": int(y_true[i]),
                        "a0_pred": int(a0_preds[i]),
                        "b1_pred": int(b1_preds[i]),
                        "raw_prob": float(raw_probs[i]),
                        "a0_adj_prob": float(a0_adj[i]),
                        "b1_adj_prob": float(b1_adj[i]),
                        "threat_score": float(score),
                        "match_type": mtype,
                        "change_type": "TP_RECOVERED" if y_true[i] == 1 else "FP_INDUCED"
                    })

        metrics_a0 = compute_binary_metrics(y_true, a0_preds, a0_adj)
        metrics_b1 = compute_binary_metrics(y_true, b1_preds, b1_adj)

        combined_results[cname] = {
            "n_total": n,
            "matches_total": int(np.sum(match_flags)),
            "matches_tp": int(np.sum(match_flags & (y_true == 1))),
            "matches_fp": int(np.sum(match_flags & (y_true == 0))),
            "baseline_a0": metrics_a0,
            "candidate_b1": metrics_b1,
            "delta_tp": int(metrics_b1["tp"] - metrics_a0["tp"]),
            "delta_fp": int(metrics_b1["fp"] - metrics_a0["fp"]),
            "delta_recall": float(metrics_b1["recall"] - metrics_a0["recall"]),
            "delta_fpr": float(metrics_b1["fpr"] - metrics_a0["fpr"])
        }

        print(f"\nCorpus: {cname} (N = {n:,})")
        print(f"  Threat Matches: {combined_results[cname]['matches_total']} (TP: {combined_results[cname]['matches_tp']}, FP: {combined_results[cname]['matches_fp']})")
        print(f"  Baseline A0: Recall = {metrics_a0['recall']*100:.3f}% ({metrics_a0['tp']}/{metrics_a0['n_pos']}), FPR = {metrics_a0['fpr']*100:.3f}% ({metrics_a0['fp']}/{metrics_a0['n_neg']})")
        print(f"  Candidate B1: Recall = {metrics_b1['recall']*100:.3f}% ({metrics_b1['tp']}/{metrics_b1['n_pos']}), FPR = {metrics_b1['fpr']*100:.3f}% ({metrics_b1['fp']}/{metrics_b1['n_neg']})")
        print(f"  Delta: TPs = {combined_results[cname]['delta_tp']:+d}, FPs = {combined_results[cname]['delta_fp']:+d}")

    # Additional diagnostic cohorts for Gates 3 and 5:
    # Gate 3: Benchmark Category 1 Bare-Apex (N = 200)
    bench_apex_mask = np.array([c == "bare_apex" for c in corpora["benchmark_overall"]["categories"]], dtype=bool)
    y_b_apex = corpora["benchmark_overall"]["y_true"][bench_apex_mask]
    preds_b_apex_a0 = corpora["benchmark_overall"]["a0_preds"][bench_apex_mask]
    preds_b_apex_b1 = (combined_results["benchmark_overall"]["candidate_b1"]["tp"] + combined_results["benchmark_overall"]["candidate_b1"]["fp"]) # evaluated via mask below
    # compute directly
    b_apex_urls = [corpora["benchmark_overall"]["urls"][i] for i in range(len(bench_apex_mask)) if bench_apex_mask[i]]
    b_apex_hosts = [corpora["benchmark_overall"]["hosts"][i] for i in range(len(bench_apex_mask)) if bench_apex_mask[i]]
    b_apex_a0_adj = corpora["benchmark_overall"]["a0_adj_probs"][bench_apex_mask]
    b_apex_b1_adj = np.copy(b_apex_a0_adj)
    b_apex_b1_preds = np.copy(preds_b_apex_a0)
    for i in range(len(b_apex_urls)):
        is_hit, score, _ = is_threat_match(b_apex_hosts[i], threat_tokens_set)
        if is_hit:
            b_apex_b1_adj[i] = max(b_apex_b1_adj[i], 0.9500)
            b_apex_b1_preds[i] = 1

    bench_apex_a0_met = compute_binary_metrics(y_b_apex, preds_b_apex_a0, b_apex_a0_adj)
    bench_apex_b1_met = compute_binary_metrics(y_b_apex, b_apex_b1_preds, b_apex_b1_adj)

    # Gate 5: Clean Test Phishing Bare-Apex (N = 4,254)
    # Using exact V8 normalization bare-apex mask
    from run_phase_1d_1_a0_a1_a2 import is_bare_apex_qualified
    ct_urls = corpora["clean_test"]["urls"]
    ct_y = corpora["clean_test"]["y_true"]
    ct_a0_preds = corpora["clean_test"]["a0_preds"]
    ct_a0_adj = corpora["clean_test"]["a0_adj_probs"]
    ct_b1_preds = np.copy(ct_a0_preds)
    ct_b1_adj = np.copy(ct_a0_adj)

    for i in range(len(ct_urls)):
        is_hit, score, _ = is_threat_match(corpora["clean_test"]["hosts"][i], threat_tokens_set)
        if is_hit:
            ct_b1_adj[i] = max(ct_b1_adj[i], 0.9500)
            ct_b1_preds[i] = 1

    g5_mask = np.array([is_bare_apex_qualified(ct_urls[i]) and ct_y[i] == 1 for i in range(len(ct_urls))], dtype=bool)
    g5_y = ct_y[g5_mask]
    g5_a0_met = compute_binary_metrics(g5_y, ct_a0_preds[g5_mask], ct_a0_adj[g5_mask])
    g5_b1_met = compute_binary_metrics(g5_y, ct_b1_preds[g5_mask], ct_b1_adj[g5_mask])

    # Gate 7: Golden Fixtures regression check
    gold_a0_preds = corpora["golden_fixtures"]["a0_preds"]
    gold_b1_preds = np.copy(gold_a0_preds)
    gold_regressions = 0
    for i in range(len(gold_a0_preds)):
        is_hit, _, _ = is_threat_match(corpora["golden_fixtures"]["hosts"][i], threat_tokens_set)
        if is_hit:
            gold_b1_preds[i] = 1
        if gold_b1_preds[i] != gold_a0_preds[i]:
            gold_regressions += 1

    # 5. Compile Pre-Registered Gates
    gate_eval_data = {
        "clean_test": combined_results["clean_test"]["candidate_b1"],
        "benchmark_bare_apex": bench_apex_b1_met,
        "benchmark_overall": combined_results["benchmark_overall"]["candidate_b1"],
        "test_phishing_bare_apex": g5_b1_met,
        "adversarial_split": combined_results["adversarial_split"]["candidate_b1"],
        "golden_fixtures": {"n_regressions": gold_regressions}
    }
    gate_results = verify_gate_policy(gate_eval_data)

    print("\n" + "=" * 80)
    print("Pre-Registered 7-Gate Acceptance Outcomes (3-Tier Policy):")
    print("=" * 80)
    for gname, gres in gate_results.items():
        val_str = f"{gres['value']:.5f}" if isinstance(gres["value"], float) else str(gres["value"])
        print(f"  {gname:45s}: {gres['status']:14s} (Observed: {val_str}, Target: {gres['target']})")

    # 6. Part D: Mode 2 Experimental Variable (Feature-Level Extraction Analysis)
    print("\n" + "=" * 80)
    print("Part D: Mode 2 Experimental Variable (Feature-Level Extraction Analysis)")
    print("=" * 80)

    # Test sample URLs for feature shifts and probability shifts
    import v7_features
    old_brands = set(v7_features.COMMON_BRANDS)
    mode_2_samples = [
        "https://www.mygov-login.hmc.edu.au",
        "http://app-uniswap.com.kz",
        "https://hk-poshmark.com/#/",
        "https://mygov.in/",
        "https://pancakeswap-v4.pw/"
    ]
    mode_2_audit = []
    for u in mode_2_samples:
        v7_features.COMMON_BRANDS = old_brands
        v_base, feat_names = vectorize_v7([u])
        p_base = float(champ_model.base_model.predict_proba(v_base)[0, 1])

        v7_features.COMMON_BRANDS = old_brands.union(threat_tokens_set)
        v_exp, _ = vectorize_v7([u])
        p_exp = float(champ_model.base_model.predict_proba(v_exp)[0, 1])

        idx_imp = feat_names.index("BrandImpersonationScore")
        idx_safe = feat_names.index("Safe_Brand_Domain")
        mode_2_audit.append({
            "url": u,
            "feat_0_brand_imp_base": float(v_base[0, idx_imp]),
            "feat_0_brand_imp_exp": float(v_exp[0, idx_imp]),
            "feat_60_safe_brand_base": float(v_base[0, idx_safe]),
            "feat_60_safe_brand_exp": float(v_exp[0, idx_safe]),
            "raw_prob_base": p_base,
            "raw_prob_exp": p_exp,
            "raw_prob_delta": float(p_exp - p_base)
        })
        print(f"  URL: {u}")
        print(f"    Feat 0 (BrandImpScore): {v_base[0, idx_imp]} -> {v_exp[0, idx_imp]}")
        print(f"    Feat 60 (SafeBrand):    {v_base[0, idx_safe]} -> {v_exp[0, idx_safe]}")
        print(f"    Raw HistGBM Prob:       {p_base:.6f} -> {p_exp:.6f} (Delta: {p_exp - p_base:+.6f})")

    v7_features.COMMON_BRANDS = old_brands

    # 7. Export Artifacts
    # A. Decision changes CSV
    df_changes = pd.DataFrame(decision_changes)
    changes_path = EXP_DIR / "decision_changes_b1.csv"
    df_changes.to_csv(changes_path, index=False)
    print(f"\nRecorded {len(df_changes)} total decision flips -> {changes_path.name}")

    # B. Metrics JSON
    metrics_output = {
        "metadata": {
            "experiment": "Phase 1D.1-B1 (16-Token Threat-Dictionary Evaluation)",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "champion_model_sha256": obs_champ_hash,
            "threat_dictionary_sha256": obs_dict_hash,
            "n_threat_tokens": len(threat_tokens_list),
            "threat_tokens": threat_tokens_list,
            "python_version": platform.python_version(),
            "execution_duration_sec": time.time() - start_time
        },
        "gates": gate_results,
        "combined_results": combined_results,
        "benchmark_category_1_bare_apex": {
            "baseline_a0": bench_apex_a0_met,
            "candidate_b1": bench_apex_b1_met
        },
        "gate_5_clean_test_phishing_bare_apex": {
            "baseline_a0": g5_a0_met,
            "candidate_b1": g5_b1_met
        },
        "per_token_results": per_token_results,
        "mode_2_feature_extraction_audit": mode_2_audit
    }

    metrics_json_path = EXP_DIR / "phase_1d_1_b1_metrics.json"
    with open(metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(metrics_output, f, indent=2)
    print(f"Final Metrics JSON Saved: {metrics_json_path.name}")
    print(f"Total Execution Duration: {time.time()-start_time:.2f}s")


if __name__ == "__main__":
    main()
