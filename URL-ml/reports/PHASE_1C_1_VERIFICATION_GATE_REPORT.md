# Sentinel — Phase 1C.1 Verification Gate Report (Read-Only)

**Date:** 2026-10-19  
**Git Repository Root:** `sentinel-ai/` (Branch: `reforge`)  
**Workspace Directory:** `sentinel-ml/URL-ml/` (Regular workspace directory outside Git root)  
**Evaluation Target:** `sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json` ($N = 500$)  
**Baseline Prediction File:** `sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_predictions.csv`  
**Counterfactual File:** `sentinel-ml/URL-ml/reports/bare_vs_www_counterfactual_200.csv`  
**Prior Phase Report:** `sentinel-ml/URL-ml/reports/HARD_BENIGN_BENCHMARK_REPORT.md`  

---

## 1. Executive Verdict

### **VERDICT: VERIFIED WITH CAVEATS**

The Phase 1C.1 benchmark and baseline evaluation are **independently reproducible with machine-epsilon numerical precision** ($1.11 \times 10^{-16}$). Zero data leakage against all training, validation, and testing partitions (`cleaned_dataset.csv`, `v7_structural_benign.csv`, and `hard_dataset.csv`) is mathematically verified across all 177,018 pre-existing domains. 

However, release freeze as an immutable gate is qualified by **five specific caveats**:
1. **Golden Fixture Overlap:** `https://codenames.game` (Category 1, record #100) overlaps exactly with `golden_urls_v8.json` (the existing Android unit test fixture) and is hardcoded in `v8_classifier.py` (`GAMING_DOMAINS` and `VERIFIED_HIGH_SCORE_ROOTS`).
2. **Category 2 Depth Discrepancy:** The report asserted that all repository URLs have `PathDepth >= 5`. In reality, 135/150 (90.0%) have depth $\ge 5$, while 15/150 (10.0%) have depth $= 4$ (e.g. `/iptables/tree/extensions/libipt_conntrack.c`).
3. **Intra-Benchmark Cross-Category Domain Overlap:** 11 registrable domains in Category 1 (bare apex) also appear in Category 2 (deep repo paths), yielding 209 unique registrable domains overall.
4. **Counterfactual Confounding:** Transforming `https://` to `https://www.` alters 7 features concurrently, not `NoOfSubDomain` alone. Single-feature counterfactual perturbation confirms `NoOfSubDomain` explains 99.28% of the drop, but score differences violate normality ($p = 2.57 \times 10^{-20}$), requiring the non-parametric Wilcoxon test ($p = 1.44 \times 10^{-34}$).
5. **Git Tracking Boundary:** `sentinel-ml/` is a workspace directory located outside the `sentinel-ai/` Git root. The benchmark artifacts are not currently tracked in Git.

---

## 2. Independent Reproduction of Baseline Metrics

All 500 benchmark records and their predictions were independently reproduced using the saved files and live re-inference against the frozen production V8 model:

```
+---------------------------------------------------------------------------------------------------+
|                         REPRODUCED BASELINE METRICS (REPORTED VS. REPRODUCED)                     |
+---------------------+-------+-------------------+--------------------+--------------------+-------+
| Slice / Category    |   N   | Reported FPR @0.28| Reproduced FPR @0.28| Reproduced FPR @0.50| Status|
+---------------------+-------+-------------------+--------------------+--------------------+-------+
| Category 1 (Apex)   |  200  |  100.00% (200/200)|   100.00% (200/200)|    99.00% (198/200)| EXACT |
| Category 2 (Repo)   |  150  |   96.67% (145/150)|    96.67% (145/150)|    94.67% (142/150)| EXACT |
| Category 3 (Search) |  150  |   50.00%  (75/150)|    50.00%  (75/150)|    38.00%  (57/150)| EXACT |
+---------------------+-------+-------------------+--------------------+--------------------+-------+
| OVERALL BENCHMARK   |  500  |   84.00% (420/500)|    84.00% (420/500)|    79.40% (397/500)| EXACT |
+---------------------+-------+-------------------+--------------------+--------------------+-------+
```

### Numerical Alignment Audit
- **Prediction-to-Record Alignment:** 500 of 500 URLs match 1-to-1 in the exact same sequence. No missing, duplicate, or orphan predictions.
- **Max Absolute Score Difference (Live vs. Saved):**
  - Raw probability: $\max |p_{\text{live}} - p_{\text{saved}}| = 1.11 \times 10^{-16}$ (floating point precision limit).
  - Final adjudicated probability: $\max |p_{\text{live}} - p_{\text{saved}}| = 1.11 \times 10^{-16}$.
- **Adjudication Rule Alignment:** 100% agreement across all 500 records (496 `NONE_PASSTHROUGH`, 4 `MALICIOUS_OVERRIDE`).

### Discrepancy Log
```
+---------------------------------------------------------------------------------------------------+
| Expected in Report Text       | Observed in Data / Code       | Likely Explanation    | Severity  |
+-------------------------------+-------------------------------+-----------------------+-----------+
| "All paths have PathDepth>=5" | 135 have depth>=5, 15 depth=4 | Netfilter/BusyBox cgit| Minor     |
| "Zero overlap with all sets"  | 1 URL in golden_urls_v8.json  | codenames.game fixture| Moderate  |
| "NoOfSubDomain sole driver"   | 7 features change on string   | Co-occurring length   | Minor     |
| Master exclusion: 177,018     | 177,018 (URL split-consistent)| Hostname parser type  | Negligible|
+---------------------------------------------------------------------------------------------------+
```

---

## 3. Model & Runtime Identity

The exact inference components producing the benchmark results were verified:

```
+--------------------------------------------------------------------------------------------------------------------------------+
| Component / File Path                                    | Byte Size | SHA-256 Checksum                                        |
+--------------------------------------------------------------------------------------------------------------------------------+
| sentinel-ml/URL-ml/models/v8_champion.joblib             |   709,417 | 073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51... |
| sentinel-ml/URL-ml/models/v8_champion_portable.json      | 1,029,275 | e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d837028... |
| android-app/core/src/test/resources/v8_champion_porta... | 1,029,275 | e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d837028... |
| sentinel-ml/URL-ml/scripts/v8_classifier.py              |    13,093 | bdaf2b502aa7c97884eae0ff507da780b71e440ecaa8941712b8a0... |
| sentinel-ml/URL-ml/scripts/v7_features.py                |    18,587 | 86cd3ba552efd1f3773d78f3e2d46b28752dc6a4166e58e6c5148c... |
| sentinel-ml/URL-ml/scripts/v8_normalization.py           |     4,894 | e252f727bf20ba9a51ef9e9e6371283d4772251ec1b31f65f0730a... |
+--------------------------------------------------------------------------------------------------------------------------------+
```

### Runtime Verification Notes
- **Python / Android JSON Equivalence:** `v8_champion_portable.json` in `sentinel-ml/URL-ml/models/` and `android-app/core/src/test/resources/` are **100% bit-for-bit identical** (identical size and SHA-256).
- **Base Estimator:** `HistGradientBoostingClassifier` with 350 iterations, 1 tree per iteration, max leaf nodes 40, L2 regularization 5.0.
- **Operating Threshold:** Formally verified at $0.2800$.
- **Adjudicator Wrapper:** `V8RelationalURLClassifier` enforcing Security Invariants 1–5, with zero route-shape suppression as locked in Step 3.2.

---

## 4. Benchmark Labels & Provenance Audit

All 500 URLs were audited for syntactic validity, structural conformance, category assignment, and benign provenance evidence:

```
+---------------------------------------------------------------------------------------------------+
|                               BENCHMARK PROVENANCE AUDIT BREAKDOWN                                |
+---------------------+-------+-------------------+-------------------+--------------------+--------+
| Category            | Total | Verified Benign   | Lexical Warning   | Structural Anomaly | Status |
+---------------------+-------+-------------------+-------------------+--------------------+--------+
| Category 1 (Apex)   |  200  | 199 (99.5%)       | 1 (`vitest.dev`)  | 0 (0.0%)           | PASS   |
| Category 2 (Repo)   |  150  | 135 (90.0%)       | 0 (0.0%)          | 15 (depth == 4)    | CAVEAT |
| Category 3 (Search) |  150  | 150 (100.0%)      | 0 (0.0%)          | 0 (0.0%)           | PASS   |
+---------------------+-------+-------------------+-------------------+--------------------+--------+
| OVERALL BENCHMARK   |  500  | 484 (96.8%)       | 1 (0.2%)          | 15 (3.0%)          | CAVEAT |
+---------------------+-------+-------------------+-------------------+--------------------+--------+
```

### Detailed Provenance Assessment
- **Category 1 (Bare Apex):** All 200 records represent verified, authoritative organizational and technical homepages. The single flag on `https://vitest.dev` was caused by a substring heuristic (`test` in `vi-test`); `vitest.dev` is confirmed to be the official homepage of the Vite-native test framework.
- **Category 2 (Deep Repo Paths):** All 150 URLs belong to official open-source trees on independent forges. However, 15 Netfilter and BusyBox URLs have `PathDepth == 4` (e.g. `/iptables/tree/extensions/libipt_conntrack.c`) because cgit uses `/tree/` as a 1-level separator. All 150 remain genuine open-source source files.
- **Category 3 (Search Queries):** All 150 queries were verified to contain authentic, non-hostile educational, scientific, and technical search terms. Zero command injection, XSS, or path traversal tokens are present.

---

## 5. Isolation & Leakage Audit

Cross-referencing against all training, validation, testing, and evaluation partitions confirms zero leakage:

```
+---------------------------------------------------------------------------------------------------+
|                                 DATASET ISOLATION & LEAKAGE AUDIT                                 |
+--------------------------------+---------+---------------+-----------------+----------------------+
| Dataset Partition              | Rows    | Unique Domains| Overlapping URLs| Overlapping Domains  |
+--------------------------------+---------+---------------+-----------------+----------------------+
| cleaned_dataset.csv (Train)    | 141,178 | 101,388       | 0 (0.00%)       | 0 (0.00%)            |
| cleaned_dataset.csv (Val)      |  44,106 |  33,796       | 0 (0.00%)       | 0 (0.00%)            |
| cleaned_dataset.csv (Test)     |  50,511 |  33,797       | 0 (0.00%)       | 0 (0.00%)            |
| v7_structural_benign.csv       |  48,290 |  15,045       | 0 (0.00%)       | 0 (0.00%)            |
| hard_dataset.csv               |   2,800 |     688       | 0 (0.00%)       | 0 (0.00%)            |
| URL_REMEDIATION_ADVERSARIAL... |   3,900 |     390       | 0 (0.00%)       | 0 (0.00%)            |
+--------------------------------+---------+---------------+-----------------+----------------------+
| MASTER EXCLUSION UNION         | 440,865 | 177,018       | 0 (0.00%)       | 0 (0.00%) STRICT PASS|
+--------------------------------+---------+---------------+-----------------+----------------------+
| golden_urls_v8.json (Fixture)  |     174 |     119       | 1 URL (0.57%)   | 1 Domain (0.84%)     |
+--------------------------------+---------+---------------+-----------------+----------------------+
```

### Reconciling Exclusion-Set Sizing
- The master exclusion set size of **177,018** unique registrable domains is reconciled:
  - `cleaned_dataset.csv`: 168,981 domains via `domain_group`, expanded to 175,368 via `extract_parent_domain`.
  - `v7_structural_benign.csv`: 15,045 domains.
  - `hard_dataset.csv`: 688 domains.
  - `adversarial_eval`: 390 domains.
  - Master union across all partitions $= 177,018$ unique domains.
- Against this master union of 177,018 domains, the benchmark domain set exhibits **mathematically proven zero overlap**.
- **Golden Fixture Overlap Note:** `https://codenames.game` was included in Category 1 because it was not in `cleaned_dataset.csv` or `v7_structural_benign.csv`. However, it exists in `golden_urls_v8.json`. This should be replaced or formally accepted as a known fixture overlap.

---

## 6. Audit of the Bare-vs-WWW Experiment

The 200 matched pairs from `bare_vs_www_counterfactual_200.csv` were audited to evaluate the causality claim:

### 1. Multi-Feature Co-occurrence
Transforming `https://<domain>` to `https://www.<domain>` changes **7 features concurrently**, not `NoOfSubDomain` alone:
- `DomainLength`: $+4.00$
- `URLLength`: $+4.00$
- `NoOfSubDomain`: $+1.00$
- `SpecialCharRatio`: $+0.0401$ (mean)
- `HostEntropy`: $+0.0714$ (mean)
- `URLCharEntropy`: $+0.0711$ (mean)
- `HostDigitRatio`: $-0.0002$ (mean)

### 2. Isolated Single-Feature Perturbation
To isolate causality, an independent synthetic perturbation was executed: modifying *only* `NoOfSubDomain` ($0 \to 1$) in the feature vector while holding all other 66 features strictly constant:
- Total observed delta on URL string transform: **$0.9093$**
- Delta when perturbing *only* `NoOfSubDomain`: **$0.9027$**
- **Conclusion:** `NoOfSubDomain` accounts for **$99.28\%$** of the risk drop. While not the *sole* changing feature in the URL string, it is demonstrably the dominant causal driver in the tree splits.

### 3. Statistical Validity
- **Normality Check:** Shapiro-Wilk test on score differences yields $W = 0.6407, p = 2.57 \times 10^{-20}$, decisively rejecting normality.
- **Parametric Caveat:** The paired $t$-test cited in the report assumes a normal distribution of differences; reporting it as formal proof was a parametric overstatement.
- **Non-Parametric Confirmation:** The distribution-free paired Wilcoxon signed-rank test yields $W = 0.0000, p = 1.44 \times 10^{-34}$, confirming that the score reduction is statistically significant beyond doubt.

---

## 7. Artifact Integrity & Git State

### Artifact Hashes & Storage Locations
All three benchmark files were verified against reported SHA-256 checksums:

```
+--------------------------------------------------------------------------------------------------------------------------------+
| File Path                                                | Byte Size | SHA-256 Checksum                                        |
+--------------------------------------------------------------------------------------------------------------------------------+
| sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json   |   222,523 | d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6b... |
| sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_... |    81,449 | e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987... |
| sentinel-ml/URL-ml/reports/bare_vs_www_counterfactual... |    36,378 | d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efe... |
+--------------------------------------------------------------------------------------------------------------------------------+
```

### Git Repository Status
- **Current Branch:** `reforge` (verified via `git branch`).
- **Git Working Tree:** `git status --short` in `sentinel-ai` confirms exactly 59 pre-existing entries preserved. Zero files were staged, committed, reset, reverted, cleaned, or modified.
- **Git Tracking Status:** All benchmark artifacts reside in `sentinel-ml/URL-ml/`, which is outside the `sentinel-ai/` Git repository root. They are untracked by Git.

---

## 8. Recommendations & Release Gate Decision

### Can the Benchmark be Frozen?
**YES, subject to acknowledging the following three items:**
1. **Accept or Swap `codenames.game`:** `https://codenames.game` is currently in `golden_urls_v8.json`. If strict disjointness from unit test fixtures is required, replace record #100 with an unreferenced apex domain (e.g. `https://lichess.org` or `https://colonist.io`).
2. **Accept `PathDepth == 4` on 15 Records:** Formally recognize that Category 2 contains 135 URLs at depth $\ge 5$ and 15 URLs at depth $4$. All 150 URLs remain authentic source-code files.
3. **Recognize Domain Count:** Acknowledge that the benchmark contains 209 unique registrable domains (since Category 2 open-source forges share apex domains with Category 1).

### Stop Condition Met
Phase 1C.1 verification is complete. No candidate retraining, feature extraction changes, threshold adjustments, or Phase 1C.2 tasks have been initiated. Execution is halted awaiting review.
