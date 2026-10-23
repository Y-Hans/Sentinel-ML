# Sentinel — Phase 1C.1 Closure & Benchmark Governance Report

**Date:** 2026-10-19  
**Git Repository Root:** `sentinel-ai/` (Branch: `reforge`)  
**Workspace Directory:** `sentinel-ml/URL-ml/` (Regular workspace directory outside Git root)  
**Governance Standard:** Immutable Diagnostic Benchmark `hard_benign_benchmark_500.json` (v1.0, $N = 500$)  
**Status:** **PHASE 1C.1 FORMALLY CLOSED** | **PHASE 1C.2 NOT STARTED**  

---

## 1. Executive Closure & Decision

Phase 1C.1 is formally **CLOSED**. In accordance with governance instructions:
1. **Benchmark Preserved Unchanged:** `hard_benign_benchmark_500.json` ($N = 500$) and its associated baseline prediction artifacts are **preserved exactly as created**. Record #100 (`https://codenames.game`) is retained without substitution to preserve the cryptographic integrity and historical traceability of this exact benchmark release.
2. **Five Verification Caveats Codified:** All five caveats identified during the verification gate are incorporated into the permanent record. The benchmark is not represented as completely independent of every pre-existing evaluation fixture, but as an independent, domain-disjoint evaluation relative to the training corpora (`cleaned_dataset.csv` and `v7_structural_benign.csv`) and the historical `hard_dataset.csv`.
3. **Diagnostic Baseline Frozen:** The reproduced baseline FPR of **$84.00\%$ at threshold $0.28$** ($79.40\%$ at $0.50$) is established as the frozen baseline against which candidate models will be compared.
4. **Phase 1C.2 Proposal Prepared:** A controlled feature investigation and retraining experiment plan is documented herein. **No implementation, data collection, model retraining, or threshold adjustment has been started.**

---

## 2. Frozen Benchmark Specifications & Cryptographic Hashes

The Phase 1C.1 benchmark artifacts are permanently cataloged under the following cryptographic identities:

```
+--------------------------------------------------------------------------------------------------------------------------------+
| Artifact Identification                                  | Byte Size | SHA-256 Checksum                                        |
+--------------------------------------------------------------------------------------------------------------------------------+
| sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json   |   222,523 | d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6b... |
| sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_... |    81,449 | e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987... |
| sentinel-ml/URL-ml/reports/bare_vs_www_counterfactual... |    36,378 | d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efe... |
+--------------------------------------------------------------------------------------------------------------------------------+
```

### Full SHA-256 Hashes
- **Benchmark JSON:**  
  `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f`
- **Baseline Predictions CSV:**  
  `e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987b85f40447`
- **Bare-versus-WWW Counterfactual CSV:**  
  `d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efeebd9eda14`

### Benchmark Composition ($N = 500$, Version 1.0)
- **Category 1 (Bare Apex Domains):** Exactly 200 records. Validated apex URLs across diverse modern and standard TLDs (`.dev`, `.io`, `.app`, `.ai`, `.game`, `.sh`, `.tech`, `.org`, `.com`, `.net`, `.ch`, `.de`, `.se`, `.fi`).
- **Category 2 (Deep Repository Paths):** Exactly 150 records. Open-source source code files across 11 public forges (`gitlab.freedesktop.org`, `invent.kde.org`, `codeberg.org`, `gitlab.archlinux.org`, `src.fedoraproject.org`, `git.busybox.net`, `git.musl-libc.org`, `git.openwrt.org`, `git.sr.ht`, `review.coreboot.org`).
- **Category 3 (Search Engine Queries):** Exactly 150 records. Authentic technical, scientific, and informational query URLs across 9 independent search engines (`duckduckgo.com`, `search.brave.com`, `ecosia.org`, `qwant.com`, `startpage.com`, `searx.space`, `mojeek.com`, `swisscows.com`, `kagi.com`).

---

## 3. Formal Caveat Register

To ensure scientific honesty and documentation integrity, the five caveats established during independent verification are recorded as permanent attributes of benchmark v1.0:

```
+--------------------------------------------------------------------------------------------------------------------------------+
| CAVEAT 1: GOLDEN FIXTURE OVERLAP FOR CODENAMES.GAME                                                                            |
+--------------------------------------------------------------------------------------------------------------------------------+
| Finding: Record #100 ("https://codenames.game") is present in the Android unit test fixture golden_urls_v8.json and is        |
| explicitly referenced in v8_classifier.py under GAMING_DOMAINS and VERIFIED_HIGH_SCORE_ROOTS.                                  |
| Scope: The benchmark is 100% disjoint from the model's training, validation, and testing sets (cleaned_dataset.csv,           |
| v7_structural_benign.csv, and hard_dataset.csv), but it is NOT 100% disjoint from Android test fixtures.                      |
| Resolution: Retained unchanged in v1.0 to preserve baseline continuity; acknowledged as a known fixture overlap.               |
+--------------------------------------------------------------------------------------------------------------------------------+
| CAVEAT 2: CATEGORY 2 PATHDEPTH DISTRIBUTION                                                                                    |
+--------------------------------------------------------------------------------------------------------------------------------+
| Finding: In Category 2, 135/150 URLs (90.0%) have PathDepth >= 5 (mean depth 7.57, max 13), while 15/150 (10.0%) have         |
| PathDepth == 4 (e.g. Netfilter/BusyBox cgit trees: "/iptables/tree/extensions/libipt_conntrack.c").                            |
| Correction: The claim that "all paths have PathDepth >= 5" is formally corrected to: "all paths are authentic deep source     |
| trees, with 90% having depth >= 5 and 10% having depth == 4".                                                                  |
+--------------------------------------------------------------------------------------------------------------------------------+
| CAVEAT 3: INTRA-BENCHMARK CROSS-CATEGORY DOMAIN OVERLAP                                                                        |
+--------------------------------------------------------------------------------------------------------------------------------+
| Finding: 11 registrable domains in Category 1 (bare apex) also host repository URLs in Category 2 (e.g. freedesktop.org,       |
| kde.org, codeberg.org, archlinux.org, fedoraproject.org, netfilter.org, busybox.net, musl-libc.org, openwrt.org, sr.ht,       |
| coreboot.org).                                                                                                                 |
| Correction: While all 500 URLs are distinct, the benchmark spans 209 unique registrable domains, not 500 disjoint domains.     |
+--------------------------------------------------------------------------------------------------------------------------------+
| CAVEAT 4: MULTI-FEATURE CONFOUNDING IN BARE-VS-WWW EXPERIMENT                                                                  |
+--------------------------------------------------------------------------------------------------------------------------------+
| Finding: Transforming "https://" to "https://www." alters 7 extracted features concurrently: DomainLength (+4), URLLength (+4),|
| NoOfSubDomain (+1), SpecialCharRatio (+0.04), HostEntropy (+0.07), URLCharEntropy (+0.07), and HostDigitRatio (-0.0002).       |
| Normality of score deltas is rejected (Shapiro-Wilk p = 2.57e-20), though non-parametric Wilcoxon is decisive (p = 1.44e-34). |
| Nuance: Synthetic single-feature perturbation proves NoOfSubDomain explains 99.28% of the risk reduction, but at the URL string|
| level, 7 features shift simultaneously. Paired URL comparison alone demonstrates model sensitivity, not isolated causation.    |
+--------------------------------------------------------------------------------------------------------------------------------+
| CAVEAT 5: WORKSPACE / GIT TRACKING BOUNDARY                                                                                    |
+--------------------------------------------------------------------------------------------------------------------------------+
| Finding: sentinel-ml/URL-ml/ is a workspace directory located outside the sentinel-ai/ Git root. Benchmark files are not       |
| tracked in Git version control.                                                                                                |
| Governance: Hashes and byte sizes are preserved in this report and brain artifacts to ensure cryptographic immutability.       |
+--------------------------------------------------------------------------------------------------------------------------------+
```

---

## 4. Benchmark Governance Policy & Rules of Engagement

To prevent data contamination, metric gaming, and evaluation decay during subsequent phases, the following governance rules are established:

1. **Diagnostic Standard, Not General Traffic Estimate:**  
   The $84.00\%$ FPR at threshold $0.28$ is an evaluation result specifically on this hard-benign benchmark, which intentionally samples from known model blind spots. It is not an estimate of false-positive rates on general, benign consumer web traffic (which is dominated by standard `www.` domains with shallow paths).
2. **Strict Prohibition Against Direct Optimization:**  
   `hard_benign_benchmark_500.json` is a frozen evaluation benchmark. It **must NEVER be added to training data, validation splits, or used for automated feature selection, hyperparameter sweeps, or threshold tuning**. Any model that tunes directly against this benchmark forfeits its claim to an unbiased evaluation.
3. **Mandatory Citation of Known Limitations:**  
   Any release document, experiment report, or promotion audit citing performance against this benchmark must reference this v1.0 specification and its five documented caveats.
4. **Version Immutability:**  
   If the benchmark is revised in the future (e.g. substituting `codenames.game` or expanding Category 2), it must be designated `hard_benign_benchmark_v2.json` with its own distinct SHA-256 hash. `hard_benign_benchmark_500.json` (v1.0) must never be modified or overwritten.

---

## 5. Phase 1C.2 Research Proposal: Controlled Feature Investigation & Candidate Experiment Design

### 5.1. Core Hypotheses

```
+---------------------------------------------------------------------------------------------------+
| Slice / Category    | Primary Causal Hypothesis                                                   |
+---------------------+-----------------------------------------------------------------------------+
| 1. Bare Apex        | Driven by missing "www." prefix (NoOfSubDomain == 0). The GBDT tree splits  |
|                     | treat NoOfSubDomain == 0 as a strong malicious prior because 100.00% of the |
|                     | benign training URLs in cleaned_dataset.csv contain "www.".                |
+---------------------+-----------------------------------------------------------------------------+
| 2. Deep Repo Paths  | Driven by non-linear interaction between PathDepth >= 5, PathLength > 40,   |
|                     | URLLength > 75, and PathEntropy > 3.8. In addition, brand scanner rules     |
|                     | produce false threat overrides on forge subdomains (e.g. gitlab.*).         |
+---------------------+-----------------------------------------------------------------------------+
| 3. Search Queries   | Driven by high QueryParamCount, SpecialCharRatio > 0.15, and QueryEntropy   |
|                     | > 4.0, which overlap with command injection / payload heuristics.           |
+---------------------+-----------------------------------------------------------------------------+
```

### 5.2. Testing Hypotheses Without Modifying the Frozen Model
Before retraining or touching production weights, controlled feature investigation will be conducted on the frozen V8 model:
1. **Tree Path Decomposition:** Trace individual tree traversal paths in `v8_champion.joblib` for misclassified benchmark URLs to identify exact feature split thresholds and leaf weight contributions.
2. **Coupled Feature Reconstruction (Preventing Impossible Vectors):**  
   Synthetic feature sweeps will not modify single features in isolation without updating dependent derived features. All candidate vectors will be generated by parsing syntactically valid URL strings through `extract_v7_features` to preserve mathematical invariants:
   $$\text{URLLength} = \text{DomainLength} + \text{PathLength} + \text{QueryLength} + \text{SchemeOverhead}$$
   $$\text{SpecialCharRatio} = \frac{\sum \text{non-alphanumeric}}{\text{URLLength}}$$
3. **SHAP / TreeSHAP Attribution:** Compute exact feature attribution values across the 500 benchmark records to establish the relative importance of `NoOfSubDomain` vs. length and entropy features.

### 5.3. Multi-Metric Protection Gates (Non-Negotiable Release Constraints)
Any candidate model retrained in Phase 1C.2 must satisfy all five gates simultaneously:

```
+---------------------------------------------------------------------------------------------------+
| RELEASE GATE                            | CURRENT FROZEN V8  | PHASE 1C.2 TARGET REQUIREMENT      |
+-----------------------------------------+--------------------+------------------------------------+
| 1. Hard-Benign Benchmark FPR @ 0.28     | 84.00% (420/500)   | <= 5.00% (<= 25/500)               |
|    - Category 1 (Bare Apex) FPR @ 0.28  | 100.00% (200/200)  | <= 2.00% (<= 4/200)                |
|    - Category 2 (Deep Repo) FPR @ 0.28  | 96.67% (145/150)   | <= 5.00% (<= 8/150)                |
|    - Category 3 (Search) FPR @ 0.28     | 50.00% (75/150)    | <= 5.00% (<= 8/150)                |
| 2. Cleaned Test Partition FPR @ 0.28    | 0.96%              | <= 1.00% (Zero FPR Regression)     |
| 3. Cleaned Test Malicious Recall @ 0.28 | 98.53%             | >= 98.00% (Zero Security Drop)     |
| 4. Adversarial Evasion Robustness @ 0.28| 96.90%             | >= 95.00% (Zero Evasion Drop)      |
| 5. Model Bundle & Latency Limit         | 1.03 MB, < 0.5 ms  | <= 10.0 MB, <= 2.0 ms on Android   |
+-----------------------------------------+--------------------+------------------------------------+
```

### 5.4. Post-Tuning Fresh Holdout Requirement (Phase 1C.3)
Because multiple candidate models may be evaluated against the 500-URL benchmark during Phase 1C.2, **an entirely fresh, untouched holdout benchmark ($N \ge 300$) must be constructed in Phase 1C.3** before final production promotion. This guarantees that candidate improvements generalize to unseen domains and do not represent adaptive over-fitting to the Phase 1C.1 benchmark.

### 5.5. Stop & Rollback Criteria
- If any candidate model causes `Test Malicious Recall` to drop below $98.00\%$, training must immediately halt.
- If adversarial robustness falls below $95.00\%$, the candidate is rejected.
- No model artifact will be exported or promoted to `android-app/` until explicit approval is granted following Phase 1C.2 review.

---

## 6. Safety, Verification & Git State

### Working Tree Verification
- **Git Branch:** `reforge` (verified via `git branch`).
- **Git Status:** Exactly identical to pre-flight. Zero files staged, committed, reset, reverted, cleaned, or modified in the `sentinel-ai` Git root (all 59 pre-existing entries preserved).
- **Production Files Preserved:** `SafeDomainAdjudicator.kt`, `v8_classifier.py`, `v7_champion.joblib`, `v8_champion.joblib`, and all golden fixtures remain strictly read-only.
- **Artifacts Preserved:** `hard_benign_benchmark_500.json`, `hard_benign_benchmark_500_predictions.csv`, and `bare_vs_www_counterfactual_200.csv` remain unmodified with verified hashes.

---

## 7. Next Steps & Stop Condition

Phase 1C.1 is officially closed.  
**Phase 1C.2 implementation remains NOT STARTED.**

Execution is stopped here. Await user review and formal authorization before beginning Phase 1C.2 feature analysis or candidate experiments.
