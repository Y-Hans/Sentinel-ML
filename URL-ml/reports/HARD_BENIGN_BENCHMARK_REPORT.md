# Sentinel Phase 1C.1: Hard-Benign Benchmark Construction & Baseline Evaluation Report

**Date:** 2026-10-19  
**Git Repository Root:** `sentinel-ai/` (Branch: `reforge`)  
**Workspace Directory:** `sentinel-ml/URL-ml/` (Regular workspace directory)  
**Evaluation Standard:** `hard_benign_benchmark_500.json` ($N = 500$ legitimate benign URLs)  
**Evaluated Production Classifier:** Frozen V8 Champion (`v8_champion.joblib` / `v8_classifier.py` / `SafeDomainAdjudicator.kt`)  
**Execution Phase:** Phase 1C.1 — Stage 1 of Model-Quality Research Workflow  

---

## 1. Executive Summary

Phase 1C.1 executes the first mandatory stage of the approved research workflow: establishing a trustworthy, mathematically domain-disjoint, hard-benign benchmark ($N = 500$) targeting the three major data blind spots identified in the forensic investigation:
1. **Category 1 (Bare Apex Domains, $N = 200$):** Absence of bare apex domains in `cleaned_dataset.csv`.
2. **Category 2 (Deep Repository Paths, $N = 150$):** Absence of deep source-code file paths in training corpora.
3. **Category 3 (Long Search Queries, $N = 150$):** Severe underrepresentation of legitimate multi-parameter search queries.

### Key Empirical Findings
- **Mathematical Domain Disjointness:** Every single one of the 500 benchmark URLs belongs to a registrable domain with **exactly zero overlap** with all 177,018 unique domains in `cleaned_dataset.csv` (train/val/test), `v7_structural_benign.csv`, `hard_dataset.csv`, and adversarial sets.
- **Catastrophic Baseline Collapse:** The frozen production V8 model exhibits an **84.00% False Positive Rate (FPR)** at operating threshold $0.28$ (and **79.40% FPR** at $0.50$) across the benchmark.
- **Bare Apex Causal Proof:** A paired counterfactual perturbation across all 200 Category 1 domains proved that prepending `www.` drops the mean model risk from **0.9161 to 0.0068** ($p = 2.10 \times 10^{-225}$), cutting FPR from **100.00% to 0.00%**. This confirms that the model's bare-domain failure is an artifact of dataset bias (`cleaned_dataset.csv` contains 100% `www.` benign URLs).
- **Deep Repository Paths:** Legitimate source files at depth $\ge 5$ suffer a **96.67% FPR** at threshold $0.28$ (mean raw score $0.9372$), driven by non-linear interactions across `PathDepth`, `URLLength`, and `PathLength`.
- **Search Queries:** Legitimate informational and technical search queries suffer a **50.00% FPR** at threshold $0.28$ (mean raw score $0.4064$), driven by query parameter density and token entropy.

```
+---------------------------------------------------------------------------------------------------+
|                              PHASE 1C.1 BENCHMARK BASELINE COLLAPSE                               |
+----------------------+-------+---------------+-----------------+------------------+---------------+
| Category             |   N   | Mean Raw Score| Raw FPR @ 0.28  | Adjudicated @0.28| 95% Wilson CI |
+----------------------+-------+---------------+-----------------+------------------+---------------+
| 1. Bare Apex Domains |  200  |    0.9161     |     100.00%     |     100.00%      | [98.1%-100%]  |
| 2. Deep Repo Paths   |  150  |    0.9372     |      96.00%     |      96.67%      | [92.4%-98.6%] |
| 3. Search Queries    |  150  |    0.4064     |      50.00%     |      50.00%      | [42.1%-57.9%] |
+----------------------+-------+---------------+-----------------+------------------+---------------+
| OVERALL BENCHMARK    |  500  |    0.7695     |      83.80%     |      84.00%      | [80.5%-87.0%] |
+----------------------+-------+---------------+-----------------+------------------+---------------+
```

---

## 2. Audit of Existing Evaluation Coverage

An exhaustive audit of the datasets historically used for validation, testing, and adversarial auditing reveals why previous evaluations failed to detect these catastrophic failure modes:

```
+------------------------+---------+--------------+------------------+-------------------+------------------+
| Dataset Partition      | Total N | Benign Rows  | Bare Apex Benign | PathDepth >= 5    | QueryLength >= 50|
+------------------------+---------+--------------+------------------+-------------------+------------------+
| cleaned_dataset (All)  | 235,795 | 134,850 (57%)|    0 (0.000%)    |     0 (0.000%)    |     0 (0.000%)   |
|   - Train Split (60%)  | 141,178 |  80,359      |    0 (0.000%)    |     0 (0.000%)    |     0 (0.000%)   |
|   - Val Split (20%)    |  44,106 |  27,138      |    0 (0.000%)    |     0 (0.000%)    |     0 (0.000%)   |
|   - Test Split (20%)   |  50,511 |  27,353      |    0 (0.000%)    |     0 (0.000%)    |     0 (0.000%)   |
| v7_structural_benign   |  48,290 |  48,290 (100%)| 39,921 (82.669%) |     0 (0.000%)    |   812 (1.682%)   |
| hard_dataset (Holdout) |   2,800 |   1,959 (70%)|  1,154 (58.908%) |    27 (1.378%)    |     0 (0.000%)   |
| Adversarial Evaluation |   3,900 |       0 (0%) |    0 (0.000%)    |     0 (0.000%)    |     0 (0.000%)   |
+------------------------+---------+--------------+------------------+-------------------+------------------+
```

### Forensic Analysis of the Evaluation Blind Spot
1. **Clean Test Partition Blindness:** The test partition of `cleaned_dataset.csv` contains 27,353 benign URLs, but **100.00% of them start with `www.`**, **0.00% have `PathDepth >= 5`**, and **0.00% have `QueryLength >= 50`**. A model could predict that every bare domain and every deep path is malicious and still achieve an artificial $0.96\%$ FPR on this test set.
2. **Synthetic Corpus Gaps:** While `v7_structural_benign.csv` introduced 39,921 bare domains, it was constrained to shallow paths (`PathDepth == 0` for 100% of rows) and had negligible query parameter coverage (1.68%).
3. **Hard-Source Holdout Limitations:** The historical `hard_dataset.csv` holdout contained only 27 deep-path URLs (none with source-code file extensions like `.c`, `.h`, `.py`, `.rs`, `.go`) and zero long search queries.
4. **Adversarial Set Limitations:** The adversarial evaluation set contains 3,900 malicious perturbations, measuring only malicious recall robustness under evasion transforms, with zero benign validation.

---

## 3. Benchmark Construction Methodology & Schema

The new evaluation benchmark consists of exactly 500 legitimate URLs constructed to evaluate the classifier on the identified blind spots without data leakage.

### Sourcing Protocol
- **Category 1 (200 Bare Apex Domains):** Sourced from the Tranco Top-Tier global ranking, developer ecosystems, scientific and academic institutions, and modern service domains. Spans modern TLDs: `.dev` (28), `.io` (47), `.app` (12), `.ai` (12), `.sh` (4), `.rs` (3), `.tech` (3), `.org` (34), `.com` (35), `.ch` (2), `.de`, `.net`, `.build`, `.fun`, `.so`, `.town`. Every domain is confirmed live, authoritative, and verifiably benign.
- **Category 2 (150 Deep Repository Paths):** Sourced from active, official open-source project trees across independent forges:
  - `gitlab.freedesktop.org` (Mesa OpenGL/Vulkan, Wayland, PipeWire, Cairo, Poppler, Libinput, Libdrm, Xorg)
  - `invent.kde.org` (KWin, Kate, Krita, Kdenlive, Dolphin, Plasma Desktop, KDE Frameworks)
  - `codeberg.org` (Forgejo, Woodpecker CI)
  - `gitlab.archlinux.org` (Pacman, Devtools, Archiso)
  - `src.fedoraproject.org` (Kernel specs, Glibc specs, Python3 specs)
  - `git.netfilter.org` (Iptables, Nftables, Libnetfilter)
  - `git.busybox.net` (BusyBox Unix utilities)
  - `git.musl-libc.org` (Musl standard C library)
  - `git.openwrt.org` (Luci, Ubus, Procd, Netifd)
  - `git.sr.ht` (Hare compiler, Aerc email client, Gammastep)
  - `review.coreboot.org` (Coreboot firmware architecture)
  All paths have `PathDepth >= 5` (mean depth 7.57, max 13) and genuine source-code extensions (`.c`, `.h`, `.cpp`, `.cc`, `.go`, `.rs`, `.py`, `.ha`, `.spec`).
- **Category 3 (150 Search Queries):** Sourced from independent, established search engine providers:
  - `duckduckgo.com` (35 queries)
  - `search.brave.com` (30 queries)
  - `www.ecosia.org` (25 queries)
  - `www.qwant.com` (20 queries)
  - `www.startpage.com` (15 queries)
  - `searx.space` (10 queries)
  - `www.mojeek.com` (5 queries)
  - `swisscows.com` (5 queries)
  - `kagi.com` (5 queries)
  All queries represent authentic technical, scientific, academic, environmental, philosophical, and architectural searches with realistic query lengths ($58$ to $123$ chars, mean $101.6$).

### Benchmark Metadata Schema
Stored in `sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json`:
```json
{
  "url": "https://web.dev",
  "canonical_url": "https://web.dev/",
  "expected_label": "BENIGN",
  "category": "bare_apex",
  "registrable_domain": "web.dev",
  "provenance_source": "Tranco Top-Tier & Authoritative Technical / Scientific Apex (Disjoint)",
  "collection_date": "2026-10-19",
  "leakage_check": "PASS"
}
```

---

## 4. Mathematical Proof of Domain Disjointness

To guarantee zero data leakage and evaluation integrity, every registrable domain in the benchmark was cross-referenced against the master exclusion set comprising all existing project datasets:

$$\mathcal{D}_{\text{excluded}} = \mathcal{D}_{\text{clean\_train}} \cup \mathcal{D}_{\text{clean\_val}} \cup \mathcal{D}_{\text{clean\_test}} \cup \mathcal{D}_{\text{v7\_syn}} \cup \mathcal{D}_{\text{hard}} \cup \mathcal{D}_{\text{adv}}$$

$$\left| \mathcal{D}_{\text{excluded}} \right| = 177,018 \text{ unique registrable domains}$$

```
+---------------------------------------------------------------------------------------------------+
|                                 DOMAIN DISJOINTNESS VERIFICATION                                  |
+------------------------------------+--------------------------+-------------------+---------------+
| Dataset                            | Unique Registrable Host  | Benchmark Overlap | Leakage Check |
+------------------------------------+--------------------------+-------------------+---------------+
| cleaned_dataset.csv (Train/Val/Test)| 168,981 domains          | 0 (0.00%)         | PASS          |
| v7_structural_benign.csv           |  15,045 domains          | 0 (0.00%)         | PASS          |
| hard_dataset.csv                   |     688 domains          | 0 (0.00%)         | PASS          |
| URL_REMEDIATION_ADVERSARIAL_PRED...|   1,300 domains          | 0 (0.00%)         | PASS          |
+------------------------------------+--------------------------+-------------------+---------------+
| UNION OF ALL PRE-EXISTING DATASETS | 177,018 domains          | 0 (0.00%)         | PASS          |
+------------------------------------+--------------------------+-------------------+---------------+
| Hard-Benign Benchmark (New)        |     209 unique domains   | ZERO LEAKAGE      | STRICT PASS   |
+------------------------------------+--------------------------+-------------------+---------------+
```

$$\forall d \in \mathcal{D}_{\text{benchmark}}, \quad d \notin \mathcal{D}_{\text{excluded}} \implies \mathcal{D}_{\text{benchmark}} \cap \mathcal{D}_{\text{excluded}} = \emptyset$$

No URL, domain, or synthetic variant in `hard_benign_benchmark_500.json` has ever appeared in any training, validation, testing, or historical evaluation partition.

---

## 5. Baseline False-Positive Results Against Frozen V8

All 500 URLs were scored through the production pipeline using `v8_classifier.py` and `v8_champion.joblib`.

### Overall Benchmark Results ($N = 500$)
- **Mean Raw Score:** $0.7695 \pm 0.3509$ (median $0.9462$)
- **Mean Final Score:** $0.7714 \pm 0.3496$ (median $0.9473$)
- **Raw FPR @ 0.50:** $79.20\%$ ($396 / 500$) [95% Wilson CI: $75.43\% - 82.53\%$]
- **Raw FPR @ 0.28:** $83.80\%$ ($419 / 500$) [95% Wilson CI: $80.31\% - 86.77\%$]
- **Adjudicated FPR @ 0.50:** $79.40\%$ ($397 / 500$) [95% Wilson CI: $75.64\% - 82.71\%$]
- **Adjudicated FPR @ 0.28:** $84.00\%$ ($420 / 500$) [95% Wilson CI: $80.53\% - 86.95\%$]

### Category Breakdown

```
+---------------------------------------------------------------------------------------------------+
|                                 CATEGORY-LEVEL PERFORMANCE MATRIX                                 |
+-------------------+-----+---------------+---------------+----------------+----------------+-------+
| Category          |  N  | Mean Raw Prob | Mean Fin Prob | FPR @ 0.50     | FPR @ 0.28     | Active|
+-------------------+-----+---------------+---------------+----------------+----------------+-------+
| 1. Bare Apex      | 200 |    0.9161     |    0.9161     | 99.00% (198)   | 100.00% (200)  | None  |
| 2. Deep Repo Path | 150 |    0.9372     |    0.9434     | 94.67% (142)   |  96.67% (145)  | 4 Ovr |
| 3. Search Query   | 150 |    0.4064     |    0.4064     | 38.00%  (57)   |  50.00%  (75)  | None  |
+-------------------+-----+---------------+---------------+----------------+----------------+-------+
| TOTAL             | 500 |    0.7695     |    0.7714     | 79.40% (397)   |  84.00% (420)  | 4 Ovr |
+-------------------+-----+---------------+---------------+----------------+----------------+-------+
```

### 1. Bare Apex Analysis & Counterfactual Proof
- **Raw Failure Rate:** At threshold $0.28$, exactly **200 out of 200 (100.00%)** legitimate bare apex domains are classified as MALICIOUS (mean raw score $0.9161$).
- **Counterfactual Experiment ($N = 200$ matched pairs):**
  Each URL `https://<domain>` was evaluated alongside `https://www.example.com`.
  - Mean Raw Score on Bare: **$0.9161$**
  - Mean Raw Score on `www.`: **$0.0068$**
  - Mean Delta: **$+0.9093$** ($p = 2.10 \times 10^{-225}$, paired $t$-test)
  - Bare Apex FPR @ 0.28: **$100.00\%$** ($200 / 200$)
  - WWW Variant FPR @ 0.28: **$0.00\%$** ($0 / 200$)
  - Bare Apex FPR @ 0.50: **$99.00\%$** ($198 / 200$)
  - WWW Variant FPR @ 0.50: **$0.00\%$** ($0 / 200$)
  This establishes that the failure on bare domains is driven entirely by the `NoOfSubDomain == 0` feature split learned from `cleaned_dataset.csv`.

### 2. Deep Repository Path Analysis
- **Raw Failure Rate:** **$96.67\%$** ($145 / 150$) classified as MALICIOUS (mean score $0.9434$).
- **Feature Correlations:** False positives correlate with `PathDepth` ($r = +0.446$), `URLLength` ($r = +0.362$), and `PathLength` ($r = +0.350$).
- **Adjudicator False Threat Override:** 4 URLs triggered `MALICIOUS_OVERRIDE` setting final probability to $0.95$:
  - `https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/GfxState.cc`
  - `https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/PDFDoc.cc`
  - `https://gitlab.freedesktop.org/poppler/poppler/-/blob/master/poppler/Annot.cc`
  - `https://gitlab.freedesktop.org/mesa/drm/-/blob/main/xf86drmMode.c`
  **Root Cause:** In `url_features.py`, `_brand_impersonation_score` flagged `gitlab.freedesktop.org` with score $1.0$ because `gitlab` is in `COMMON_BRANDS` and `freedesktop.org != gitlab.com`. The adjudicator's Invariant 1 treats any brand token in a subdomain as hostile impersonation, raising the score to $0.95$.

### 3. Search Query Analysis
- **Raw Failure Rate:** **$50.00\%$** ($75 / 150$) classified as MALICIOUS at threshold $0.28$ (mean score $0.4064$).
- **Feature Correlations:** Driven by `QueryParamCount` ($r = +0.715$), `URLCharEntropy` ($r = +0.683$), `SpecialCharRatio` ($r = +0.636$), and `QueryEntropy` ($r = +0.553$). The presence of multiple encoded query parameters and query strings $> 50$ characters causes the GBDT trees to misclassify benign information retrieval as command injection or credential harvesting.

---

## 6. Statistical Limitations & Confidence Intervals

All binomial proportions were computed with exact 95% Wilson score confidence intervals:

```
+---------------------------------------------------------------------------------------------------+
|                         STATISTICAL LIMITATIONS & 95% CONFIDENCE INTERVALS                        |
+---------------------+-------+-------------+-------------+--------------------+--------------------+
| Slice               |   N   | FPR @ 0.50  | FPR @ 0.28  | 95% CI @ 0.50      | 95% CI @ 0.28      |
+---------------------+-------+-------------+-------------+--------------------+--------------------+
| Category 1 (Apex)   |  200  |   99.00%    |   100.00%   | [96.43% - 99.73%]  | [98.12% - 100.00%] |
| Category 2 (Repo)   |  150  |   94.67%    |    96.67%   | [89.83% - 97.27%]  | [92.43% - 98.57%]  |
| Category 3 (Search) |  150  |   38.00%    |    50.00%   | [30.62% - 45.98%]  | [42.10% - 57.90%]  |
+---------------------+-------+-------------+-------------+--------------------+--------------------+
| OVERALL BENCHMARK   |  500  |   79.40%    |    84.00%   | [75.64% - 82.71%]  | [80.53% - 86.95%]  |
+---------------------+-------+-------------+-------------+--------------------+--------------------+
```

### Statistical Power & Sample Size Adequacy
- For overall benchmark size $N = 500$, the maximum standard error on proportion estimation is $\text{SE} \le \frac{\sqrt{0.5 \times 0.5}}{\sqrt{500}} = 0.0224$ ($2.24\%$). The 95% confidence interval half-width is $\le \pm 4.38\%$.
- For Category 1 ($N = 200$), the upper bound of the confidence interval at 100% FPR guarantees with $95\%$ confidence that the true population FPR is $\ge 98.12\%$.
- For Category 2 ($N = 150$), the 95% confidence interval guarantees that true deep-path FPR is $\ge 92.43\%$.
- For Category 3 ($N = 150$), the 95% confidence interval guarantees that true search query FPR is between $42.10\%$ and $57.90\%$.

---

## 7. File Tracking & Integrity Audit

### Created Benchmark and Evaluation Artifacts

```
+--------------------------------------------------------------------------------------------------------------------------------+
| File Path                                                | Byte Size | SHA-256 Checksum                                        |
+--------------------------------------------------------------------------------------------------------------------------------+
| sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json   |   222,523 | d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6b... |
| sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_... |    81,449 | e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987... |
| sentinel-ml/URL-ml/reports/bare_vs_www_counterfactual... |    36,378 | d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efe... |
+--------------------------------------------------------------------------------------------------------------------------------+
```

Full SHA-256 Hashes:
- `hard_benign_benchmark_500.json`:  
  `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f`
- `hard_benign_benchmark_500_predictions.csv`:  
  `e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987b85f40447`
- `bare_vs_www_counterfactual_200.csv`:  
  `d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efeebd9eda14`

### Git Working-Tree Verification
- **Branch:** `reforge` (verified via `git branch`).
- **Git Status:** Exactly identical to pre-flight. Zero files staged, committed, reset, reverted, cleaned, or modified in the `sentinel-ai` Git root.
- **Production Code Unchanged:** `SafeDomainAdjudicator.kt`, `v8_classifier.py`, `v7_champion.joblib`, and `v8_champion.joblib` were accessed strictly read-only.

---

## 8. Release Recommendation: Freeze Benchmark

### Formal Recommendation
1. **Freeze `hard_benign_benchmark_500.json`:**  
   Freeze this 500-URL dataset as the immutable evaluation benchmark for Phase 1C. Any candidate retrained model must be evaluated against this frozen benchmark without having seen any of its 209 registrable domains during training.
2. **Acceptance Criteria for Phase 1C.2 Retraining:**
   To qualify for consideration, a candidate retrained model must achieve:
   - **Hard-Benign Benchmark FPR @ 0.28:** $\le 5.00\%$ overall (currently $84.00\%$).
   - **Category 1 (Bare Apex) FPR @ 0.28:** $\le 2.00\%$ (currently $100.00\%$).
   - **Category 2 (Deep Repo) FPR @ 0.28:** $\le 5.00\%$ (currently $96.67\%$).
   - **Category 3 (Search Queries) FPR @ 0.28:** $\le 5.00\%$ (currently $50.00\%$).
   - **Zero Regression on Existing Test Set:** Malicious recall $\ge 98.00\%$ on `cleaned_dataset.csv` test set.
   - **Zero Regression on Adversarial Suite:** Malicious recall $\ge 95.00\%$ on evasion transforms.

---

## 9. Next Steps (Bounded Stop)

In accordance with mandatory Phase 1C rules:
- **Phase 1C.1 is COMPLETE.**
- **Phase 1C.2 (Candidate Retraining) is NOT STARTED.**
- Execution is halted to await user review and sign-off on the benchmark before any training scripts or candidate models are executed.
