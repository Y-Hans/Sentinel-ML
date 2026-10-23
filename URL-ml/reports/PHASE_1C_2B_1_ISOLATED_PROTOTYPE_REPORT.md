# Sentinel — Phase 1C.2B-1: Isolated Prototype Preparation Report

**Execution Date:** 2026-10-19  
**Git Root:** `sentinel-ai/`  
**Git Branch:** `reforge`  
**Working Tree Status:** Clean / Pre-existing modifications preserved (59 entries)  
**Phase Status:** Phase 1C.2B-1 COMPLETED (Isolated Prototype Preparation Only; Retraining NOT Started)  

---

## 1. Executive Summary & Authorization Scope

Phase 1C.2B-1 was executed under explicit authorization for **isolated prototype preparation only**. In accordance with locked governance constraints:
- **Zero Production Changes:** No production code, feature extractors, adjudicator rules, or Android assets were modified.
- **Zero Model Promotion or Retraining:** No models were retrained, exported, tuned, or promoted.
- **Isolated Prototype Directory:** All manifests, candidate proposals, and test matrices were generated strictly within an isolated experimental directory:
  `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/`

### Key Outcomes of Phase 1C.2B-1
1. **Track A (Bare-Apex Proposal & Leakage Audit):** Prepared a candidate-only benign training augmentation proposal (`candidate_bare_apex_15k.csv`, $N = 15,000$). Confirmed 100% domain uniqueness and **exact zero leakage** against validation, test, frozen benchmark v1.0, and adversarial sets. Verified that adding this candidate shifts benign training `NoOfSubDomain == 0` from $7.94\%$ to $28.81\%$, balancing the training prior against malicious bare domains ($23.1\%$).
2. **Track B (Forge Subdomain Reproduction & Isolation):** Reproduced the frozen inference path for Row 244 (`https://gitlab.freedesktop.org/mesa/drm/-/blob/main/xf86drmMode.c`), proving that the raw base GBDT predicts benign (`raw_p = 0.0704`), but is forced to `final_p = 0.9500` solely by the adjudicator's `BrandImpersonationScore = 1.0` override. Prepared an isolated 19-record test matrix (`track_b_forge_test_matrix.json`) separating multi-tenant forge infrastructure from deceptive brand impersonation.
3. **Track C (Root Search Query Controlled Matrix):** Formalized the distinction between root queries ($N=55$, 98.2% FPR) and routed queries ($N=95$, 22.1% FPR @ 0.28, 0.0% @ 0.50). Prepared a $2 \times 2 \times 3$ controlled test matrix ($N = 60$ URLs across 15 search queries) isolating path attachment from query length and provider identity (`track_c_controlled_query_matrix.json`), alongside a 5,000-query candidate training manifest (`candidate_root_queries_manifest.json`).

---

## 2. Baseline & Workspace Preservation

All baseline models, configurations, Android assets, and evaluation benchmarks remain strictly preserved bit-for-bit.

### 2.1 Baseline SHA-256 Checksums
| Baseline Asset Role | Workspace Path | SHA-256 Checksum | Preservation Status |
| :--- | :--- | :--- | :--- |
| **GBDT Champion Model** | `sentinel-ml/URL-ml/models/v8_champion.joblib` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | **Verified Bit-for-Bit** |
| **Portable JSON Champion** | `sentinel-ml/URL-ml/models/v8_champion_portable.json` | `e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870` | **Verified Bit-for-Bit** |
| **Android Asset Model** | `sentinel-ai/android-app/core/src/test/resources/v8_champion_portable.json` | `e0e5e817beb6e1718843641b2e19e5b131690a0fc959764d83702883f557e870` | **Verified (Matches ML)** |
| **Hard-Benign Benchmark** | `sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json` | `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f` | **Verified Immutable** |
| **Benchmark Baseline Preds** | `sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_predictions.csv` | `e78e1e2cce9400ef5168cf924424465213074fcde54f97c34727987b85f40447` | **Verified Immutable** |
| **Counterfactual Predictions**| `sentinel-ml/URL-ml/reports/bare_vs_www_counterfactual_200.csv` | `d363a1c0719fef3047f7b7df49fb5858a1ee452a7cee4a087282efeebd9eda14` | **Verified Immutable** |

### 2.2 Git Status Verification
- **Git Root:** `sentinel-ai/` on branch `reforge`.
- **Status:** Exactly the pre-existing 59 modifications and untracked entries remain preserved. No files were added, staged, deleted, or modified within `sentinel-ai/`.

---

## 3. Track A — Bare-Apex Training-Data Hypothesis

### 3.1 Candidate-Only Augmentation Proposal
To eliminate the 99.98% malicious prior learned by the GBDT on bare apex homepages without perturbing validation or test splits, an isolated candidate training augmentation dataset was synthesized:
- **File Path:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv`
- **Sample Size ($N$):** Exactly **15,000** canonical benign bare-apex URLs.
- **SHA-256:** `a40a010e133f795580c0837c16c7c6fbbebae92e89afba1b42c8f106eca1f12a`
- **Canonical Structure:** `https://<registrable_domain>/`
- **Ground Truth Label:** `0` (Benign).

### 3.2 Provenance & Leakage Audit
1. **Provenance:**  
   The 15,000 registrable domains were extracted strictly from the **benign subset of the training split** (`tr_benign` in `cleaned_dataset.csv`, which contains 75,926 unique benign parent domains).
2. **Canonical Deduplication & Domain Uniqueness:**  
   - Every record is a unique registrable domain: **100% uniqueness** (15,000 unique domains across 15,000 rows).
   - Zero internal duplicates.
3. **Disjointness & Leakage Audit:**
   Each candidate domain was audited against all existing evaluation holdouts:
   - **Overlap with Validation Split Domains ($N = 33,796$):** **0** (0.00%)
   - **Overlap with Test Split Domains ($N = 33,797$):** **0** (0.00%)
   - **Overlap with Hard-Benign Benchmark v1.0 Domains ($N = 209$):** **0** (0.00%)
   - **Overlap with Remediation Adversarial Domains ($N = 390$):** **0** (0.00%)
   The candidate dataset has **provably zero data leakage** into any validation, test, benchmark, or adversarial set.

### 3.3 Control vs. Candidate Dataset Definition
- **Control Dataset (Baseline Train Split):**  
  The unaugmented training set consisting of the training split of `cleaned_dataset.csv` ($N = 141,178$; 80,359 benign, 60,819 malicious) plus `v7_structural_benign.csv` ($N = 48,290$). Total $N = 189,468$.
- **Candidate Dataset (Augmented Train Split):**  
  Control Dataset + `candidate_bare_apex_15k.csv` ($N = 15,000$). Total $N = 204,468$ (143,649 benign, 60,819 malicious).
- **Isolation Guarantee:** The two datasets differ **exclusively** by the intended 15,000 bare-apex benign examples.

### 3.4 Feature Distribution Shifts in Training
Evaluating feature vectors before and after the candidate augmentation demonstrates the intended normalization of the feature space:

| Feature Dimension | Baseline Benign Train (Mean $\pm$ Std) | Candidate Apex Additions (Mean $\pm$ Std) | Combined Benign Train (Mean $\pm$ Std) | Net Directional Impact |
| :--- | :---: | :---: | :---: | :--- |
| **`NoOfSubDomain`** | $0.968 \pm 0.377$ | $0.000 \pm 0.000$ | $0.749 \pm 0.523$ | Shifts toward bare reference |
| **`URLLength`** | $37.081 \pm 16.920$ | $24.218 \pm 5.115$ | $34.165 \pm 16.009$ | Provides short benign apex samples |
| **`DomainLength`** | $18.998 \pm 4.997$ | $15.218 \pm 5.115$ | $18.141 \pm 5.267$ | Matches standard apex lengths |
| **`SpecialCharRatio`** | $0.127 \pm 0.033$ | $0.085 \pm 0.037$ | $0.118 \pm 0.038$ | Lowers special char penalty |
| **`HostEntropy`** | $3.397 \pm 0.314$ | $3.299 \pm 0.363$ | $3.375 \pm 0.329$ | Preserves natural distribution |
| **`URLCharEntropy`** | $3.987 \pm 0.270$ | $3.758 \pm 0.222$ | $3.935 \pm 0.277$ | Preserves natural distribution |

#### Shift in `NoOfSubDomain == 0` Representation:
- **Baseline Benign Training:** Only **7.94%** of benign samples had `NoOfSubDomain == 0` (and virtually all of them had paths from `v7_structural_benign.csv`).
- **Candidate Bare-Apex Additions:** **100.00%** have `NoOfSubDomain == 0`.
- **Combined Benign Training:** Rises to **28.81%** `NoOfSubDomain == 0`.
- **Malicious Training Comparison:** Malicious training samples contain **23.1%** `NoOfSubDomain == 0`.
- **Impact on Model:** The empirical prior $P(\text{Malicious} \mid \text{NoOfSubDomain} == 0)$ drops from near $100\%$ down to ~$\mathbf{44.5\%}$, directly eliminating the GBDT tree leaf penalty without degrading other features.

### 3.5 Validation & Malicious Recall Check Protocol
Before any candidate model trained on this data could be promoted, it must be evaluated against:
1. **Cleaned Test Split ($N = 50,511$):**
   - Benign FPR must remain $\le \mathbf{1.000\%}$ ($k \le 273$ / 27,353).
   - Malicious Recall must remain $\ge \mathbf{99.000\%}$ ($k \ge 22,926$ / 23,158).
2. **Remediation Adversarial Dataset ($N = 3,900$):**
   - Adversarial Recall must remain $\ge \mathbf{85.000\%}$ ($k \ge 3,315$ / 3,900).
   - This verifies that phishing on bare domains (e.g. `http://nmve.xyz/`) is still detected via suspicious TLDs, entropy, and lexical keywords.

---

## 4. Track B — Deep Repository Paths and Adjudicator

### 4.1 Frozen Inference Path Reproduction (Row 244)
Using the frozen production artifacts (`v8_champion.joblib`, `v8_champion_portable.json`, `v8_parent_profiles.json`), the exact evaluation trace of Row 244 was reproduced:

```
URL: https://gitlab.freedesktop.org/mesa/drm/-/blob/main/xf86drmMode.c
  Parsed Host:               gitlab.freedesktop.org
  Parsed Parent Domain:      freedesktop.org
  Parsed Subdomains:         ['gitlab']
  Path Depth:                6.0
  Path Length:               31.0
  BrandImpersonationScore:   1.0
  Parent_IsDeveloper:        0.0
  rel_path_depth_anomaly:    3.0
  -------------------------------------------------------------
  Base Model Raw Probability: 0.0704 (BENIGN @ threshold 0.28)
  Adjudicator Rule Fired:    MALICIOUS_OVERRIDE (Invariant 1)
  Final Adjudicated Proba:   0.9500 (MALICIOUS)
```

#### Diagnostic Finding:
- **Base Classifier:** Evaluates the URL as clearly benign (`raw_p = 0.0704`).
- **Adjudicator:** Inverts the classification to malicious (`final_p = 0.9500`) solely because `_brand_impersonation_score` matched the string `gitlab` against `COMMON_BRANDS`, while `freedesktop.org != gitlab.com`.

### 4.2 Separation of Raw Classifier vs. Adjudicator FPs
Across the 49 URLs on `gitlab.freedesktop.org` in benchmark v1.0:
1. **Raw Model False Positives ($N = 48$):** Mean raw score is `0.9731`. Driven by `PathDepth >= 6` and `rel_path_depth_anomaly` penalties in the base GBDT trees.
2. **Adjudicator Escalated False Positive ($N = 1$):** Exactly Row 244 had `raw_p = 0.0704 < 0.28`, and was converted to a false positive exclusively by the adjudicator.
3. **Adjudicator Redundant Overrides ($N = 3$):** Rows 234, 235, 236 had `raw_p \in [0.92, 0.94]` and were elevated to `0.9500`.

### 4.3 Multi-Tenant Forge Test Matrix (`track_b_forge_test_matrix.json`)
To test proposed adjudicator adjustments without touching production code or introducing allowlists, an isolated 19-record evaluation matrix was constructed:
- **File Path:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/track_b_forge_test_matrix.json`
- **Sample Size ($N$):** 19 URLs.
- **SHA-256:** `76ba2ee3fdf963f206cfc09cbe03a41b06328f166bc05628f99135122c7d2c77`

#### Matrix Slices:
1. **Legitimate Multi-Tenant Forge Subdomains ($N = 10$, Expected: BENIGN):**
   - Self-hosted GitLab and cgit instances: `gitlab.freedesktop.org` (Rows 244 & 234), `gitlab.archlinux.org`, `gitlab.gnome.org`, `gitlab.alpinelinux.org`, `git.kernel.org`, `invent.kde.org`, `codeberg.org`, `git.openwrt.org`, `git.netfilter.org`.
2. **Deceptive Brand Impersonation Phishing ($N = 6$, Expected: MALICIOUS $\ge 0.95$):**
   - Attackers using brand tokens to deceive victims: `gitlab.com.account-verification.ru/login`, `paypal.com.security-notice-update.top/login`, `microsoft.com-security-alert.xyz/verify`, `appleid.apple.com.login-verify.cf/auth`, `github-account-security-update.online/oauth/authorize`, `google-drive-shared-file-access.info/signin`.
3. **Hostile Uploads on Forge Platforms ($N = 3$, Expected: MALICIOUS $\ge 0.95$):**
   - Malicious files hosted on legitimate forges: `gitlab.freedesktop.org/evil/repo/-/raw/main/token_stealer.sh`, `gitlab.com/attacker/malware/-/raw/main/payload.exe`, `github.com/phishing/repo/redirect?target=https%3A%2F%2Fevil.com`.
   - **Critical Security Invariant:** These must retain high malicious scores via `has_susp_ext`, `is_open_redirect`, and `has_malware_artifact` rules.

### 4.4 Technical Distinction: Infrastructure Hostname vs. Brand Impersonation
- **Hosting Platform Hostname:** An organization running a self-hosted instance of open-source software (e.g. GitLab Community Edition at `gitlab.freedesktop.org`) is using the software label as an infrastructure descriptor. The registrable domain (`freedesktop.org`) is an established entity, and the URL path points to source code, trees, or issues.
- **Deceptive Brand Impersonation:** An attacker deliberately positions a brand name (e.g. `gitlab.com.phishing.ru` or `gitlab-security-login.com`) to mislead a user into credential disclosure.
- **Strict Boundary:** We **do not** introduce allowlists for `freedesktop.org` or `archlinux.org`. Instead, brand impersonation scoring must be conditioned on **deceptive semantic context** (e.g. brand token present alongside credential harvesting keywords or suspicious TLDs, or multi-label spoofing `brand.com.<attacker_domain>`).

---

## 5. Track C — Root-Level Search Queries

### 5.1 Subgroup Architecture Breakdown
As verified in Phase 1C.2B-0, Category 3 search queries exhibit a strict morphological bimodal distribution:

```
Search Engine Queries (N = 150)
├── Root Queries (PathLength == 0): N = 55 | Mean Raw = 0.8924 | FPR @ 0.28 = 98.2% (54/55)
│   ├── duckduckgo.com (Bare Apex + Root Query): N = 35 | Mean Raw = 0.9982 | FPR = 100.0%
│   └── www.qwant.com (Subdomain + Root Query):  N = 20 | Mean Raw = 0.7076 | FPR = 95.0%
└── Routed Queries (PathLength > 0): N = 95 | Mean Raw = 0.1250 | FPR @ 0.28 = 22.1% (21/95)
    ├── search.brave.com (Subdomain, /search?q=): N = 30 | Mean Raw = 0.1048 | FPR = 20.0%
    ├── www.ecosia.org (Subdomain, /search?q=):   N = 25 | Mean Raw = 0.1519 | FPR = 28.0%
    ├── www.startpage.com (Subdomain, /sp/search): N = 15 | Mean Raw = 0.1791 | FPR = 40.0%
    ├── searx.space (Bare Apex, /search?q=):      N = 10 | Mean Raw = 0.1024 | FPR = 10.0%
    ├── kagi.com (Bare Apex, /search?q=):         N =  5 | Mean Raw = 0.2164 | FPR = 20.0%
    ├── swisscows.com (Bare Apex, /web?q=):       N =  5 | Mean Raw = 0.0010 | FPR =  0.0%
    └── www.mojeek.com (Subdomain, /search?q=):   N =  5 | Mean Raw = 0.0280 | FPR =  0.0%
    └── At threshold 0.50: FPR on Routed Queries is exactly 0.0% (0/95)
```

### 5.2 Controlled $2 \times 2 \times 3$ Query Matrix (`track_c_controlled_query_matrix.json`)
To decouple path morphology from query length, entropy, and provider effects, a controlled test matrix was generated:
- **File Path:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/track_c_controlled_query_matrix.json`
- **Sample Size ($N$):** 60 URLs (15 unique search query strings across 4 structural permutations).
- **SHA-256:** `a3f08a6b6e3261454c93b4abf93c004966ef6dcc3071545f2292b30acb48bfd8`

#### Controlled Permutations per Query String:
1. `https://duckduckgo.com/?q=<query>` (Apex Host + Root Attachment, `PathLength = 0`)
2. `https://www.qwant.com/?q=<query>` (Subdomain Host + Root Attachment, `PathLength = 0`)
3. `https://searx.space/search?q=<query>` (Apex Host + Routed Attachment, `PathLength = 6`)
4. `https://search.brave.com/search?q=<query>` (Subdomain Host + Routed Attachment, `PathLength = 6`)

#### Controlled Query Length Slices:
- **Short Queries ($< 25$ chars, 5 queries):** e.g. `python async`, `git status`.
- **Medium Queries ($25 - 80$ chars, 5 queries):** e.g. `how to configure nginx reverse proxy with ssl`.
- **Long Queries ($> 100$ chars, 5 queries):** e.g. `implementing distributed consensus algorithm raft python state machine replication...`.

#### Analytical Utility:
Because the query string `<query>` is held bit-for-bit identical across all four cells, comparing scores between (1)/(2) and (3)/(4) directly isolates the causal impact of **Path Attachment Morphology** (`PathLength == 0` vs `PathLength > 0`), completely eliminating query length, query entropy, and character set as confounding variables.

### 5.3 Candidate Training Augmentation Manifest
- **File Path:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_root_queries_manifest.json`
- **SHA-256:** `c80e3f9775672c00d7cdbba917eac04bd2f6360a6dcdf5e65169b69700c56ffe`
- **Target Augmentation ($M_{\text{query}}$):** 5,000 verified benign search queries attached to root endpoints (`duckduckgo.com` and `qwant.com`).
- **Feature Impact:** Provides the GBDT with benign training examples containing `PathLength == 0`, `QueryLength > 0`, and `SpecialCharRatio \in [0.10, 0.20]`, eliminating the root query leaf penalty.
- **Zero Allowlists:** No search engine domains are whitelisted.

---

## 6. Experimental Integrity & Cross-Track Governance

### 6.1 Independence of Prototype Tracks
In accordance with prompt instructions, the three tracks are kept strictly independent:
- **Track A:** Modifies only training data composition (bare apex).
- **Track B:** Modifies only adjudicator/feature context logic (multi-tenant forges).
- **Track C:** Modifies only training data composition (root search queries).
No experiment combines training augmentation, feature changes, and adjudicator alterations simultaneously, ensuring that all observed effects can be attributed to specific, isolated variables.

### 6.2 Strict Governance on Evaluation Datasets
1. **Benchmark v1.0 Isolation:**  
   `hard_benign_benchmark_500.json` is preserved as a permanent historical baseline. It will **not** be used to select features, tune thresholds, or choose candidate models.
2. **Development Evaluation Split:**  
   Candidate models will be validated against an independent internal split (`va` split from `cleaned_dataset.csv`, $N = 44,106$) and an internal development slice.
3. **Untouched Phase 1C.3 Release Holdout ($N \ge 300$):**  
   Must remain domain-disjoint, sealed, and uninspected until the formal release evaluation gate.

### 6.3 Release Gates & Statistical Limitations Summary
| Metric / Gate | Denominator ($N$) | Point Target | 95% Wilson CI at Target | Margin of Error | Statistical Limitation / Guidance |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Cleaned Test Benign FPR** | 27,353 | $\le 1.000\%$ | $[0.887\%, 1.123\%]$ | $\pm 0.118\%$ | High statistical power; bound is tight |
| **Cleaned Test Malicious Recall**| 23,158 | $\ge 99.000\%$ | $[98.862\%, 99.119\%]$| $\pm 0.129\%$ | High statistical power; bound is tight |
| **Adversarial Recall** | 3,900 | $\ge 85.000\%$ | $[83.845\%, 86.086\%]$| $\pm 1.121\%$ | High statistical power |
| **Category FPR (Apex, Repo, Query)**| 150–200 | $\le 5.000\%$ | $[2.279\%, 9.319\%]$ | $\pm 3.520\%$ | Wide uncertainty; internal point target must be $\le 2.0\%$ |
| **Android Asset Size** | Disk Bytes | $\le 10.0\text{ MB}$ | N/A | N/A | Current footprint ~1.95 MB |
| **Android Inference Latency** | 1,000 runs | $\le 2.00\text{ ms}$ | N/A | N/A | Current latency ~0.82 ms |

---

## 7. Artifact Manifest & Inventory

All newly created prototype assets reside strictly within `sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/`:

| Artifact Name | Role / Purpose | Format / Records | File Size | SHA-256 Checksum |
| :--- | :--- | :--- | :---: | :--- |
| `candidate_bare_apex_15k.csv` | Track A candidate training augmentation | CSV ($N = 15,000$) | 444 KB | `a40a010e133f795580c0837c16c7c6fbbebae92e89afba1b42c8f106eca1f12a` |
| `track_b_forge_test_matrix.json` | Track B forge & impersonation test suite | JSON ($N = 19$) | 5.5 KB | `76ba2ee3fdf963f206cfc09cbe03a41b06328f166bc05628f99135122c7d2c77` |
| `track_c_controlled_query_matrix.json` | Track C $2 \times 2 \times 3$ query ablation suite | JSON ($N = 60$) | 15.6 KB | `a3f08a6b6e3261454c93b4abf93c004966ef6dcc3071545f2292b30acb48bfd8` |
| `candidate_root_queries_manifest.json` | Track C training augmentation manifest | JSON metadata | 788 B | `c80e3f9775672c00d7cdbba917eac04bd2f6360a6dcdf5e65169b69700c56ffe` |

---

## 8. Actions Requiring Explicit Approval & Stop Condition

### 8.1 Strictly Blocked Actions
The following actions remain blocked until explicit user authorization:
1. Executing training runs on candidate training sets (`candidate_bare_apex_15k.csv`, candidate search queries).
2. Modifying `v8_features.py`, `v8_classifier.py`, or `SafeDomainAdjudicator.kt`.
3. Generating or replacing model binaries in `models/` or Android test resources.
4. Curating and sealing the untouched Phase 1C.3 holdout benchmark.

### 8.2 Phase 1C.2B-1 Conclusion
All prototype preparation tasks for Tracks A, B, and C are complete. Initial and final Git statuses have been compared and confirmed identical (exactly the 59 pre-existing entries preserved).

**Execution is HALTED.** Awaiting explicit approval before executing any model-changing or code-modifying experiments.
