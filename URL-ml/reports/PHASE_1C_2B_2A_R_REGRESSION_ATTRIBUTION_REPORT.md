# Sentinel Phase 1C.2B-2A-R — Bare-Apex Regression Attribution Report

**Date:** 2026-10-20  
**Phase:** 1C.2B-2A-R (Read-Only Forensic Analysis)  
**Status:** **INVESTIGATION COMPLETE — CANDIDATE REMAINS REJECTED**  
**Repository Branch:** `reforge` (Workspace Git Status preserved, 59 tracked entries intact)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified)  
**Forensics Output Directory:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_regression_forensics/`  

---

## 1. Executive Summary & Core Forensic Finding

During the Phase 1C.2B-2A candidate training experiment (Track A: augmenting 15,000 benign bare-apex URLs), benchmark bare-apex false positives were successfully reduced from **100.0% (200/200)** to **4.0% (8/200)**. However, the Track A candidate suffered an unexpected malicious recall drop on the Clean Test Split ($N = 50,511$):
- **Malicious Recall:** Fell from **$98.605\%$ (22,835 / 23,158)** to **$97.405\%$ (22,557 / 23,158)** ($\Delta = -1.200\%$).
- **Regressed Malicious URLs:** Exactly **320 URLs** correctly detected by Control (`ctrl_p >= 0.28`) were newly missed by Candidate (`cand_p < 0.28`), resulting in **278 net missed malicious URLs** (against 42 newly caught).
- **Bare-Apex Recall Regression:** Malicious bare-apex recall plummeted by **$-5.97\%$** (from $98.03\%$ to $92.05\%$).

### The Primary Attribution
Forensic analysis establishes that the baseline V8 model's high recall on bare-apex phishing lures was **spurious**:
1. In `cleaned_dataset.csv`, **0.00%** of benign training URLs possessed zero subdomains (`NoOfSubDomain == 0`). In contrast, thousands of malicious URLs had zero subdomains.
2. The control GBDT ensemble learned to use `NoOfSubDomain <= 0.5` across **242 out of 350 trees** as an aggressive shortcut to push samples into positive malicious leaves.
3. Adding 15,000 benign bare-apex URLs in Track A neutralized this artificial shortcut.
4. Once the shortcut was removed, an underlying **feature representation blind spot** in `v7_features.py` was exposed:
   - For malicious bare-apex domains that have an empty or shallow path and non-flagged TLDs (e.g., `https://itaucardfaturadigital.app`, `https://meinedkb.me/`, `https://hdbankfinance.shop/`), **none of the 67 features extract lexical tokens from the registrable domain**.
   - `PathSuspiciousWords` and `QuerySuspiciousWords` only inspect the URL path and query string (which are empty).
   - `BrandImpersonationScore` only checks 175 major multinational brands (`COMMON_BRANDS`) and fails on unlisted/regional financial brands (`itaucard`, `dkb`, `hdbank`, `amendes`, `cajaspiura`).
   - `Safe_Clean_Domain` actively awards a **1.0** "clean domain" signal to these bare phishing lures.
   - Without the tree-level `NoOfSubDomain` shortcut, their predicted probabilities collapsed from **~0.85–0.99** down to **~0.04–0.14**, causing 272 bare-apex and 48 borderline subdomain lures to cross below the 0.28 threshold.

---

## 2. Quantitative Subgroup Forensic Breakdown

The 320 regressed malicious URLs were partitioned into structural, morphological, and prediction-margin cohorts.

```
Total Regressed Malicious URLs: 320
├── Bare Apex Host (NoOfSubDomain == 0): 272 (85.0%)
│   ├── Empty Path (PathLength <= 1): 250 (91.9%)
│   ├── Non-Empty Path (PathLength > 1): 22 (8.1%)
│   ├── Non-Suspicious TLD (SuspiciousTLD == 0): 271 (99.6%)
│   └── Zero Existing Threat Flags: 250 (91.9%)
└── Subdomain Host (NoOfSubDomain >= 1): 48 (15.0%)
    ├── Single Subdomain (depth == 1): 45 (93.8%) [12 are 'www.']
    └── Multi-level Subdomain (depth >= 2): 3 (6.2%)
```

### 2.1 Host Architecture & Clean Test Denominators

| Test Set Cohort | Total in Test Split | Control Caught | Candidate Caught | Regressed (Missed) | Recall Delta |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **All Malicious Test URLs** | **23,158** | **22,835 (98.61%)** | **22,557 (97.41%)** | **320 (1.38%)** | **-1.20%** |
| ├── **Bare-Apex Malicious** | **4,254** | **4,170 (98.03%)** | **3,916 (92.05%)** | **272 (6.39%)** | **-5.97%** |
| └── **Subdomain Malicious** | **18,904** | **18,665 (98.74%)** | **18,641 (98.61%)** | **48 (0.25%)** | **-0.13%** |

- **Bare-apex lures** represent **85.0%** of all regressions ($272 / 320$).
- In contrast, subdomain malicious URLs showed high stability ($98.74\% \to 98.61\%$, only 48 regressions across nearly 19,000 examples).

### 2.2 Path & Query Morphology (Bare-Apex Cohort, N = 272)
- **Empty Path (`clean_path == ''`, `PathLength <= 1`):** **250 / 272 (91.9%)**
- **Non-Empty Path (`PathLength > 1`):** **22 / 272 (8.1%)**
- **Query Present (`QueryLength > 0`):** **1 / 272 (0.4%)**
- **HTTPS Enabled (`IsHTTPS == 1.0`):** **270 / 272 (99.3%)**

### 2.3 Top TLD Frequencies (Bare-Apex Cohort, N = 272)
The regressed bare-apex phishing lures overwhelmingly rely on standard, widely trusted TLDs:
- `.com`: **189** (69.5%)
- `.net`: **10** (3.7%)
- `.co`: **8** (2.9%)
- `.de`: **7** (2.6%)
- `.life`: **6** (2.2%)
- `.shop`: **4** (1.5%)
- `.cyou`: **4** (1.5%)
- `.au`: **3** (1.1%)
- `.site`: **3** (1.1%)
- `.fr`: **3** (1.1%)
- `.org`: **3** (1.1%)
- `.me`: **2** (0.7%)
- `.br`: **2** (0.7%)
- `.io`: **2** (0.7%)
- `.pro`: **2** (0.7%)

**Crucial Finding:** In `v7_features.py`, `SUSPICIOUS_TLDS` does not contain `.com`, `.net`, `.de`, `.shop`, `.app`, `.me`, `.site`, `.cyou`, or `.live`. As a result, **271 out of 272 (99.6%)** had `SuspiciousTLD == 0.0`.

### 2.4 Prediction Margin Distribution
The collapse in predicted probability was severe, not a marginal boundary effect:

| Probability Range | Count | Percentage | Cumulative |
| :--- | :---: | :---: | :---: |
| `cand_p < 0.05` | 56 | 17.5% | 17.5% |
| `cand_p` [0.05, 0.10) | 86 | 26.9% | 44.4% |
| `cand_p` [0.10, 0.20) | 113 | 35.3% | 79.7% |
| `cand_p` [0.20, 0.28) | 65 | 20.3% | 100.0% |

- **Control Score Aggregates:** Mean = **0.8386**, Median = **0.9539**
- **Candidate Score Aggregates:** Mean = **0.1253**, Median = **0.1124**
- **Mean Score Drop ($\Delta p$):** **+0.7133** (Median: **+0.8403**)
- Over **79.7%** of the regressed lures dropped below `0.20`, with nearly half collapsing below `0.10`.

---

## 3. Four-Cohort Comparative Feature Analysis

To isolate why the Candidate model retained 3,916 malicious bare-apex URLs while losing 272, we compared feature averages across four distinct populations:
1. **Regressed Bare-Apex Malicious ($N = 272$)**
2. **Retained Bare-Apex Malicious ($N = 3,916$)**
3. **Benchmark v1.0 Bare-Apex Benign ($N = 200$)**
4. **Baseline Control Clean Test False Positives ($N = 263$)**

| Feature Name | Regressed Malicious ($N=272$) | Retained Malicious ($N=3,916$) | Benchmark Benign ($N=200$) | Baseline Test FP ($N=263$) | Retained vs Regressed $\Delta$ |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `URLLength` | **25.92** | 75.60 | 18.60 | 34.06 | **+49.69** |
| `PathLength` | **1.08** | 37.50 | 0.00 | 0.00 | **+36.42** |
| `QueryLength` | **0.03** | 14.61 | 0.00 | 0.00 | **+14.58** |
| `PathEntropy` | **0.25** | 3.33 | 0.00 | 0.00 | **+3.08** |
| `PathDepth` | **0.14** | 2.14 | 0.00 | 0.00 | **+2.00** |
| `QueryEntropy` | **0.01** | 0.65 | 0.00 | 0.00 | **+0.64** |
| `URLCharEntropy` | **3.82** | 4.40 | 3.61 | 4.00 | **+0.57** |
| `DomainLength` | **15.79** | 13.41 | 10.60 | 26.06 | **-2.38** |
| `HostEntropy` | **3.38** | 3.10 | 3.01 | 3.65 | **-0.28** |
| `IsHTTPS` | **0.99** | 0.75 | 1.00 | 1.00 | **-0.24** |
| `Safe_Clean_Domain` | **0.9963** | 0.7888 | 1.0000 | 0.4297 | **-0.21** |
| `BrandImpersonationScore` | **0.0000** | 0.1020 | 0.0000 | 0.2071 | **+0.10** |
| `SuspiciousTLD` | **0.0037** | 0.0988 | 0.0000 | 0.0000 | **+0.09** |

### Key Diagnostic Takeaways
1. **Retained Bare-Apex URLs had Strong Path/Query Evidence:** The 3,916 retained malicious bare-apex URLs have average path lengths of 37.5 chars, path depth of 2.14, query length of 14.6 chars, and path entropy of 3.33. They were caught on their rich route structures, not their bare hostnames.
2. **Regressed Malicious URLs Structurally Mimic Benign Apex Domains:** In `regressed_bare_mal`, path length is 1.08, query length is 0.03, and `Safe_Clean_Domain` is 0.9963. They are indistinguishable from legitimate apex domains across all current syntactic features.

---

## 4. Forensic Anatomy of the Regressed Malicious Lures

Inspection of `regressed_malicious_320.csv` confirms these are genuine phishing and credential theft lures:

### 4.1 Sample Forensic Case Studies

1. **`https://itaucardfaturadigital.app`**
   - **Target:** Banco Itaú (Brazil’s largest bank) credit card invoice portal (`itaucard fatura digital`).
   - **Control Probability:** `0.8455` (Caught via `NoOfSubDomain == 0` leaf penalty).
   - **Candidate Probability:** `0.0444` (Raw logit dropped from `+1.70` to `-3.07`).
   - **Feature Failure:** Itaú is not in `COMMON_BRANDS`. `SuspiciousTLD == 0` (`.app` not in list). Path is empty. `Safe_Clean_Domain == 1.0`.
2. **`https://meinedkb.me/` and `https://auth-dkb-online.de/`**
   - **Target:** Deutsche Kreditbank (DKB, Germany).
   - **Control Probability:** `0.9436` and `0.9905`.
   - **Candidate Probability:** `0.0405` and `0.1355`.
   - **Feature Failure:** DKB is not in `COMMON_BRANDS`. Neither `.de` nor `.me` are in `SUSPICIOUS_TLDS`. Path is empty.
3. **`https://hdbankfinance.shop/`**
   - **Target:** HDBank (Vietnam).
   - **Control Probability:** `0.9869` $\to$ **Candidate Probability:** `0.0396`.
   - **Feature Failure:** `hdbank` not in `COMMON_BRANDS`. `.shop` not in `SUSPICIOUS_TLDS`. Path is empty.
4. **`https://amendes-gouvs.com/` and `https://vignette-critair-fr.com/`**
   - **Target:** French government official fine payment (`amendes.gouv.fr`) and vehicle emission certificate (`certificat-air.gouv.fr`).
   - **Control Probability:** `0.9958` and `0.9922` $\to$ **Candidate Probability:** `0.1987` and `0.2566`.
   - **Feature Failure:** Government spoofing keywords (`gouvs`, `vignette-critair`) exist solely in the domain name. Path is empty.
5. **`https://dexstatuschain.com/` and `https://pancake-staking.com/`**
   - **Target:** Decentralized exchange (DEX) / Web3 crypto wallet draining.
   - **Control Probability:** `0.9878` and `0.9944` $\to$ **Candidate Probability:** `0.0432` and `0.1611`.

### 4.2 Domain Lexical Token Analysis
Across the 272 bare-apex regressions, **49 domains (18.0%)** contain explicit financial/credential tokens in the registrable label (`id`, `secure`, `online`, `pay`, `login`, `fatura`, `bank`, `coin`, `auth`, `service`, `verify`, `support`, `card`, `finance`, `alert`), and another **~45%** contain brand or enterprise names not indexed in `COMMON_BRANDS`. 

Because `v7_features.py` **never tokenizes or extracts words from the hostname or registrable domain**, all these signals are invisible to the model.

---

## 5. Architectural Audit of Existing 67 Features

A line-by-line review of `sentinel-ml/URL-ml/scripts/v7_features.py` and `v8_classifier.py` reveals four structural limitations:

### 5.1 Host Lexical Blind Spot
- `SUSPICIOUS_WORDS` (23 keywords including `login`, `verify`, `account`, `banking`, `password`, `token`) is evaluated **only** against `path` (`PathSuspiciousWords`) and `query` (`QuerySuspiciousWords`).
- Not a single feature in `V7_FEATURE_NAMES` evaluates `SUSPICIOUS_WORDS` on the `host` or `parent_domain`.

### 5.2 Brand Impersonation Scope
- `BrandImpersonationScore` evaluates exclusively against `COMMON_BRANDS` (175 multinational tech/finance brands, heavily US-centric).
- Regional banks (e.g., Itaú, DKB, Banrisul, Caixa, Postepay, HDBank) and government services (`amendes`, `mygov`, `critair`) are absent.

### 5.3 Safe_Clean_Domain Inversion
`Safe_Clean_Domain` is defined as:
```python
safe_clean_domain = float(
    susp_tld == 0 and brand_impersonation == 0 and is_ip == 0 and 
    subdomain_depth <= 1 and host_punycode == 0 and has_port == 0 and 
    url_upper_ratio < 0.15 and not has_non_ascii
)
```
Because bare phishing domains have `subdomain_depth == 0` and standard TLDs, **`Safe_Clean_Domain` was assigned 1.0 for 271 of the 272 regressed lures**, effectively penalizing the model from flagging them.

### 5.4 Adjudication Invariant Coupling
In `v8_classifier.py`, the financial safety override (`is_fin`) requires:
```python
is_fin = any(w in reg_domain for w in (...)) and any(w in path_lower for w in (...))
```
Because `is_fin` strictly mandates a keyword in the **path**, empty-path bare apex financial lures (`https://itaucardfaturadigital.app`) fail the invariant check.

---

## 6. GBDT Ensemble Split & Logit Dynamics

Inspection of `HistGradientBoostingClassifier` tree structures between Control and Candidate models:
1. **Tree Splits on `NoOfSubDomain` (Feature 18):**
   - Control Model: Split in **242 / 350 trees**.
   - Candidate Model: Split in **289 / 350 trees**.
2. **Logit Collapse:**
   - In Control, a sample with `NoOfSubDomain == 0`, `PathLength == 0`, and `QueryLength == 0` accumulated substantial positive leaf values simply because benign bare-apex samples did not exist in the training distribution.
   - For `https://itaucardfaturadigital.app`, the raw decision function was **`+1.700`** in Control (`prob = 0.8455`). In Candidate, the decision function dropped to **`-3.068`** (`prob = 0.0444`), representing a net shift of **`-4.77 logits`**.
3. **Prior Shift Effect on Subdomains ($N = 48$):**
   - Adding 15,000 benign URLs increased training benign proportion from $51.11\%$ to $54.70\%$, slightly shifting the base prior downward by ~0.10 logits.
   - For 48 subdomain URLs that were already borderline under Control (`ctrl_p` mean $0.3989$), this slight prior shift combined with tree regularization pulled them below $0.2800$ (`cand_p` mean $0.2097$).

---

## 7. Proposed Unexecuted Experiment Matrix (Phase 1C.2B Planning)

*In accordance with Phase 1C safety rules, these experiments are designed only and remain UNEXECUTED.*

| Experiment ID | Title | Hypothesized Mechanism | Primary Target Metric | Risk / Side-Effects |
| :--- | :--- | :--- | :--- | :--- |
| **Exp-R1** | **Domain-Level Lexical Features** | Add `DomainSuspiciousWords` and `DomainFinancialScore` to inspect registrable labels. | Recover 100+ bare-apex phishing lures (e.g. `itaucard`, `hdbankfinance`). | May increase false positives on benign domain names containing substrings (e.g., `bank`, `pay`). |
| **Exp-R2** | **Balanced Malicious Bare-Apex Augmentation** | Supplement the candidate training set with 3,000–5,000 diverse malicious bare-apex URLs alongside the 15,000 benign URLs. | Restore balanced leaf splits for bare apex without biasing prior. | Requires careful domain-disjoint validation against test split. |
| **Exp-R3** | **Expanded Brand & Entity Dictionary** | Expand `COMMON_BRANDS` from 175 to 500+ global entities (regional banks, gov portals, couriers). | Activate `BrandImpersonationScore` on regional phishing lures. | Dictionary maintenance overhead in Android client. |
| **Exp-R4** | **Adjudication Invariant Decoupling** | Update `is_fin` in adjudication to trigger when domain has high-risk brand/credential tokens even with empty path. | Deterministically catch high-risk bare lures (`auth-dkb`, `faturadigital`). | Adjudication rule complexity; potential false positives on legit financial root domains. |
| **Exp-R5** | **Monotonic Constraints on Host Features** | Constrain `NoOfSubDomain` monotonicity to prevent artificial leaf penalization. | Eliminate GBDT instability on host depth. | May degrade overall tree flexibility. |

---

## 8. Artifact & Data Governance Registry

All forensic data files have been generated and hashed in the isolated experiment directory:

| Filename | Path | Size | SHA-256 Hash |
| :--- | :--- | :---: | :--- |
| `regressed_malicious_320.csv` | `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_regression_forensics/` | 46,994 B | `c4e7017ee5fcd23d7eb43b377294bfd6873235e15cd0878d4cc5eb68701abbd4` |
| `regression_forensics_summary.json` | `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_regression_forensics/` | 3,220 B | `e5dc0dc9f0271c190642dbb7ee07a820bda7f501377d6cef3b134038c1ba76a6` |
| `cohort_feature_comparison.json` | `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_regression_forensics/` | 4,828 B | `61baa2b93fe38072056a4c996cd90f02f528e9a03b77d9acfed3afd3fe6b7bc7` |

### Safety Verification
- **Track A Candidate Status:** Formally **REJECTED**. Not promoted to champion.
- **Benchmark v1.0:** Frozen, unaltered, and not used for model selection.
- **Production Files:** Preserved with zero edits.
- **Git Status:** Clean, 59 pre-existing entries preserved bit-for-bit.
- **Champion V8 Hash:** Verified as `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`.
