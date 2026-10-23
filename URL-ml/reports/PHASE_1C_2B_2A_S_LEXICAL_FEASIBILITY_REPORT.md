# Sentinel Phase 1C.2B-2A-S — Lexical Signal Feasibility Study

**Date:** 2026-10-20  
**Phase:** 1C.2B-2A-S (Read-Only Signal Feasibility Study & Experiment Design)  
**Status:** **FEASIBILITY STUDY COMPLETE — EXPERIMENTS UNEXECUTED — TRACK A REMAINS REJECTED**  
**Repository Branch:** `reforge` (Workspace Git Status preserved, 59 tracked entries intact)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified)  
**Forensics Directory:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_lexical_feasibility/`  

---

## 1. Executive Summary & Core Feasibility Verdict

Phase 1C.2B-2A-S evaluated whether existing or expanded registrable-domain lexical features can reliably recover the **272 regressed bare-apex malicious URLs** without causing false-positive regressions on legitimate bare-apex domains.

### The Primary Feasibility Verdict
> **Direct lexical keyword matching on the registrable domain is INFEASIBLE as a standalone solution for the 272 bare-apex regressions.**

1. **Low Coverage on Phishing Lures:** Only **14.0%** (38/272) of the regressed bare-apex lures contain common financial or auth keywords (`login`, `secure`, `bank`, `pay`, `fatura`, `verify`). Over **80%** of regressed lures belong to other archetypes: unlisted regional entities (`dkb`, `hdbank`, `amendes`, `cajaspiura`), compromised websites (`wealdgymnastics.com`), or algorithmic/typo domains (`sbjbsank.com`, `inzizi.com`).
2. **High Benign Collision Rate:** Common financial and platform tokens appear in **1.66%** (249 / 15,000) of legitimate, independently verified bare-apex domains (e.g., `southbankmosaics.com`, `cardiff.ac.uk`, `expressscripts.com`, `nowsecure.com`, `fairbanksmuseum.org`).
3. **Severe Precision/Recall Asymmetry:** Simple lexical decision rules catch at most **4.0% to 9.6%** of regressed lures while generating **12 to 110 false positives per 15,000 clean domains** (a false-positive multiplier of $1.5\times$ to $5\times$ over baseline tolerances).
4. **Viable Architectural Direction:** Recovery of bare-apex malicious detection cannot rely on naive keyword rules. Instead, it requires:
   - **Entity/Brand Dictionary Expansion** targeting specific institutional domains (Rank 1).
   - **Balanced Malicious Bare-Apex Training Augmentation** to restore natural GBDT leaf partitions without distorting class priors (Rank 2).

---

## 2. Feature Coverage Audit: The Existing 67-Feature Engine

We performed a line-by-line audit of `sentinel-ml/URL-ml/scripts/v7_features.py` and `v8_classifier.py`.

### 2.1 Verification of Feature Blind Spot
- **Verified Claim:** **Zero features in `V7_FEATURE_NAMES` tokenize, split, or extract lexical words from the registrable domain.**
- `SUSPICIOUS_WORDS` (23 keywords including `login`, `signin`, `verify`, `account`, `banking`, `password`, `token`) is evaluated **strictly** in:
  - Line 60: `path_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in path_lower or w in path_compact))`
  - Line 74: `query_susp_words = float(sum(1 for w in SUSPICIOUS_WORDS if w in query_lower or w in query_compact))`
- It is **never** evaluated on `host`, `parent_domain`, or `reg_label`.

### 2.2 Taxonomy of Existing Host/Domain Features
Of the 67 features in V8, exactly 15 inspect the host or domain name:

| Feature Name | Feature Type | What It Actually Encodes | Direct Lexical Word Tokenization? |
| :--- | :--- | :--- | :---: |
| `DomainLength` | Morphological | Total characters in `host` (`len(host)`) | **NO** (Length only) |
| `NoOfSubDomain` | Structural | Count of subdomain labels (`_subdomain_depth`) | **NO** (Count only) |
| `HostEntropy` | Statistical | Shannon character entropy of `host` | **NO** (Entropy only) |
| `HostDigitRatio` | Statistical | Ratio of digits `0-9` in `host` | **NO** (Numeric ratio) |
| `HostHyphenCount` | Morphological | Total `-` occurrences in `host` | **NO** (Punctuation count) |
| `HostUnderscoreCount` | Morphological | Total `_` occurrences in `host` | **NO** (Punctuation count) |
| `HostPunycode` | Flag | Presence of `xn--` in `host` | **NO** (Encoding flag) |
| `HostHexPattern` | Flag | 8+ consecutive hex characters | **NO** (Pattern flag) |
| `HostVowelRatio` | Statistical | Ratio of `aeiou` in alphabetic host characters | **NO** (Letter ratio) |
| `HostNumericLabels` | Structural | Count of all-digit labels in `host` | **NO** (Structural count) |
| `IsDomainIP` / `IsIPv4` | Flag | Valid IPv4/IPv6 address detection | **NO** (IP syntax) |
| `SuspiciousTLD` | Lookup | TLD match in `SUSPICIOUS_TLDS` (36 TLDs) | **NO** (TLD suffix only) |
| `KnownBrandDomain` | Lookup | Host label exactly in `COMMON_BRANDS` (175 brands) | **NO** (Exact match only) |
| `BrandImpersonationScore` | Fuzzy Match | Substring/edit distance against `COMMON_BRANDS` | **PARTIAL** (175 brands only; ignores non-brands) |
| `Safe_Clean_Domain` | Composite Rule | Negative indicator if TLD clean, brand imp = 0, depth $\le 1$ | **NO** (Syntactic negation) |

### 2.3 Direct Lexical vs Indirect Proxies
- **Direct Lexical Coverage:** Does **not exist** for domain names. The only lexical dictionary in the host extractor is `COMMON_BRANDS` (175 major international brand names).
- **Indirect Proxies:** The baseline model relied entirely on `NoOfSubDomain == 0` as a proxy for malicious apex domains. When Track A neutralized that proxy, no other feature could capture the semantic intent of the domain name.
- **The Inversion Trap:** Because bare-apex phishing lures have `subdomain_depth == 0` and standard TLDs (`.com`, `.net`, `.de`), `Safe_Clean_Domain` evaluates to **1.0** on **271 out of 272 (99.6%)** of the regressed lures, actively suppressing their risk score.

---

## 3. Five-Cohort Empirical Lexical Comparison

To evaluate signal distribution, we extracted domain label properties across five distinct cohorts:
1. **Cohort 1:** Regressed Malicious Bare Apex ($N = 272$)
2. **Cohort 2:** Retained Malicious Bare Apex ($N = 3,916$)
3. **Cohort 3:** Frozen Benchmark Benign Bare Apex ($N = 200$)
4. **Cohort 4:** Baseline Clean-Test Benign False Positives ($N = 263$)
5. **Cohort 5:** Independent Benign Bare Apex (`candidate_bare_apex_15k.csv`, $N = 15,000$)

### 3.1 Quantitative Cohort Lexical Metrics

| Metric / Feature | Regressed Malicious ($N=272$) | Retained Malicious ($N=3,916$) | Benchmark Benign ($N=200$) | Baseline Test FP ($N=263$) | Independent Benign ($N=15,000$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Mean Label Length** | **11.72** | 9.48 | 6.88 | 13.05 | 11.02 |
| **Median Label Length** | **11.0** | 9.0 | 6.0 | 12.0 | 10.0 |
| **Has Hyphen (`-`)** | **25.74%** (70) | 22.11% (866) | 3.50% (7) | 38.78% (102) | 7.74% (1,161) |
| **Has Digit (`0-9`)** | **2.94%** (8) | 13.00% (509) | 0.50% (1) | 20.15% (53) | 2.72% (408) |
| **V7 Suspicious Word in Domain** | **5.88%** (16) | 1.12% (44) | 0.50% (1) | 0.38% (1) | 0.24% (36) |
| **Extended Phish Keyword in Domain** | **13.97%** (38) | 5.06% (198) | 1.50% (3) | 3.04% (8) | 1.66% (249) |
| **High-Precision Credential Token** | **4.78%** (13) | 0.72% (28) | 0.50% (1) | 0.00% (0) | 0.09% (13) |
| **Common Brand Token in Domain** | **1.47%** (4) | 9.93% (389) | 1.00% (2) | 5.70% (15) | 0.46% (69) |

### 3.2 Top Detected Keywords by Cohort
- **Regressed Malicious ($N = 272$):** `secure` (8), `login` (5), `fatura` (4), `bank` (4), `coin` (3), `auth` (2), `delivery` (2), `service` (2), `office` (2), `verify` (2).
- **Retained Malicious ($N = 3,916$):** `express` (27), `service` (22), `support` (14), `auth` (13), `fatura` (12), `bank` (10), `secure` (9), `access` (8), `update` (7), `security` (7).
- **Independent Benign ($N = 15,000$):** `bank` (35), `card` (22), `express` (20), `coin` (15), `service` (14), `portal` (12), `office` (12), `invest` (11), `fund` (10), `security` (10).

### 3.3 Overlap Limitations & Denominator Rigor
- The presence of `bank` in 35 benign domains (`southbankmosaics.com`, `burbankhousing.org`, `redbanknj.org`, `outerbanks.org`) confirms that single-token substring matching has an inherent benign false-positive floor of ~0.25%–0.50%.
- Conversely, `Regressed Malicious` exhibits 25.74% hyphenation (vs 7.74% in benign), reflecting phishing compound naming patterns (e.g. `auth-dkb-online.de`, `vignette-critair-fr.com`, `pancake-staking.com`).

---

## 4. Feasibility Testing of Decision Rules (Without Training)

We evaluated five candidate deterministic lexical decision rules against the 272 regressed malicious lures and 15,000 independent benign bare-apex domains.

| Rule ID | Rule Logic / Description | Malicious Detected (TP / 272) | Malicious Recall | Benign False Positives (FP / 15k) | Benign 15k FPR | Benchmark v1.0 FP (/200) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Rule L1** | Exact V7 `SUSPICIOUS_WORDS` in domain label | 16 / 272 | **5.88%** | 36 / 15,000 | **0.240%** | 1 / 200 (0.5%) |
| **Rule L2** | High-precision credential tokens (`login`, `verify`, `fatura`, `banking`, `checkout`) | 11 / 272 | **4.04%** | 12 / 15,000 | **0.080%** | 1 / 200 (0.5%) |
| **Rule L3** | Broad financial + auth keywords (`bank`, `pay`, `auth`, `secure`, `fatura`, `coin`) | 26 / 272 | **9.56%** | 110 / 15,000 | **0.733%** | 2 / 200 (1.0%) |
| **Rule L4** | Compound Rule: Broad financial token **AND** (has hyphen OR length $\ge 14$) | 19 / 272 | **6.99%** | 51 / 15,000 | **0.340%** | 1 / 200 (0.5%) |
| **Rule L5** | Extended brand token match (`COMMON_BRANDS` + 8 regional targets) | 16 / 272 | **5.88%** | 69 / 15,000 | **0.460%** | 2 / 200 (1.0%) |

### Concrete Examples of Benign Collisions
- **Rule L1/L2 Collisions:** `verificationhandbook.com`, `nowsecure.com`, `accounts4tutorials.com`, `ubiqsecurity.com`, `islamic-banking.com`, `manycontacts.com`.
- **Rule L3/L4 Collisions:** `southbankmosaics.com`, `cryptocompare.com`, `matthieuricard.org` (`card`), `cutbankpioneerpress.com`, `thefederalsavingsbank.com`.
- **Rule L5 Collisions:** `gov.au`, `gov.ng`, `gov.sg`, `wp-amazon-plugin.com`.

### Diagnostic Takeaway
Even compound lexical rules suffer from an unfavorable trade-off: catching **19 malicious URLs (6.99%)** requires accepting **51 false positives** on clean domains. Standalone lexical filtering is mathematically incapable of solving this regression.

---

## 5. Taxonomy of Bare-Apex Phishing Lures

To understand why lexical rules have low recall, the 272 regressed bare-apex lures were classified into five functional archetypes:

```
272 Regressed Bare-Apex Malicious Lures
├── Archetype A: Generic Action / Credential Lexicon (14% - 18%) [~45 lures]
│   └── Examples: verifica-secure.com, recverifica.com, itaucardfaturadigital.app
├── Archetype B: Regional & Unlisted Brand Impersonation (35% - 40%) [~105 lures]
│   └── Examples: meinedkb.me, hdbankfinance.shop, amendes-gouvs.com, hk-poshmark.com
├── Archetype C: Brand Typosquatting / Permutation (10% - 15%) [~35 lures]
│   └── Examples: projectsnetfix.com, mtb3mobiie.com, sbjbsank.com
├── Archetype D: Compromised Aged Websites / Small Business Roots (20% - 25%) [~60 lures]
│   └── Examples: wealdgymnastics.com, forodhaniparkhotel.com, katimplastics.com.au
└── Archetype E: DGA / Pseudorandom / Gibberish Labels (10% - 15%) [~30 lures]
    └── Examples: inzizi.com, jposdqu.com, chiaat.com, dacetnroj-gemes.com
```

- **Archetype A** is the only category accessible to generic phishing dictionaries.
- **Archetype B** can only be recognized by institutional entity dictionaries.
- **Archetype C & E** require edit-distance or n-gram entropy representations.
- **Archetype D** cannot be detected from host syntax alone when paths are empty; they require external reputation, host history, or path-level payloads.

---

## 6. Ranked Candidate Experiment Designs (Unexecuted)

*In strict compliance with safety rules, these experiments are designed only. No training or code changes have been executed.*

```
Experiment Proposal Ranking:
┌────────────────────────────────────────────────────────────────────────┐
│ Rank 1: Exp-E1 — Brand/Entity Dictionary Expansion (COMMON_BRANDS)      │
│         Minimal change: Zero model retraining, zero schema changes     │
├────────────────────────────────────────────────────────────────────────┤
│ Rank 2: Exp-E2 — Balanced Malicious Bare-Apex Training Augmentation    │
│         Minimal change: Data-only rebalance; 67-feature pipeline intact │
├────────────────────────────────────────────────────────────────────────┤
│ Rank 3: Exp-E3 — Adjudication Invariant Refinement (Decouple is_fin)   │
│         Minimal change: Adjudicator logic only; zero model retraining  │
├────────────────────────────────────────────────────────────────────────┤
│ Rank 4: Exp-E4 — Domain-Level Lexical Features in v7_features.py       │
│         High risk: Schema expansion (67 -> 69) breaks Android parity   │
└────────────────────────────────────────────────────────────────────────┘
```

### Rank 1: Exp-E1 — Brand/Entity Dictionary Expansion (`COMMON_BRANDS`)
- **Hypothesis:** Expanding `COMMON_BRANDS` from 175 to ~300 verified international financial and public-sector institutions will enable `BrandImpersonationScore` to fire on Archetype B lures without requiring model retraining.
- **Minimal Changed Variable:** Add 125 curated institution tokens (`dkb`, `itaucard`, `hdbank`, `amendes`, `critair`, `cajaspiura`, `uniswap`, `raydium`, `dhl`) to `COMMON_BRANDS`.
- **Required Controls:** Evaluate frozen Control and Track A Candidate models with old vs expanded dictionary.
- **Evaluation Slices:** The 272 regressed lures, Tranco Top 10k, Android Golden URLs ($N = 50$).
- **Regression Risks:** Overlapping common words (`air` in `critair`, `mark` in `poshmark`).
- **Stop Criteria:** If dictionary tokens cause $> 0.05\%$ false brand matches on Tranco Top 10k domains, prune the token.

### Rank 2: Exp-E2 — Balanced Malicious Bare-Apex Training Augmentation
- **Hypothesis:** Track A failed because adding 15,000 benign apex URLs with zero malicious apex URLs severely distorted the class prior for `NoOfSubDomain == 0`. Adding a balanced set of 3,000 domain-disjoint malicious bare-apex URLs alongside the 15,000 benign URLs will restore balanced tree splits.
- **Minimal Changed Variable:** Augment training set with 3,000 verified malicious bare-apex URLs (domain-disjoint from test split). Zero code changes; 67 features preserved.
- **Required Controls:** Baseline Control model ($N = 189,468$), Track A Candidate ($N = 204,468$), and Balanced Candidate ($N = 207,468$).
- **Evaluation Slices:** Clean Test Split ($N = 50,511$), Benchmark v1.0 ($N = 500$), Android Golden Fixtures ($N = 50$).
- **Regression Risks:** Test set leakage if domain grouping is imperfect.
- **Stop Criteria:** If Clean Test FPR exceeds $1.00\%$ or malicious bare-apex recall does not improve by at least $+3.0\%$, abort.

### Rank 3: Exp-E3 — Adjudication Invariant Refinement (Decoupling `is_fin`)
- **Hypothesis:** In `v8_classifier.py`, `is_fin` requires both a domain keyword AND a path keyword. Decoupling `is_fin` to trigger when a domain combines high-risk financial and credential tokens (e.g. `auth` + `dkb`, `itaucard` + `fatura`) on bare roots will prevent suppression without model retraining.
- **Minimal Changed Variable:** Modify `is_fin` in `v8_classifier.py` to allow compound domain matches.
- **Required Controls:** Score comparison across all 50,511 clean test URLs.
- **Evaluation Slices:** The 272 regressed malicious URLs, Clean Test Benign ($N = 27,353$).
- **Regression Risks:** Over-flagging legitimate financial root domains.
- **Stop Criteria:** If any of the 200 benchmark bare-apex domains are flagged, abort.

### Rank 4: Exp-E4 — Adding Domain-Level Lexical Features to `v7_features.py`
- **Hypothesis:** Supplying the GBDT with continuous features (`DomainSuspiciousWords`, `DomainEntropyRatio`) allows the trees to learn non-linear interactions rather than hardcoded cutoffs.
- **Minimal Changed Variable:** Add 2 numeric features to `V7_FEATURE_NAMES` (schema expands from 67 to 69).
- **Required Controls:** Full re-training on Track A dataset with identical hyperparameters and seeds.
- **Evaluation Slices:** Clean Test Split, Benchmark v1.0, Kotlin parity suite.
- **Regression Risks:** Breaks backward compatibility with Android deserialization (`HistGbmTreeEvaluator.kt`, `UrlFeatureExtractor.kt`).
- **Stop Criteria:** Parity mismatch $> 10^{-5}$ between Python and Kotlin on Golden URLs.

---

## 7. Artifact & Workspace Integrity Governance

All evaluation outputs have been generated and hashed in the dedicated directory:

| Filename | Path | Size | SHA-256 Hash |
| :--- | :--- | :---: | :--- |
| `cohort_lexical_analysis.json` | `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_lexical_feasibility/` | 3,115 B | `30b849c8b97f291b74ea2a7df8ce119313c911727d9538b5c12a8a37f4fc5541` |
| `lexical_rules_feasibility.json` | `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_lexical_feasibility/` | 4,210 B | `826ec1a30c56ddfd7ac674259e16d23abd2610a183e3854d3105b5c6af905739` |

### Safety Invariants Confirmed
- **Track A Candidate:** Formally **REJECTED**. Not promoted.
- **Benchmark v1.0:** Frozen, unaltered, and not iteratively tuned.
- **Production Code:** Bit-for-bit identical to baseline.
- **Git Status:** Clean, exactly 59 tracked entries intact.
- **Champion V8 Binary:** SHA-256 confirmed as `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`.
- **Execution State:** **HALTED**. Awaiting explicit user approval before proceeding to any experimental phase.
