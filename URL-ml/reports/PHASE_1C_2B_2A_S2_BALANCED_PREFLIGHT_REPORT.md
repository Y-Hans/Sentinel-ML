# Sentinel Phase 1C.2B-2A-S2 — Balanced Bare-Apex Training Experiment Design and Preflight Report

**Date:** 2026-10-20  
**Phase:** 1C.2B-2A-S2 (Balanced Bare-Apex Experiment Design and Preflight)  
**Status:** **PREFLIGHT COMPLETE — READY FOR AUTHORIZATION — ZERO MODEL TRAINING EXECUTED**  
**Repository Branch:** `reforge` (Workspace Git Status preserved, 59 tracked entries intact)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified)  
**Experiment Directory:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/`  

---

## 1. Executive Summary & Preflight Findings

Phase 1C.2B-2A-S2 prepared and preflighted—**without training any models or altering production artifacts**—a strictly controlled experiment to evaluate whether augmenting the training set with verified malicious bare-apex URLs alongside benign bare-apex augmentation can restore malicious recall while preserving the reduction in benign apex false positives.

```
Augmentation Preflight Architecture:
┌────────────────────────────────────────────────────────────────────────┐
│ Pool of Eligible Dedicated Malicious Apex Domains in Train: 25,456     │
├────────────────────────────────────────────────────────────────────────┤
│ Selected Balanced Candidate Dataset: 3,000 Unique Domains (N = 3,000)   │
│ SHA-256: 5472d5ac9dd8074fccfde688816cde0fea85401426d90de106954fdadf300225 │
├────────────────────────────────────────────────────────────────────────┤
│ Domain Overlap Across Protected Evaluation Sets (68,693 Domains):       │
│ • Test Split Overlap: 0                                                │
│ • Validation Split Overlap: 0                                          │
│ • Android Golden Fixtures (174 URLs) Overlap: 0                        │
│ • Hard-Benign Benchmark v1.0 (500 URLs) Overlap: 0                     │
│ • Adversarial Evaluation Set Overlap: 0                                │
└────────────────────────────────────────────────────────────────────────┘
```

### Core Preflight Conclusions
1. **Data Availability Verified:** An abundant pool of **25,456 dedicated malicious registrable domains** was discovered in the training split parents. A curated, stratified sample of **3,000 bare-apex URLs** was generated and verified to have **ZERO overlap** across all evaluation splits.
2. **Mathematical Root Cause of Track A Identified:** In the baseline training set, there were 2,659 malicious root bare-apex URLs and **0 benign bare-apex URLs**. Track A added 15,000 benign bare-apex URLs and 0 malicious bare-apex URLs, creating a **5.64 : 1 benign-to-malicious imbalance** on root domains that forced GBDT trees to heavily penalize `NoOfSubDomain == 0.0`.
3. **Single-Variable Control Established:** To prevent confounding attribution, the 16-token entity dictionary evaluated in Phase 1C.2B-2A-S1 is strictly **EXCLUDED** from this initial training experiment. All feature extraction, hyperparameters, random seeds, and thresholds remain fixed.
4. **Pre-Registered Evaluation Gates:** Seven quantitative release gates are pre-registered, including a hard-fail ceiling of $\le 1.00\%$ on clean test benign FPR and a floor of $\ge 98.20\%$ on clean test malicious recall.

---

## 2. Candidate Malicious Data Availability & Overlap Audit

### 2.1 Extraction Methodology & Provenance
To guarantee 100% label validity without web scraping or synthetic generation:
- Malicious candidates were derived strictly from verified malicious parent domains in `cleaned_dataset.csv`'s training split (`Train Clean`, $N = 141,178$).
- Shared hosting providers, cloud storage, and PaaS platforms (`web.app`, `pages.dev`, `workers.dev`, `weebly.com`, `firebaseapp.com`, `github.io`, `repl.co`) were **strictly excluded** to prevent legitimate platforms from being canonicalized to root apex.
- Registrable parent domains with `_subdomain_depth == 0` under `v7_features.py` were canonicalized to standard HTTPS root URLs (`https://<parent_domain>/`).

### 2.2 Five-Way Overlap Audit Across Protected Evaluation Sets
To prevent evaluation leakage, every candidate domain was audited against all protected evaluation assets ($68,693$ total protected domains):

| Evaluation Corpus | Total Entries | Unique Registrable Domains | Domain Overlap with Candidate 3k | Exact URL Overlap | Audit Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Clean Test Split** | 50,511 URLs | 34,069 domains | **0** | **0** | **VERIFIED DISJOINT** |
| **Clean Validation Split** | 44,106 URLs | 34,198 domains | **0** | **0** | **VERIFIED DISJOINT** |
| **Android Golden Fixtures** | 174 URLs | 121 domains | **0** | **0** | **VERIFIED DISJOINT** |
| **Hard-Benign Benchmark v1.0** | 500 URLs | 209 domains | **0** | **0** | **VERIFIED DISJOINT** |
| **Adversarial Evaluation Set** | 8,054 URLs | 7,495 domains | **0** | **0** | **VERIFIED DISJOINT** |

*(Note: Initial unfiltered extraction contained 4 domain overlaps with golden fixtures from shared cleaned-dataset roots; these were pruned prior to final candidate dataset generation).*

### 2.3 Candidate Dataset Properties & TLD Distribution
- **Dataset File:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv`
- **Row Count:** Exactly 3,000 URLs across 3,000 unique registrable domains.
- **SHA-256:** `5472d5ac9dd8074fccfde688816cde0fea85401426d90de106954fdadf300225`
- **TLD Stratification:**
  - `.com`: **1,500** (50.0%)
  - `.net`: **137** (4.6%)
  - `.org`: **92** (3.1%)
  - `.xyz`: **77** (2.6%)
  - `.top`: **76** (2.5%)
  - `.ru`: **69** (2.3%)
  - `.fr`: **53** (1.8%)
  - `.info`: **45** (1.5%)
  - `.de`: **40** (1.3%)
  - Other ccTLDs / new gTLDs: **911** (30.3%)

---

## 3. Augmentation Design & Statistical Justification

### 3.1 Why Track A Failed: The Bare-Apex Prior Collapse
In the baseline reproduction dataset ($N = 189,468$):
- Global malicious balance: $60,819 / 189,468 = 32.10\%$.
- Bare-apex root domains ($clean\_path == ''$ and $NoOfSubDomain == 0$): **2,659 malicious vs 0 benign**.
- Under this distribution, `NoOfSubDomain == 0` was 100% correlated with malicious labels.

In Track A ($N = 204,468$):
- Added 15,000 benign bare-apex URLs.
- Bare-apex root domains became: **2,659 malicious vs 15,000 benign ($5.64 : 1$ benign-to-malicious imbalance)**.
- GBDT trees reassigned root bare-apex samples to negative leaf weights. For phishing lures without path tokens (e.g. `itaucardfaturadigital.app`), scores plummeted from $>0.85$ to $<0.15$.

### 3.2 Proposed Balanced Augmentation Design (Candidate A1)
By adding **3,000 verified malicious bare-apex URLs** alongside the 15,000 benign bare-apex URLs:
- **Total Training Size:** $207,468$ ($+9.5\%$ over baseline Control).
- **Global Malicious Balance:** $63,819 / 207,468 = 30.76\%$ (closely matches baseline $32.10\%$).
- **Bare-Apex Root Balance:** $5,659$ malicious vs $15,000$ benign ($2.65 : 1$ ratio).
- **Statistical Function:** Restores positive leaf pathways for bare-apex domains possessing subtle domain-level anomalies (entropy, hyphenation, character ratios) without re-introducing the spurious blanket penalty.

### 3.3 Training-Procedure Invariance
To ensure pure, single-variable experimental attribution:
- **Feature Vector:** Fixed at exactly 67 features (`V7_FEATURE_NAMES`).
- **Model Family:** Fixed at `HistGradientBoostingClassifier`.
- **Hyperparameters:** `max_iter=350, max_depth=8, min_samples_leaf=30, learning_rate=0.08, l2_regularization=0.1, random_state=42`.
- **Sample Weighting:** Preserved using identical inverse-class frequency formula.
- **Seeds:** Outer split `42`, inner split `43`, model `42`.
- **Threshold:** Fixed at `0.2800`.
- **Single Changed Variable:** Addition of `candidate_malicious_bare_apex_3k.csv` to Candidate training set.

---

## 4. Pre-Registered Evaluation Gates (7 Immutable Gates)

The candidate model must pass all seven pre-registered evaluation gates upon future authorized training:

| Gate ID | Target Metric & Corpus | Baseline Control | Track A Candidate (Rejected) | Pre-Registered Gate Threshold | Hard-Fail Boundary |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Gate 1** | **Clean Test Malicious Recall** ($N = 23,158$) | $98.605\%$ (22,835) | $97.405\%$ (22,557) | $\ge \mathbf{98.200\%}$ ($\le 0.40\%$ drop) | $< 98.000\%$ |
| **Gate 2** | **Clean Test Benign FPR** ($N = 27,353$) | $0.962\%$ (263) | $1.068\%$ (292) | $\le \mathbf{1.000\%}$ ($\le 273$ FPs) | $> 1.100\%$ |
| **Gate 3** | **Benchmark v1.0 Bare-Apex FPR** ($N = 200$) | $100.0\%$ (200) | $4.0\%$ (8) | $\le \mathbf{6.0\%}$ ($\le 12$ FPs) | $> 10.0\%$ |
| **Gate 4** | **Benchmark v1.0 Overall FPR** ($N = 500$) | $60.8\%$ (304) | $22.4\%$ (112) | $\le \mathbf{25.0\%}$ ($\le 125$ FPs) | $> 30.0\%$ |
| **Gate 5** | **Test Bare-Apex Malicious Recall** ($N = 4,254$) | $98.03\%$ (4,170) | $92.05\%$ (3,916) | $\ge \mathbf{96.00\%}$ ($\ge 4,084$) | $< 95.00\%$ |
| **Gate 6** | **Adversarial Split Recall** ($N = 8,054$) | $98.24\%$ | $98.24\%$ | $\ge \mathbf{98.00\%}$ | $< 97.50\%$ |
| **Gate 7** | **Android Golden Fixture Parity** ($N = 174$) | 100% Agreement | 100% Agreement | **Exactly 0 Regressions** | $\ge 1$ Regression |

---

## 5. Experiment Plan & Control/Candidate Matrix

```
Proposed Experiment Execution Matrix:
┌────────────────────────────────────────────────────────────────────────┐
│ Model C0: Control Model (Reproduced V8 Baseline)                       │
│           Dataset: Train Clean (141,178) + Synthetic Benign (48,290)   │
│           Total: N = 189,468 | Threshold: 0.2800                       │
├────────────────────────────────────────────────────────────────────────┤
│ Model C1: Track A Candidate (Rejected Reference Baseline)              │
│           Dataset: Control (189,468) + Benign Bare Apex (15,000)       │
│           Total: N = 204,468 | Threshold: 0.2800                       │
├────────────────────────────────────────────────────────────────────────┤
│ Model C2: Balanced Candidate A1 (Primary Proposed Candidate)          │
│           Dataset: Track A (204,468) + Malicious Bare Apex (3,000)     │
│           Total: N = 207,468 | Threshold: 0.2800                       │
└────────────────────────────────────────────────────────────────────────┘
```

### Reproducibility Specification
- An unexecuted, standalone training protocol script has been authored and verified:
  `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/run_balanced_experiment_protocol.py`
  (SHA-256: `fcc8b378a4ba4dcd3e8dccad897468e7c52ed9a67f121bd22ccef31765bbebfd`).
- No background jobs or training tasks were executed during this phase.

---

## 6. Artifact Manifest & Verification

All preflight artifacts are stored in the isolated experiment directory:

| Filename | Description | Size | SHA-256 Hash |
| :--- | :--- | :---: | :--- |
| `candidate_malicious_bare_apex_3k.csv` | 3,000 verified, dedicated, domain-disjoint malicious bare-apex URLs | 101,671 B | `5472d5ac9dd8074fccfde688816cde0fea85401426d90de106954fdadf300225` |
| `candidate_malicious_bare_apex_manifest.json` | Complete data provenance, TLD distribution, and overlap audit | 1,228 B | `0d2c0fd8b207d7dd4c3235d3af77e0c8a5e3c25dce8eda5b563dc56dc59a5778` |
| `malicious_bare_apex_preflight_audit.json` | Preflight pool metrics and initial domain counts | 664 B | `e66ce39154dc2e06fd88dde650dcbb2bb7878e980e99e89d5160ae1a121d07f9` |
| `run_balanced_experiment_protocol.py` | Standalone, unexecuted Python training and evaluation protocol | 4,507 B | `fcc8b378a4ba4dcd3e8dccad897468e7c52ed9a67f121bd22ccef31765bbebfd` |

### Safety Invariants Confirmed
- **Track A Candidate:** Formally **REJECTED**.
- **Model Binaries & Android Assets:** Preserved bit-for-bit.
- **Git Status:** 59 tracked entries intact in `sentinel-ai/`.
- **Champion V8 Binary:** SHA-256 confirmed as `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`.
- **Execution State:** **HALTED**. Awaiting explicit user approval before executing any model training.
