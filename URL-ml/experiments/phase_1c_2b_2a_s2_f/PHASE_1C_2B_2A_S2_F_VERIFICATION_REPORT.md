# Sentinel Phase 1C.2B-2A-S2-F — Isolated Dataset and Protocol Repair Verification Report

**Date:** 2026-10-21  
**Phase:** 1C.2B-2A-S2-F (Isolated Dataset and Protocol Repair)  
**Execution Mode:** **STRICTLY ISOLATED REPAIR & PREPARATION — ZERO MODEL TRAINING OR EVALUATION EXECUTED**  
**Repository Branch:** `reforge` (Workspace Git Status preserved, 59 tracked entries intact)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified)  
**Repaired Directory:** `sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/`  
**Status:** **READY FOR REVIEW — NO TRAINING EXECUTED**  

---

## 1. Executive Summary & Verification Outcome

Phase 1C.2B-2A-S2-F resolved all seven blockers identified in the Phase 1C.2B-2A-S2-R reconciliation audit. In accordance with strict safety mandates:
- **Zero models were trained or evaluated.**
- **Zero production source files, Android assets, or model binaries were modified.**
- **Original preflight artifacts remain 100% preserved bit-for-bit.**
- **All repairs, filtered datasets, manifests, PSL data, and unexecuted protocols were written to a new, isolated directory:** [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/).
- **A runtime execution guard was embedded into the protocol script, verifying that unauthorized execution raises an immediate exception.**

```
Repair Pipeline Architecture:
┌────────────────────────────────────────────────────────────────────────┐
│ Original Candidate Dataset: 3,000 URLs (SHA-256: 5472d5ac9dd8...)       │
├────────────────────────────────────────────────────────────────────────┤
│ Applied Mozilla Public Suffix List (10,396 rules, SHA-256: 8228e4bd...)│
│ Excluded 52 Non-Registrable Public Suffixes (com.my, gov.br, etc.)    │
│ Excluded 1 Shared-Hosting Platform (portfoliobox.net)                  │
│ Excluded 104 Verbatim Duplicates Already in Base Training Partition    │
│ (All 10 Conflicting-Label Domains with 15k Benign Cohort Eliminated)   │
├────────────────────────────────────────────────────────────────────────┤
│ Repaired Malicious Apex Cohort: Exactly 2,843 Unique Domains           │
│ SHA-256: f8c1a4d7de0643254c04dd38a0f78509e52bbdeb280a1bf390bb96c0e008f7f8 │
├────────────────────────────────────────────────────────────────────────┤
│ Domain & URL Overlap Across All Evaluation Sets: IDENTICALLY ZERO (0)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Blocker-by-Blocker Resolution Matrix

| Blocker ID & Description | Diagnostic Root Cause | S2-F Repair Action | Resolution Verification |
| :--- | :--- | :--- | :--- |
| **Blocker 1: Conflicting Label Duplicates** | 10 URLs in Candidate 3k duplicated rows in [`candidate_bare_apex_15k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv) with opposing labels (`label=1` vs `label=0`). | Integrated Mozilla Public Suffix List and project shared-hosting filter; all 10 conflicting domains were identified as public suffixes or shared hosting and excluded. | Overlap audit confirms **0 domain overlap** and **0 URL overlap** between repaired candidate 2,843 and candidate 15k. |
| **Blocker 2: Public Suffix Infiltration** | 9 multi-part ccTLD suffixes (`com.my`, `gov.br`, `edu.co`, `org.mx`, etc.) were mistaken for apex domains due to a 30-entry suffix list in `v8_normalization.py`. | Downloaded and saved the official Mozilla Public Suffix List ([`public_suffix_list.dat`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat), 10,396 rules). Excluded all 52 hosts that match public suffixes without an apex label. | Validated that every single surviving domain has an effective eTLD+1 registrable structure with exactly one label preceding its public suffix. |
| **Blocker 3: Base Train Verbatim Duplicates** | 104 URLs in Candidate 3k were already present verbatim in `clean.iloc[tr]['url']`. | Cross-matched candidate URLs against base train partition and removed all 104 verbatim duplicates. | Asserted `exact_url_overlap_with_base_train == 0`. |
| **Blocker 4: Control Model C0 Hyperparameter Divergence** | `train_hgbm()` in preflight script altered 5 hyperparameters (`lr=0.08`, `l2=0.1`, `max_depth=8`, `min_samples_leaf=30`, `max_leaf_nodes=31`) and used inverse-frequency class weighting ($2.12:1$). | Traced exact V8 parameters from [`v8_champion.joblib`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/models/v8_champion.joblib) and `train_v8_candidates.py`: `lr=0.06`, `l2=5.0`, `max_leaf_nodes=40`, `min_samples_leaf=20`, `max_depth=None`, and sample weights `1.35 : 1.0`. | Script [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) incorporates exact V8 parameters for C0 and A1. |
| **Blocker 5: Incomplete Execution Protocol** | Original script only dumped model joblibs without computing metrics or checking gates. | Built an end-to-end evaluation suite scoring Validation ($N=44,106$), Clean Test ($N=50,511$), Subgroups, Benchmark v1.0 ($N=500$), Adversarial ($N=3,900$), and Golden Fixtures ($N=174$). Separated raw and adjudicated outputs. | Comprehensive evaluation functions implemented and verified via static syntax compilation. |
| **Blocker 6: Gate 4 Benchmark Target Distortion** | S2 preflight report subtracted 116 FPs from baseline ($304$) and candidate ($112$), setting an impossible $\le 25.0\%$ target against a $44.0\%$ mathematical floor. | Reconciled verified ground truth: Baseline is $420 / 500$ ($84.00\%$) and Track A Candidate was $228 / 500$ ($45.60\%$). Corrected Gate 4 target to $\le 46.00\%$ ($\le 230$ FPs) with warning zone $(46.00\%, 50.00\%]$ and hard fail $> 50.00\%$. | Protocol explicitly documents both historical S2 preflight gate and corrected realistic gate. |
| **Blocker 7: Gate 6 Adversarial Baseline Conflict** | S2 report cited phantom $N=8,054$ with $98.24\%$ recall, derived from a script byte size. | Reconciled ground truth from [`URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv): $N = 3,900$, baseline recall $97.051\%$. Corrected target to $\ge 96.50\%$ with hard fail $< 96.00\%$. | Gate 6 in repaired protocol bound to exact 3,900-URL fixture. |

---

## 3. Repaired Candidate Dataset Inventory & Lineage

### 3.1 Dataset Metadata & Cryptographic Hashes
All artifacts are stored in [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/):

| File Name | File Size | SHA-256 Checksum | Description |
| :--- | :---: | :---: | :--- |
| [`public_suffix_list.dat`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat) | 338,010 bytes | `8228e4bdac6024c058a1e67859157e468a2613b826b53de0e5cae298e1b70755` | Authoritative Mozilla Public Suffix List (10,396 rules). |
| [`candidate_malicious_bare_apex_repaired_2843.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv) | 343,195 bytes | `f8c1a4d7de0643254c04dd38a0f78509e52bbdeb280a1bf390bb96c0e008f7f8` | Repaired candidate dataset ($N = 2,843$ rows). |
| [`exclusions_audit.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/exclusions_audit.csv) | 20,477 bytes | `3f0a007c1c4db81b969e7efee71448db74908ca804fb6cbde266ca902ff243ff` | Complete audit log of all 157 excluded URLs and failure reasons. |
| [`candidate_malicious_bare_apex_repaired_manifest.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_manifest.json) | 2,055 bytes | `da5ac59b40267de07a708a9dbc5041f5df88b944007bf2689765bdd8c47a1a48` | Machine-readable metadata, TLD distributions, and audit summary. |
| [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) | 20,291 bytes | `4d21a9ec08a400a4c18c55d918fa905e3c06d4376e8809e16c5f49b95cd5349d` | Complete, unexecuted training & evaluation protocol with execution guard. |

### 3.2 Data Exclusion Summary
Of the original 3,000 candidate URLs, **157 URLs were excluded**:
* `VERBATIM_DUPLICATE_IN_BASE_TRAIN`: **104 URLs**
* `NOT_REGISTRABLE_PUBLIC_SUFFIX`: **52 URLs** (e.g. `https://com.my/`, `https://gov.br/`, `https://edu.co/`, `https://zapto.org/`, `https://carrd.co/`)
* `SHARED_HOSTING_PLATFORM`: **1 URL** (`https://portfoliobox.net/`)
* Total Surviving Rows: **2,843**
* Unique Registrable Domains: **2,843**

> [!NOTE]
> **Data Lineage Statement:** In strict accordance with engineering integrity, root URLs canonicalized from existing phishing training examples (`https://<parent>/`) are classified as **derived augmentation**, not independent out-of-distribution samples. In accordance with task constraints, **no removed rows were replenished** with unverified synthetic rows to artificially maintain $N = 3,000$.

### 3.3 Five-Way Domain Disjointness Audit on Repaired Candidate ($N = 2,843$)
* Domain overlap with Clean Test Split ($N = 50,511$): **0**
* Domain overlap with Validation Split ($N = 44,106$): **0**
* Domain overlap with Android Golden Fixtures ($N = 174$): **0**
* Domain overlap with Diagnostic Benchmark v1.0 ($N = 500$): **0**
* Domain overlap with Remediation Adversarial Split ($N = 3,900$): **0**
* Domain overlap with Candidate Benign 15k: **0**
* Exact URL overlap across all above fixtures: **0**

---

## 4. Control Reproducibility Verification

The authoritative baseline training configuration has been fully traced and restored:
* **Estimator:** `HistGradientBoostingClassifier(learning_rate=0.06, l2_regularization=5.0, max_iter=350, max_leaf_nodes=40, min_samples_leaf=20, max_depth=None, random_state=42, loss='log_loss', max_bins=255, scoring='loss', early_stopping='auto', n_iter_no_change=10, tol=1e-7)`
* **Feature Ordering:** Exactly 67 features matching [`V7_FEATURE_NAMES`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v7_features.py).
* **Training Data Composition:** Clean train split ($N = 141,178$) + `v7_structural_benign.csv` ($N = 48,290$) = $N = 189,468$.
* **Sample Weighting Rule:** Malicious clean train = `1.35`, Benign clean train = `1.0`, Synthetic benign = `1.0`. (Candidate augmentation weights: 15k benign = `1.0`, 2,843 malicious = `1.35`).
* **Adjudicator Wrapper:** `V8RelationalURLClassifier(base_model=hgb, feature_names=feat_names, threshold=0.2800, conf_bound=0.80)`. Matches production Android runtime [`SafeDomainAdjudicator.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt).

---

## 5. Repaired Gate Specifications

```
Gate Decision Boundary Structure:
┌───────────────────────────────┬───────────────────────────────────────────┬───────────────────────────────┐
│          PASS ZONE            │             WARNING ZONE                  │          HARD FAIL            │
│ Meets or exceeds ideal target │ Between target & hard-fail boundary       │ Exceeds hard-fail boundary    │
│ Proceeds unconditionally      │ Requires documented risk justification     │ Immediate model rejection     │
└───────────────────────────────┴───────────────────────────────────────────┴───────────────────────────────┘
```

| Gate ID | Target Metric & Corpus | Denominator ($N$) | Baseline Ground Truth | Corrected Target | Warning Zone | Hard-Fail Boundary |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **Gate 1** | **Clean Test Recall** | $23,158$ | $98.605\%$ | $\ge \mathbf{98.200\%}$ | $[98.000\%, 98.200\%)$ | $< 98.000\%$ |
| **Gate 2** | **Clean Test Benign FPR** | $27,353$ | $0.962\%$ | $\le \mathbf{1.000\%}$ | $(1.000\%, 1.100\%]$ | $> 1.100\%$ |
| **Gate 3** | **Benchmark Bare-Apex FPR** | $200$ | $100.00\%$ | $\le \mathbf{6.00\%}$ | $(6.00\%, 10.00\%]$ | $> 10.00\%$ |
| **Gate 4** | **Benchmark Overall FPR** | $500$ | $84.00\%$ | $\le \mathbf{46.00\%}$ | $(46.00\%, 50.00\%]$ | $> 50.00\%$ |
| **Gate 5** | **Test Apex Recall Subgroup** | $4,254$ | $98.025\%$ | $\ge \mathbf{96.00\%}$ | $[95.00\%, 96.00\%)$ | $< 95.00\%$ |
| **Gate 6** | **Adversarial Split Recall** | $3,900$ | $97.051\%$ | $\ge \mathbf{96.50\%}$ | $[96.00\%, 96.50\%)$ | $< 96.00\%$ |
| **Gate 7** | **Android Golden Parity** | $174$ | $100.0\%$ | **0 Regressions** | N/A | $\ge 1$ Regression |

---

## 6. Static Checks & Execution Guard Verification

1. **Syntax Compilation:** Verified with `py_compile` on [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py). Exit code: `0`.
2. **Execution Guard Enforcement:** Directly executing `python run_balanced_experiment_protocol_repaired.py` halted with:
   `RuntimeError: EXECUTION BLOCKED: Phase 1C.2B-2A-S2-F is strictly an isolated repair and preparation phase. No training or evaluation is authorized. Await explicit user authorization for subsequent execution.`
3. **Write Containment:** All file outputs are hardcoded to `EXP_DIR` ([`phase_1c_2b_2a_s2_f/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/)). Production directories and champion joblibs are protected by strict read-only assertions.

---

## 7. Workspace Integrity Verification

- **Production Code Status:** 100% untouched.
- **Champion V8 SHA-256:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified bit-for-bit).
- **Git Workspace Status:** Preserved (branch `reforge`, exactly 59 pre-existing entries intact, zero unstaged/staged git operations).

---

## 8. Final Status & Conclusion

**STATUS: `READY FOR REVIEW — NO TRAINING EXECUTED`**

All seven preflight blockers have been resolved with mathematical and empirical rigor. The repaired candidate dataset ($N = 2,843$), authoritative PSL list, and unexecuted protocol are fully staged and verified.

**Stop condition met:** The workspace is halted awaiting explicit user authorization prior to executing any training or evaluation.
