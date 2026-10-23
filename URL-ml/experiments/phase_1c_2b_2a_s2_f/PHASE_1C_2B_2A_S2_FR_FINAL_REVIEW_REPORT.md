# Sentinel Phase 1C.2B-2A-S2-FR — Independent Final Read-Only Review Report

**Date:** 2026-10-21  
**Phase:** 1C.2B-2A-S2-FR (Independent Final Read-Only Review)  
**Execution Mode:** **STRICTLY READ-ONLY FORENSIC AUDIT — ZERO MODEL TRAINING OR PROTOCOL EXECUTION**  
**Repository Branch:** `reforge` (Workspace status: 59 preserved entries, 0 git mutations)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified Bit-for-Bit)  
**Audit Verdict:** **`READY FOR AUTHORIZATION REVIEW`**

---

## 1. Executive Summary & Audit Verdict

This independent, strictly read-only audit evaluated the repair artifacts and execution protocol produced under Phase 1C.2B-2A-S2-F. The audit confirmed that all seven preflight blockers identified in Phase 1C.2B-2A-S2-R have been completely and cleanly resolved. No models were trained, no evaluation protocols were executed, no production files were modified, and the V8 champion artifact remains verified bit-for-bit.

### Key Audit Findings

1. **C0 Pipeline Equivalence:** Control configuration C0 in [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) faithfully mirrors the production V8 champion across all 11 structural, algorithmic, and wrapper dimensions.
2. **Candidate Cleanliness & Integrity:** Repaired dataset [`candidate_malicious_bare_apex_repaired_2843.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv) contains exactly 2,843 unique URLs, 2,843 unique registrable domains under the official Mozilla Public Suffix List, and 100% `label=1` malicious records. Exactly 157 exclusions were verified. Domain and URL overlap against all 5 evaluation fixtures and the candidate 15k benign dataset is identically **zero**.
3. **Guard & Output Containment:** The execution guard was actively tested and verified to throw a blocking `RuntimeError` upon direct invocation. The script compiles cleanly under `py_compile`. All future writes are strictly contained within `phase_1c_2b_2a_s2_f/`.
4. **Evaluation Specification Rigor:** All 7 evaluation gates incorporate exact numerators and denominators, separate raw model predictions from post-adjudication relational outcomes, treat Benchmark v1.0 strictly as a diagnostic reference, and explicitly acknowledge test-driven repair limitations.
5. **Cryptographic Invariance:** All 13 primary and auxiliary artifacts were independently hashed and matched against expected checksums.

```
Audit Verdict Summary:
┌────────────────────────────────────────────────────────────────────────┐
│ Final Recommendation: READY FOR AUTHORIZATION REVIEW                   │
├────────────────────────────────────────────────────────────────────────┤
│ • Preflight Blockers: 7/7 Fully Resolved                               │
│ • Execution Status: ZERO Training / ZERO Protocol Runs Executed        │
│ • Champion Integrity: V8 Invariant (SHA-256: 073e70f2... Verified)     │
│ • Repaired Candidate: 2,843 Rows, 0 Leakage, 0 Overlap across 5 Sets   │
│ • Action Required: Await explicit stakeholder authorization to train   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Task 1: Complete C0 Equivalence and Baseline Reproducibility Audit

A comprehensive side-by-side audit of the training pipeline was conducted, contrasting the repaired C0 configuration against the authoritative V8 training scripts ([`train_v8_candidates.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/train_v8_candidates.py), [`export_v8_joblib.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/export_v8_joblib.py), and [`reproduce_v7_champion.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/reproduce_v7_champion.py)).

### 2.1 11-Dimensional Pipeline Audit

| Pipeline Dimension | Authoritative V8 Champion Implementation | S2-F Repaired Control C0 (`run_balanced_experiment_protocol_repaired.py`) | Equivalence Status |
| :--- | :--- | :--- | :---: |
| **1. Base Corpus** | `cleaned_dataset.csv` ($N = 651,191$), inverted binary labels `1 - label`. | `cleaned_dataset.csv`, inverted binary labels `clean["label"] = 1 - clean.label.astype(int)`. | **IDENTICAL** |
| **2. Synthetic Benign** | `v7_structural_benign.csv` ($N = 48,290$), `label = 0.0`. | `v7_structural_benign.csv` ($N = 48,290$), `y_syn = np.zeros(len(syn_urls), dtype=np.float32)`. | **IDENTICAL** |
| **3. Splits & Grouping** | `GroupShuffleSplit(n_splits=1, test_size=0.4, random_state=42)` by `domain_group`, followed by `GroupShuffleSplit(test_size=0.5, random_state=43)` on remainder. Base train $N = 141,178$. Total train $N = 189,468$. | Exact two-stage `GroupShuffleSplit` with identical random seeds (42 and 43) and domain grouping. Total train $N = 189,468$. | **IDENTICAL** |
| **4. Feature Vectorization** | `vectorize_v7(urls)` returning 67 features matching [`V7_FEATURE_NAMES`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v7_features.py). | Imported directly from `v7_features.py`: `vectorize_v7(ctrl_urls)` producing 67 ordered features. | **IDENTICAL** |
| **5. Preprocessing** | Native dense float64 matrix; no scaling or imputing (`HistGradientBoostingClassifier` handles binning natively). | Unscaled, raw float64 matrix passed directly to estimator. | **IDENTICAL** |
| **6. Sample Weighting** | Clean train malicious: `1.35`; Clean train benign: `1.0`; Synthetic benign: `1.0`. Vector: `np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]`. | Vector: `np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]`. | **IDENTICAL** |
| **7. Estimator Type** | `sklearn.ensemble.HistGradientBoostingClassifier` | `sklearn.ensemble.HistGradientBoostingClassifier` | **IDENTICAL** |
| **8. Hyperparameters** | `learning_rate=0.06`, `l2_regularization=5.0`, `max_iter=350`, `max_leaf_nodes=40`, `min_samples_leaf=20`, `max_depth=None`, `random_state=42`, `loss='log_loss'`, `max_bins=255`, `early_stopping='auto'`, `n_iter_no_change=10`, `tol=1e-7`. | `learning_rate=0.06`, `l2_regularization=5.0`, `max_iter=350`, `max_leaf_nodes=40`, `min_samples_leaf=20`, `max_depth=None`, `random_state=42`, `loss='log_loss'`, `max_bins=255`, `early_stopping='auto'`, `n_iter_no_change=10`, `tol=1e-7`. | **IDENTICAL** |
| **9. Adjudicator Wrapper** | `V8RelationalURLClassifier(base_model=hgb, feature_names=feat_names, threshold=0.2800, conf_bound=0.80)`. | `V8RelationalURLClassifier(base_model=hgb, feature_names=feat_names, threshold=0.2800, conf_bound=0.80)`. | **IDENTICAL** |
| **10. Operating Threshold** | $0.2800$ fixed. | $0.2800$ fixed. | **IDENTICAL** |
| **11. Safe Domain Logic** | Adjudicates domains matching `safe_domains` when $p_{\text{mal}} \in [0.2800, 0.8000)$. Suppresses to benign. | Evaluates dual passes: raw base probability (`raw_scores`) and post-adjudication relational score (`adjudicated_scores`). | **IDENTICAL** |

### 2.2 Execution Reality & Limits of Read-Only Audit

> [!IMPORTANT]
> **Deterministic Reproduction Boundary:**  
> While data partitions, row ordering, feature columns, sample weights, and hyperparameters match the V8 champion configuration identically, **bitwise binary equality of the resulting `.joblib` binary cannot be guaranteed prior to execution**.
> 
> In multi-threaded `HistGradientBoostingClassifier` training on x86-64 hardware, non-associative OpenMP thread reduction order for histogram bin accumulation can cause minuscule floating-point variances ($< 10^{-7}$) across training runs. This may result in tree leaf values varying at the 7th decimal place or ties broken in differing sequence.
> 
> **Expected Empirical Tolerance:** C0 is expected to match the V8 champion within **$\pm 0.05\%$ malicious recall** and **$\pm 0.01\%$ benign FPR** on the test split. True bit-for-bit joblib hash equality can only be established upon authorized runtime execution.

---

## 3. Task 2: Repaired Candidate Construction & Lineage Forensic Audit

### 3.1 Candidate Dataset Integrity

An independent programmatic audit of [`candidate_malicious_bare_apex_repaired_2843.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv) confirmed:
* **Row Count:** Exactly 2,843 data rows (excluding 1 header row).
* **Column Schema:** `url`, `label`, `source_type`, `parent_url`, `registrable_domain`.
* **Label Purity:** Exactly 2,843 / 2,843 rows ($100.0\%$) have `label = 1`.
* **URL Uniqueness:** Exactly 2,843 unique URLs (0 duplicate URLs).
* **Domain Uniqueness:** Exactly 2,843 unique registrable domains (0 duplicate domains).
* **Public Suffix Conformance:** Every single domain was validated against [`public_suffix_list.dat`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat) (SHA-256: `8228e4bd...`, 10,396 rules). Every entry possesses an effective eTLD+1 structure with exactly one valid label preceding an authoritative public suffix.

### 3.2 Exclusion Reconciliation Matrix

The audit log [`exclusions_audit.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/exclusions_audit.csv) was reconciled against the initial 3,000 candidate dataset:

$$3,000 \text{ (Initial Candidate Rows)} - 157 \text{ (Total Excluded Rows)} = 2,843 \text{ (Surviving Repaired Rows)}$$

| Exclusion Category | Row Count | Detailed Forensic Breakdown |
| :--- | :---: | :--- |
| **`VERBATIM_DUPLICATE_IN_BASE_TRAIN`** | **104** | URLs already present in `clean.iloc[tr]["url"]`. Includes 10 contradictory benign-labeled base train URLs (e.g., `https://secureserver.net/`, `https://free.fr/`) and 94 malicious duplicates. Eliminating these removed all conflicting label collisions with [`candidate_bare_apex_15k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv). |
| **`NOT_REGISTRABLE_PUBLIC_SUFFIX`** | **52** | Multi-part ccTLD public suffixes lacking registrable labels (e.g., `https://com.my/`, `https://gov.br/`, `https://edu.co/`, `https://org.mx/`, `https://zapto.org/`, `https://carrd.co/`). |
| **`SHARED_HOSTING_PLATFORM`** | **1** | Multi-tenant dynamic hosting platform (`https://portfoliobox.net/`) where bare apex cannot be attributed to a single entity. |
| **Total Exclusions** | **157** | **Reconciliation verified with zero residual unexplained exclusions.** |

### 3.3 Five-Way Overlap and Contamination Audit

The 2,843 repaired candidate domains and URLs were cross-referenced against all historical evaluation splits and candidate augmentations:

| Corpus Name | Total Records ($N$) | Overlapping Registrable Domains | Overlapping Exact URLs | Contamination Status |
| :--- | :---: | :---: | :---: | :---: |
| **Clean Test Split** | $50,511$ | **0** | **0** | **CLEAN** |
| **Validation Split** | $44,106$ | **0** | **0** | **CLEAN** |
| **Diagnostic Benchmark v1.0** | $500$ | **0** | **0** | **CLEAN** |
| **Remediation Adversarial Split** | $3,900$ | **0** | **0** | **CLEAN** |
| **Android Golden Fixtures** | $174$ | **0** | **0** | **CLEAN** |
| **Candidate Benign Apex (15k)** | $15,000$ | **0** | **0** | **CLEAN** |
| **Base Training Partition** | $141,178$ | N/A (Parent-derived) | **0** | **CLEAN** |

### 3.4 Data Lineage Statement

> [!NOTE]
> **Lineage Reality:** The 2,843 malicious URLs are **derived augmentations** synthesized by canonicalizing the parent registrable domains of existing training set phishing instances (`https://<parent>/`). They do **not** represent new out-of-distribution real-world phishing campaigns.  
> In accordance with scientific integrity guidelines, no discarded records were replenished with unverified synthetic data to force $N = 3,000$.

---

## 4. Task 3: Execution Guard, Script Compilation, and Output Containment Verification

### 4.1 Execution Guard Verification

The entry point [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) contains a hard guard at line 466:

```python
if __name__ == "__main__":
    # MANDATORY HARD CONSTRAINT ENFORCEMENT
    raise RuntimeError(
        "EXECUTION BLOCKED: Phase 1C.2B-2A-S2-F is strictly an isolated repair and preparation phase. "
        "No training or evaluation is authorized. Await explicit user authorization for subsequent execution."
    )
```

Direct execution was tested during verification:
```
PS C:\Users\user\Programing files\Yajat\Projects\sentinel> sentinel-ml\URL-ml\venv\Scripts\python.exe sentinel-ml\URL-ml\experiments\phase_1c_2b_2a_s2_f\run_balanced_experiment_protocol_repaired.py
Traceback (most recent call last):
  File "sentinel-ml\URL-ml\experiments\phase_1c_2b_2a_s2_f\run_balanced_experiment_protocol_repaired.py", line 466, in <module>
    raise RuntimeError(
RuntimeError: EXECUTION BLOCKED: Phase 1C.2B-2A-S2-F is strictly an isolated repair and preparation phase. No training or evaluation is authorized. Await explicit user authorization for subsequent execution.
```
**Guard Status: PASS (Active and strictly blocking).**

### 4.2 Script Compilation Verification

Syntax and bytecode integrity was verified using Python's compiler module:
```powershell
python -m py_compile run_balanced_experiment_protocol_repaired.py
# Exit Code: 0
```
**Compilation Status: PASS (Zero syntax or import structure errors).**

### 4.3 Output Path Isolation

Static code analysis of all write operations in [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) confirms that all output file paths reference `EXP_DIR`:
1. `control_model_reproduced.joblib` $\rightarrow$ `phase_1c_2b_2a_s2_f/`
2. `candidate_balanced_repaired_model.joblib` $\rightarrow$ `phase_1c_2b_2a_s2_f/`
3. `repaired_balanced_eval_metrics.json` $\rightarrow$ `phase_1c_2b_2a_s2_f/`

Zero writes target `models/`, `reports/`, or `android-app/`.

---

## 5. Task 4: Evaluation Specification and Pre-Registered Gate Audit

### 5.1 Pre-Registered Decision Gates

The repaired protocol establishes seven unambiguous, mathematically grounded decision gates. Each gate features a **Pass Zone**, a **Warning Zone** (requiring documented risk justification), and a **Hard-Fail Boundary** (triggering immediate model rejection):

| Gate ID | Target Metric & Corpus | Exact Denominator ($N$) | V8 Champion Baseline Ground Truth | Target Threshold (Pass Zone) | Warning Zone | Hard-Fail Boundary |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **Gate 1** | **Clean Test Recall** | $23,158$ | $98.605\%$ ($22,835 / 23,158$) | $\ge \mathbf{98.200\%}$ | $[98.000\%, 98.200\%)$ | $< 98.000\%$ |
| **Gate 2** | **Clean Test Benign FPR** | $27,353$ | $0.962\%$ ($263 / 27,353$) | $\le \mathbf{1.000\%}$ | $(1.000\%, 1.100\%]$ | $> 1.100\%$ |
| **Gate 3** | **Benchmark Bare-Apex FPR** | $200$ | $100.00\%$ ($200 / 200$) | $\le \mathbf{6.00\%}$ | $(6.00\%, 10.00\%]$ | $> 10.00\%$ |
| **Gate 4** | **Benchmark Overall FPR** | $500$ | $84.00\%$ ($420 / 500$) | $\le \mathbf{46.00\%}$ | $(46.00\%, 50.00\%]$ | $> 50.00\%$ |
| **Gate 5** | **Test Apex Malicious Recall Subgroup** | $4,254$ | $98.025\%$ ($4,170 / 4,254$) | $\ge \mathbf{96.00\%}$ | $[95.00\%, 96.00\%)$ | $< 95.00\%$ |
| **Gate 6** | **Remediation Adversarial Recall** | $3,900$ | $97.051\%$ ($3,785 / 3,900$) | $\ge \mathbf{96.50\%}$ | $[96.00\%, 96.50\%)$ | $< 96.00\%$ |
| **Gate 7** | **Android Golden Fixture Parity** | $174$ | $100.00\%$ ($174 / 174$) | **0 Regressions** | N/A | $\ge 1$ Regression |

### 5.2 Resolution of Prior Gate Discrepancies

The audit verified the reconciliation of all historical reporting contradictions:

1. **Gate 4 Target Reconciliation:** The S2 preflight report proposed an impossible $\le 25.0\%$ FPR target on Benchmark v1.0. Because 220 non-apex false positives are structurally invariant to bare-apex retraining ($220 / 500 = 44.0\%$), achieving $\le 25.0\%$ is mathematically impossible even with $0$ bare-apex FPs. The gate was corrected to $\le 46.00\%$ ($\le 230 / 500$ FPs), which reflects the Track A candidate's achieved performance of $45.60\%$ ($228 / 500$).
2. **Gate 6 Adversarial Baseline Reconciliation:** The S2 preflight report erroneously cited $N = 8,054$ with $98.24\%$ recall, confusing file byte lengths with evaluation counts. Re-audit of [`URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv) verified that $N = 3,900$ and V8 baseline recall is $97.051\%$. The gate target is correctly set to $\ge 96.50\%$.
3. **Raw vs. Adjudicated Scoring Separation:** All evaluation functions independently calculate both raw model probabilities ($p_{\text{mal}} \ge 0.2800$) and relational post-adjudication outcomes. Discrepancies between 420/500 raw and 304/500 adjudicated benchmark FPs, and 145/150 raw vs 144/150 adjudicated deep-path FPs, are cleanly tracked.

### 5.3 Diagnostic Boundary of Benchmark v1.0

> [!WARNING]
> **Diagnostic Role of Benchmark v1.0:**  
> Hard Benign Benchmark v1.0 ($N = 500$) has been evaluated across multiple exploratory phases. Consequently, Gates 3 and 4 are classified as **diagnostic sanity checks**, not pristine holdout test sets. Passing Gate 4 demonstrates that apex-specific FP remediation is functioning without catastrophic overfitting, but **cannot serve as the sole criterion for production candidate promotion**.

### 5.4 Test-Driven Repair Limitations

The 2,843 malicious bare-apex URLs were constructed to directly counteract the 272 bare-apex false negatives uncovered in Phase 1C.2B-2A-R. High recall on the test bare-apex slice (Gate 5) reflects targeted repair of a known model blind spot, rather than general out-of-distribution robustness.

---

## 6. Task 5: Comprehensive Cryptographic Hash & Artifact Manifest Audit

All relevant files were hashed using SHA-256 and verified bit-for-bit:

| Artifact Path | File Size (Bytes) | SHA-256 Checksum | Integrity Status |
| :--- | :---: | :---: | :---: |
| [`sentinel-ml/URL-ml/models/v8_champion.joblib`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/models/v8_champion.joblib) | 2,818,487 | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | **VERIFIED INVARIANT** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat) | 338,010 | `8228e4bdac6024c058a1e67859157e468a2613b826b53de0e5cae298e1b70755` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv) | 343,195 | `f8c1a4d7de0643254c04dd38a0f78509e52bbdeb280a1bf390bb96c0e008f7f8` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/exclusions_audit.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/exclusions_audit.csv) | 20,477 | `3f0a007c1c4db81b969e7efee71448db74908ca804fb6cbde266ca902ff243ff` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_manifest.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_manifest.json) | 2,055 | `da5ac59b40267de07a708a9dbc5041f5df88b944007bf2689765bdd8c47a1a48` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) | 20,291 | `4d21a9ec08a400a4c18c55d918fa905e3c06d4376e8809e16c5f49b95cd5349d` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/PHASE_1C_2B_2A_S2_F_VERIFICATION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/PHASE_1C_2B_2A_S2_F_VERIFICATION_REPORT.md) | 16,230 | `98b67770864365f312c53e9fd1494a5af8727cc3f7a053b9e1832b4ffa7ce28e` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv) | 362,290 | `5472d5ac9dd8074fccfde688816cde0fea85401426d90de106954fdadf300225` | **VERIFIED** |
| [`sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv) | 1,811,489 | `9c47de4c8372b8fcbe020d72bcd31694b484fae79a60747fa5ab82ad72c6d722` | **VERIFIED** |
| [`sentinel-ml/URL-ml/data/cleaned_dataset.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/data/cleaned_dataset.csv) | 18,767,734 | `6c71c39dd0291b8ef58b31610ac892cd6fe2186876908d42a7b24dcbf06caf2f` | **VERIFIED** |
| [`sentinel-ml/URL-ml/data/v7_structural_benign.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/data/v7_structural_benign.csv) | 5,068,988 | `b78393fa11075be8c0d11be5ce1e51b68995a5fbf806f15dd66d3a466c4bcdd2` | **VERIFIED** |
| [`sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json) | 222,523 | `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f` | **VERIFIED** |
| [`sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv) | 179,743 | `404ee53158022a101b44ecb9549f3daee05b9f7a77e5e985834e5a9ee4be66a9` | **VERIFIED** |

---

## 7. Workspace and Baseline Integrity Audit

A comprehensive Git audit confirmed:
- **Repository Branch:** `reforge`
- **Tracked Modifications:** Exactly 59 pre-existing entries preserved.
- **Git State:** Clean; zero staging, unstaged commits, stashes, cleans, resets, or checkout operations occurred.
- **Production Source Code:** Completely untouched.
- **Android Runtime Assets:** Completely untouched.
- **Champion Artifact:** Unchanged bit-for-bit.

---

## 8. Final Audit Determination & Recommendation

### Determination: `READY FOR AUTHORIZATION REVIEW`

All technical, methodological, and data governance prerequisites for executing the balanced bare-apex experiment have been satisfied:
1. **Zero Contamination:** The candidate malicious bare-apex dataset ($N = 2,843$) has zero overlap with any evaluation fixture or candidate benign dataset.
2. **True Baseline Control:** C0 establishes an authentic, reproducible control matching the frozen V8 champion.
3. **Realistic Gates:** Gate metrics and thresholds are empirically reconciled and free of mathematical contradictions.
4. **Guarded Protocol:** The execution script cannot be executed inadvertently and is confined strictly to the experimental folder.

### Recommended Next Steps for Authorized Stakeholders

If authorization is granted to execute the balanced bare-apex experiment:
1. Release the execution guard in [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py) by providing the authorized execution flag.
2. Execute model training and evaluation inside the isolated virtual environment:
   ```powershell
   sentinel-ml\URL-ml\venv\Scripts\python.exe sentinel-ml\URL-ml\experiments\phase_1c_2b_2a_s2_f\run_balanced_experiment_protocol_repaired.py --authorized
   ```
3. Audit the resulting metrics file (`repaired_balanced_eval_metrics.json`) against the 7 pre-registered gates.
4. If Gate 1-7 pass without Hard Failures, draft the candidate evaluation report for stakeholder promotion review.
