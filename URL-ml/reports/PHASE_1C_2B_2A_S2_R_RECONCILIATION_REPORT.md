# Sentinel Phase 1C.2B-2A-S2-R — Pre-Execution Reconciliation and Protocol Audit Report

**Date:** 2026-10-21  
**Phase:** 1C.2B-2A-S2-R (Pre-Execution Reconciliation and Protocol Audit)  
**Execution Mode:** **STRICTLY READ-ONLY FORENSIC AUDIT — ZERO MODEL TRAINING OR EXECUTION**  
**Repository Branch:** `reforge` (Workspace Git Status preserved, 59 tracked entries intact)  
**Champion V8 Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified)  
**Audit Status:** **BLOCKED — AUTHORIZATION WITHHELD PENDING RESOLUTION OF 7 CRITICAL BLOCKERS**  

---

## 1. Executive Summary & Audit Verdict

This independent, strictly read-only audit examined the Phase 1C.2B-2A-S2 preflight report, the candidate dataset [`candidate_malicious_bare_apex_3k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv), manifest, overlap audit, and [`run_balanced_experiment_protocol.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/run_balanced_experiment_protocol.py).

> [!CAUTION]
> **AUDIT VERDICT: BLOCKED.**  
> Authorization to execute the balanced training experiment **CANNOT BE GRANTED** in the current state. The audit has uncovered seven fundamental discrepancies, empirical contradictions, and script deficiencies:
> 1. **Control Model C0 Cannot Reproduce V8 Baseline:** The script alters 5 GBDT hyperparameters and replaces fixed class weights with inverse-frequency weights, producing an invalid control.
> 2. **Incomplete Execution Protocol:** The script trains and dumps models but contains zero evaluation routines for any test, benchmark, golden, or adversarial fixtures.
> 3. **Conflicting Label Contradictions:** 10 URLs in the 3,000 candidate dataset duplicate rows in [`candidate_bare_apex_15k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv) with **opposite labels** (label `0` vs label `1`).
> 4. **Public Suffix Infiltration:** 9 of the 10 conflicting domains are multi-part public suffixes (`com.my`, `gov.br`, `edu.co`, `org.mx`, etc.) erroneously classified as bare apex domains due to PSL parsing limitations.
> 5. **Base Training Duplication:** 104 URLs in the 3,000 candidate dataset already exist verbatim in the training partition.
> 6. **Hallucinated Benchmark Metrics in Gate 4:** The S2 preflight report claimed baseline FPs were $304 / 500$ ($60.8\%$) and Track A candidate FPs were $112 / 500$ ($22.4\%$), whereas verified ground truth is **$420 / 500$ ($84.00\%$)** and **$228 / 500$ ($45.60\%$)**. Exactly 116 FPs were subtracted from both counts, fabricating an unachievable target of $\le 25.0\%$.
> 7. **Phantom Adversarial Baseline in Gate 6:** Gate 6 cited $N = 8,054$ with $98.24\%$ recall, which was a phantom artifact caused by misinterpreting the byte size of `verify_parity.py` ($8,054$ bytes) as a dataset row count. Verified adversarial ground truth is **$N = 3,900$ with $97.051\%$ recall**.

---

## 2. Source-Traceable Discrepancy Reconciliation

### 2.1 The 420 vs 304 and 228 vs 112 Benchmark Discrepancy

In the Phase 1C.2B-2A-S2 preflight report, Gate 4 was specified as:
`| Gate 4 | Benchmark v1.0 Overall FPR (N = 500) | 60.8% (304) | 22.4% (112) | <= 25.0% (<= 125 FPs) | > 30.0% |`

A forensic trace across all prediction files ([`hard_benign_benchmark_500_predictions.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/hard_benign_benchmark_500_predictions.csv), [`benchmark_diagnostic_predictions.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_track_a/benchmark_diagnostic_predictions.csv), and [`candidate_eval_metrics.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_track_a/candidate_eval_metrics.json)) conclusively reveals the truth:

| Source Artifact / Evaluation Stage | Scoring Path | Bare Apex ($N=200$) | Deep Repo ($N=150$) | Search Query ($N=150$) | Total FPs ($N=500$) | Overall FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **V8 Baseline (Frozen Champion)** | Raw (`raw_p >= 0.28`) | 200 | 144 | 75 | **419** | **83.80%** |
| **V8 Baseline (Frozen Champion)** | Adjudicated (`final_p >= 0.28`) | 200 | 145 | 75 | **420** | **84.00%** |
| **Track A Control (`control_model`)** | Adjudicated (`final_p >= 0.28`) | 200 | 145 | 75 | **420** | **84.00%** |
| **Track A Candidate (`candidate_model`)**| Raw (`raw_p >= 0.28`) | 8 | 146 | 73 | **227** | **45.40%** |
| **Track A Candidate (`candidate_model`)**| Adjudicated (`final_p >= 0.28`) | 8 | 147 | 73 | **228** | **45.60%** |
| **S2 Preflight Report Table (Fabricated)** | Unspecified | *Unreported* | *Unreported* | *Unreported* | **304** | **60.80%** |
| **S2 Preflight Report Table (Fabricated)** | Unspecified | *Unreported* | *Unreported* | *Unreported* | **112** | **22.40%** |

#### Forensic Root Cause of 304 and 112:
- $420 - 304 = \mathbf{116}$
- $228 - 112 = \mathbf{116}$
- The difference between ground truth and the reported numbers is **identically 116** for both the Control and Candidate.
- In Track A, the reduction in false positives was $420 - 228 = \mathbf{192}$ FPs (a reduction of $38.40\%$, from $84.00\%$ to $45.60\%$).
- In the S2 report table, $304 - 112 = \mathbf{192}$ FPs (identically preserving the 192 FP delta).
- Someone arbitrarily subtracted 116 false positives from both baseline and candidate counts.
- **Impact:** By claiming Track A had reduced FPs to $112 / 500$ ($22.4\%$), Gate 4 set an unachievable target of $\le 25.0\%$ ($\le 125$ FPs). In reality, Track A candidate had **$228$ FPs ($45.60\%$)**. Because non-bare-apex categories (Deep Repo + Search Query) contribute $147 + 73 = \mathbf{220}$ FPs, any bare-apex model has a mathematical lower bound of $220 / 500 = \mathbf{44.0\%}$ FPR on Benchmark v1.0. The $\le 25.0\%$ gate would guarantee failure even if bare-apex FPs dropped to zero.

---

### 2.2 Forensic Trace of the Adversarial Split ($N=3,900$ vs $N=8,054$)

In the S2 report, Gate 6 cited:
`| Gate 6 | Adversarial Split Recall (N = 8,054) | 98.24% | 98.24% | >= 98.00% | < 97.50% |`

An exhaustive audit of the repository's adversarial assets resolves the conflict:
1. [`URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv) contains **3,900 rows** (combining `URL_FINAL_REMEDIATION_ADVERSARIAL.csv` of 2,100 rows and `adversarial_predictions.csv` of 1,800 rows).
2. On this verified 3,900-URL split, the frozen baseline achieves:
   - True Positives: **3,785 / 3,900**
   - Baseline Recall: **$97.051\%$** [95% Wilson CI: $96.472\% - 97.538\%$]
   - False Negatives: **115**
3. Track A candidate achieved:
   - True Positives: **3,758 / 3,900**
   - Candidate Recall: **$96.359\%$** [95% Wilson CI: $95.724\% - 96.903\%$]
   - False Negatives: **142** (a drop of 27 TPs, $-0.692\%$)
4. **Origin of $8,054$:** The number $8,054$ was copied from a shell file listing that reported `Total Bytes: 8054` for the scratch script `verify_parity.py`. It does not correspond to any dataset, split, or URL count in the Sentinel project. The associated $98.24\%$ figure was an artifact of earlier V4 evaluation registry logs.

---

## 3. Control Reproducibility Verdict: Model C0

> [!WARNING]
> **VERDICT: C0 DOES NOT REPRODUCE V8 BASELINE (UNSUITABLE AS WRITTEN).**

A strict parameter-by-parameter comparison between the frozen production champion [`v8_champion.joblib`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/models/v8_champion.joblib), the verified Track A control model [`control_model.joblib`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_track_a/control_model.joblib), and the unexecuted C0 training protocol in [`run_balanced_experiment_protocol.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/run_balanced_experiment_protocol.py):

| Parameter / Dimension | Frozen V8 Champion | Track A Control Model | Script C0 Protocol | Reproducibility Status |
| :--- | :---: | :---: | :---: | :--- |
| **Base Estimator** | `HistGradientBoostingClassifier` | `HistGradientBoostingClassifier` | `HistGradientBoostingClassifier` | Compatible |
| **Feature Dimension** | 67 (`V7_FEATURE_NAMES`) | 67 (`V7_FEATURE_NAMES`) | 67 (`V7_FEATURE_NAMES`) | Compatible |
| **Training Split Size** | $N = 189,468$ | $N = 189,468$ | $N = 189,468$ | Compatible |
| **Clean Train / Synthetic** | 141,178 clean / 48,290 syn | 141,178 clean / 48,290 syn | 141,178 clean / 48,290 syn | Compatible |
| **Split Seed & Logic** | `GroupShuffleSplit` (42 / 43) | `GroupShuffleSplit` (42 / 43) | `GroupShuffleSplit` (42 / 43) | Compatible |
| **Random State** | `42` | `42` | `42` | Compatible |
| **Operating Threshold** | `0.2800` | `0.2800` | `0.2800` | Compatible |
| **Learning Rate** | **`0.06`** | **`0.06`** | **`0.08`** | **MISMATCH (+33.3%)** |
| **L2 Regularization** | **`5.0`** | **`5.0`** | **`0.1`** | **MISMATCH (50x weaker)** |
| **Max Depth** | **`None`** | **`None`** | **`8`** | **MISMATCH (Tree truncated)** |
| **Max Leaf Nodes** | **`40`** | **`40`** | **`31`** (default for depth 8) | **MISMATCH (-22.5%)** |
| **Min Samples Leaf** | **`20`** | **`20`** | **`30`** | **MISMATCH (+50.0%)** |
| **Class Weighting Strategy**| **Fixed: Malicious clean=1.35, Benign clean=1.0, Syn=1.0** | **Fixed: Malicious clean=1.35, Benign clean=1.0, Syn=1.0** | **Inverse-frequency balanced ($w_{pos} \approx 1.56, w_{neg} \approx 0.74$)** | **MISMATCH (Weight ratio 2.12 : 1 vs 1.35 : 1)** |
| **Adjudicator Wrapper** | `V8RelationalURLClassifier` | `V8RelationalURLClassifier` | `V8RelationalURLClassifier` | Compatible |
| **Adjudicator `conf_bound`**| `0.80` | `0.85` | `0.80` (default) | Minor divergence |

### Root Cause of C0 Invalidation
The helper function `train_hgbm` in `run_balanced_experiment_protocol.py`:
```python
# CODE FROM run_balanced_experiment_protocol.py
def train_hgbm(X, y_train):
    n_pos = np.sum(y_train == 1)
    n_neg = np.sum(y_train == 0)
    sw = np.ones(len(y_train), dtype=np.float32)
    sw[y_train == 1] = float(len(y_train)) / (2.0 * n_pos)
    sw[y_train == 0] = float(len(y_train)) / (2.0 * n_neg)
    
    clf = HistGradientBoostingClassifier(
        max_iter=350, max_depth=8, min_samples_leaf=30,
        learning_rate=0.08, l2_regularization=0.1, random_state=42
    )
    clf.fit(X, y_train, sample_weight=sw)
    return V8RelationalURLClassifier(base_model=clf, threshold=0.28)
```
If executed as written, C0 would train a heavily regularized tree with altered tree depth, different leaf sizing, and inverse-frequency class weights that give malicious examples a $2.12\times$ boost over benign examples. It would **not reproduce V8** and would invalidate any comparison with Candidate A1 by introducing multiple confounding variables.

---

## 4. Candidate Data Lineage and Deduplication Verdict

> [!CAUTION]
> **VERDICT: DATASET CORRUPTED BY OPPOSING-LABEL DUPLICATES AND PUBLIC SUFFIXES.**

An empirical audit of [`candidate_malicious_bare_apex_3k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv) ($N = 3,000$, SHA-256: `5472d5ac9dd8074fccfde688816cde0fea85401426d90de106954fdadf300225`) revealed:

### 4.1 Provenance and Derivation
- The 3,000 URLs are **not independent out-of-distribution phishing samples**.
- They are **synthetic canonical transformations** (`https://<parent_domain>/`) derived from parent domains of malicious URLs already residing in the `cleaned_dataset.csv` training partition.
- While the candidate generation script verified domain disjointness against evaluation sets, domain disjointness from evaluation sets **does not constitute independent data provenance**.

### 4.2 Critical Findings & Flaws
1. **10 Contradictory Label Duplicates:** Exactly 10 URLs in `candidate_malicious_bare_apex_3k.csv` are identical duplicates of URLs in [`candidate_bare_apex_15k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv), but with **directly contradictory labels**:
   ```
   Domain: com.my           | 3k: https://com.my/ (Label 1) vs 15k: https://com.my/ (Label 0)
   Domain: gov.br           | 3k: https://gov.br/ (Label 1) vs 15k: https://gov.br/ (Label 0)
   Domain: edu.co           | 3k: https://edu.co/ (Label 1) vs 15k: https://edu.co/ (Label 0)
   Domain: org.mx           | 3k: https://org.mx/ (Label 1) vs 15k: https://org.mx/ (Label 0)
   Domain: edu.my           | 3k: https://edu.my/ (Label 1) vs 15k: https://edu.my/ (Label 0)
   Domain: school.nz        | 3k: https://school.nz/ (Label 1) vs 15k: https://school.nz/ (Label 0)
   Domain: net.pl           | 3k: https://net.pl/ (Label 1) vs 15k: https://net.pl/ (Label 0)
   Domain: waw.pl           | 3k: https://waw.pl/ (Label 1) vs 15k: https://waw.pl/ (Label 0)
   Domain: com.np           | 3k: https://com.np/ (Label 1) vs 15k: https://com.np/ (Label 0)
   Domain: portfoliobox.net | 3k: https://portfoliobox.net/ (Label 1) vs 15k: https://portfoliobox.net/ (Label 0)
   ```
   When `run_balanced_experiment_protocol.py` concatenates `cand_urls = ctrl_urls + cand_ben_urls + cand_mal_urls`, these 10 URLs appear twice with opposite labels, injecting conflicting gradients into tree training.
2. **Public Suffixes Mistaken as Registrable Domains:** 9 of the 10 conflicting domains (`com.my`, `gov.br`, `edu.co`, `org.mx`, `edu.my`, `school.nz`, `net.pl`, `waw.pl`, `com.np`) are **multi-part ccTLD public suffixes**, not registrable apex domains. Because `v8_normalization.parse_v8_url` lacks a complete Public Suffix List (PSL), it extracted the public suffix as the `parent_domain`.
3. **Shared Hosting Platform Leaked:** `portfoliobox.net` is a shared portfolio hosting platform that escaped the `SHARED_HOSTING_PATTERNS` filter.
4. **104 Verbatim Duplicates of Training URLs:** 104 URLs in `candidate_malicious_bare_apex_3k.csv` were already present verbatim in `clean.iloc[tr]['url']` (e.g., `https://mabaomatao.com/`, `https://personal-recargas-com.ml/`).

---

## 5. Corrected, Internally Consistent Gate Specifications

To eliminate ambiguity and resolve conflicting baseline values, every gate is defined with its exact numerator, denominator, evaluation pipeline, and decision boundary. The original gates are preserved, and corrected targets are formally documented.

```
Evaluation Decision Pipeline:
┌───────────────────────────────┬───────────────────────────────────────────┬───────────────────────────────┐
│          PASS ZONE            │             WARNING ZONE                  │          HARD FAIL            │
│ Meets or exceeds ideal target │ Between target & hard-fail boundary       │ Exceeds hard-fail boundary    │
│ Proceeds unconditionally      │ Requires documented risk justification     │ Immediate model rejection     │
└───────────────────────────────┴───────────────────────────────────────────┴───────────────────────────────┘
```

| Gate ID | Target Metric & Corpus | Denominator ($N$) & Exact Pipeline | Verified Baseline (Control) | Verified Track A (Rejected) | Original Target (S2 Preflight) | Corrected Target | Hard-Fail Boundary | Decision Rule |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Gate 1** | **Clean Test Malicious Recall** | $N = 23,158$ (`test_df[label==1]`), threshold $0.2800$ | **$98.605\%$** ($22,835$) | $97.405\%$ ($22,557$) | $\ge 98.200\%$ | $\ge \mathbf{98.200\%}$ | $< 98.000\%$ | $\ge 98.20\%$: Pass<br>$[98.00\%, 98.20\%)$: Warning<br>$< 98.00\%$: Fail |
| **Gate 2** | **Clean Test Benign FPR** | $N = 27,353$ (`test_df[label==0]`), threshold $0.2800$ | **$0.962\%$** ($263$) | $1.068\%$ ($292$) | $\le 1.000\%$ | $\le \mathbf{1.000\%}$ | $> 1.100\%$ | $\le 1.00\%$: Pass<br>$(1.00\%, 1.10\%]$: Warning<br>$> 1.10\%$: Fail |
| **Gate 3** | **Benchmark v1.0 Bare-Apex FPR** | $N = 200$ (Category 1 bare apex), threshold $0.2800$ | **$100.00\%$** ($200$) | $4.00\%$ ($8$) | $\le 6.00\%$ | $\le \mathbf{6.00\%}$ | $> 10.00\%$ | $\le 6.00\%$: Pass<br>$(6.00\%, 10.00\%]$: Warning<br>$> 10.00\%$: Fail |
| **Gate 4** | **Benchmark v1.0 Overall FPR** | $N = 500$ (Full diagnostic benchmark v1.0), threshold $0.2800$ | **$84.00\%$** ($420$) | $45.60\%$ ($228$) | $\le 25.00\%$ *(Invalid: based on 112 FPs)* | $\le \mathbf{46.00\%}$ ($\le 230$ FPs) | $> 50.00\%$ ($> 250$ FPs) | $\le 46.00\%$: Pass<br>$(46.00\%, 50.00\%]$: Warning<br>$> 50.00\%$: Fail |
| **Gate 5** | **Test Bare-Apex Malicious Recall** | $N = 4,254$ (`test_df` bare apex phishing), threshold $0.2800$ | **$98.025\%$** ($4,170$) | $92.055\%$ ($3,916$) | $\ge 96.00\%$ | $\ge \mathbf{96.00\%}$ ($\ge 4,084$) | $< 95.00\%$ ($< 4,042$) | $\ge 96.00\%$: Pass<br>$[95.00\%, 96.00\%)$: Warning<br>$< 95.00\%$: Fail |
| **Gate 6** | **Adversarial Split Recall** | $N = 3,900$ (`URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv`), threshold $0.2800$ | **$97.051\%$** ($3,785$) | $96.359\%$ ($3,758$) | $\ge 98.00\%$ *(Invalid: based on phantom $N=8,054$)* | $\ge \mathbf{96.50\%}$ ($\ge 3,764$) | $< 96.00\%$ ($< 3,744$) | $\ge 96.50\%$: Pass<br>$[96.00\%, 96.50\%)$: Warning<br>$< 96.00\%$: Fail |
| **Gate 7** | **Android Golden Fixture Parity** | $N = 174$ (`golden_urls_v8.json`), threshold $0.2800$ | **100% Parity** (0 reg.) | 100% Parity (0 reg.) | 0 Regressions | **0 Regressions** | $\ge 1$ Regression | $0$ regressions: Pass<br>$\ge 1$: Fail |

---

## 6. Evaluation Integrity Assessment

1. **Benchmark v1.0 is a Diagnostic Development Set:** The 500-URL benchmark was repeatedly analyzed in Phase 1C.1, 1C.2A, and 1C.2B. It cannot be treated as an untouched blind test. Gate 3 and Gate 4 serve as **diagnostic behavioral indicators**, not release proof.
2. **Test Set Contamination Limitation:** The 272 missed malicious URLs from the Clean Test split were forensically dissected during Phases 1C.2B-2A-R, S, and S1. Augmenting training with malicious bare apex URLs specifically targets the failure mode observed on the test set. While domain disjointness is maintained ($0$ domain overlap), the clean test set is no longer an independent blind evaluation for this failure mode. True production generalization must be verified on future out-of-domain telemetry.
3. **Android Golden Fixtures:** The 174 golden URLs acted as an active filter during candidate curation (4 overlapping domains were pruned). The candidate dataset was shaped around this evaluation fixture.

---

## 7. Script Execution Safety Review

Inspection of [`run_balanced_experiment_protocol.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/run_balanced_experiment_protocol.py):

| Check Item | Finding / Assessment | Safety Verdict |
| :--- | :--- | :--- |
| **Write Isolation** | Writes only to `EXP_DIR / "control_model_reproduced.joblib"` and `EXP_DIR / "candidate_balanced_model.joblib"`. Zero writes to production directories. | **SAFE** |
| **Overwrites** | Does not overwrite `v8_champion.joblib` or any existing evaluation fixture. | **SAFE** |
| **Imports** | Uses standard internal scripts (`v7_features`, `v8_classifier`, `v8_normalization`, `url_features`). Zero network calls. | **SAFE** |
| **Evaluation Set Leakage** | Does not append `val_df`, `test_df`, `bench`, `golden`, or `adv` to training data. | **SAFE** |
| **Missing Pipeline Logic** | **The script does NOT compute metrics or evaluate gates.** It stops immediately after dumping model joblibs. | **DEFICIENT** |
| **Hyperparameter Parity** | Diverges on 5 hyperparameters (`lr`, `l2`, `max_depth`, `min_samples_leaf`, `max_leaf_nodes`) and class weighting. | **DEFICIENT** |

---

## 8. Final Status & Mandatory Unresolved Blockers

**CURRENT STATUS: `BLOCKED`**

To achieve `READY FOR EXPLICIT AUTHORIZATION`, the following blockers must be resolved:

- [ ] **Blocker 1 (Candidate Dataset Label Conflicts):** Remove the 10 conflicting domains (`com.my`, `gov.br`, `edu.co`, `org.mx`, `edu.my`, `school.nz`, `net.pl`, `waw.pl`, `com.np`, `portfoliobox.net`) from [`candidate_malicious_bare_apex_3k.csv`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_balanced_preflight/candidate_malicious_bare_apex_3k.csv).
- [ ] **Blocker 2 (Candidate Dataset Public Suffix Pruning):** Ensure all multi-part public suffixes and shared hosting domains are pruned using an explicit PSL validator so that only true registrable apex domains remain.
- [ ] **Blocker 3 (Candidate Deduplication against Base Train):** Prune the 104 URLs that already exist verbatim in the base training partition.
- [ ] **Blocker 4 (C0 Hyperparameter Correction in Script):** Update `train_hgbm` in `run_balanced_experiment_protocol.py` to match the exact V8 parameters: `learning_rate=0.06`, `l2_regularization=5.0`, `max_leaf_nodes=40`, `min_samples_leaf=20`, `max_depth=None`, and sample weights `np.r_[np.where(y_tr == 1, 1.35, 1.0), np.full(len(syn_urls), 1.0)]`.
- [ ] **Blocker 5 (Complete Evaluation Pipeline in Script):** Implement the full evaluation suite in `run_balanced_experiment_protocol.py` to score Validation ($N=44,106$), Clean Test ($N=50,511$), Adversarial ($N=3,900$), Benchmark v1.0 ($N=500$), and Golden Fixtures ($N=174$) and output `balanced_eval_metrics.json`.
- [ ] **Blocker 6 (Gate 4 Target Correction):** Formally adopt the corrected Gate 4 target ($\le 46.00\%$, hard fail $> 50.00\%$) reflecting the mathematical lower bound imposed by Category 2 and Category 3 false positives.
- [ ] **Blocker 7 (Gate 6 Adversarial Correction):** Formally adopt the corrected Gate 6 specification ($N = 3,900$, baseline $97.051\%$, target $\ge 96.50\%$, hard fail $< 96.00\%$).

---

## 9. Verification & Safety Sign-Off

- **Production Code Status:** 100% UNTOUCHED (Zero modifications to Android assets, feature extraction, or model binaries).
- **Champion Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` (Verified).
- **Workspace Git Status:** Preserved (branch `reforge`, exactly 59 pre-existing entries intact).
- **Stop Condition:** Training has **NOT** been executed. Awaiting resolution of blockers and explicit authorization.
