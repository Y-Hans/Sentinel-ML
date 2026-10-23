# SENTINEL MESSAGES — NEXT ARCHITECTURE RESEARCH EXECUTION REPORT

**Document ID**: `SENTINEL-EXECUTION-REPORT-V4_5-STAGE2-2026-09-25`  
**Author**: Lead ML/Security Architecture & Safety Engineer  
**Date**: September 25, 2026  
**Status**: CONTROLLED EXPERIMENT COMPLETED — FULL EVALUATION AUDITED  
**Final Disposition**: **`A. PROMISING — CONTINUE TO CONTROLLED VALIDATION`**  
**Production Status**: Sentinel Messages V4.3 Candidate-D remains the active, frozen production reference. No Android code modified. No model promoted to production.

---

## 1. Executive Summary & Core Results

In accordance with the project research directive, a two-stage hybrid architecture was designed, implemented, and empirically evaluated across 21 evaluation suites ($N = 4,478$ records).

### Architectural Philosophy:
Unlike the rejected V4.5 experiment (which attempted to replace V4.3's feature space with frozen MiniLM and suffered 307 regressions), this architecture implements an **asymmetric two-stage evidence structure**:
1. **Primary Detector**: Sentinel V4.3 Candidate-D ($\tau = 0.6100$, 4,019 dimensions) remains the authoritative detector for all global predictions.
2. **Auxiliary Model**: A contextual semantic evidence model (`all-MiniLM-L6-v2` + regularized multi-class classifier) operates exclusively in V4.3's ambiguity region.
3. **Decision Arbitration**:
   - **Variant A**: Pure frozen V4.3 Candidate-D baseline.
   - **Variant B (Additive / Upgrade Evidence Only)**: The auxiliary model can provide additional malicious evidence to upgrade sub-threshold or missed threats, but possesses **zero downgrade authority**.
   - **Variant C (Tightly Gated Downgrade)**: The auxiliary model can upgrade sub-threshold threats and may only downgrade a V4.3 threat if 5 strict, independently validated safety conditions are simultaneously satisfied.

---

## 2. Global Primary Test & Four-Way Analysis

### 2.1 Four-Way Malicious Primary TEST Matrix ($N = 1,556$):

| Category | Description | Count | Percentage | Research Finding |
|:---:|:---|:---:|:---:|:---|
| **A** | **Both V4.3 and New Architecture Correct** | **1,510** | **97.04%** | Baseline security detections fully preserved. |
| **B** | **V4.3 Correct / New Architecture Wrong (Regression)** | **0** | **0.00%** | **ZERO REGRESSIONS**. No V4.3-caught threat was lost. |
| **C** | **V4.3 Wrong / New Architecture Correct (Recovered)** | **1** | **0.06%** | Genuine near-threshold recovery via contextual semantics. |
| **D** | **Both Wrong (Remaining Missed Threats)** | **45** | **2.89%** | Residual false negatives unreached by conservative gating. |

```
Primary TEST Malicious Detections (N = 1,556)
├── Category A: Both Correct ─────────────────── 1,510 (97.04%)
├── Category B: Regressions (V4.3 lost) ────────     0  (0.00%)  <-- ZERO REGRESSION GATE PASSED
├── Category C: Recoveries (V4.3 missed) ───────     1  (0.06%)  <-- 1 NEW RECOVERY
└── Category D: Both Missed ────────────────────    45  (2.89%)
```

### 2.2 Global Benchmark Comparison:

| Metric | Primary TEST ($N=2,264$) | Primary OOD ($N=1,132$) | Clean OOD ($N=1,075$) |
|:---|:---:|:---:|:---:|
| **V4.3 Baseline Malicious Recall** | 1,510 / 1,556 (97.04%) | 761 / 794 (95.84%) | 715 / 747 (95.72%) |
| **Variant B (No Downgrade) Recall** | **1,511 / 1,556 (97.11%)** | 761 / 794 (95.84%) | 715 / 747 (95.72%) |
| **Variant C (Gated Downgrade) Recall**| **1,511 / 1,556 (97.11%)** | 761 / 794 (95.84%) | 715 / 747 (95.72%) |
| **V4.3 Baseline Benign FPR** | 2 / 520 (0.38%) | 1 / 255 (0.39%) | 1 / 249 (0.40%) |
| **Variant B Benign FPR** | **2 / 520 (0.38%)** | 1 / 255 (0.39%) | 1 / 249 (0.40%) |
| **Variant C Benign FPR** | **2 / 520 (0.38%)** | 1 / 255 (0.39%) | 1 / 249 (0.40%) |

---

## 3. What Was Changed vs What Was Frozen

### 3.1 Strictly Frozen Components:
- **Primary Model Weights & Scaler**: Sentinel Messages V4.3 Candidate-D (`messages_v4_3/models/candidate_d/`) remains 100% bit-for-bit immutable (SHA-256: `9b747822a941a92d278f11d0e1458c48497c14ce8c35ecf58dc72e7effaff7e0`).
- **Evaluation Datasets**: `test.jsonl`, `ood.jsonl`, and all 7 holdout suites were completely untouched and unmodified.
- **Android Codebase**: `sentinel-ai/` was completely untouched.

### 3.2 Implemented Auxiliary Components:
- **Audited Auxiliary Corpus**: Authored and audited `auxiliary_train.jsonl` ($N = 12,753$), passing strict 6-step isolation gates.
- **Auxiliary Contextual Model**: Trained `auxiliary_semantic_model.pkl` on 384-dimensional `all-MiniLM-L6-v2` embeddings.
- **Two-Stage Arbitration Policy**: Implemented decision logic in `run_next_architecture_experiment.py`.

---

## 4. Exact Data Provenance & 6-Step Isolation Audit

To eliminate the co-generation and contamination failures of earlier iterations, the auxiliary training corpus was filtered through a 6-step isolation audit before model training:

### Audit Results:
1. **Total Candidate Records Evaluated**: 15,869
2. **Exact String Collisions**: **0** (no candidate text matched any evaluation record).
3. **Aggressive Normalized Collisions**: **175 records rejected** (any record sharing normalized structure with test/ood/holdouts was purged).
4. **Message-ID Collisions**: **0**
5. **Token Jaccard Similarity ($\ge 0.70$)**: **2,941 records rejected** (every sample exhibiting near-duplicate overlap $\ge 0.70$ against any evaluation record was discarded).
6. **Passed Clean Records**: **12,753 records**
   - Class Breakdown: 8,101 Malicious, 3,614 Benign, 1,038 Suspicious Spam.
   - Status: **APPROVED CLEAN** (`PROVENANCE_AUDIT.json`).

---

## 5. Model Architecture & Calibration Specifications

### 5.1 Architecture Details:
- **Primary Pipeline**:
  - Deterministic 19-signal structural extractor + 1,500 word TF-IDF + 2,500 subword character morphemes (`char_wb` 2–5).
  - Scaler: Standard scaler.
  - Classifier: HistGradientBoostingClassifier.
- **Auxiliary Pipeline**:
  - Embedding Engine: Pretrained frozen `all-MiniLM-L6-v2` (384 dimensions, normalized).
  - Classifier: LogisticRegression ($C = 1.0$, balanced class weights, L2 penalty).
  - Confidence Margin: $\text{Margin} = \max_k P(k) - \text{second\_max}_k P(k)$.

### 5.2 Threshold Calibration (Calibrated ONLY on `val.jsonl`):
All decision parameters were calibrated strictly on `data/processed/val.jsonl` ($N = 3,397$: 807 Benign, 274 Spam, 2,316 Malicious):
- **Primary V4.3 Threshold**: $\tau = 0.6100$.
- **Variant B Upgrade Threshold**: $\theta_{\text{upgrade}} = 0.9500$, with $\text{Margin}_{\text{min}} = 0.4000$.
  - Preserves validation benign FPR $\le 1.98\%$.
- **Variant C Gated Downgrade Thresholds**:
  1. $P_{V4.3}(\text{MALICIOUS}) < 0.7000$ (must not be high-confidence threat).
  2. Delivery vectors absent (`has_url == 0`, `has_phone == 0`, `has_suspicious_tld == 0`, `has_hex_or_ip_url == 0`, no `.apk`).
  3. $P_{\text{aux}}(\text{BENIGN}) \ge 0.9500$.
  4. $P_{\text{aux}}(\text{MALICIOUS}) \le 0.0500$.
  5. $\text{Margin}_{\text{aux}} \ge 0.5000$.

---

## 6. Comprehensive Evaluation Matrix Across 21 Suites

```
========================================================================================================================
SUITE                                    | V4.3 Mal     | V4.3 FPR  | Var B Mal    | Var B FPR | Var C Mal    | Var C FPR
========================================================================================================================
Primary TEST                             | 1510/1556    | 0.38%     | 1511/1556    | 0.38%     | 1511/1556    | 0.38%    
Primary OOD                              | 761/794      | 0.39%     | 761/794      | 0.39%     | 761/794      | 0.39%    
Clean OOD                                | 715/747      | 0.40%     | 715/747      | 0.40%     | 715/747      | 0.40%    
Real Mobile Simulation                   | 3/3          | 4.81%     | 3/3          | 4.81%     | 3/3          | 4.81%    
Benchmark: slice_banking_scam            | 3/3          | 0.00%     | 3/3          | 0.00%     | 3/3          | 0.00%    
Benchmark: slice_electricity_scam        | 1/3          | 0.00%     | 1/3          | 0.00%     | 1/3          | 0.00%    
Benchmark: slice_hard_negatives          | 0/0          | 50.00%    | 0/0          | 50.00%    | 0/0          | 50.00%   
Benchmark: slice_hinglish_smishing       | 2/3          | 0.00%     | 2/3          | 0.00%     | 2/3          | 0.00%    
Benchmark: slice_institutional_partnerships | 12/16        | 6.25%     | 12/16        | 6.25%     | 12/16        | 6.25%    
Benchmark: slice_legit_banking           | 0/0          | 66.67%    | 0/0          | 66.67%    | 0/0          | 66.67%   
Benchmark: slice_legit_delivery          | 0/0          | 33.33%    | 0/0          | 33.33%    | 0/0          | 33.33%   
Benchmark: slice_legit_otp               | 0/0          | 20.00%    | 0/0          | 20.00%    | 0/0          | 20.00%   
Benchmark: slice_otp_theft               | 4/4          | 0.00%     | 4/4          | 0.00%     | 4/4          | 0.00%    
Benchmark: synthetic_pipeline_fixtures   | 5/7          | 42.86%    | 5/7          | 42.86%    | 5/7          | 42.86%   
Holdout: holdout_apk_payload             | 30/30        | 20.00%    | 30/30        | 23.33%    | 30/30        | 23.33%   
Holdout: holdout_conversational_social_eng | 66/102       | 5.71%     | 66/102       | 5.71%     | 66/102       | 5.71%    
Holdout: holdout_counterfactual_semantic | 46/55        | 40.00%    | 46/55        | 41.82%    | 46/55        | 41.82%   
Holdout: holdout_electricity             | 30/55        | 50.91%    | 38/55        | 56.36%    | 38/55        | 56.36%   
Holdout: holdout_greetings               | 46/55        | 12.73%    | 49/55        | 12.73%    | 49/55        | 12.73%   
Holdout: holdout_institutional_callback  | 23/30        | 40.00%    | 23/30        | 40.00%    | 23/30        | 36.67%   
Holdout: holdout_system_notifications    | 0/0          | 50.91%    | 0/0          | 50.91%    | 0/0          | 50.91%   
========================================================================================================================
```

---

## 7. Deep Forensic Analysis of Recovered & Regression Cases

### 7.1 Category C: Primary TEST Recovered Threat ($N = 1$)
- **Record Identifier**: `MSG_SRC_IMC25_FISHING_SMISHING_0018109`
- **Raw Message Text**: `"The account may be suspended. Click for details."`
- **Ground Truth**: `MALICIOUS`
- **Primary V4.3 Prediction**:
  - $P(\text{B}) = 0.4629, P(\text{S}) = 0.0017, P(\text{M}) = 0.5354$
  - Non-benign probability: $P(\text{nb}) = 0.5371 < \tau_{V4.3} (0.6100) \implies$ **`BENIGN` (False Negative)**.
  - V4.3 correctly sensed malicious tendency ($P(\text{M}) = 0.5354 > P(\text{B})$), but lacked sufficient subword confidence to cross the global threshold.
- **Auxiliary Contextual Evidence**:
  - $P_{\text{aux}}(\text{M}) = 0.9952, P_{\text{aux}}(\text{B}) = 0.0027, P_{\text{aux}}(\text{S}) = 0.0022$
  - Margin: $0.9925$ (High confidence).
- **New Architecture Result**:
  - Upgraded to **`MALICIOUS`**.
  - **Characterization**: Demonstrates genuine contextual semantic recovery of a short, URL-less account suspension lure that V4.3 missed due to threshold calibration.

### 7.2 Targeted Holdout Recoveries:
- **`holdout_electricity`**: Malicious recall improved from **30 / 55 (54.55%)** to **38 / 55 (69.09%)** (+8 authentic threats recovered).
- **`holdout_greetings`**: Malicious recall improved from **46 / 55 (83.64%)** to **49 / 55 (89.09%)** (+3 authentic greeting lures recovered).
- **`holdout_institutional_callback`**: Benign false alarms dropped from 12 to 11 ($\text{FPR}$ dropped from $40.00\%$ to $36.67\%$, 1 false alarm successfully downgraded without any malicious leakage).

### 7.3 Category B: Regressions ($N = 0$):
Across all 1,510 V4.3-caught primary test malicious messages, **zero detections were downgraded or lost**.

---

## 8. Limitations & Engineering Bottlenecks

While the two-stage architecture achieved zero regressions, the audit reveals important limitations:
1. **Conservative Gating Limits Primary Recall Gains**:
   - Because the upgrade threshold was calibrated strictly at $\theta_{\text{up}} = 0.9500$ on validation to safeguard benign FPR, only 1 of the 46 missed primary test threats was recovered.
   - 45 residual threats remain in Category D (missed by both models).
2. **Benign False Alarm Creep on Specific Holdouts**:
   - On `holdout_electricity`, upgrading ambiguous messages increased benign false alarms from 28 to 31 ($\text{FPR} = 50.91\% \to 56.36\%$).
   - On `holdout_apk_payload`, 1 additional false alarm occurred ($\text{FPR} = 20.00\% \to 23.33\%$).
3. **Downgrade Conservatism**:
   - The 5 safety gates for Variant C are so strict that only 1 benign false alarm was downgraded across all holdouts. However, this strictness is what ensured Category B remained exactly 0.

---

## 9. Final Disposition & Next Steps

### Selected Disposition:
$$\mathbf{A \text{ — } PROMISING \text{ — } CONTINUE \text{ } TO \text{ } CONTROLLED \text{ } VALIDATION}$$

### Rationale:
1. This is the **first multi-model architecture** in the Sentinel project that successfully incorporates contextual semantic representations without suffering catastrophic global regressions.
2. It establishes an empirical baseline where:
   - Primary TEST Malicious Recall is **$\ge 97.11\%$** (higher than V4.3).
   - Primary TEST Benign FPR is **$0.38\%$** (identical to V4.3).
   - Clean OOD Malicious Recall is **$95.72\%$** (identical to V4.3).
   - Category B regressions on primary test are **exactly zero**.
3. In accordance with governance constraints, **no Android modifications** were made. Production deployment remains locked until further iterations demonstrate expanded Category C yield.

---

**Artifacts Generated**:
- Experiment Script: [`run_next_architecture_experiment.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/run_next_architecture_experiment.py)
- Configuration: [`config.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/config.json)
- Provenance Audit: [`PROVENANCE_AUDIT.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/PROVENANCE_AUDIT.json)
- Training Manifest: [`training_manifest.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/training_manifest.json)
- Artifact Manifest: [`artifact_manifest.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/artifact_manifest.json)
- Evaluation Results: [`evaluation_results.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/evaluation_results.json)
- Regression Forensic: [`regression_forensic.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/regression_forensic.json)
- Final Report: [`NEXT_ARCHITECTURE_EXECUTION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/reports/NEXT_ARCHITECTURE_EXECUTION_REPORT.md)
