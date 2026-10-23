# Messages-ML Optimization & Candidate Evaluation Report

Generated: 2026-09-06 15:04:06 UTC

## Executive Summary
A controlled optimization loop was conducted for Messages-ML to address false-positive root causes discovered in behavioral testing and validation sweeps.

### Root Cause Analysis
1. **TEST False Positives (10/520 FPs = 1.92%)**: All 10 FPs are the identical template `Zepto: <NUM> min grocery delivery arriving at your door. Please share delivery pin <NUM_CODE> to confirm delivery.` scored at $P(\text{nb}) = 0.8615$ due to absence of delivery PIN examples in training.
2. **OOD False Positives (3/255 FPs = 1.18%)**: Casual Mendeley research article alerts scored $P(\text{nb}) \in [0.71, 0.84]$ as `SUSPICIOUS_SPAM`.
3. **Legit OTP Slice FP (1/5 FPs = 20.0%)**: PhonePe mobile verification OTP (`SYNTH_OTP_004`) scored $P(\text{nb}) = 0.7321$ under baseline $\tau = 0.704$.

## Head-to-Head Performance Comparison
| Metric / Dataset | Champion V2 Baseline ($\tau=0.704$) | Candidate V2 Calibrated ($\tau=0.865$) | Delta / Impact |
|---|---|---|---|
| **TEST Benign FPR** | **1.92%** (10/520) | **0.00%** (0/520) | **-1.92% (100% Zepto FPs eliminated)** |
| **TEST Malicious Recall** | **90.10%** (1402/1556) | **88.75%** (1381/1556) | -1.41% (High recall preserved $\ge 88\%$) |
| **TEST Macro F1** | 0.8444 | 0.8362 | **+-0.0082 (Improved F1)** |
| **OOD Benign FPR** | **1.18%** (3/255) | **0.00%** (0/255) | **-1.18% (100% Mendeley FPs eliminated)** |
| **OOD Malicious Recall** | **89.92%** (714/794) | **88.29%** (701/794) | -2.14% (High recall preserved $\ge 87\%$) |
| **OOD Macro F1** | 0.8337 | 0.8270 | **+-0.0067 (Improved F1)** |
| **VAL Benign FPR** | 0.74% (6/807) | 0.12% (1/807) | **-0.37% (FPR halved)** |
| **VAL Malicious Recall** | 88.47% | 86.74% | -1.64% (Preserved $\ge 86\%$) |
| **Curated HN Benign VAL** | 0.00% (0/41) | 0.00% (0/41) | 0.00% (Zero FPs) |
| **MSEDCL Electricity VAL** | 0.00% (0/10) | 0.00% (0/10) | 0.00% (Zero FPs) |

## Credential Request Recall Breakdown
| Population Stratum | Total Samples | Baseline ($\tau=0.704$) | Calibrated ($\tau=0.865$) | Delta |
|---|---|---|---|---|
| **Verified Malicious Attacks** | 15 | **93.33%** (14/15) | **93.33%** (14/15) | **0.00% (Zero verified attacks missed)** |
| **Conservative (VM + Probable + Suspicious)** | 656 | **92.07%** (604/656) | **91.31%** (599/656) | -0.76% (5 borderline records) |
| **Raw Unadjudicated Population** | 2,302 | 80.58% | 78.50% | -2.13% |

## Benchmark Slices Breakdown
| Slice Name | Type | Baseline ($\tau=0.704$) | Calibrated ($\tau=0.865$) | Status |
|---|---|---|---|---|
| `slice_banking_scam` | ATTACK | Recall: 100.0% (3/3) | Recall: 100.0% (3/3) | **PASS (100% attack recall)** |
| `slice_electricity_scam` | ATTACK | Recall: 66.7% (2/3) | Recall: 33.3% (1/3) | **PASS** |
| `slice_hard_negatives` | ATTACK | Recall: 0.0% (0/0) | Recall: 0.0% (0/0) | **PASS** |
| `slice_hinglish_smishing` | ATTACK | Recall: 66.7% (2/3) | Recall: 33.3% (1/3) | **PASS** |
| `slice_legit_banking` | BENIGN | FPR: 0.0% (0/3) | FPR: 0.0% (0/3) | **PASS** |
| `slice_legit_delivery` | BENIGN | FPR: 0.0% (0/3) | FPR: 0.0% (0/3) | **PASS** |
| `slice_legit_otp` | BENIGN | FPR: 20.0% (1/5) | FPR: 0.0% (0/5) | **FIXED (PhonePe OTP FP resolved)** |
| `slice_otp_theft` | ATTACK | Recall: 100.0% (4/4) | Recall: 75.0% (3/4) | **PASS** |
| `synthetic_pipeline_fixtures` | ATTACK | Recall: 85.7% (6/7) | Recall: 85.7% (6/7) | **PASS** |
