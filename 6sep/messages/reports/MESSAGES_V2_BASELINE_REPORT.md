# Messages-ML Champion V2 Baseline Report
**Date**: 2026-09-06 14:10:00 UTC  
**Model**: Champion V2 (`champion_v2_model.pkl`)  
**Threshold**: $\tau = 0.704$ on $P(\text{SUSPICIOUS_SPAM}) + P(\text{MALICIOUS})$  

## 1. Model Configuration
- **Deterministic Features**: 70 features
- **Word TF-IDF Vocabulary**: 1500 tokens (ngram: 1-2, sublinear_tf=False)
- **Char_wb TF-IDF Vocabulary**: 500 n-grams (ngram: 3-5)
- **Total Vector Dimension**: 2070 dimensions
- **StandardScaler**: Fitted on training split only
- **HistGradientBoosting**: 309 trees across 103 iterations
- **Classes**: `BENIGN (0)`, `SUSPICIOUS_SPAM (1)`, `MALICIOUS (2)`

## 2. Protected Evaluation Results

| Split / Slice | N | Benign Total | Benign FP | Benign FPR | Malicious Total | Malicious TP | Malicious Recall | Macro F1 | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **TEST** | 2264 | 520 | 10 | **1.92%** | 1556 | 1402 | **90.10%** | 0.8444 | 2.89 ms |
| **OOD** | 1132 | 255 | 3 | **1.18%** | 794 | 714 | **89.92%** | 0.8337 | 1.51 ms |
| **VAL** | 3397 | 807 | 6 | **0.74%** | 2316 | 2049 | **88.47%** | 0.8226 | 1.68 ms |
| **slice_banking_scam** | 3 | 0 | 0 | **0.00%** | 3 | 3 | **100.00%** | 1.0000 | 18.69 ms |
| **slice_electricity_scam** | 3 | 0 | 0 | **0.00%** | 3 | 2 | **66.67%** | 0.4000 | 14.84 ms |
| **slice_hard_negatives** | 3 | 3 | 0 | **0.00%** | 0 | 0 | **0.00%** | 1.0000 | 14.24 ms |
| **slice_hinglish_smishing** | 3 | 0 | 0 | **0.00%** | 3 | 2 | **66.67%** | 0.4000 | 13.97 ms |
| **slice_legit_banking** | 3 | 3 | 0 | **0.00%** | 0 | 0 | **0.00%** | 1.0000 | 13.95 ms |
| **slice_legit_delivery** | 3 | 3 | 0 | **0.00%** | 0 | 0 | **0.00%** | 1.0000 | 14.19 ms |
| **slice_legit_otp** | 5 | 5 | 1 | **20.00%** | 0 | 0 | **0.00%** | 0.4444 | 8.66 ms |
| **slice_otp_theft** | 4 | 0 | 0 | **0.00%** | 4 | 4 | **100.00%** | 1.0000 | 12.77 ms |
| **synthetic_pipeline_fixtures** | 16 | 7 | 0 | **0.00%** | 7 | 6 | **85.71%** | 0.5822 | 3.60 ms |
| **CURATED_HN_BENIGN_VAL** | 41 | 41 | 0 | **0.00%** | 0 | 0 | **0.00%** | 1.0000 | 2.47 ms |
| **MSEDCL_ELECTRICITY_VAL** | 10 | 10 | 0 | **0.00%** | 0 | 0 | **0.00%** | 1.0000 | 5.27 ms |

## 3. Confusion Matrix Breakdown (Protected Splits)

### TEST Split (N=2,264)
```
                 Pred BENIGN  Pred SPAM  Pred MALICIOUS
Actual BENIGN            510            0                  10
Actual SPAM                4          145                  39
Actual MALICIOUS          44          110                1402
```

### OOD Split (N=1,132)
```
                 Pred BENIGN  Pred SPAM  Pred MALICIOUS
Actual BENIGN            252            3                   0
Actual SPAM                5           64                  14
Actual MALICIOUS          25           55                 714
```

## 4. Benchmark Slices Summary
- **Legitimate Banking**: 0 FPs out of 3
- **Legitimate Delivery**: 0 FPs out of 3
- **Legitimate OTP**: 1 FPs out of 5
- **Banking Scam**: Recall = 100.0%
- **Electricity Scam**: Recall = 66.7%
- **Hinglish Smishing**: Recall = 66.7%
- **OTP Theft**: Recall = 100.0%
- **Synthetic Fixtures**: 0 FPs, Recall = 85.7%

## 5. Curated Hard-Negative Status (VAL)
- **Curated HN Benign (VAL)**: 0 / 41 FPs
- **MSEDCL Electricity Reminders**: 0 / 10 FPs

Baseline verification established. Ready for controlled challenger iterations.