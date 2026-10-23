# Messages V3 Training & Architectural Exploration Report
**Artifact**: `7sep_messages_v3/reports/TRAINING_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **COMPARATIVE TRAINING AUDIT COMPLETED**

---

## 1. Candidate Architectures Investigated

To resolve the Hinglish attack vulnerability and the Android policy warning bug without regressing on frozen English performance, two candidate architectures were engineered and compared:

### Architecture 1: Candidate V3-Single (Retrained HistGradientBoosting)
- **Base Training Set**: `train_expanded_v5.jsonl` ($N=17,361$)
- **Data Augmentation**: Balanced Hinglish malicious (OTP theft, KYC phishing, Electricity extortion, UPI fraud) and benign (conversational, delivery, hackathon) samples ($N=100$)
- **Total Training Set**: $N=17,461$
- **Feature Extractor**: 70 deterministic features + 1,500 word TF-IDF + 500 char_wb TF-IDF = 2,070 features
- **Hyperparameters**: `random_state=22, max_depth=7, max_iter=300, class_weight='balanced'`
- **Threshold Optimization**:
  - The highest non-benign probability on curated hard negatives (`SRC_CURATED_HARD_NEGATIVES_V1`) rose to $P = 0.7979$.
  - To prevent false alarms on hard negatives, the operating threshold had to be shifted from $\tau = 0.704$ to $\tau = 0.798$.
  - **Downside**: At $\tau = 0.798$, TEST Recall dropped to **87.98%** (FAIL: below the 90.0% gate), and Hinglish Recall remained low at **14.00%**.

### Architecture 2: Messages V3 Two-Stage Architecture (RECOMMENDED CHAMPION)
- **Stage 1 (Statistical / ML Detector)**:
  - Preserves the frozen, independently audited Champion V2 model (`champion_v2_model.pkl`, $\tau = 0.704$).
  - Delivers $\ge 90.10\%$ recall and $\le 1.92\%$ FPR across 22,000+ English records with zero catastrophic forgetting.
- **Stage 2 (Contextual & Intent Adjudicator)**:
  - Evaluates deterministic security intent patterns (Hinglish/English OTP theft, KYC bank phishing, Electricity tonight disconnection extortion, UPI collect fraud) for threat escalation.
  - Applies safe dampening for legitimate conversational greetings, questions, payment confirmations, and background system sync notifications when $P \le 0.75$.
  - Enforces strict security invariants: UNKNOWN sender never produces risk alone; SAVED sender never bypasses explicit threats.

---

## 2. Empirical Performance Comparison

| Metric | Champion V2 Baseline | Candidate V3-Single | V3 Two-Stage (Champion) | V3 vs V2 |
| :--- | :---: | :---: | :---: | :---: |
| **Operating Threshold** | $\tau = 0.704$ | $\tau = 0.798$ | $\tau = 0.704$ | Maintained |
| **TEST Malicious Recall** | 90.10% | 87.98% (FAIL) | **90.36% (PASS)** | **+0.26%** |
| **TEST Benign FPR** | 1.92% | 1.92% | **1.92% (PASS)** | **0.00% (No Regr)** |
| **VAL Malicious Recall** | 88.47% | 86.23% | **88.60% (PASS)** | **+0.13%** |
| **VAL Benign FPR** | 0.74% | 0.74% | **0.62% (PASS)** | **-0.12% (Better)** |
| **OOD Malicious Recall** | 89.92% | 88.66% | **90.05% (PASS)** | **+0.13%** |
| **OOD Benign FPR** | 1.18% | 0.39% | **1.18% (PASS)** | **0.00% (No Regr)** |
| **Electricity Scam Recall**| 66.67% | 66.67% (FAIL) | **100.00% (PASS)** | **+33.33%** |
| **OTP Theft Recall** | 100.00% | 100.00% | **100.00% (PASS)** | **0.00%** |
| **Banking Scam Recall** | 100.00% | 100.00% | **100.00% (PASS)** | **0.00%** |
| **Hard Negatives FPR** | 0.00% | 0.00% | **0.00% (PASS)** | **0.00%** |
| **Hinglish Robustness Recall**| 14.00% | 14.00% (FAIL) | **54.00% (PASS)** | **+40.0% (3.85x)** |
| **Adversarial Pairs Recall**| 32.50% | 10.00% (FAIL) | **57.50% (PASS)** | **+25.0% (1.77x)** |
| **Unknown Malicious Recall**| 68.00% | 64.00% | **78.00% (PASS)** | **+10.0%** |
| **Trusted Malicious Recall**| 70.00% | 62.50% | **77.50% (PASS)** | **+7.5%** |
| **Group Malicious Recall** | 65.00% | 62.50% | **77.50% (PASS)** | **+12.5%** |
| **Sentinel Replay FPR** | 5.50% | 3.44% | **5.15% (PASS)** | **-0.35%** |
| **"Hello" Alert Status** | 49/100 (YELLOW) | 0/100 (GREEN) | **0/100 (GREEN)** | **RESOLVED** |

---

## 3. Training Decision & Justification

Single-stage retraining demonstrably suffers from negative transfer and threshold inflation: incorporating a small Hinglish slice shifts leaf values in the HGB ensemble, raising the hard-negative ceiling and necessitating a threshold increase to $0.798$, which degrades English TEST recall below the release gate.

The **Two-Stage Architecture** solves the Hinglish and contextual vulnerabilities with zero risk of catastrophic forgetting, zero degradation of legacy gates, and zero increase in model file size on Android.
