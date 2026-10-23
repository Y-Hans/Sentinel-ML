# Hinglish Adversarial Robustness Report
**Artifact**: `7sep_messages_v3/reports/HINGLISH_ROBUSTNESS_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **COMPREHENSIVE MULTILINGUAL BENCHMARK COMPLETED**

---

## 1. Vulnerability Analysis: The Hinglish Blindspot in V2

Messages-ML Champion V2 was trained predominantly on English corpora with standard character and word TF-IDF n-grams. When deployed against colloquial Indian SMS and WhatsApp messages written in Romanized Hindi (Hinglish), V2 exhibited an acute vulnerability:

- **Hinglish Robustness Slice ($N=100$)**: Champion V2 malicious recall was only **14.00%** (missed 43 out of 50 malicious attacks!).
- **Semantic Contrastive Pairs ($N=80$)**: Champion V2 malicious recall was only **32.50%**.
- **Electricity Disconnection Scam ($N=3$)**: Champion V2 malicious recall was **66.67%** (missed the Mahavitaran tonight cut attack).

### Critical Vulnerability Examples Missed by Champion V2

```
1. "Hello, OTP bhej do."
   -> P(non-benign) = 0.5203, Predicted: BENIGN (Threshold = 0.704)
   -> Real-world impact: Critical account takeover bypass.

2. "Bhai OTP aaya hoga, mujhe forward kar."
   -> P(non-benign) = 0.2315, Predicted: BENIGN
   -> Real-world impact: Peer-spoofing credential theft bypass.

3. "Dear user electricity power disconnected tonight at 9:30 pm call 9876543210 Mahavitaran MSEDCL"
   -> P(non-benign) = 0.6982, Predicted: BENIGN
   -> Real-world impact: Extortion utility scam bypass.
```

---

## 2. Comparative Evaluation: Single-Stage Retraining vs. Two-Stage Architecture

Two architectural paradigms were developed and rigorously evaluated across identical benchmark slices:

1. **Candidate V3-Single (Single-Stage Retrained HGB)**:
   - Augmenting `train_expanded_v5.jsonl` with Hinglish samples and fitting a single HistGBM model.
   - Result: Hard-negative boundary shifted, requiring the operating threshold to increase from $\tau = 0.704$ to $\tau = 0.798$.
   - At $\tau = 0.798$, TEST Recall collapsed to **87.98%** (FAIL: below 90% gate), and Hinglish Recall remained at only **14.00%**.

2. **Messages V3 Two-Stage Architecture (Champion V2 + Stage 2 Contextual Adjudicator)**:
   - Preserves Champion V2's high-recall ML detector (Stage 1).
   - Introduces Stage 2 Contextual Adjudication to escalate deterministic security threat intent (OTP theft, KYC phishing, Electricity extortion, UPI pin fraud) and dampen conversational greetings/status updates.
   - Result: **Zero regression on TEST FPR (1.92%)**, while Hinglish Recall surged to **54.00%** (a 3.85x improvement) and Electricity Scam Recall reached **100.00%**.

---

## 3. Benchmark Results Comparison

| Dataset Slice | Slice Description | N | V2 Baseline Recall | V3-Single Recall | V3 Two-Stage Recall | V3 vs V2 Gain |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Hinglish Robustness** | Colloquial Hindi-English SMS attacks | 100 | 14.00% | 14.00% | **54.00%** | **+40.0% (3.85x)** |
| **Semantic Pairs** | Minimal edit distance benign/malicious | 80 | 32.50% | 10.00% | **57.50%** | **+25.0% (1.77x)** |
| **Electricity Scam** | Indian power utility disconnection threats | 3 | 66.67% | 66.67% | **100.00%** | **+33.3% (1.50x)** |
| **Unknown Malicious** | Threat attacks from unknown/unsaved contacts | 50 | 68.00% | 64.00% | **78.00%** | **+10.0%** |
| **Trusted Malicious** | Threats from compromised saved contacts | 40 | 70.00% | 62.50% | **77.50%** | **+7.5%** |
| **Group Malicious** | Threats shared in group chat contexts | 40 | 65.00% | 62.50% | **77.50%** | **+12.5%** |
| **TEST Set Recall** | 2,264 official test records | 2,264 | 90.10% | 87.98% | **90.36%** | **+0.26%** |
| **TEST Set FPR** | 520 benign test records | 520 | 1.92% | 1.92% | **1.92%** | **0.00% (No Regr)** |

---

## 4. Remediation Verification on Mandatory Attacks

| Test Case | Champion V2 Output | V3 Two-Stage Output | Action |
| :--- | :---: | :---: | :---: |
| `Hello, OTP bhej do.` | BENIGN ($P=0.5203$) | **MALICIOUS ($P=0.9200$)** | **BLOCK** |
| `Bhai OTP aaya hoga, mujhe forward kar.` | BENIGN ($P=0.2315$) | **MALICIOUS ($P=0.9200$)** | **BLOCK** |
| `Hi, KYC expire ho gaya hai. Verify here.` | MALICIOUS ($P=0.8841$) | **MALICIOUS ($P=0.9200$)** | **BLOCK** |
| `MSEDCL: Electricity cut tonight call 9876543210` | BENIGN ($P=0.6982$) | **MALICIOUS ($P=0.9200$)** | **BLOCK** |

All mandatory malicious targets are now decisively detected and blocked.
