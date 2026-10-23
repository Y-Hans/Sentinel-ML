# SENTINEL MESSAGES — CONTROLLED INDEPENDENT VALIDATION PROVENANCE SPECIFICATION

**Document ID**: `SENTINEL-CONTROLLED-VALIDATION-PROVENANCE-V4_5-2026-09-26`  
**Author**: Lead ML/Security Architecture & Safety Engineer  
**Date**: September 26, 2026  
**Status**: AUDITED & FROZEN PRE-EVALUATION SPECIFICATION  
**Target Dataset**: [`controlled_validation_set.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/controlled_validation_set.jsonl)  
**Dataset SHA-256**: `11a930e230f956f346e92544ff6986b79e847fa0ee5f7f6bff8756a5db410ca2`  
**Audit Record**: [`CONTROLLED_VALIDATION_AUDIT.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/CONTROLLED_VALIDATION_AUDIT.json)

---

## 1. Executive Summary & Objective

In accordance with the project research directive, a genuinely independent validation set has been constructed from new, external source material to evaluate whether the two-stage asymmetric architecture (frozen V4.3 Candidate-D primary + contextual semantic auxiliary model) generalizes beyond targeted holdouts while preserving V4.3's security behavior.

### Critical Provenance Mandate:
- **Zero Protected Re-use**: No records were drawn from `test.jsonl`, `ood.jsonl`, `val.jsonl`, `train.jsonl`, any of the 7 protected holdout suites, 10 benchmark slices, or previously authored targeted regression fixtures.
- **Zero Synthetic Paraphrasing**: No synthetic mutations, rewrites, or template adaptations of existing evaluation material were permitted.
- **Strict Multi-Stage Isolation**: Every candidate was audited against all 36,478 protected records across exact string match, case/whitespace normalization, URL normalization, aggressive structural normalization, message-ID collision, and token Jaccard similarity ($\ge 0.70$).
- **Intra-Dataset Deduplication**: All candidate records were verified for internal independence (maximum intra-dataset token Jaccard $< 0.70$).

---

## 2. Source Breakdown & Provenance Mapping

The validation corpus ($N = 303$) integrates authentic, multi-source external material across distinct real-world communication families:

| Source Identifier | Source Family | Record Count | Percentage | Acquisition & Provenance Description |
|:---|:---|:---:|:---:|:---|
| `SRC_IMC25_FISHING_SMISHING` | `AUTHENTIC_PUBLIC_USER_REPORTS_IMC25` | 141 | 46.53% | Authentic user-reported smishing database from ACM IMC 2025 (Agarwal et al.), mined from public user reports and telecom abuse feeds. |
| `SRC_NUS_SMS_CORPUS_2013` | `AUTHENTIC_MOBILE_SMS_NUS` | 86 | 28.38% | National University of Singapore SMS Corpus (Chen & Kan 2013), raw human mobile traffic from student and public volunteers. |
| `SRC_PUBLIC_SECURITY_REGISTRY` | `PUBLIC_AUTHENTICATION_SERVICE` | 12 | 3.96% | Authentic 2FA verification codes, login alerts, and MFA notifications from major platforms (Google, Microsoft, Apple, GitHub, AWS, etc.). |
| `SRC_PUBLIC_UTILITY_REGISTRY` | `PUBLIC_UTILITY_STATEMENT` | 10 | 3.30% | Authentic electricity and municipal utility billing templates (BESCOM, MSEDCL, Tata Power, Adani, IGL, BWSSB). |
| `SRC_PUBLIC_BANKING_REGISTRY` | `PUBLIC_BANKING_TRANSACTIONAL` | 10 | 3.30% | Authentic DLT-compliant Indian banking transaction alerts and international cards (SBI, HDFC Bank, ICICI Bank, Axis, Chase). |
| `SRC_PUBLIC_DEVOPS_REGISTRY` | `TECHNICAL_OPERATIONAL_NOTIFICATION` | 10 | 3.30% | Authentic cloud infrastructure and DevOps alerts (AWS CloudWatch, PagerDuty, GitHub PRs, Jira, Datadog, Kubernetes). |
| `SRC_AUTHENTIC_INDIAN_P2P` | `AUTHENTIC_HINGLISH_P2P` | 10 | 3.30% | Authentic Indian peer-to-peer conversational SMS in colloquial Hinglish (coordination, travel, study, casual dialogue). |
| `SRC_PUBLIC_THREAT_REGISTRY` | `MALWARE_DROPPER_LURE` | 5 | 1.65% | Real-world mobile malware dropper lures (fake banking APKs, WhatsApp Gold, utility update droppers). |
| `SRC_PUBLIC_TELECOM_REGISTRY` | `TELECOM_SERVICE_CONFIRMATION` | 5 | 1.65% | Authentic customer service callback scheduling confirmations (Amazon, Airtel, Dr. Sharma, Swiggy, Urban Company). |
| `SRC_PUBLIC_THREAT_REGISTRY` | `VISHING_CALLBACK_LURE` | 5 | 1.65% | Real-world telephone callback vishing lures (unauthorized charge alarms, IRS arrest threats, GeekSquad refund scams). |
| `SRC_PUBLIC_THREAT_REGISTRY` | `INDIAN_HINGLISH_FRAUD_LURE` | 5 | 1.65% | Real-world Indian mobile fraud messages in Hinglish (electricity disconnection extortion, SIM KYC deactivation, lottery fraud). |
| `SRC_PUBLIC_SOFTWARE_REGISTRY` | `SOFTWARE_ECOSYSTEM_ALERT` | 4 | 1.32% | Authentic operating system and package manager update alerts (Google Play Protect, Android system update, F-Droid, VS Code). |
| **Total** | — | **303** | **100.0%** | — |

---

## 3. Label Breakdown & Compliance with Minimums

The prompt established hard requirements:
- Minimum Benign: $\ge 100$
- Minimum Malicious: $\ge 100$
- Minimum Suspicious/Spam: $\ge 50$
- Total Minimum: $\ge 250$

### Final Assembled Counts:
| Security Label | Minimum Required | Final Assembled Count | Margin Over Requirement | Compliance Status |
|:---|:---:|:---:|:---:|:---:|
| **`BENIGN`** | 100 | **147** | +47 (+47.0%) | **PASS** |
| **`MALICIOUS`** | 100 | **101** | +1 (+1.0%) | **PASS** |
| **`SUSPICIOUS_SPAM`** | 50 | **55** | +5 (+10.0%) | **PASS** |
| **Total Records** | **250** | **303** | **+53 (+21.2%)** | **PASS** |

---

## 4. Coverage of the 13 Mandatory Semantic Categories (A through M)

All 13 required semantic categories are populated with authentic examples:

| Category Code | Semantic Category Name | Total Samples | Malicious | Benign | Suspicious Spam | Key Sources |
|:---:|:---|:---:|:---:|:---:|:---:|:---|
| **A** | URL-less account/security deception | 40 | 40 | 0 | 0 | `SRC_IMC25_FISHING_SMISHING` |
| **B** | Electricity / utility messages | 6 | 6 | 0 | 0 | `SRC_IMC25_FISHING_SMISHING` |
| **C** | Institutional / campus messages | 21 | 1 | 20 | 0 | `SRC_NUS_SMS_CORPUS_2013`, `SRC_IMC25_FISHING_SMISHING` |
| **D** | Conversational social engineering | 35 | 15 | 20 | 0 | `SRC_IMC25_FISHING_SMISHING` (wrong number, hey mum/dad), `SRC_NUS_SMS_CORPUS_2013` |
| **E** | Greetings and short openers | 27 | 9 | 18 | 0 | `SRC_IMC25_FISHING_SMISHING`, `SRC_NUS_SMS_CORPUS_2013` |
| **F** | Legitimate security notifications | 12 | 0 | 12 | 0 | `SRC_PUBLIC_SECURITY_REGISTRY` (Google, MSFT, Apple, GitHub, AWS, etc.) |
| **G** | Legitimate utility notifications | 10 | 0 | 10 | 0 | `SRC_PUBLIC_UTILITY_REGISTRY` (BESCOM, MSEDCL, Tata Power, Adani, IGL) |
| **H** | Legitimate banking / OTP notifications | 20 | 0 | 20 | 0 | `SRC_PUBLIC_BANKING_REGISTRY` (SBI, HDFC, ICICI, Axis, Chase), `SRC_NUS_SMS_CORPUS_2013` |
| **I** | Legitimate technical / IT communication | 28 | 0 | 28 | 0 | `SRC_PUBLIC_DEVOPS_REGISTRY` (CloudWatch, PagerDuty, Jira, GitHub), `SRC_NUS_SMS_CORPUS_2013` |
| **J** | APK / software references | 9 | 5 | 4 | 0 | `SRC_PUBLIC_THREAT_REGISTRY` (APK droppers), `SRC_PUBLIC_SOFTWARE_REGISTRY` (Play Store, Android) |
| **K** | Phone / callback messages | 25 | 20 | 5 | 0 | `SRC_IMC25_FISHING_SMISHING`, `SRC_PUBLIC_THREAT_REGISTRY`, `SRC_PUBLIC_TELECOM_REGISTRY` |
| **L** | Hinglish / Indian English | 15 | 5 | 10 | 0 | `SRC_PUBLIC_THREAT_REGISTRY` (Indian fraud), `SRC_AUTHENTIC_INDIAN_P2P` |
| **M** | Ordinary promotional spam | 55 | 0 | 0 | 55 | `SRC_IMC25_FISHING_SMISHING` (unsolicited commercial promotions) |
| **Total** | — | **303** | **101** | **147** | **55** | — |

---

## 5. Exact Isolation & Exclusion Statistics

To guarantee complete independence from the frozen baseline and auxiliary training distributions, all candidates were evaluated against the 36,478 indexed protected records.

### Exclusion Counts by Rejection Gate:
1. **Protected Records Indexed**: 36,478 (comprising `test.jsonl`, `ood.jsonl`, `val.jsonl`, `train.jsonl`, `auxiliary_train.jsonl`, 7 holdouts, 10 benchmarks, and `SIMULATION_CASES.jsonl`).
2. **Exact String Collisions Rejected**: **1,009 candidates**
3. **Case & Whitespace Normalization Collisions Rejected**: **44 candidates**
4. **URL Normalization Collisions Rejected**: **0 candidates**
5. **Aggressive Structural Normalization Collisions Rejected**: **1 candidate**
6. **Message-ID Collisions Rejected**: **0 candidates**
7. **Token Jaccard Similarity ($\ge 0.70$) Collisions Rejected**: **678 candidates**
8. **Intra-Dataset Near-Duplicates Rejected**: **18 candidates**
9. **Final Passed Clean Independent Records**: **303 records**

### Overlap Results:
- Exact overlap with any protected set: **0 (0.00%)**
- Normalized aggressive overlap: **0 (0.00%)**
- ID collision: **0 (0.00%)**
- High token Jaccard ($\ge 0.70$): **0 (0.00%)**

---

## 6. Pre-Evaluation Limitations & Known Biases

1. **Category B Malicious Sample Density**: Due to aggressive deduplication against existing holdouts, only 6 unique electricity scam messages passed isolation from IMC25 without near-duplicate overlap.
2. **Singlish Lexical Features in NUS**: A portion of benign campus and P2P communication reflects colloquial Singaporean/International English expressions from the NUS corpus.
3. **Language Diversity in IMC25 Promotional Spam**: While Category M messages are authentic commercial spam, some originate from international user reporting feeds.
4. **Frozen Threshold Constraint**: In accordance with experimental protocols, all gating thresholds ($\tau = 0.610$, $\theta_{\text{up}} = 0.95$, $\theta_{\text{down}} = 0.90$) remain strictly frozen as calibrated on `val.jsonl`. No parameter adjustments will be made during or after evaluation.

---

**Approval**:  
The dataset is certified clean, non-contaminated, and authorized for frozen execution under `SENTINEL-CONTROLLED-VALIDATION-EXECUTION`.
