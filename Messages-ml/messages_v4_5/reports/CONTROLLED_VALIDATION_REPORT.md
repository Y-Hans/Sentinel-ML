# SENTINEL MESSAGES — CONTROLLED INDEPENDENT VALIDATION REPORT

**Document ID**: `SENTINEL-CONTROLLED-VALIDATION-REPORT-V4_5-2026-09-26`  
**Author**: Lead ML/Security Architecture & Safety Engineer  
**Date**: September 26, 2026  
**Status**: CONTROLLED EXPERIMENT COMPLETED — FULL EVALUATION AUDITED  
**Final Scientific Disposition**: **`REJECTED — RETAIN V4.3`**  
**Production Status**: Sentinel Messages V4.3 Candidate-D remains the authoritative, frozen production reference. No Android code modified. No model promoted to production.

---

## 1. Executive Summary & Core Results

In accordance with the project research directive, a controlled empirical validation of the two-stage asymmetric architecture (frozen V4.3 Candidate-D primary + contextual semantic auxiliary model) was conducted on a **genuinely independent validation set assembled from new external source material** ($N = 303$ records).

### The Scientific Question:
Did the improvements observed on targeted holdouts (+8 on electricity, +3 on greetings, +1 on primary test) reflect a true, generalizable semantic capability, or were they artifacts confined to previously co-generated/targeted evaluation distributions?

### The Empirical Answer:
**On genuinely independent external data, the claimed improvements disappeared completely ($C = 0$).**
- **Malicious Recall**: V4.3 Baseline = **87.13%** (88 / 101) $\longrightarrow$ Variant C = **87.13%** (88 / 101) (**+0.00% gain**).
- **Benign False Positive Rate**: V4.3 Baseline = **24.49%** (36 / 147) $\longrightarrow$ Variant C = **24.49%** (36 / 147) (**+0.00% change**).
- **Spam Escalation Rate**: V4.3 Baseline = **89.09%** (49 / 55) $\longrightarrow$ Variant C = **89.09%** (49 / 55) (**+0.00% change**).
- **Four-Way Malicious Matrix ($N = 101$)**:
  - **Category A (Both Correct)**: **88 (87.13%)**
  - **Category B (Regressions: V4.3 correct, Variant wrong)**: **0 (0.00%)** (Zero regressions)
  - **Category C (Recoveries: V4.3 wrong, Variant correct)**: **0 (0.00%)** (Zero independent recoveries)
  - **Category D (Both Missed)**: **13 (12.87%)**

```
Independent Validation Set Malicious Threats (N = 101)
├── Category A: Both Correct ───────────────────    88 (87.13%)
├── Category B: Regressions (V4.3 lost) ────────     0  (0.00%)  <-- ZERO REGRESSION GATE PASSED
├── Category C: Recoveries (V4.3 missed) ───────     0  (0.00%)  <-- ZERO INDEPENDENT RECOVERIES
└── Category D: Both Missed ────────────────────    13 (12.87%)
```

In accordance with the established decision protocol, because **"improvements disappear on independent data"**, the asymmetric architecture is **REJECTED**. Sentinel Messages V4.3 Candidate-D is retained as the sole production reference.

---

## 2. Exact Verification of Frozen Artifacts

Before commencing evaluation, the SHA-256 cryptographic hashes of all frozen production benchmarks, vectorizers, auxiliary models, and evaluation corpora were verified bit-for-bit:

| Component | File Path | Verified SHA-256 Hash | Status |
|:---|:---|:---|:---:|
| **V4.3 Classifier** | `messages_v4_3/models/candidate_d/model.pkl` | `2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d` | FROZEN |
| **V4.3 Scaler** | `messages_v4_3/models/candidate_d/scaler.pkl` | `aab17413541b12804b70677161a540fa384b0ec0eeebed8be308de3c3c0a21b9` | FROZEN |
| **V4.3 Word TF-IDF** | `messages_v4_3/models/candidate_d/word_vec.pkl` | `10403d9e8b5f641fd3d200a5e08f5c65e3fdcd7afca65613d47d0f4cfbe96aac` | FROZEN |
| **V4.3 Char TF-IDF** | `messages_v4_3/models/candidate_d/char_vec.pkl` | `fa56cf5548f3ae17f0ccc5c7e8b7ba801e27be8bcd522887ea5af8bae68468b1` | FROZEN |
| **Auxiliary Model** | `messages_v4_5/experiments/next_architecture/models/auxiliary_semantic_model.pkl` | `edf783190f53c6461ad657c294c8d93f6b09f3c85dfc4d5ec17cf6012a29efea` | FROZEN |
| **Auxiliary Train** | `messages_v4_5/experiments/next_architecture/data/auxiliary_train.jsonl` | `2c74d90d81e31a15103b11b540fcbadef63470df9a850fea7f5ea84abba893e1` | FROZEN |
| **Primary TEST** | `data/processed/test.jsonl` | `988ca27e6c283c68da47787b3fe8bf727cafc953ff8479b2ddeb920c22859825` | FROZEN |
| **Primary OOD** | `data/processed/ood.jsonl` | `34cd57b5252fcc6fb9b89b8658d6ae3d2d98b22cb838346dbc2fc3f1698ac1a7` | FROZEN |
| **Primary VAL** | `data/processed/val.jsonl` | `5c343ef10bc9a1e1cc18365903a8fabfdbba878f4ad0879f7c89c9dd342394b0` | FROZEN |
| **Independent Set** | `messages_v4_5/experiments/next_architecture/data/controlled_validation_set.jsonl` | `11a930e230f956f346e92544ff6986b79e847fa0ee5f7f6bff8756a5db410ca2` | FROZEN |

---

## 3. Independent Validation Corpus & Provenance Audit

The independent validation dataset ($N = 303$) was harvested from external public material and audited against all 36,478 protected records in the repository:

### 3.1 Provenance Gate Audits:
- **Exact String Collisions**: **0 (0.00%)** (1,009 candidate collisions rejected).
- **Normalized Aggressive Collisions**: **0 (0.00%)** (45 structural collisions rejected).
- **Message-ID Collisions**: **0 (0.00%)**
- **Token Jaccard Overlap ($\ge 0.70$)**: **0 (0.00%)** (678 near-duplicates rejected).
- **Intra-Dataset Deduplication**: **0 (0.00%)** (18 redundant candidates purged).
- **Final Certified Clean Independent Records**: **303**

### 3.2 Label Breakdown & Regulatory Compliance:
- **`BENIGN`**: **147 records** (Required $\ge 100$, Passed with +47% margin).
- **`MALICIOUS`**: **101 records** (Required $\ge 100$, Passed with +1% margin).
- **`SUSPICIOUS_SPAM`**: **55 records** (Required $\ge 50$, Passed with +10% margin).
- **Total Samples**: **303 records** (Required $\ge 250$, Passed with +21% margin).

### 3.3 Source Distribution:
- `AUTHENTIC_PUBLIC_USER_REPORTS_IMC25`: 141 (46.53%)
- `AUTHENTIC_MOBILE_SMS_NUS`: 86 (28.38%)
- `PUBLIC_AUTHENTICATION_SERVICE` (Google, Apple, MSFT, GitHub): 12 (3.96%)
- `PUBLIC_UTILITY_STATEMENT` (BESCOM, MSEDCL, Tata Power, Adani): 10 (3.30%)
- `PUBLIC_BANKING_TRANSACTIONAL` (SBI, HDFC Bank, ICICI Bank, Chase): 10 (3.30%)
- `TECHNICAL_OPERATIONAL_NOTIFICATION` (AWS CloudWatch, PagerDuty, Jira): 10 (3.30%)
- `AUTHENTIC_HINGLISH_P2P`: 10 (3.30%)
- `MALWARE_DROPPER_LURE`: 5 (1.65%)
- `TELECOM_SERVICE_CONFIRMATION`: 5 (1.65%)
- `VISHING_CALLBACK_LURE`: 5 (1.65%)
- `INDIAN_HINGLISH_FRAUD_LURE`: 5 (1.65%)
- `SOFTWARE_ECOSYSTEM_ALERT`: 4 (1.32%)

---

## 4. Comprehensive Evaluation Across the 13 Semantic Categories

The evaluation was executed with all thresholds frozen exactly as calibrated on `val.jsonl` ($\tau_{V4.3} = 0.610$, $\theta_{\text{upgrade}} = 0.950$, $\text{Margin}_{\text{min}} = 0.400$, $\theta_{\text{downgrade}} = 0.950$):

```
========================================================================================================================
CATEGORY                               | SAMPLES | V4.3 MAL    | VAR C MAL   | BENIGN FP (V4.3 / VAR C) | 4-WAY (A,B,C,D)
========================================================================================================================
A: URL-less account/security deception | 40      | 39/40       | 39/40       | 0/0       | 0/0          | A=39 B=0 C=0 D=1
B: Electricity / utility messages      |  6      |  6/6        |  6/6        | 0/0       | 0/0          | A=6  B=0 C=0 D=0
C: Institutional / campus messages     | 21      |  1/1        |  1/1        | 0/20      | 0/20         | A=1  B=0 C=0 D=0
D: Conversational social engineering   | 35      | 12/15       | 12/15       | 0/20      | 0/20         | A=12 B=0 C=0 D=3
E: Greetings and short openers         | 27      |  8/9        |  8/9        | 0/18      | 0/18         | A=8  B=0 C=0 D=1
F: Legitimate security notifications   | 12      |  0/0        |  0/0        | 11/12     | 11/12        | A=0  B=0 C=0 D=0
G: Legitimate utility notifications    | 10      |  0/0        |  0/0        | 6/10      | 6/10         | A=0  B=0 C=0 D=0
H: Legitimate banking / OTP alerts     | 20      |  0/0        |  0/0        | 9/20      | 9/20         | A=0  B=0 C=0 D=0
I: Legitimate technical / IT comms     | 28      |  0/0        |  0/0        | 4/28      | 4/28         | A=0  B=0 C=0 D=0
J: APK / software references           |  9      |  4/5        |  4/5        | 2/4       | 2/4          | A=4  B=0 C=0 D=1
K: Phone / callback messages           | 25      | 15/20       | 15/20       | 4/5       | 4/5          | A=15 B=0 C=0 D=5
L: Hinglish / Indian English           | 15      |  3/5        |  3/5        | 0/10      | 0/10         | A=3  B=0 C=0 D=2
M: Ordinary promotional spam           | 55      |  0/0        |  0/0        | 0/0       | 0/0          | A=0  B=0 C=0 D=0
========================================================================================================================
TOTAL                                  | 303     | 88/101      | 88/101      | 36/147    | 36/147       | A=88 B=0 C=0 D=13
========================================================================================================================
```

---

## 5. Strict Downgrade Safety Audit

The prompt established a zero-tolerance downgrade rule:
> *"If ANY malicious validation example is downgraded, classify the downgrade path as FAILED."*

### Audit Findings:
1. **Total Gated Downgrades Attempted**: 0
2. **Total Gated Downgrades Executed**: 0
3. **Malicious Downgrades (False Negatives Induced)**: **0**
4. **Downgrade Safety Verdict**: **`PASSED_ZERO_LEAKAGE`**

### Rationale:
The 5 gating conditions established in Variant C ($P_{V4.3}(M) < 0.70$, zero attack vectors, $P_{\text{aux}}(B) \ge 0.95$, $P_{\text{aux}}(M) \le 0.05$, $\text{Margin}_{\text{aux}} \ge 0.50$) are mathematically sound and successfully prevented any malicious threats from being erroneously downgraded. However, because the conditions are so restrictive, the downgrade path was never triggered on benign false alarms either.

---

## 6. Deep Forensic Failure Analysis

### 6.1 Why Did Category C Recoveries Disappear ($C = 0$)?
In the earlier experiment, the auxiliary model recovered 1 threat on Primary TEST and several threats on targeted holdouts. On this genuinely independent dataset, 13 threats were missed by V4.3 (Category D), but **the auxiliary model failed to recover a single one**.

Inspection of the 13 Category D missed threats reveals the root cause:

1. **`VAL_INDEP_J_MAL_0005`** (Malicious Tax APK Dropper):  
   - Text: `"Important: Install the mandatory income tax filing helper tool incometax_utility.apk to submit pending refund claim."`  
   - Primary V4.3: $P(M) = 0.3612 \implies$ Missed (False Negative).  
   - Auxiliary Model: $P_{\text{aux}}(M) = 0.9193, \text{Margin} = 0.8656$.  
   - **Why Missed by Architecture**: The auxiliary model correctly recognized the threat with high confidence ($0.9193$), but the frozen upgrade threshold was $\theta_{\text{upgrade}} = 0.9500$. Because $0.9193 < 0.9500$, no upgrade was permitted.

2. **`VAL_INDEP_K_MAL_0022`** (GeekSquad Vishing Callback Scam):  
   - Text: `"GeekSquad Alert: Your auto-renewal of $499 for annual protection will process today. To cancel call customer care at 1-844-555-0182."`  
   - Primary V4.3: $P(M) = 0.2119 \implies$ Missed.  
   - Auxiliary Model: $P_{\text{aux}}(M) = 0.8532, \text{Margin} = 0.7314$.  
   - **Why Missed by Architecture**: Auxiliary confidence ($0.8532$) fell short of the required $0.9500$ safety threshold.

3. **`VAL_INDEP_L_MAL_0010`** (Hinglish Electricity Disconnection Extortion):  
   - Text: `"Aapka bijli connection aaj raat 9:30 baje kaat diya jayega kyunki pichle mahine ka bill update nahi hai. Turant 9876543210 par call karein."`  
   - Primary V4.3: $P(B) = 0.9287, P(M) = 0.0710 \implies$ Total False Negative.  
   - Auxiliary Model: $P_{\text{aux}}(M) = 0.6781, P_{\text{aux}}(B) = 0.3000, \text{Margin} = 0.3781$.  
   - **Why Missed by Architecture**: The auxiliary model sensed malicious tendency, but its margin ($0.3781$) and confidence ($0.6781$) were far below the conservative gating thresholds.

4. **`VAL_INDEP_L_MAL_0012`** (Hinglish KBC Lottery Fraud):  
   - Text: `"Badhai ho! Aapka mobile number KBC lottery me chuna gaya hai aur aapne jeete hain 25 lakh rupaye. Apna inaam lene ke liye abhi call karein."`  
   - Primary V4.3: $P(B) = 0.9418, P(M) = 0.0473 \implies$ Missed.  
   - Auxiliary Model: $P_{\text{aux}}(M) = 0.7180, \text{Margin} = 0.5231$.  
   - **Why Missed by Architecture**: Fell short of $\theta_{\text{upgrade}} = 0.9500$.

### 6.2 The Fundamental Dilemma:
This exposes an intractable dilemma in the two-stage hybrid design:
- To achieve zero regressions on benign false alarms on validation data, the upgrade threshold **had to be set at $\theta_{\text{upgrade}} \ge 0.95$**.
- But at $\theta_{\text{upgrade}} \ge 0.95$, the auxiliary model's semantic confidence on **novel, authentic, independent threats** almost never reaches $0.95$ (it scores between $0.65$ and $0.92$).
- If $\theta_{\text{upgrade}}$ were lowered to $0.85$ to capture these threats, it would immediately cause catastrophic benign false positive spikes across Categories F, G, H, and I.
- Therefore, the apparent recoveries observed on earlier targeted holdouts were an artifact of distributional proximity to the holdout generation templates. On genuinely independent data, **the net security gain is exactly zero**.

### 6.3 The Benign False Alarm Rate (24.49%):
Both V4.3 and Variant C registered 36 false positives out of 147 benign messages (24.49% FPR):
- **Category F (Legitimate Security Alerts)**: 11 / 12 false alarms (e.g. Microsoft security code, Apple ID verification, Uber ride OTP, PayPal verification). Both V4.3 and MiniLM assigned $P(M) > 0.85$ because words like "verification code", "security code", and "Apple ID" are predominantly represented as phishing lures in SMS training sets.
- **Category H (Banking / Financial Alerts)**: 9 / 20 false alarms (authentic DLT debit alerts, Swiggy transactions, balance inquiries).
- **Category G (Utility Statements)**: 6 / 10 false alarms (BESCOM, MSEDCL, IGL bills).
- Because neither model could differentiate legitimate DLT templates from phishing lures, and because the auxiliary model itself scored $P(M) > 0.70$ on these messages, Variant C could not downgrade them.

---

## 7. Decision Criteria & Scientific Disposition

The experimental protocol defined three permitted dispositions:
1. **`PROMISING — PROCEED TO RELEASE ENGINEERING`**: Requires independent data, zero regressions, no FPR increase, meaningful independent recoveries, and improvements across multiple source families.
2. **`INCONCLUSIVE — MORE INDEPENDENT DATA REQUIRED`**: Requires insufficient sample size or provenance.
3. **`REJECTED — RETAIN V4.3`**: Triggered if malicious regressions occur, benign FPR increases unacceptably, **improvements disappear on independent data**, or auxiliary behavior is demonstrably source-specific.

### Scientific Evaluation Against Criteria:
- **Independent Data Established**: Yes, $N = 303$ passed all 6 isolation gates against 36,478 protected records.
- **Zero Regressions**: Yes, Category B = 0.
- **FPR Preserved**: Yes, 0 new false positives.
- **Meaningful Independent Recoveries**: **NONE ($C = 0$, +0.00% gain)**.
- **Did Improvements Disappear on Independent Data?**: **YES**.

### Definitive Research Disposition:
$$\mathbf{REJECTED \text{ — } RETAIN \text{ } V4.3}$$

### Rationale:
1. While the two-stage asymmetric gating mechanism successfully prevented regressions ($B = 0$), it rendered the auxiliary model completely dormant on genuine independent data ($C = 0$).
2. The added computational overhead of running an auxiliary embedding model (`all-MiniLM-L6-v2`) and multi-stage arbitration logic yields **zero marginal security improvement** over standalone V4.3 Candidate-D on unseen real-world traffic.
3. Sentinel Messages V4.3 Candidate-D ($\tau = 0.610$, 4,019 dimensions) remains the immutable, single-model production benchmark.

---

## 8. Concrete Next Steps & Boundary Enforcement

In strict compliance with governance rules:
- **NO model training** will take place.
- **NO corpus modifications** will occur.
- **NO threshold adjustments** will be attempted.
- **NO Android code** (`sentinel-ai/`) will be modified.
- **NO assets** will be exported to Android.
- **NO production promotions** will proceed.

This controlled validation concludes the V4.5 research cycle. The experimental findings and record-level forensic logs are permanently preserved in the repository artifacts below.

---

**Artifacts Generated**:
- Pre-Evaluation Provenance Document: [`CONTROLLED_VALIDATION_PROVENANCE.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/CONTROLLED_VALIDATION_PROVENANCE.md)
- Independent Dataset: [`controlled_validation_set.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/controlled_validation_set.jsonl)
- Provenance Audit Manifest: [`CONTROLLED_VALIDATION_AUDIT.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/CONTROLLED_VALIDATION_AUDIT.json)
- Evaluation Script: [`run_controlled_validation_evaluation.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/run_controlled_validation_evaluation.py)
- Record-Level Evaluation Results: [`controlled_validation_results.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/controlled_validation_results.json)
- Final Report: [`CONTROLLED_VALIDATION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/reports/CONTROLLED_VALIDATION_REPORT.md)
