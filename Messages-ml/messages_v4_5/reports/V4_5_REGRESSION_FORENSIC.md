# SENTINEL MESSAGES V4.5 — GLOBAL REGRESSION FORENSIC REPORT

**Author**: Lead ML/Repository Engineer  
**Date**: September 23, 2026  
**Evaluation Scope**: Primary TEST Split (`data/processed/test.jsonl`, $N=2264$)  
**Comparison**: Sentinel V4.3 Production Baseline ($\tau=0.610$) vs Sentinel V4.5 Stage 1 Ablation C ($\tau=0.860$)  

---

## 1. Executive Summary & Aggregate Balance Sheet

On the primary test benchmark (`test.jsonl`), comparing the frozen V4.3 production baseline against V4.5 Stage 1 (Contextual + Structural):

| Metric | V4.3 Production Baseline | V4.5 Stage 1 (Ablation C) | Net Delta |
|:---|:---:|:---:|:---:|
| **Malicious Test Recall** | **97.04%** (1510 / 1556) | **77.70%** (1209 / 1556) | **-19.34% (-301 records)** |
| **Benign Test FPR** | **0.38%** (2 / 520) | **3.08%** (16 / 520) | **+2.70% (+14 FPs)** |
| **Malicious Correctly Caught** | 1510 | 1209 | -301 |
| **Malicious Newly Missed** | — | **307** | — |
| **Malicious Newly Recovered** | — | **6** | — |
| **Benign FPs Newly Introduced** | — | **15** | — |
| **Benign FPs Corrected** | — | **1** | — |

**Core Forensic Finding**: While V4.5 Stage 1 drastically improved targeted semantic holdouts (reducing greeting FPs to 0% and utility FPs from 50.9% to 5.5%), it caused a catastrophic **net loss of 301 malicious primary test records** and an **8x increase in benign test false positive rate**.

---

## 2. Failure Mechanism Taxonomy (The 307 Missed Malicious Records)

The 307 primary test malicious records correctly identified by V4.3 but missed by V4.5 fall into two primary structural mechanisms:

```
Total Missed Malicious Records (N=307)
├── 1. MALICIOUS → SPAM Class Confusion: 166 records (54.1%)
└── 2. MALICIOUS → BENIGN Threshold Drop:  141 records (45.9%)
```

### Mechanism 1: MALICIOUS $\to$ SUSPICIOUS_SPAM Class Confusion ($N=166$, 54.1%)
In frozen MiniLM embedding space, generic sentence embeddings cluster messages based on topical similarity rather than threat intent. As a result, commercial smishing, lottery lures, pre-approved loan traps, and gift card scams are mapped into the commercial `SPAM` centroid rather than the `MALICIOUS` centroid ($P(\text{SPAM}) > P(\text{MALICIOUS})$).
Because the Sentinel security policy requires a positive malicious classification ($P(\text{MALICIOUS}) \ge P(\text{SPAM})$), these 166 records fail the primary threat gate.

**Key Examples**:
1. `MSG_SRC_IMC25_FISHING_SMISHING_0019840`:
   - *Text*: `"Approval in <DATE_TIME> and loan credit in <DATE_TIME>. You are one click away to get pre-approved loan..."`
   - *V4.3*: $P(\text{B})=0.000, P(\text{S})=0.098, P(\text{M})=0.902 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.003, P(\text{S})=0.576, P(\text{M})=0.422 \to$ **SUSPICIOUS_SPAM** (Missed)
2. `MSG_SRC_IMC25_FISHING_SMISHING_0018443`:
   - *Text*: `"Welcome To PAYTM MALL COMPANY <URL> Dear Customer, Congratulations, Your Name is Selected In The Lucky Draw..."`
   - *V4.3*: $P(\text{B})=0.001, P(\text{S})=0.119, P(\text{M})=0.880 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.001, P(\text{S})=0.859, P(\text{M})=0.141 \to$ **SUSPICIOUS_SPAM** (Missed)
3. `MSG_SRC_IMC25_FISHING_SMISHING_0020343`:
   - *Text*: `"Dear customer Your Car is to sell in <NUM> hr Free RC Transfer Give misscall <PHONE_NUMBER>..."`
   - *V4.3*: $P(\text{B})=0.000, P(\text{S})=0.080, P(\text{M})=0.920 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.007, P(\text{S})=0.683, P(\text{M})=0.310 \to$ **SUSPICIOUS_SPAM** (Missed)

### Mechanism 2: MALICIOUS $\to$ BENIGN Threshold Drop ($N=141$, 45.9%)
To enforce $\text{FPR} \le 2.0\%$ on `val.jsonl`, the V4.5 decision threshold climbed to $\tau=0.8600$ (compared to V4.3's $\tau=0.6100$). A large fraction of malicious messages (especially bank impersonations, delivery failures, and conversational pings) scored between $0.40$ and $0.85$ non-benign probability and were therefore classified as completely `BENIGN`.

**Key Examples**:
1. `MSG_SRC_IMC25_FISHING_SMISHING_0015687`:
   - *Text*: `"Dear user your SBI YONO Account will be closed today please update PAN card immediately..."`
   - *V4.3*: $P(\text{B})=0.002, P(\text{S})=0.001, P(\text{M})=0.997 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.749, P(\text{S})=0.006, P(\text{M})=0.245 \to$ **BENIGN** (Severe Miss)
2. `MSG_SRC_IMC25_FISHING_SMISHING_0017534`:
   - *Text*: `"Dear Customer your electricity powar will be disconnect <DATE_TIME> your bill is not update please call..."`
   - *V4.3*: $P(\text{B})=0.000, P(\text{S})=0.001, P(\text{M})=0.999 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.253, P(\text{S})=0.008, P(\text{M})=0.739 \to$ **BENIGN** (Missed at $\tau=0.860$)
3. `MSG_SRC_IMC25_FISHING_SMISHING_0016805`:
   - *Text*: `"DPD UK: Your delivery could not be scheduled due to one or more issues. You can view more information here..."`
   - *V4.3*: $P(\text{B})=0.000, P(\text{S})=0.000, P(\text{M})=1.000 \to$ **MALICIOUS**
   - *V4.5*: $P(\text{B})=0.505, P(\text{S})=0.011, P(\text{M})=0.483 \to$ **BENIGN** (Missed)

---

## 3. Signal Presence in Missed Malicious Records

| Threat Signal Detected | Count in Missed Records | % of Missed Pool |
|:---|:---:|:---:|
| **Conversational Pings / Salutations** | 74 | 24.1% |
| **Institutional & Bank Mentions** | 40 | 13.0% |
| **OTP / Code Verifications** | 26 | 8.5% |
| **Utility & Electricity Terms** | 16 | 5.2% |
| **Hinglish / Romanized Hindi** | 1 | 0.3% |

---

## 4. Newly Introduced Benign False Positives ($N=15$)

V4.5 introduced 15 false positives on benign test messages that V4.3 correctly classified as BENIGN. 
These messages are conversational P2P texts that the frozen MiniLM representation pushed into the SPAM/MALICIOUS cluster:
1. `MSG_SRC_MENDELEY_SMISHING_2022_0003839`:
   - *Text*: `"I didnt get ur full msg..sometext is missing, send it again"`
   - *V4.3*: $P(\text{B})=0.994 \to$ **BENIGN**
   - *V4.5*: $P(\text{B})=0.119, P(\text{S})=0.634, P(\text{M})=0.247 \to$ **SUSPICIOUS_SPAM (FP)**
2. `MSG_SRC_MENDELEY_SMISHING_2022_0000863`:
   - *Text*: `"Hiya , have u been paying money into my account? If so, thanks. Got a pleasant surprise when i checked..."`
   - *V4.3*: $P(\text{B})=0.937 \to$ **BENIGN**
   - *V4.5*: $P(\text{B})=0.063, P(\text{S})=0.138, P(\text{M})=0.799 \to$ **MALICIOUS (Severe FP)**
3. `MSG_SRC_MENDELEY_SMISHING_2022_0001780`:
   - *Text*: `"Webpage s not available!"`
   - *V4.3*: $P(\text{B})=0.890 \to$ **BENIGN**
   - *V4.5*: $P(\text{B})=0.124, P(\text{S})=0.127, P(\text{M})=0.749 \to$ **MALICIOUS (Severe FP)**

---

## 5. Forensic Conclusion

The regression analysis provides undeniable empirical evidence:
1. **Linear classification heads over frozen generic transformer embeddings are completely inadequate for SMS security detection.**
2. While `all-MiniLM-L6-v2` captures high-level semantics that neatly separate curated counterfactual pairs ("Never share OTP" vs "Share OTP"), it lacks domain-specific smishing boundaries.
3. The resulting high overlap between benign and malicious representations forces the decision boundary to $\tau=0.860$, which sacrifices 19.34% of primary test recall.
4. **V4.5 Stage 1 cannot be deployed or promoted.**
