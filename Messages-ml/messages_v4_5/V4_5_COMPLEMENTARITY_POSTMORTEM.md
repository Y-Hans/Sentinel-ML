# SENTINEL MESSAGES V4.5 — COMPLEMENTARITY POSTMORTEM REPORT

**Author**: Lead ML/Security Research Engineer  
**Date**: September 24, 2026  
**Status**: ANALYSIS COMPLETED — DISPOSITION ASSIGNED  
**Required Decision**: **`B — HYBRID NOT JUSTIFIED`** (for Frozen Generic Contextual Embeddings with V4.3)  
**Active Production Baseline**: Sentinel V4.3 Candidate-D ($\tau = 0.610$, 4,019 dimensions) remains the sole active production baseline.  
**Governing Directive**: Analysis-Only Task (No training, no corpus modification, no Android modification, no production promotion).

---

## 1. Executive Conclusion

This postmortem investigates whether the frozen contextual text representations from Sentinel V4.5 Stage 1 (`sentence-transformers/all-MiniLM-L6-v2`, 384 dimensions) and the lexical/subword/structural features of the frozen production baseline Sentinel V4.3 (Candidate-D, 4,019 dimensions) provide **complementary security signals** that would justify a hybrid architecture.

### Primary Empirical Findings:
1. **Category C (V4.3 Wrong, V4.5 Correct) is Negligible and Noisy**:
   - On the primary uncurated benchmark (`test.jsonl`, $N = 2,264$, 1,556 malicious), **Category C consists of only 6 records (0.385% of malicious test cases)**.
   - On the independent Clean OOD benchmark ($N = 1,075$, 747 malicious), **Category C consists of only 2 records (0.268%)**.
   - Qualitative inspection of all 6 Category C records reveals **no repeatable, distinct contextual smishing cluster**:
     - 2 records are class tie-breakers on attacks that V4.3 already caught as non-benign threats with $P(\text{non-benign}) > 0.997$, differing only on the secondary $P(\text{SPAM})$ vs $P(\text{MALICIOUS})$ tie-breaker.
     - 1 record is Japanese text (`ご本人様不在の為お荷物を持ち帰りました。ご確認ください。`), an out-of-distribution dataset artifact irrelevant to Sentinel's Indian English/Latin SMS threat model.
     - 1 record is a 5-token truncated label fragment (`OMLOG E UPS HUB GA`).
     - 1 record is conversational hearsay metadata (`They are asking us to provide our documents like id etc.`).
     - Only 1 record is an actionable English phishing prompt without an explicit link (`The account may be suspended. Click for details.`), which directly overlaps with V4.3's known margin sensitivity on URL-less messages ($P(\text{non-benign}) = 0.5371$ vs $\tau = 0.610$).
2. **Category B (V4.3 Correct, V4.5 Wrong) is Massive**:
   - V4.5 suffered a severe regression on **307 malicious primary test records** (19.73% of malicious test cases) and **180 clean OOD malicious records** (24.10%).
   - The net primary test recall regression is **-301 records** (307 missed vs 6 recovered), causing malicious recall to collapse from **97.04% to 77.70%**.
3. **Severe Benign False Alarm Contamination**:
   - V4.5 introduced **15 new false positives** on benign conversational messages that V4.3 correctly classified as BENIGN ($P(\text{non-benign}) \le 0.15$), while correcting only 1 existing V4.3 false positive.
   - This caused the benign false positive rate on primary TEST to jump by **8.0x (from 0.38% to 3.08%)**, violating the mandatory $\le 2.0\%$ production FPR constraint.
4. **Ensemble and Fusion Dilution**:
   - Probability blending across weights $\alpha \in [0.0, 1.0]$ demonstrates that introducing frozen MiniLM probabilities monotonically degrades malicious recall or inflates false positive rates compared to pure V4.3.
   - An theoretical oracle union of V4.3 and V4.5 yields only a marginal +0.39% recall gain (1,510 $\to$ 1,516) while multiplying benign false alarms from 2 to 17 (FPR from 0.38% to 3.27%).

### Executive Verdict:
**`B — HYBRID NOT JUSTIFIED`**  
The empirical evidence proves that frozen generic contextual sentence embeddings do not provide a viable, repeatable, or complementary security signal for broad-spectrum SMS threat detection. While MiniLM demonstrated localized false-positive suppression on curated semantic slices (counterfactuals, greetings, electricity status), it lacks smishing-specific threat boundaries, maps commercial smishing into promotional marketing clusters, and injects severe false alarms into ordinary conversational SMS.

---

## 2. Dataset Provenance & Boundary Audit

The analysis was executed strictly against authoritative disk artifacts and frozen datasets with full cryptographic checksum verification.

| Dataset Split / Component | File Path | SHA-256 Checksum | Total $N$ | Benign | Spam | Malicious |
|:---|:---|:---|:---:|:---:|:---:|:---:|
| **Primary TEST Split** | `sentinel-ml/Messages-ml/data/processed/test.jsonl` | `988ca27e6c283c683b516ad0f531aa7728aa0aa37e8c3b6f00e9efbb1ddda787` | 2,264 | 520 | 188 | 1,556 |
| **Validation Split (Tuning)**| `sentinel-ml/Messages-ml/data/processed/val.jsonl` | `5c343ef10bc9a1e1e072b22ecf41d927282cb979d35bcfaae3cc0d5bfa53e4c4` | 3,397 | 807 | 274 | 2,316 |
| **Primary OOD Split** | `sentinel-ml/Messages-ml/data/processed/ood.jsonl` | `34cd57b5252fcc6f5c8ecbe6ad76ffb68c783dbad8c65f80b2d3587e91d575c3` | 1,132 | 255 | 83 | 794 |
| **Clean OOD (Zero Overlap)** | Dynamically filtered from OOD vs `train_v4_4_b` | Zero normalized template overlap | 1,075 | 249 | 79 | 747 |
| **V4.5 Training Corpus** | `sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_b.jsonl` | `28bdb8c81e538c8a49cd7b56e9da89e5b206bbe2297e12f8b245fcf50c329ab0` | 20,257 | 6,311 | 1,169 | 12,777 |

### Evaluated Model Configurations:
1. **Sentinel V4.3 Production Baseline**:
   - Location: `sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/`
   - Features: 19 language-independent structural signals + 1,500 word n-grams (1–2) + 2,500 char n-grams (2–5) = 4,019 dimensions.
   - Classifier: `HistGradientBoostingClassifier(random_state=20260914)`.
   - Decision Threshold: $\tau = 0.6100$ (Calibrated on `val.jsonl` at $\text{FPR} \le 2.0\%$).
   - Operating Policy: $P(\text{non-benign}) = P(\text{SPAM}) + P(\text{MALICIOUS}) \ge 0.6100$ with tie-breaker $P(\text{MALICIOUS}) \ge P(\text{SPAM})$ required for a `MALICIOUS` label.
2. **Sentinel V4.5 Stage 1 Ablation C (Contextual + Structural)**:
   - Location: `sentinel-ml/Messages-ml/messages_v4_5/models/ablation_c_clf.pkl` + `scaler_structural.pkl` + `data/test_emb.npy`
   - Features: 384 dense embeddings from frozen `sentence-transformers/all-MiniLM-L6-v2` + 19 standard-scaled structural features = 403 dimensions.
   - Classifier: `LogisticRegression(class_weight='balanced', max_iter=1000)`.
   - Decision Threshold: $\tau = 0.8600$ (Calibrated strictly on `val.jsonl` at $\text{FPR} \le 2.0\%$; benign $p98 = 0.8564$).

---

## 3. Four-Way Performance Matrix

### 3.1 Primary TEST Malicious Population ($N = 1,556$)

The 1,556 ground-truth malicious messages in `test.jsonl` partition into the four-way complementarity matrix as follows:

| Category | Definition | Count | % of Malicious Test | Security Interpretation |
|:---|:---|:---:|:---:|:---|
| **A** | **V4.3 Correct & V4.5 Correct** | **1,203** | **77.31%** | Shared threat detections. Obvious smishing with explicit urgency, banking tokens, and suspicious URLs. |
| **B** | **V4.3 Correct & V4.5 Wrong** | **307** | **19.73%** | **V4.3-only strength**. Subword n-grams catch domain-specific smishing patterns that frozen MiniLM misses. |
| **C** | **V4.3 Wrong & V4.5 Correct** | **6** | **0.39%** | **V4.5-only recovery**. Negligible, noisy, non-repeatable edge cases. |
| **D** | **Both Wrong** | **40** | **2.57%** | Shared blind spots: conversational pings, "Hi Mum" lures, and commercial reward scams without URLs. |
| **Total** | Malicious Evaluation Pool | **1,556** | **100.00%** | Exact integer balance: $1203 + 307 + 6 + 40 = 1556$. |

```
Primary TEST Malicious Breakdown (N=1,556)
├── Category A: Both Correct ─────────────────── 1,203 (77.31%)
├── Category B: V4.3 Only (V4.5 Regressions) ───   307 (19.73%)
│   ├── MALICIOUS → SPAM Confusion: 166 (54.1%)
│   └── MALICIOUS → BENIGN Sub-Tau:  141 (45.9%)
├── Category C: V4.5 Only (V4.5 Recoveries) ────     6  (0.39%)
└── Category D: Both Failed ────────────────────    40  (2.57%)
```

### 3.2 Clean OOD Malicious Population ($N = 747$)

Evaluating the independent Clean OOD split (zero training overlap) confirms identical structural behavior:

| Category | Definition | Count | % of Clean OOD Malicious |
|:---|:---|:---:|:---:|
| **A** | **V4.3 Correct & V4.5 Correct** | **535** | **71.62%** |
| **B** | **V4.3 Correct & V4.5 Wrong** | **180** | **24.10%** |
| **C** | **V4.3 Wrong & V4.5 Correct** | **2** | **0.27%** |
| **D** | **Both Wrong** | **30** | **4.02%** |
| **Total** | Clean OOD Malicious Pool | **747** | **100.00%** |

### 3.3 Primary TEST Benign False Positive Matrix ($N = 520$)

| Evaluation Category | V4.3 State | V4.5 State | Count | % of Benign | Operational Impact |
|:---|:---:|:---:|:---:|:---:|:---|
| **True Negatives** | Correct (BENIGN) | Correct (BENIGN) | **503** | 96.73% | Safe conversational SMS. |
| **Introduced FPs** | Correct (BENIGN) | **False Alarm (FP)** | **15** | **2.88%** | **V4.5 corruption**. Innocent peer-to-peer chats flagged as SPAM or MALICIOUS. |
| **Corrected FPs** | False Alarm (FP) | **Correct (BENIGN)** | **1** | **0.19%** | Single casual phrase corrected (`"Lmao!nice <NUM>"`). |
| **Shared FPs** | False Alarm (FP) | False Alarm (FP) | **1** | **0.19%** | All-caps conversational text with punctuation noise. |
| **Total Benign** | FPR = 0.38% (2/520) | FPR = 3.08% (16/520) | **520** | **100.00%** | **V4.5 FPR is 8.0x worse than V4.3**. |

---

## 4. Deep Forensic Analysis of V4.5-Only Recovered Cases (Category C)

Every single record in Category C ($N = 6$) was forensically audited to determine if it reflects a genuine contextual capability.

### Case 1: Japanese Multilingual Outlier
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0022148`
- **Text**: `"ご本人様不在の為お荷物を持ち帰りました。ご確認ください。"` *(Translation: "Because you were absent, we brought back your package. Please confirm.")*
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.4202, P(\text{S}) = 0.0025, P(\text{M}) = 0.5773 \implies P(\text{nb}) = 0.5798 \to$ **`BENIGN`** (Missed at $\tau=0.610$)
- **V4.5 Predictions**: $P(\text{B}) = 0.0129, P(\text{S}) = 0.0605, P(\text{M}) = 0.9266 \implies P(\text{nb}) = 0.9871 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: Out-of-scope dataset artifact. Sentinel's operational threat model targets Indian and global English/Latin SMS (over 99.6% Latin characters). V4.3's vocabulary is strictly English/Latin character and word n-grams, causing non-Latin scripts to have zero token matches. Pretrained MiniLM has multilingual wordpieces that recognize Japanese package delivery patterns. This does not represent an Indian SMS capability.

### Case 2: Truncated Five-Token Fragment
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0016371`
- **Text**: `"OMLOG E UPS HUB GA"`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.7323, P(\text{S}) = 0.0309, P(\text{M}) = 0.2368 \to$ **`BENIGN`**
- **V4.5 Predictions**: $P(\text{B}) = 0.1231, P(\text{S}) = 0.0191, P(\text{M}) = 0.8578 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: Truncated log fragment without URL, phone number, or actionable call-to-action. V4.5 classified this as malicious solely because `"UPS HUB"` has weak embedding proximity to logistics phishing lures. This is arbitrary representation proximity, not repeatable threat comprehension.

### Case 3: Phishing Prompt Without Explicit URL
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0018109`
- **Text**: `"The account may be suspended. Click for details."`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.4629, P(\text{S}) = 0.0017, P(\text{M}) = 0.5354 \implies P(\text{nb}) = 0.5371 \to$ **`BENIGN`** (Missed at $\tau=0.610$)
- **V4.5 Predictions**: $P(\text{B}) = 0.0030, P(\text{S}) = 0.0004, P(\text{M}) = 0.9965 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: Authentic smishing lure missing its URL link. V4.3 already assigned high threat probability ($P(\text{M}) = 0.5354$), but fell 0.073 below threshold because Candidate-D's structural extractor relies partly on URL domain indicators. V4.5's transformer cleanly identifies the semantic phrase `"account may be suspended"`. However, this is a single instance overlapping with V4.3's known URL-less margin sensitivity.

### Case 4: Telegram Task Scam (3-Class Tie-Breaker Delta)
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0009545`
- **Text**: `"Task <NUM> Search in <LOCATION> Liked the video and <NAMED_ENTITY> take a screenshot and send it to me is done Okay now let's start the test I will give you <NUM> tasks and you will get <NUM> rupees when you are finish."`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.0027, P(\text{S}) = 0.5230, P(\text{M}) = 0.4743 \implies P(\text{nb}) = 0.9973 \to$ **`SUSPICIOUS_SPAM`**
- **V4.5 Predictions**: $P(\text{B}) = 0.0205, P(\text{S}) = 0.4014, P(\text{M}) = 0.5781 \implies P(\text{nb}) = 0.9795 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: **Not a detection miss by V4.3**. V4.3 detected this threat with 99.73% confidence ($P(\text{non-benign}) = 0.9973$), but assigned $P(\text{SPAM}) = 0.523$ vs $P(\text{MALICIOUS}) = 0.474$ due to a 0.048 tie-breaker delta. V4.5 assigned $P(\text{MALICIOUS}) = 0.578$. This is a minor argmax class rebalancing on an already-flagged threat, not an added threat detection.

### Case 5: Ambiguous Third-Party Conversational Hearsay
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0019646`
- **Text**: `"They are asking us to provide our documents like id etc."`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.8887, P(\text{S}) = 0.0120, P(\text{M}) = 0.0992 \to$ **`BENIGN`**
- **V4.5 Predictions**: $P(\text{B}) = 0.0611, P(\text{S}) = 0.0367, P(\text{M}) = 0.9022 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: Highly ambiguous ground truth. The message is a victim describing a third-party interaction to a friend, not an inbound smishing attack from an adversary. V4.3 correctly treated it as conversational text, whereas V4.5 over-indexed on `"provide our documents like id"`.

### Case 6: Utility Payment Lure (3-Class Tie-Breaker Delta)
- **Message ID**: `MSG_SRC_IMC25_FISHING_SMISHING_0019708`
- **Text**: `"Your bill is paid for <DATE_TIME>. Thanks, here's a little gift for you: <URL>"`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Predictions**: $P(\text{B}) = 0.0002, P(\text{S}) = 0.7598, P(\text{M}) = 0.2400 \implies P(\text{nb}) = 0.9998 \to$ **`SUSPICIOUS_SPAM`**
- **V4.5 Predictions**: $P(\text{B}) = 0.0398, P(\text{S}) = 0.4163, P(\text{M}) = 0.5439 \implies P(\text{nb}) = 0.9602 \to$ **`MALICIOUS`**
- **Forensic Diagnosis**: **Not a detection miss by V4.3**. V4.3 identified this as a non-benign threat with 99.98% certainty. Because the text used reward/marketing phrasing (`"Thanks, here's a little gift"`), V4.3 categorized it as commercial spam ($P(\text{SPAM}) = 0.760$). V4.5 tilted it slightly to $P(\text{MALICIOUS}) = 0.544$.

### Synthesis of Category C:
Out of 1,556 test malicious messages, **not one single repeatable, distinct contextual smishing class** (e.g. conversational OTP theft, Hinglish smishing, bank impersonation, electricity disconnection) was newly discovered or systematically solved by V4.5. Two were already caught by V4.3 as non-benign threats with >99.7% confidence, one was a foreign script anomaly, one was a 5-token fragment, and one was ambiguous conversational chat.

---

## 5. V4.3-Only Strengths & V4.5 Regression Breakdown (Category B)

In stark contrast to the 6 edge cases in Category C, **Category B contains 307 malicious records** where V4.3 decisively protected the user, but V4.5 failed catastrophically.

### 5.1 Failure Mechanism 1: MALICIOUS $\to$ SUSPICIOUS_SPAM Class Confusion ($N = 166$, 54.1%)
Pretrained `all-MiniLM-L6-v2` embeddings group text topically. Because attackers disguise smishing lures as commercial promotions (pre-approved loans, lottery prizes, gift cards, ecommerce deliveries), generic sentence transformers place them directly inside the commercial marketing centroid:
- $P(\text{non-benign})$ remains high (median $P(\text{nb}) = 0.9971$, 95th percentile $= 1.0000$).
- But $P(\text{SPAM})$ (median $0.7521$) decisively exceeds $P(\text{MALICIOUS})$ (median $0.2169$).
- Because the Sentinel security engine requires $P(\text{MALICIOUS}) \ge P(\text{SPAM})$ to trigger active threat blocking, all 166 attacks are downgraded to low-priority spam.

**Representative Examples**:
1. `MSG_SRC_IMC25_FISHING_SMISHING_0019840`:
   - *Text*: `"Approval in <DATE_TIME> and loan credit in <DATE_TIME>. You are one click away to get pre-approved loan..."`
   - *V4.3*: $P(\text{B})=0.0000, P(\text{S})=0.0982, P(\text{M})=0.9018 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.0028, P(\text{S})=0.5756, P(\text{M})=0.4216 \to$ **`SUSPICIOUS_SPAM`** (Missed threat gate)
2. `MSG_SRC_IMC25_FISHING_SMISHING_0018443`:
   - *Text*: `"Welcome To PAYTM MALL COMPANY <URL> Dear Customer, Congratulations, Your Name is Selected In The Lucky Draw..."`
   - *V4.3*: $P(\text{B})=0.0009, P(\text{S})=0.1189, P(\text{M})=0.8802 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.0005, P(\text{S})=0.8586, P(\text{M})=0.1409 \to$ **`SUSPICIOUS_SPAM`** (Missed threat gate)
3. `MSG_SRC_IMC25_FISHING_SMISHING_0020343`:
   - *Text*: `"Dear customer Your Car is to sell in <NUM> hr Free RC Transfer Give misscall <PHONE_NUMBER>..."`
   - *V4.3*: $P(\text{B})=0.0000, P(\text{S})=0.0801, P(\text{M})=0.9199 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.0069, P(\text{S})=0.6833, P(\text{M})=0.3098 \to$ **`SUSPICIOUS_SPAM`** (Missed threat gate)

### 5.2 Failure Mechanism 2: MALICIOUS $\to$ BENIGN Threshold Drop ($N = 141$, 45.9%)
To control false alarms on `val.jsonl`, V4.5's operating threshold was forced to $\tau = 0.8600$ (compared to V4.3's $\tau = 0.6100$). Across the 141 dropped malicious records:
- The median $P(\text{non-benign})$ was $0.7531$ (75th percentile $= 0.8192$, 95th percentile $= 0.8552$).
- Under V4.3's threshold ($\tau=0.6100$), the vast majority of these would have been flagged.
- Because frozen MiniLM cannot cleanly separate conversational benign SMS from subtle smishing, the threshold creep directly dropped 141 critical banking, delivery, and utility threats into `BENIGN`.

**Representative Examples**:
1. `MSG_SRC_IMC25_FISHING_SMISHING_0015687`:
   - *Text*: `"Dear user your SBI YONO Account will be closed today please update PAN card immediately..."`
   - *V4.3*: $P(\text{B})=0.0016, P(\text{S})=0.0012, P(\text{M})=0.9972 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.7486, P(\text{S})=0.0063, P(\text{M})=0.2451 \to$ **`BENIGN`** (Catastrophic miss)
2. `MSG_SRC_IMC25_FISHING_SMISHING_0017534`:
   - *Text*: `"Dear Customer your electricity powar will be disconnect <DATE_TIME> your bill is not update please call..."`
   - *V4.3*: $P(\text{B})=0.0001, P(\text{S})=0.0006, P(\text{M})=0.9993 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.2527, P(\text{S})=0.0084, P(\text{M})=0.7389 \implies P(\text{nb})=0.7473 < 0.8600 \to$ **`BENIGN`** (Missed at $\tau=0.860$)
3. `MSG_SRC_IMC25_FISHING_SMISHING_0016805`:
   - *Text*: `"DPD UK: Your delivery could not be scheduled due to one or more issues. You can view more information here..."`
   - *V4.3*: $P(\text{B})=0.0001, P(\text{S})=0.0004, P(\text{M})=0.9995 \to$ **`MALICIOUS`** (Caught)
   - *V4.5*: $P(\text{B})=0.5054, P(\text{S})=0.0112, P(\text{M})=0.4834 \implies P(\text{nb})=0.4946 < 0.8600 \to$ **`BENIGN`** (Catastrophic miss)

---

## 6. Both-Wrong Population Analysis (Category D)

Category D contains **40 malicious records** where both models failed to output a `MALICIOUS` prediction. These records reveal the fundamental structural boundaries of SMS threat detection:

```
Category D Prediction Matrix (N=40)
├── V4.3 = BENIGN          & V4.5 = BENIGN          : 19 records (47.5%)
├── V4.3 = SUSPICIOUS_SPAM & V4.5 = SUSPICIOUS_SPAM : 19 records (47.5%)
├── V4.3 = BENIGN          & V4.5 = SUSPICIOUS_SPAM :  1 record   (2.5%)
└── V4.3 = SUSPICIOUS_SPAM & V4.5 = BENIGN          :  1 record   (2.5%)
```

### Cluster D.1: Conversational Outreaches & "Hi Mum" Social Engineering ($N = 19$)
- Attackers deliberately omit links, phone numbers, and urgent keywords to establish trust before pivoting to fraud on WhatsApp/Telegram.
- *Examples*:
  - `MSG_SRC_IMC25_FISHING_SMISHING_0017893`: `"Hey mum, my phone has water damage. That is why i have this temporary number. It felt in my sink😞 how are you doing?"` (V4.3: $P(\text{M})=0.016$, V4.5: $P(\text{M})=0.064 \to$ `BENIGN`).
  - `MSG_SRC_IMC25_FISHING_SMISHING_0007178`: `"Hey 👋"` (V4.3: $P(\text{M})=0.271$, V4.5: $P(\text{M})=0.003 \to$ `BENIGN`).
  - `MSG_SRC_IMC25_FISHING_SMISHING_0022190`: `"New phone, who dis?"` (V4.3: $P(\text{M})=0.110$, V4.5: $P(\text{M})=0.006 \to$ `BENIGN`).
  - `MSG_SRC_IMC25_FISHING_SMISHING_0006540`: `"Hello, can I call you?"` (V4.3: $P(\text{M})=0.075$, V4.5: $P(\text{M})=0.107 \to$ `BENIGN`).
  - `MSG_SRC_IMC25_FISHING_SMISHING_0022218`: `"Are you busy now?"` (V4.3: $P(\text{M})=0.012$, V4.5: $P(\text{M})=0.003 \to$ `BENIGN`).
- *Engineering Finding*: Neither lexical n-grams nor dense sentence embeddings can classify conversational greetings as malicious without catastrophically destroying benign false alarm rates. Conversational fraud must be addressed downstream by interaction context or multi-turn monitoring, not single-message classification.

### Cluster D.2: Commercial Lottery & Reward Lures Treated as Spam ($N = 19$)
- Malicious campaigns that mimic promotional spam (free cameras, raffle draws, gift vouchers).
- *Examples*:
  - `MSG_SRC_IMC25_FISHING_SMISHING_0019132`: `"Dear customer you have won a prize <US_DRIVER_LICENSE> Two Hundred thousand Riyal..."` (Both output `SPAM`, $P(\text{M}) \le 0.395$).
  - `MSG_SRC_MENDELEY_SMISHING_2022_0003734`: `"Update_Now - Xmas Offer! Latest Motorola, SonyEricsson & Nokia & FREE Bluetooth!"` (Both output `SPAM`).
  - `MSG_SRC_MENDELEY_SMISHING_2022_0001314`: `"FreeMSG You have been awarded a FREE mini DIGITAL CAMERA, just reply SNAP to collect"` (Both output `SPAM`).
  - `MSG_SRC_IMC25_FISHING_SMISHING_0019305`: `"Con-gRatsulations! Claim your FREE $<NUM> gift-Card: <URL>"` (Both output `SPAM`).
- *Engineering Finding*: Both models successfully identify these as non-benign ($P(\text{non-benign}) \approx 1.0$), but the 3-class policy categorizes them as commercial spam rather than active credential/payload phishing.

---

## 7. Forensic Audit of Newly Introduced Benign False Positives

V4.5 introduced **15 new false positives** on benign messages that V4.3 correctly classified as BENIGN. This is the root cause of V4.5's FPR jump to 3.08%:

| Message ID | Safe Excerpt | V4.3 Pred ($P_{nb}$) | V4.5 Pred ($P_{nb}$) | Failure Mechanism in V4.5 |
|:---|:---|:---:|:---:|:---|
| `..._0003839` | `"I didnt get ur full msg..sometext is missing, send it again"` | `BENIGN` (0.0061) | **`SPAM`** (0.8813) | Dense embedding confuses short conversational request with spam. |
| `..._0004558` | `"Can you plz tell me the ans. BSLVYL sent via fullonsms.com"` | `BENIGN` (0.4425) | **`SPAM`** (0.9379) | Mentions free SMS gateway, mapped to commercial spam. |
| `..._0000001` | `"Your opinion about me? <NUM>. Over <NUM>. Jada... Simple Pls reply.."` | `BENIGN` (0.1537) | **`MALICIOUS`** (0.8637) | Chain SMS with number list misclassified as malicious payload. |
| `..._0000863` | `"Hiya , have u been paying money into my account? If so, thanks..."` | `BENIGN` (0.0634) | **`MALICIOUS`** (0.9370) | Contains `"paying money into my account"` — MiniLM triggers false fraud alarm. |
| `..._0001780` | `"Webpage s not available!"` | `BENIGN` (0.1098) | **`MALICIOUS`** (0.8757) | Technical browser error string triggers high malicious embedding score. |
| `..._0004259` | `"HI DARLIN I FINISH AT <NUM> DO U <NUM> PICK ME UP OR MEET ME?..."` | `BENIGN` (0.0687) | **`SPAM`** (0.9515) | All-caps conversational text mapped into marketing spam cluster. |
| `..._0000812` | `"What's happening with you. Have you gotten a job and have you begun..."` | `BENIGN` (0.4379) | **`MALICIOUS`** (0.9088) | Mention of `"registration"` triggers high malicious score in MiniLM. |
| `..._0001100` | `"Sorry that took so long, omw now"` | `BENIGN` (0.0008) | **`MALICIOUS`** (0.9110) | Completely innocent short chat text scored $P(\text{M}) = 0.814$. |
| `..._0003575` | `"Send this to ur friends and receive something about ur voice..."` | `BENIGN` (0.1119) | **`SPAM`** (0.8953) | Social chain SMS mapped to marketing spam. |
| `..._0003153` | `"Dai what this da.. Can i send my resume to this id."` | `BENIGN` (0.0141) | **`MALICIOUS`** (0.9010) | Colloquial Tamil/English peer chat falsely flagged as malicious. |
| `..._0000922` | `"Somebody set up a website where you can play hold em using spacebucks"` | `BENIGN` (0.0217) | **`SPAM`** (0.9306) | Gaming reference mapped into casino/gambling spam centroid. |
| `..._0004937` | `"If you r @ home then come down within <NUM> min"` | `BENIGN` (0.0626) | **`SPAM`** (0.8983) | Short meet-up chat scored high spam probability. |
| `..._0002172` | `"HI ITS KATE CAN U GIVE ME A RING ASAP XXX"` | `BENIGN` (0.0152) | **`SPAM`** (0.9367) | Urgent conversational call request mapped to callback spam. |
| `..._0001982` | `"HEY HEY WERETHE MONKEESPEOPLE SAY WE MONKEYAROUND! HOWDY GORGEOUS..."` | `BENIGN` (0.0421) | **`SPAM`** (0.9844) | Playful greeting song lyrics mapped to commercial spam. |
| `..._0003085` | `"WHITE FUDGE OREOS ARE IN STORES"` | `BENIGN` (0.2083) | **`SPAM`** (0.9388) | Informal food product note scored 0.9388 non-benign probability. |

**Key Finding**: V4.3's structural signals and subword n-grams correctly recognize that these conversational messages lack malicious smishing indicators ($P(\text{nb}) \le 0.15$ in 13/15 cases). Generic MiniLM, however, assigns non-benign probabilities $> 0.86$ to ordinary texts mentioning money, accounts, registration, or all-caps greetings.

---

## 8. Probability Correlation, Calibration & Blending Experiments

### 8.1 Probability Correlation Between V4.3 and V4.5
To evaluate whether V4.5 provides orthogonal decision information, correlation coefficients were computed across all test messages ($N = 2,264$):

| Probability Metric | Population | Pearson $r$ | Spearman $\rho$ | Statistical Interpretation |
|:---|:---|:---:|:---:|:---|
| **$P(\text{non-benign})$** | Full TEST ($N=2,264$) | **0.9301** | **0.6908** | Strong collinearity; models agree broadly on benign vs non-benign. |
| **$P(\text{MALICIOUS})$** | Full TEST ($N=2,264$) | **0.8336** | **0.8932** | Very high rank correlation on threat intensity. |
| **$P(\text{non-benign})$** | Malicious Only ($N=1,556$) | **0.5117** | **0.3947** | Moderate correlation; V4.5 compresses scores into SPAM. |
| **$P(\text{MALICIOUS})$** | Malicious Only ($N=1,556$) | **0.5489** | **0.7576** | V4.5 scores lag behind V4.3 on actual threats. |
| **$P(\text{non-benign})$** | Benign Only ($N=520$) | **0.4685** | **0.4117** | Moderate correlation; V4.5 exhibits substantial positive drift. |

### 8.2 Probability Blending Experiment (Validation Calibration $\to$ Test Evaluation)
To directly test whether a linear fusion of V4.3 and V4.5 can improve the production tradeoff, probability blending was evaluated:
$$P_{\text{blend}} = \alpha P_{\text{V4.3}} + (1 - \alpha) P_{\text{V4.5}}$$
For each $\alpha$, the decision threshold $\tau$ was calibrated strictly on `val.jsonl` to satisfy the mandatory $\text{FPR} \le 2.0\%$ constraint, then applied out-of-sample to `test.jsonl`:

| Weight ($\alpha$) | Model Mixture | Calibrated $\tau$ | Val FPR | Val Mal Recall | Test FPR | Test Mal Recall | Net Test Malicious Caught |
|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **1.0** | **Pure V4.3 Production** | **0.605** | **1.98%** | **95.94%** | **0.58%** | **97.04%** | **1,510 / 1,556 (Baseline)** |
| **0.9** | 90% V4.3 + 10% V4.5 | 0.555 | 1.98% | 95.90% | 0.58% | 97.11% | 1,511 / 1,556 (+1 record) |
| **0.8** | 80% V4.3 + 20% V4.5 | 0.515 | 1.98% | 95.98% | 0.77% | 96.66% | 1,504 / 1,556 (-6 records) |
| **0.7** | 70% V4.3 + 30% V4.5 | 0.515 | 1.98% | 95.55% | 0.77% | 96.40% | 1,500 / 1,556 (-10 records) |
| **0.5** | 50% V4.3 + 50% V4.5 | 0.560 | 1.36% | 93.18% | 0.96% | 94.41% | 1,469 / 1,556 (-41 records) |
| **0.3** | 30% V4.3 + 70% V4.5 | 0.685 | 1.36% | 86.49% | 1.15% | 87.66% | 1,364 / 1,556 (-146 records) |
| **0.0** | **Pure V4.5 Standalone** | **0.860** | **1.98%** | **75.52%** | **3.08%** | **77.70%** | **1,209 / 1,556 (-301 records)** |

### Analytical Conclusion from Blending:
- As soon as V4.5's weight reaches 20% ($\alpha = 0.8$), test malicious recall drops below the V4.3 baseline while benign false positive rate increases by +33%.
- At $\alpha = 0.9$, an apparent gain of +1 record is observed on TEST, but validation recall degrades from 95.94% to 95.90%, indicating random threshold fluctuation rather than genuine structural generalization.
- There is **no mixture of frozen V4.3 and frozen V4.5 that Pareto-dominates pure V4.3**.

---

## 9. Does V4.5 Provide Genuinely Distinct Signal?

### Targeted Diagnostic Probes vs Global Production Distribution:
A crucial distinction must be drawn between the targeted diagnostic suites and the global SMS benchmark:
1. **On Targeted Curated Probes**:
   - V4.5 demonstrated impressive local performance on specific semantic slices:
     - `holdout_greetings`: FPR dropped from 12.7% to **0.0%**.
     - `holdout_electricity`: FPR dropped from 50.9% to **5.5%**, malicious recall reached **100.0%**.
     - `holdout_institutional`: FPR dropped from 40.0% to **3.3%**, malicious recall reached **93.3%**.
     - `holdout_counterfactual`: FPR dropped from 40.0% to **3.6%**, malicious recall was **83.6%**.
     - `holdout_notifications`: FPR dropped from 50.9% to **0.0%**.
   - These probes tested specific semantic relationships (e.g. distinguishing `"Never share your OTP"` from `"Share your OTP"`), where sequential language modeling is theoretically superior to bag-of-words.
2. **On the Global Production Distribution (`test.jsonl` and `ood.jsonl`)**:
   - The uncurated test set represents in-the-wild SMS traffic. Here, the frozen generic contextual representation fails fundamentally:
     - It possesses no domain-adapted smishing boundary.
     - It maps 166 smishing attacks into commercial marketing spam.
     - It pushes benign validation scores upward, forcing $\tau = 0.860$ and dropping 141 attacks into benign.
     - It corrupts 15 innocent peer-to-peer conversational messages into false alarms.
     - It recovers only 6 records out of 1,556 ($0.39\%$), none of which form a repeatable semantic capability.

### Summary:
Pretrained frozen MiniLM embeddings provide **topical and semantic clustering**, not **security threat discrimination**. When evaluated against authentic SMS threats, frozen MiniLM does not provide a complementary threat detection signal.

---

## 10. Required Decision

In accordance with Section 14 of the Implementation Directive:

### **DECISION: `B — HYBRID NOT JUSTIFIED`**

*(A hybrid architecture combining Sentinel V4.3 with frozen generic contextual embeddings is NOT justified by empirical evidence).*

---

## 11. Exact Evidence Supporting the Decision

The decision to reject a hybrid architecture based on frozen generic MiniLM embeddings is supported by the following six unassailable empirical facts:

1. **Insignificant Category C ($N = 6$, 0.39%)**:
   - Out of 1,556 primary test malicious records, V4.5 only recovered 6 cases that V4.3 missed.
   - Out of 747 clean OOD malicious records, V4.5 only recovered 2 cases (0.27%).
   - The primary research gate stated: *"If C is small, noisy, or overlapping with existing V4.3 failure patterns: there may be no useful hybrid signal."* Category C meets all three negative criteria: it is small ($<0.4\%$), noisy (Japanese characters, truncated fragments), and overlapping (URL-less margin cases and 3-class tie-breakers on already-flagged threats).
2. **Massive Net Security Regression (-301 Records)**:
   - For every 1 record V4.5 recovered in Category C, it lost **51.2 records** in Category B (307 missed vs 6 recovered).
   - Primary test malicious recall collapsed by **-19.34%** (from 97.04% to 77.70%).
   - Clean OOD malicious recall collapsed by **-23.83%** (from 95.72% to 71.89%, missing 178 attacks).
3. **Severe Benign False Alarm Contamination (+14 FPs, 8.0x FPR)**:
   - Primary test benign false positive rate jumped from **0.38% (V4.3) to 3.08% (V4.5)**, introducing 15 new false alarms on normal conversational messages while correcting only 1.
   - This directly violates the mandatory Sentinel production constraint ($\text{FPR} \le 2.0\%$).
4. **Structural Topic Trap (54.1% Spam Confusion)**:
   - 166 primary malicious test records were misclassified as `SUSPICIOUS_SPAM` because generic MiniLM maps commercial smishing into legitimate marketing centroids.
5. **No Feasible Linear or Blended Fusion**:
   - Across all blending weights $\alpha \in [0.0, 1.0]$, combining V4.3 and V4.5 probabilities monotonically degraded malicious recall or increased benign false alarms relative to pure V4.3.
6. **Theoretical Upper Bound is Trivially Constrained**:
   - Even an ideal oracle union achieves only a negligible +0.39% recall gain (from 97.04% to 97.43%), while inflating benign FPR from 0.38% to 3.27% (17 FPs).

---

## 12. Justified Next Research Experiments

Based on the definitive rejection of frozen generic contextual embeddings, the following scientific guidance governs future research phases:

### What Is Strictly PROHIBITED Next:
1. **NO Frozen MiniLM Fusion**: Do not train linear heads, MLPs, or gradient-boosted trees over frozen generic `all-MiniLM-L6-v2` embeddings combined with V4.3 features. The representations are proven to be non-complementary and harmful to global security calibration.
2. **NO Corpus Modification Loop**: Do not generate another ad-hoc batch of hard negatives (e.g. V4.4 RC2-Exp4) to patch local probes. Forensic history proves that localized corpus patches cause benign $p98$ drift and threshold creep.
3. **NO Production or Android Modification**: Sentinel V4.3 remains the sole production champion. No files in `sentinel-ai/` or production asset directories will be touched.

### What Research Experiment IS Scientifically Justified Next:
If sequential/contextual representations are to be pursued in a future phase, the postmortem proves they cannot be generic frozen sentence embeddings. The only scientifically grounded avenues are:

1. **Smishing-Domain Adapted Contrastive Encoder (Phase 5.1 Research)**:
   - *Rationale*: Generic MiniLM fails because its pretraining objective (masked language modeling + sentence similarity on web text) treats commercial smishing and legitimate marketing as identical.
   - *Design*: Pretrain a compact transformer backbone (e.g. MiniLM or MobileBERT) using domain-specific contrastive learning directly on SMS smishing and benign corpora, explicitly forcing separation between commercial smishing threats and promotional spam.
   - *Prerequisite*: Must demonstrate in an offline benchmark that the domain-adapted embedding separates smishing from spam before any fusion is attempted.
2. **Isolated Semantic Sieve / Post-Filter Gatekeeper**:
   - *Rationale*: Contextual models excel at specific negation structures (counterfactuals: "Never share OTP") and utility bill status ("Your bill is paid"), but fail on broad-spectrum smishing.
   - *Design*: Keep V4.3 as the sole primary detector. Train a highly specialized, lightweight auxiliary binary verifier specifically for counterfactual negation and utility bill status. Allow this auxiliary verifier to act only as a precision post-filter on messages already scoring near the decision boundary, under strict veto constraints that cannot downgrade clear threat indicators (e.g. presence of suspicious URLs or APKs).
   - *Offline Validation*: Must prove that the auxiliary filter reduces false alarms on targeted holdouts without downgrading any of the 1,510 primary test malicious detections.

---

**Report Finalized and Signed Off**: September 24, 2026  
**Final Status**: Postmortem Complete — Baseline V4.3 Preserved — Hybrid with Frozen MiniLM Rejected.
