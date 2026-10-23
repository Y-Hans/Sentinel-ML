# SENTINEL MESSAGES V4.4 FINAL FORENSIC RELEASE AUDIT REPORT

**Date**: September 20, 2026  
**Auditor**: Lead ML & Repository Forensics Engineer  
**Status**: **HELD AS RELEASE CANDIDATE (V4.4-RC1) — PRODUCTION PROMOTION REVERTED**  
**Evaluated Candidate**: Candidate B (`messages_v4_4/models/candidate_b_refined/`, $\tau = 0.630$)  
**Baseline Reference**: Frozen Sentinel Messages V4.3 (`messages_v4_3/models/candidate_d/`, $\tau = 0.610$)  

---

## 1. Executive Summary & Audit Verdict

Following a comprehensive, forensic audit of the Sentinel Messages V4.4 candidate release artifacts, the previous report's declaration that V4.4 is "certified and promoted to production" is **REVERTED**. 

Candidate B demonstrates genuine, verified improvements in several critical areas (e.g., Hinglish electricity phishing detection, APK payload recognition, informal "Hi" false alarm suppression, and 0.00% FPR on provenance-clean OOD data). However, an unvarnished audit of stored artifacts and blind source-shift evaluation datasets reveals **critical unresolved failure modes and methodological limitations**:

1. **Severe Benign Utility False Positive Rate (47.3%)**: While malicious electricity phishing recall reached 100%, 26 out of 55 benign utility notices in the holdout (e.g., official MSEDCL bill alerts, Bescom recharges, DHBVN rebate notices) are incorrectly classified as MALICIOUS due to keyword over-indexing on `"meter"`, `"bill"`, and `"power"`.
2. **Persistent False Alarm on Bare "Hello" ($p = 0.9459$)**: While multi-word greetings were improved and "Hi" was neutralized ($p=0.5165$), the single word `"Hello"` remains heavily flagged as MALICIOUS ($p=0.9459$, expected BENIGN).
3. **Institutional Partnerships Recall Regression**: Detection recall on `slice_slice_institutional_partnerships` dropped from **75.0% (12/16)** in V4.3 to **56.2% (9/16)** in Candidate B.
4. **Holdout Co-Construction**: All 7 newly authored V4.4 holdouts were generated in the same session by the same process as the training augmentation, meaning holdout patterns were observable during corpus engineering.
5. **Previous Report Inaccuracies**: The previous report fabricated an FPR of `0.0% (0/55)` on `v44_holdout_system_notifications` when the true stored evaluation result is **45.5% (25/55 FPs)**, and dismissed 598 cross-split template collapses as "zero collisions".

**Official Verdict**: Candidate B is frozen as **Sentinel Messages V4.4-RC1**. It remains staged as a release candidate while a minimal, targeted calibration experiment (`V4.4-RC2`) is conducted. Android production deployment is held until utility false alarms and the institutional regression are resolved.

---

## 2. Leakage Reconciliation & Provenance Matrix

### 2.1 Reconciliation of the Discrepancy
The previous audit noted:
> *"598 normalized-overlap rows / 261 unique normalized texts / 1 Jaccard $\ge 0.85$ pair."*

The previous release report asserted:
> *"Gate 3: Evaluation Leakage Clearance — 0 train-to-test or train-to-holdout record collisions."*

This discrepancy arose because the release report applied the narrowest possible filter: **literal character-exact equality (`raw_text == raw_text`) and record ID string equality**. Under this naive definition, collisions were indeed 0. 

However, SMS datasets are dominated by parameterized templates (varying only by OTP digits, amounts, dates, or punctuation). When structural normalization is applied (masking URLs, phone numbers, numeric codes, and punctuation), **598 rows in V4.3 train** and **601 rows in Candidate B train** collapse onto **261 and 263 unique normalized keys** in the evaluation splits.

### 2.2 Complete Train vs. Evaluation Provenance Matrix
Evaluated across all 8,320 records in 29 evaluation files against `train_v4_4_b.jsonl` (20,257 rows):

| Split / Suite Group | Total Records | Exact String | Case & Whitespace | URL-Norm | Aggressive Norm | Template Cluster | ID Collision | Token Jaccard $\ge 0.85$ |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Test Split** (`test.jsonl`) | 2,264 | 0 | 0 | 0 | 130 | 0 | 0 | 2,661 pairs |
| **Validation Split** (`val.jsonl`) | 3,397 | 0 | 0 | 0 | 193 | 0 | 0 | 5,637 pairs |
| **OOD Split** (`ood.jsonl`) | 1,132 | 0 | 0 | 0 | 77 | 0 | 0 | 1,496 pairs |
| **Benchmarks (V4.3/Legacy)** | 815 | 0 | 0 | 810 | 842 | 834 | 0 | 35 pairs |
| **V4.4 Holdouts (7 Suites)** | 712 | 0 | 0 | 0 | 3 | 0 | 0 | 2 pairs |
| **Total Cross-Split Collisions** | **8,320** | **0** | **0** | **810** | **1,245** | **834** | **0** | **9,831 pairs** |

#### Key Provenance Findings:
1. **URL-Norm Replay Collapse (810 matches)**: In `bench_sentinel_replay`, 270 training rows containing bare URLs (e.g., `http://userver.net52.cc/?token=...`) collapse to `<URL>`, matching evaluation records.
2. **Template Near-Duplicates in Holdouts (2 Jaccard pairs, 1 Norm Conflict)**:
   - In `holdout_system_notifications.jsonl`: Train had `"Alarm set for 6:00 AM tomorrow morning"`, while Holdout had `"Alarm set for 6:30 AM tomorrow morning."` ($j = 1.000$).
   - In `holdout_apk_payload.jsonl`: Train had `"Download our official partner rewards app at rewards.apk"`, while Holdout had `"Download our official partner rewards app at rewards.apk: http://partner-rewards.top/rewards.apk"` ($j = 0.889$).
   - In `holdout_greetings.jsonl`: Train had `"Hello."` (labeled MALICIOUS in legacy spam context), while Holdout had `"Hello!"` (labeled BENIGN), creating a direct semantic conflict.

---

## 3. Holdout Independence & Methodology Audit

The 7 new V4.4 holdout suites (`holdout_electricity.jsonl`, `holdout_conversational_social_eng.jsonl`, `holdout_apk_payload.jsonl`, `holdout_institutional_callback.jsonl`, `holdout_greetings.jsonl`, `holdout_system_notifications.jsonl`, `holdout_counterfactual_semantic.jsonl`) were audited for independence:

- **Generation Method**: Authored via `build_protected_holdouts.py` and `build_semantic_holdouts.py` in the same engineering session as the candidate models.
- **Independence Assessment**: **NOT GENUINELY INDEPENDENT.**
- **Corpus Engineering Observability**: The training data generation script (`generate_v4_4_candidate_b_dataset.py`) directly referenced the holdouts and used a simple string exclusion (`t_clean.lower() in protected_texts`). The engineer explicitly synthesized complementary training samples targeting the identical failure archetypes (50 "Hello" variations, 50 device status updates, multi-vendor electricity bills).
- **Implication**: These suites are **targeted regression probes**, not unconstrained out-of-distribution evaluations. High performance on these suites demonstrates that the model memorized the targeted corrections, but does not prove generalized zero-shot robustness.

---

## 4. Evidence-Based Comparison of Candidates A, B, and C

The unsupported phrase *"Candidate B proved strictly optimal"* is retracted. Each candidate embodies specific architectural and precision/recall tradeoffs:

| Evaluation Dimension | Candidate A ($\tau = 0.560$) | Candidate B ($\tau = 0.630$) | Candidate C ($\tau = 0.630$) | Tradeoff Analysis |
|:---|:---:|:---:|:---:|:---|
| **Test Malicious Recall** | **97.17% (1512/1556)** | 97.11% (1511/1556) | 96.72% (1505/1556) | Candidate A caught the most test malware; Candidate C suffered an over-regularization penalty (-6 samples). |
| **Test Benign FPR** | 0.58% (3/520) | **0.38% (2/520)** | **0.38% (2/520)** | Candidates B and C preserve V4.3's low 0.38% FPR; Candidate A elevated false alarms. |
| **OOD Benign FPR** | 0.39% (1/255) | **0.00% (0/255)** | **0.00% (0/255)** | Candidates B and C achieved 0 false alarms on standard OOD benign messages. |
| **Conversational Holdout Recall**| **77.5% (79/102)** | 76.5% (78/102) | 74.5% (76/102) | Candidate A retained the highest conversational smishing sensitivity. |
| **Validation FPR** | 2.21% (FAIL) | 1.86% (PASS $\le 2.0\%$) | **1.81% (PASS)** | Only Candidates B and C satisfied the strict validation FPR gate. |
| **Single-word "Hello" Score** | $p = 0.9821$ (FP) | $p = 0.9459$ (FP) | **$p = 0.9312$ (FP)** | All three candidates failed to neutralize bare "Hello". |

**Tradeoff Conclusion**: Candidate B is the most balanced compromise between malicious recall and validation false-alarm constraints, but it is **not strictly superior across all metrics**—it sacrificed 0.06% test recall and 1.0% conversational recall relative to Candidate A.

---

## 5. Direct Verification from Stored Pickled Artifacts

Inference was executed directly on `messages_v4_3/models/candidate_d/` and `messages_v4_4/models/candidate_b_refined/`:

### 5.1 Probe Level Verification

| Probe ID | Text Snippet | Expected | V4.3 Score & Label | Candidate B Score & Label | Forensic Finding |
|:---|:---|:---:|:---:|:---:|:---|
| `ELEC_001` | "Dear customer your electricity power will be disconnected tonight at 9:30 PM..." | MALICIOUS | $p = 0.9986$ (MAL) | $p = 0.9992$ (MAL) | Verified maintained. |
| `ELEC_002` | "Dear consumer, your electricity power will be disconnected today at 9.30 pm..." | MALICIOUS | $p = 0.9760$ (MAL) | $p = 0.9671$ (MAL) | Verified maintained. |
| `ELEC_003` | "Bijli bill update nahi hua hai. Aaj raat line disconnect ho jayegi. Turant call kare: 9812345678" | MALICIOUS | $p = 0.4985$ (BENIGN) | **$p = 0.9797$ (MAL)** | **VERIFIED FIXED (Targeted correction).** |
| `GREET_HI` | "Hi" | BENIGN | $p = 0.6497$ (MAL) | **$p = 0.5165$ (BEN)** | **VERIFIED FIXED (Marginal pass).** |
| `GREET_HELLO` | "Hello" | BENIGN | $p = 0.9914$ (MAL) | **$p = 0.9459$ (MAL)** | **CRITICAL FAILURE: Still False Positive.** |
| `APK_PAYLOAD`| "...Download our partner app to redeem: http://cashback-hub.net/rewards.apk" | MALICIOUS | $p = 0.0837$ (MISSED) | **$p = 0.8494$ (MAL)** | **VERIFIED FIXED (Subword activation).** |
| `NOTIF_USB` | "USB debugging connected. Tap to turn off USB debugging." | BENIGN | $p = 0.7055$ (MAL) | **$p = 0.1989$ (BEN)** | **VERIFIED FIXED.** |

### 5.2 Systematic Failures Discovered in Stored Metrics
- **Benign Electricity Alerts (`v44_holdout_electricity`)**:
  - Benign records: 55.
  - Candidate B False Positives: **26 / 55 (47.3% FPR)**.
  - Typical False Positive: *"Dear Consumer, your electricity bill of Rs 1,420 for Consumer No 10293847 is due on 22-Sep. Pay online via msedcl.gov.in"* ($p = 0.719$, classified as MALICIOUS).
- **Legitimate 2FA/OTP SMS (`holdout_system_notifications`)**:
  - OTP records: 25.
  - Candidate B False Positives: **17 / 25 (68.0% FPR)**.
  - Typical False Positive: *"Your Google verification code is 492019. Do not share this code with anyone."* ($p = 0.913$, classified as MALICIOUS).
- **Institutional Partnerships Regression (`slice_slice_institutional_partnerships`)**:
  - Total malware samples: 16.
  - V4.3 Recall: 75.0% (12/16).
  - Candidate B Recall: **56.2% (9/16)** — **Regressed by 3 samples (-18.8%)**.

---

## 6. Blind Provenance-Clean Source-Shift Evaluation

Candidate B was frozen and evaluated on three completely unseen external evaluation suites:

### 6.1 Real Mobile Simulation Cases (`SIMULATION_CASES.jsonl`, $N=294$)
Real-world mobile messages collected from WhatsApp, Google Messages, and Android OS notifications:

```
Confusion Matrix (Candidate B on Mobile Simulation):
                  Predicted Benign    Predicted Non-Benign
Actual Benign           280                     11  (FPR = 3.78%)
Actual Malicious          0                      3  (Recall = 100.0%)
```

- **Metrics**: Recall = **100.0% (3/3)**, Precision = **21.43% (3/14)**, FPR = **3.78% (11/291)**, F1 = **35.29%**.
- **Slice Breakdown**:
  - `BENIGN_SYSTEM_NOTIFICATION` ($N=143$): **0 FPs (0.0% FPR)** (V4.3 had 1 FP).
  - `AMBIGUOUS_CONVERSATIONAL` ($N=44$): **2 FPs (4.5% FPR)** (V4.3 had 4 FPs).
  - `BENIGN_CONVERSATIONAL_CHAT` ($N=103$): **8 FPs (7.8% FPR)** (Matches V4.3).

### 6.2 Provenance-Clean OOD Split ($N=1,075$)
Filtered to exclude all 57 records with aggressive-norm or template overlap with training data:

```
Confusion Matrix (Candidate B on Clean OOD):
                  Predicted Benign    Predicted Non-Benign
Actual Benign           249                      0  (FPR = 0.00%)
Actual Malicious         21                    805  (Recall = 97.46%)
```

- **Metrics**: Recall = **97.46% (805/826)**, Precision = **100.00%**, FPR = **0.00% (0/249)**, F1 = **98.71%**.
- **Comparison**: Matches V4.3 recall (97.46%) while eliminating the 1 false positive present in V4.3 (0.40% -> 0.00%).

### 6.3 Independent Semantic Generalization Suite ($N=50$)
Unseen brand and attack permutations authored during V4.3 development:

```
Confusion Matrix (Candidate B on Independent Semantic):
                  Predicted Benign    Predicted Non-Benign
Actual Benign            16                      9  (FPR = 36.00%)
Actual Malicious          3                     22  (Recall = 88.00%)
```

- **Metrics**: Recall = **88.00% (22/25)**, Precision = **70.97%**, FPR = **36.00% (9/25)**, F1 = **78.57%**.
- **Comparison**: Modest improvement over V4.3 (Recall 84.0% -> 88.0%, FPR 40.0% -> 36.0%).

---

## 7. Explicit Categorization of Evidence

To prevent manufactured certainty, all findings are categorized into four distinct evidence tiers:

### 7.1 Demonstrated Generalization (High Confidence)
- **Provenance-Clean OOD Generalization**: Zero false positives (0/249) and 97.46% recall on out-of-distribution messages verified to have zero lexical or template overlap with training data.
- **Real Android OS Notifications**: 0 false positives (0/143) on authentic background OS alerts (battery, backup, Wi-Fi) in the mobile simulation dataset.

### 7.2 Targeted Corpus Correction (Confirmed Narrow Fixes)
- **Hinglish Electricity Phishing (`ELEC_003`)**: Elevated from $p=0.4985$ to $p=0.9797$ through the addition of 50 compositional utility phishing templates.
- **APK Download Links**: Elevated from $p=0.0837$ to $p=0.8494$ via explicit exposure of `.apk` in smishing contexts.
- **"Hi" False Alarm Suppression**: Reduced from $p=0.6497$ to $p=0.5165$ by adding 43 short informal conversational greetings.

### 7.3 Benchmark-Specific Improvement (Overfitting Risk)
- **Slice System Notifications (30 records)**: 0.0% FPR was achieved on `bench_system_notifications` because those specific 30 templates were mirrored in training. When tested on the broader holdout, the FPR spiked to 45.5%.
- **Holdout Electricity Recall (100% on 55 records)**: Directly co-generated with the training templates, creating synthetic similarity that over-represents real-world performance.

### 7.4 Unresolved Uncertainty & Production Blockers
- **Bare "Hello" False Positive ($p = 0.9459$)**: Unresolved. Single-word "Hello" is treated as an attack.
- **Benign Electricity Notices (47.3% FPR)**: Unresolved. Official utility bills with legitimate domains (e.g. `msedcl.gov.in`) are blocked.
- **Legitimate OTP/2FA Messages (68.0% FPR)**: Unresolved. Messages containing `"verification code"` without verified banking headers are frequently flagged.
- **Institutional Partnerships Recall Drop (75.0% -> 56.2%)**: Unresolved regression on 3 attack vectors.

---

## 8. Final Status & Smallest Justified Next Experiment

### 8.1 Status: RELEASE CANDIDATE (V4.4-RC1)
Candidate B is **NOT approved for production deployment**. It remains staged in `messages_v4_4/models/candidate_b_refined/` as **V4.4-RC1**. The Android production loader (`MlModule.kt`) will continue to operate with V4.3 as the active release until RC2 is validated.

### 8.2 Smallest Justified Next Experiment (V4.4-RC2)
To resolve the identified blockers without architectural bloat:

1. **Benign Utility Counter-Weighting**: Inject 100 authentic benign utility billing and notification templates (discom receipts, bill generation alerts, scheduled maintenance notices) to neutralize the 47.3% electricity FPR.
2. **Single-Word Greeting Token Calibration**: Add single-turn isolated greeting tokens (`"Hello"`, `"Hello."`, `"Hello!"`, `"Hey"`, `"Good morning"`) directly into the benign conversational training split.
3. **Institutional Phishing Recovery**: Restore 20 institutional callback and partnership phishing samples into `train_v4_4_rc2.jsonl` to recover the 75%+ recall on `slice_institutional_partnerships`.
4. **Independent Split Validation**: Verify that the utility FPR drops below 5.0% on `holdout_electricity` and institutional recall recovers to $\ge 75\%$ before any production promotion.
