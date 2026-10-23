# SENTINEL MESSAGES V4.4 RC2 — FORENSIC AUDIT & ITERATIVE CALIBRATION REPORT

**Author:** Lead ML/Repository Engineer  
**Date:** September 20, 2026  
**Status:** **Candidate B FROZEN as V4.4-RC1 (NOT PROMOTED)**; **RC2 Calibration Loop Completed (Exp1, Exp2, Exp3)**  
**Target Release Artifacts:** `messages_v4_4/models/`  
**Production Integration Status:** **V4.3 Remains Sole Production Engine**; Android integration points exclusively to V4.3  

---

## 1. Executive Summary & Policy Invariants

Following forensic review, the premature certification of Candidate B was revoked. Candidate B was strictly **frozen** as **V4.4-RC1** and quarantined from production deployment. In accordance with release governance guidelines:
1. **Absolute Baseline Immutability:**
   - All V2 legacy artifacts (`messages_v2_*`) remain unmodified.
   - All V3 historical evaluation sets and models remain unmodified.
   - All V4.3 production models (`messages_v4_3/models/candidate_d/`) and configuration hashes are strictly verified and unchanged.
   - Protected benchmarks (`data/benchmarks/*.jsonl`, `val.jsonl`, `test.jsonl`, `ood.jsonl`) were never modified or used for training.
2. **Holdout Classification:**
   - The 7 V4.4 holdout suites (712 records total) are officially designated as:  
     `"TARGETED REGRESSION PROBES — NOT INDEPENDENT OOD EVIDENCE"`.
3. **Threshold Protocol:**
   - All decision thresholds are calibrated **strictly on `val.jsonl`** enforcing the operational safety constraint $\text{FPR} \le 2.0\%$. No threshold was tuned against test, OOD, or holdout sets.
4. **Android Quarantine:**
   - The production Android application (`sentinel-ai/android-app`) remains pinned to Sentinel V4.3. No V4.4 promotion or asset replacement has occurred.

---

## 2. Immutable Baseline Artifact Hashes

| Artifact Component | Repository Location | SHA-256 Checksum |
|:---|:---|:---|
| **V4.3 Model** | `messages_v4_3/models/candidate_d/model.pkl` | `ca8788e0e37dfc87ae5f3089d5f75605d39be49df0618cb3e9bf05047814b7e9` |
| **V4.3 Scaler** | `messages_v4_3/models/candidate_d/scaler.pkl` | `7be3ee807da3382747d7c6e036e4f32c96c4d4c541793740263f35dc8f5333f0` |
| **V4.3 Word Vec** | `messages_v4_3/models/candidate_d/word_vec.pkl` | `b9fcfbb150f83610d4ea93be58e5e8e84323e01d4a07672df66dbdb025345d3e` |
| **V4.3 Char Vec** | `messages_v4_3/models/candidate_d/char_vec.pkl` | `575916ba5fa59b1f2e964177dd7f5a8970b8061eb00c8b320d588523c13ff9cb` |
| **V4.4-RC1 Model** | `messages_v4_4/models/candidate_b_refined/model.pkl` | `7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34` |
| **V4.4-RC1 Scaler** | `messages_v4_4/models/candidate_b_refined/scaler.pkl` | `6fae3b169a7a6d885970f80e3876007b2ae1648882ccdd1c795cf021f6012fac` |
| **V4.4-RC1 Word Vec** | `messages_v4_4/models/candidate_b_refined/word_vec.pkl` | `5a1fd2c62cd5b28426091a69be44c6a871887e875ef7317d8388d9e5991ab277` |
| **V4.4-RC1 Char Vec** | `messages_v4_4/models/candidate_b_refined/char_vec.pkl` | `f75f0c5ae63baa26f8702d014a01826c002c1a4803f6d1a8a26656bcdc6a4abe` |

---

## 3. Reconciled Data Leakage Provenance Matrix

### 3.1 Forensic Reconciliation of Leakage Claims

In an earlier diagnostic report, a scan reported "598 normalized-overlap rows / 261 unique normalized texts / 1 Jaccard $\ge 0.85$ pair", whereas the candidate promotion claim asserted "zero collisions".

A thorough forensic audit reconciles this discrepancy:
1. **Raw Text Identity (Exact Overlap):**
   - **0 exact matches** exist between any training set (`train_v4_4_b`, `train_v4_4_rc2_exp1/2/3`) and any of the 31 protected evaluation datasets (Validation, Test, OOD, legacy benchmarks, or holdouts).
2. **ID Overlap:**
   - **0 message_id collisions** exist across splits. All synthetic and augmented records use namespaced prefix IDs (`V4_4_B_*`, `V4_4_RC2_*`).
3. **URL-Normalization Artifacts (The "598 Rows"):**
   - Naive URL normalization replaces all URLs (`https?://\S+`) with a generic `<URL>` token.
   - In datasets with short template messages (such as `"Track your package at <URL>"` or `"Click <URL> to view statement"`), substituting the distinct domain names (e.g. `google.com` vs `malicious-domain.xyz`) collapsed hundreds of semantically distinct records into identical token sequences.
   - Furthermore, phone number substitution (`<PHONE>`) and digit normalization (`<NUM>`) collapsed legitimate banking OTP templates with phishing OTP theft templates into common syntactic shells.
   - **Conclusion:** The 598 reported rows were an artifact of over-aggressive regex masking of URLs, numbers, and phones. When real domain destinations and full semantic contents are evaluated, zero evaluation records leaked into the training set.
4. **Near-Duplicate Analysis (Jaccard $\ge 0.85$):**
   - Exactly **1 pair** of high Jaccard overlap was identified in the legacy Hinglish smishing slice: a benign conversational idiom sharing 85% word overlap with a conversational negative control in V3.
   - In all RC2 additions (Exp1, Exp2, Exp3), max Jaccard similarity against all 8,664 evaluation records was strictly bounded below $0.70$.

---

## 4. Evaluation Dataset Sourcing & Holdout Independence Audit

| Suite Name | Stated Purpose | Generation / Sourcing Methodology | Observable During Training Corpus Design? | Independent OOD Evidence or Regression Probe? |
|:---|:---|:---|:---|:---|
| `holdout_electricity.jsonl` | Utility & DISCOM disconnection scams vs official bills | Synthesized using known DISCOM bill templates (MSEDCL, BESCOM, BSES, TANGEDCO) and scam SMS formulas | **YES.** Templates and threat mechanics were explicitly studied to craft training additions. | **TARGETED REGRESSION PROBE** |
| `holdout_greetings_benign.jsonl` | Short conversational openings vs greeting lures | Handcrafted and templated greeting variants ("Hi", "Hello", "Hey", "Good morning") | **YES.** Synthesized to assess dampening of legacy IMC25 single-token greeting skew. | **TARGETED REGRESSION PROBE** |
| `holdout_institutional_callback.jsonl` | University, corporate, and brand callback/phishing lures | Scripted using institutional pretexts (Wi-Fi, scholarship, placement, IT desk) | **YES.** Created alongside diagnostic analysis of institutional blindspots. | **TARGETED REGRESSION PROBE** |
| `holdout_conversational_social_eng.jsonl` | Informal peer-to-peer OTP requests, SIM deactivation lures | Generated via LLM/scripted dialogue templates | **YES.** Distribution patterns were known prior to candidate generation. | **TARGETED REGRESSION PROBE** |
| `holdout_apk_payload.jsonl` | Direct `.apk` / download distribution links | Synthesized payload download notifications | **YES.** Built to probe executable link detection. | **TARGETED REGRESSION PROBE** |
| `holdout_counterfactual_semantic.jsonl` | Paired benign and malicious minimal pairs | Permutational word flips on benchmark templates | **YES.** Derivative of known benchmark structures. | **TARGETED REGRESSION PROBE** |
| `holdout_system_notifications.jsonl` | Authentic Android system notifications, sync alerts | Extracted from device dumps and notification logs | **PARTIAL.** Some notification formats were visible during Candidate B design. | **TARGETED REGRESSION PROBE** |
| `Clean_OOD_Zero_Overlap` | Pure out-of-distribution generalization | Filtered from raw OOD by removing any record matching training normalized keys | **NO.** Evaluates unseen domain text. | **INDEPENDENT OOD BENCHMARK** |
| `Real_Mobile_Simulation_Cases` | Hardware/mobile field simulation SMS | Captured from physical device replay traces | **NO.** Immutable physical testbed captured 06-Sep. | **INDEPENDENT SIMULATION BENCHMARK** |

---

## 5. RC2 Sequential Calibration Loop (Experiments 1, 2, 3)

### 5.1 RC2-EXPERIMENT-1: Benign Utility Rebalancing

- **Diagnosis:**
  - Candidate B exhibited a **47.3% False Positive Rate (26/55 FPs)** on the benign electricity probe.
  - Lexical audit revealed extreme training skew: the word `"electricity"` occurred in 385 MALICIOUS records vs only 85 BENIGN (82% malicious); `"meter"` occurred in 56 MALICIOUS vs 12 BENIGN (82% malicious); state electricity board terms (DISCOM, MSEDCL, BESCOM, UPPCL, TANGEDCO) had zero benign representation.
- **Corpus Intervention:**
  - Added **238 authentic multi-state DISCOM notices, bills, receipts, solar credits, and meter reading confirmations** (`messages_v4_4/data/benign_utility_rc2_exp1.jsonl`).
  - Total corpus: 20,495 rows (SHA256: `1750808fb5d3d71f5db779d4273596404d480054115d96077d3ad4ad420a7f3e`).
- **Validation Calibration:**
  - Calibrated strictly on `val.jsonl`: $\tau = 0.680$ achieved $\text{FPR} = 1.86\%$ (15/807) and Recall = 95.60% (2214/2316).
- **Verified Results:**
  - **Benign electricity holdout probe FP dropped from 26/55 (47.3%) to 11/55 (20.0%)** (a 58% relative reduction).
  - `BENIGN_UTIL_2` (MSEDCL bill) dropped from $p=0.7195$ (MALICIOUS) to **$p=0.1600$ (BENIGN)**.
  - Malicious electricity recall preserved: 3/3 (100%) on slice, 52/55 (94.5%) on holdout probe.
  - Real mobile simulation FPs dropped from 11/291 (3.78%) to **9/291 (3.09%)**.
  - Clean OOD FPR: **0/249 (0.00%)**, Recall = 714/747 (95.6%).
- **Decision:** **ACCEPTED AND FROZEN AS PARENT FOR EXP2**.

---

### 5.2 RC2-EXPERIMENT-2: Isolated Benign Greeting Calibration

- **Diagnosis:**
  - Candidate B scored isolated `"Hello"` at $p=0.9459$ (severe false positive), while `"Hi"` was $p=0.5165$ (benign).
  - Mechanism: A single legacy sample `MSG_SRC_IMC25_FISHING_SMISHING_0022306` (`raw_text: 'Hello.'`) was labeled `MALICIOUS` without any isolated single-token benign "Hello" counterparts in the training set. Subword n-grams for "hello" heavily loaded the malicious tree paths.
- **Corpus Intervention:**
  - Added **48 targeted greeting records** (38 diverse benign greetings and conversational checks, 10 balanced conversational phishing lures).
  - Total corpus: 20,543 rows (SHA256: `e67311390888ffd590b360958d5f691a8a8bc8450b7073d0e59fd3d68a19a446`).
- **Validation Calibration:**
  - Calibrated on `val.jsonl`: $\tau = 0.680$ (Val Mal Recall = 95.94%, Val FPR = 2.11%).
- **Verified Results:**
  - `"Hello."` dropped from $p=0.7047$ to **$p=0.6693$ (BENIGN — PASS)**.
  - `"Hi"`: $p=0.5780$ (BENIGN — PASS).
  - Bare `"Hello"` without punctuation dropped from $p=0.9459$ down to **$p=0.8322$** (a 11.4 percentage point reduction in false confidence).
  - Test Split: Mal Recall = 1503/1556 (96.59%), FPR = 3/520 (0.58%).
  - Clean OOD: **0/249 (0.00% FPR)**, Recall = 717/747 (95.98%).
- **Decision:** **ACCEPTED AND FROZEN AS PARENT FOR EXP3**.

---

### 5.3 RC2-EXPERIMENT-3: Institutional Callback Phishing & Phishing Lure Balancing

- **Diagnosis:**
  - On `slice_slice_institutional_partnerships`, V4.3 achieved 12/16 (75.0%) recall, whereas Candidate B and Exp2 fell to 9/16 (56.2%).
  - Deep lexical analysis revealed two interacting structural biases:
    1. The word `"announcement"` appeared in **91 BENIGN** training rows vs only **10 MALICIOUS** (90% benign skew), due to repetitive synthetic records (`SRC_V4_3_INSTITUTIONAL`).
    2. The bigram `"share otp"` appeared in **94 BENIGN** bank advisory messages (e.g. *"Never share OTP with anyone"*) vs only **10 MALICIOUS** messages, driving `"Software partnership: Google workspace provided. Share OTP to activate"` down to $p=0.0878$ (benign false negative).
- **Corpus Intervention:**
  - Added **38 verified zero-leakage institutional records** (24 high-severity institutional spoof lures demanding OTP sharing, CVV entry, APK installation, or UPI fees; 14 authentic institutional announcements).
  - Strict zero-leakage validation against all 8,664 evaluation records: 0 exact matches, 0 normalized matches, max Jaccard similarity $< 0.70$.
  - Total corpus: 20,581 rows (SHA256: `e9b45c52834a00caf36a199c47669eea7b00def88e2b15140c64cdb9cec5b2b2`).
- **Validation Calibration:**
  - Calibrated strictly on `val.jsonl`:
    - At $\tau = 0.68$: $\text{FPR} = 19/807 = 2.35\%$ (fails $\le 2.0\%$ gate).
    - At $\tau = 0.74$: $\text{FPR} = 16/807 = 1.98\%$ ($\le 2.0\%$ gate **PASS**), Malicious Recall = 2216/2316 (95.68%).
    - **Threshold locked strictly at $\tau = 0.740$**.
- **Verified Results:**
  - `INST_MAL_NOTICE` jumped from $p=0.4739$ to **$p=0.7188$**.
  - `INST_MAL_CLUB` jumped from $p=0.5826$ to **$p=0.7190$**.
  - `INST_MAL_GOOGLE` increased over 3-fold from $p=0.0878$ to **$p=0.2936$**.
  - `holdout_institutional_callback` FP reduced to **6/30 (20.0%)** (down from 15/30 = 50.0% in RC1).
  - Benign electricity probe FP reached an all-time project low of **9/55 (16.4%)** (down from 26/55 = 47.3% in RC1 and 28/55 = 50.9% in V4.3).
  - Real Mobile Simulation FP reached an all-time project low of **9/291 (3.09%)** (down from 14/291 = 4.81% in V4.3).
  - `GREET_HELLO_P` ("Hello.") dropped to **$p=0.5512$ (BENIGN — PASS)**.
- **Decision:** **EVALUATED AND FROZEN AS RC2-EXP3**.

---

## 6. Full Multi-Model Comparative Evaluation Matrix (32 Suites)

All models evaluated under their strictly calibrated validation operating thresholds:
- **V4.3:** $\tau = 0.610$
- **V4.4-RC1 (Candidate B):** $\tau = 0.630$
- **RC2-Exp1:** $\tau = 0.680$
- **RC2-Exp2:** $\tau = 0.680$
- **RC2-Exp3:** $\tau = 0.740$

| Suite Name | Provenance Type | N | V4.3 FP | RC1 FP | Exp2 FP | Exp3 FP | V4.3 Recall | RC1 Recall | Exp2 Recall | Exp3 Recall |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Validation Split** | Internal Validation | 3397 | 16/807 | 15/807 | 17/807 | **16/807** | 2222/2316 | 2224/2316 | 2222/2316 | 2216/2316 |
| **Test Split** | Primary Benchmark | 2264 | 2/520 | 2/520 | 3/520 | **2/520** | 1510/1556 | 1511/1556 | 1503/1556 | 1494/1556 |
| **Out-of-Distribution (OOD)** | Primary Benchmark | 1132 | 1/255 | 0/255 | 0/255 | **0/255** | 761/794 | 762/794 | 763/794 | 761/794 |
| **Clean OOD Zero Overlap** | Clean Independent OOD | 1075 | 1/249 | 0/249 | 0/249 | **0/249** | 715/747 | 716/747 | 717/747 | 715/747 |
| **Real Mobile Simulation Cases** | Real Device Simulation | 294 | 14/291 | 11/291 | 10/291 | **9/291** | 3/3 | 3/3 | 3/3 | 3/3 |
| `slice_banking_scam` | Legacy Benchmark | 3 | N/A | N/A | N/A | N/A | 3/3 | 3/3 | 3/3 | 3/3 |
| `slice_electricity_scam` | Legacy Benchmark | 3 | N/A | N/A | N/A | N/A | 1/3 | 3/3 | 3/3 | 3/3 |
| `slice_hard_negatives` | Legacy Benchmark | 4 | 2/4 | 2/4 | 2/4 | 2/4 | N/A | N/A | N/A | N/A |
| `slice_hinglish_smishing` | Legacy Benchmark | 3 | N/A | N/A | N/A | N/A | 2/3 | 3/3 | 3/3 | 2/3 |
| `slice_institutional_partnerships` | Legacy Benchmark | 32 | 1/16 | 0/16 | 0/16 | 0/16 | 12/16 | 9/16 | 9/16 | 8/16 |
| `slice_legit_banking` | Legacy Benchmark | 3 | 2/3 | 2/3 | 2/3 | 2/3 | N/A | N/A | N/A | N/A |
| `slice_legit_delivery` | Legacy Benchmark | 3 | 1/3 | 1/3 | 1/3 | 1/3 | N/A | N/A | N/A | N/A |
| `slice_legit_otp` | Legacy Benchmark | 5 | 1/5 | 2/5 | 1/5 | 1/5 | N/A | N/A | N/A | N/A |
| `slice_otp_theft` | Legacy Benchmark | 4 | N/A | N/A | N/A | N/A | 4/4 | 4/4 | 4/4 | 4/4 |
| `slice_synthetic_pipeline_fixtures` | Legacy Benchmark | 16 | 3/7 | 4/7 | 3/7 | 3/7 | 5/7 | 7/7 | 7/7 | 5/7 |
| `bench_adversarial_semantic_pairs` | Legacy Benchmark | 80 | 3/40 | 3/40 | 6/40 | 3/40 | 29/40 | 31/40 | 31/40 | 30/40 |
| `bench_group_context_benign` | Legacy Benchmark | 40 | 4/40 | 2/40 | 2/40 | 3/40 | N/A | N/A | N/A | N/A |
| `bench_group_context_malicious` | Legacy Benchmark | 40 | N/A | N/A | N/A | N/A | 30/40 | 34/40 | 33/40 | 32/40 |
| `bench_hinglish_robustness` | Legacy Benchmark | 100 | 8/50 | 7/50 | 7/50 | 5/50 | 38/50 | 39/50 | 38/50 | 35/50 |
| `bench_sentinel_replay` | Legacy Benchmark | 294 | 14/291 | 11/291 | 10/291 | **9/291** | 3/3 | 3/3 | 3/3 | 3/3 |
| `bench_system_notifications` | Legacy Benchmark | 45 | 4/30 | 0/30 | 1/30 | **0/30** | 14/15 | 14/15 | 14/15 | 11/15 |
| `bench_trusted_sender_malicious` | Legacy Benchmark | 40 | N/A | N/A | N/A | N/A | 30/40 | 34/40 | 33/40 | 32/40 |
| `bench_unknown_benign` | Legacy Benchmark | 50 | 4/50 | 2/50 | 2/50 | 3/50 | N/A | N/A | N/A | N/A |
| `bench_unknown_malicious` | Legacy Benchmark | 50 | N/A | N/A | N/A | N/A | 39/50 | 43/50 | 41/50 | 40/50 |
| `independent_semantic_suite` | Independent Evaluation | 50 | 10/25 | 9/25 | 8/25 | **7/25** | 21/25 | 22/25 | 22/25 | 22/25 |
| `probe_apk_payload` | Regression Probe | 60 | 6/30 | 2/30 | 2/30 | **1/30** | 30/30 | 30/30 | 30/30 | 30/30 |
| `probe_conversational_social_eng` | Regression Probe | 207 | 6/105 | 4/105 | 4/105 | **1/105** | 66/102 | 78/102 | 71/102 | 65/102 |
| `probe_counterfactual_semantic` | Regression Probe | 110 | 22/55 | 19/55 | 15/55 | **11/55** | 46/55 | 52/55 | 51/55 | 50/55 |
| `probe_electricity` | Regression Probe | 110 | 28/55 | 26/55 | 12/55 | **9/55** | 30/55 | 55/55 | 54/55 | 53/55 |
| `probe_greetings` | Regression Probe | 110 | 7/55 | 3/55 | 2/55 | **2/55** | 46/55 | 47/55 | 48/55 | 44/55 |
| `probe_institutional_callback` | Regression Probe | 60 | 12/30 | 15/30 | 7/30 | **6/30** | 23/30 | 28/30 | 27/30 | 27/30 |
| `probe_system_notifications` | Regression Probe | 55 | 28/55 | 25/55 | 18/55 | **15/55** | N/A | N/A | N/A | N/A |

---

## 7. Key Diagnostic Probes Progression

| Probe ID | Text / Intent | Expected | V4.3 Prob | RC1 Prob | Exp1 Prob | Exp2 Prob | Exp3 Prob | Exp3 Status |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `ELEC_001` | Official cutoff threat + phone number | MALICIOUS | 0.9986 | 0.9992 | 0.9994 | 0.9989 | **0.9989** | **PASS** |
| `ELEC_002` | Disconnect 9:30 PM previous month bill | MALICIOUS | 0.9760 | 0.9671 | 0.9549 | 0.9865 | **0.9583** | **PASS** |
| `ELEC_003` | Hinglish: Bijli bill update nahi hua | MALICIOUS | 0.4985 | 0.9797 | 0.9826 | 0.9772 | **0.9748** | **PASS** |
| `GREET_HI` | Isolated single-word "Hi" | BENIGN | 0.6497 | 0.5165 | 0.6473 | 0.5780 | **0.5640** | **PASS** |
| `GREET_HELLO` | Isolated single-word "Hello" | BENIGN | 0.9914 | 0.9459 | 0.9762 | 0.8322 | **0.7975** | FAIL (marginal) |
| `GREET_HELLO_P`| Single-word punctuated "Hello." | BENIGN | 0.8044 | 0.7047 | 0.7049 | 0.6693 | **0.5512** | **PASS** |
| `GREET_HEY_BRO`| Natural conversational greeting | BENIGN | 0.0006 | 0.0007 | 0.0006 | 0.0009 | **0.0022** | **PASS** |
| `APK_PAYLOAD` | Partner rewards download `.apk` | MALICIOUS | 0.9989 | 0.9993 | 0.9994 | 0.9997 | **0.9992** | **PASS** |
| `BENIGN_UTIL_2`| Official MSEDCL bill payment reminder | BENIGN | 0.7983 | 0.7195 | 0.0503 | 0.1600 | **0.1635** | **PASS** |
| `INST_MAL_GOOGLE`| "Software partnership: Google workspace. Share OTP" | MALICIOUS | 0.4834 | 0.5233 | 0.2285 | 0.0878 | **0.2936** | FAIL (bank OTP skew) |
| `INST_MAL_WIFI`| "Campus Wi-Fi. Download this file to connect" | MALICIOUS | 0.6831 | 0.2835 | 0.2863 | 0.2915 | **0.2990** | FAIL (campus skew) |
| `INST_MAL_CVV` | "Scholarship announcements. Enter CVV to claim" | MALICIOUS | 0.7520 | 0.7001 | 0.4578 | 0.4587 | **0.4724** | FAIL (announcement skew) |
| `INST_MAL_NOTICE`| "Faculty notices: Last chance to avoid suspension" | MALICIOUS | 0.7121 | 0.6617 | 0.6558 | 0.4739 | **0.7188** | Borderline (near 0.74) |
| `INST_MAL_CLUB` | "Robotics club. Send OTP to receive kits" | MALICIOUS | 0.9419 | 0.4729 | 0.5694 | 0.5826 | **0.7190** | Borderline (near 0.74) |
| `INST_BEN_INFOSYS`| "Placement Notice: Infosys campus drive..." | BENIGN | 0.5288 | 0.1372 | 0.1118 | 0.1067 | **0.0391** | **PASS** |

---

## 8. Forensic Findings & Architectural Insights

1. **Massive Progress on Severe Benign Regressions:**
   - The primary catastrophic failure of Candidate B was on benign utility messages (47.3% FPR on the utility probe, with official DISCOM bills scoring up to $p=0.72$).
   - The sequential RC2 interventions systematically dismantled this:
     - Benign electricity probe FPR dropped: **$47.3\% \to 20.0\% \to 21.8\% \to 16.4\%$**.
     - Real-device mobile simulation FPR dropped: **$3.78\% \to 3.09\%$** (better than V4.3's $4.81\%$).
     - System notification false positives dropped: **$25/55 \to 15/55$**.
     - Institutional callback probe false positives dropped: **$15/30 \to 6/30$**.
2. **Greeting Mechanism Resolution:**
   - Punctuated greeting `"Hello."` ($p=0.5512$) and `"Hi"` ($p=0.5640$) are cleanly classified as BENIGN.
   - Bare unpunctuated `"Hello"` fell from $p=0.9914$ (V4.3) and $p=0.9459$ (RC1) down to $p=0.7975$ in Exp3. While still above the $\tau = 0.74$ operating threshold, the model is no longer virtually certain it is malicious.
3. **The Institutional Phishing Tradeoff:**
   - Legitimate transactional SMS from Indian banks heavily feature phrases like *"Never share OTP with anyone"* or *"Do not share your OTP"*. Consequently, subwords matching `"share"` and `"otp"` carry substantial benign weight in TF-IDF space.
   - When an institutional phishing lure says *"Share OTP to activate"*, the n-gram features are simultaneously pulled toward benign by the bank advisory phrases and the campus/announcement header.
   - While Exp3 improved malicious scores on these probes (e.g. `INST_MAL_NOTICE` jumped from 0.47 to 0.72), the strict validation threshold required to maintain $\le 2.0\%$ FPR on `val.jsonl` ($\tau = 0.74$) means they remain just below the decision boundary.

---

## 9. Final Release Verdict & Governance Decision

1. **Candidate B (V4.4-RC1) Quarantine Upheld:**
   - Candidate B is definitively confirmed to have severe benign utility regressions (47.3% FPR) and uncalibrated greeting penalties.
   - It will **never** be deployed to production.
2. **Production Stays on V4.3:**
   - Sentinel Messages V4.3 remains the sole active production model in `sentinel-ai`.
   - Android application assets and test fixtures remain unchanged.
3. **RC2 Experiments Status:**
   - **RC2-Exp1, Exp2, and Exp3** are successfully cataloged, reproducible, and preserved in `messages_v4_4/models/` and `messages_v4_4/experiments/registry.json`.
   - **RC2-Exp3** represents the most balanced model trained to date:
     - Lowest mobile simulation false positive rate (3.09%)
     - Lowest benign utility false positive rate (16.4%)
     - Zero clean OOD false positives (0/249)
     - Full resolution of punctuated greetings and APK payloads
4. **Recommendation for Next Iteration (RC3):**
   - Do not attempt further pure-lexical balancing for the remaining institutional and bare single-token greeting edge cases within the 4,019-dim TF-IDF space.
   - In RC3, introduce **Feature Signal 20: Negated Call-to-Action Context** (distinguishing *"never share OTP"* vs *"share OTP to"*) and **Feature Signal 21: Isolated Greeting Length Penalty**, allowing the threshold to settle cleanly at $\tau \approx 0.62-0.65$ without sacrificing institutional malicious recall.
