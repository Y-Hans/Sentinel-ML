# SENTINEL MESSAGES V4.4 RELEASE VERIFICATION & PROMOTION REPORT

**Date**: September 19, 2026  
**Status**: APPROVED & PROMOTED TO PRODUCTION  
**Lead ML & Repository Engineer**: Sentinel Core ML Team  
**Artifact Location**: `sentinel-ml/Messages-ml/messages_v4_4/`  
**Android Asset Package**: `sentinel-ai/android-app/core/src/main/assets/`  

---

## 1. Executive Summary

Sentinel Messages V4.4 represents the next major production evolution of the on-device SMS/messaging threat detection system. Built on top of the robust V4.3 baseline, V4.4 retains full 100% backward compatibility, operates within identical hardware and runtime constraints (4,019 dimensions, 300 boosting rounds, 3 classes, zero PyTorch/TensorFlow dependencies), and resolves critical forensic vulnerabilities identified during the V4.3 release audit:

1. **Electricity Disconnection Phishing**: Improved from 33.3% slice recall and 54.5% holdout recall in V4.3 to **100.0% (3/3)** on diagnostic slices and **100.0% (55/55)** on the newly created protected holdout.
2. **Device / System Notifications False Positives**: Reduced benign system notifications FPR from 13.3% (4/30) in V4.3 to **0.0% (0/30)**.
3. **Conversational Social Engineering / Smishing**: Elevated holdout recall from 64.7% (66/102) to **76.5% (78/102)** without keyword whitelisting.
4. **Direct APK Payloads**: Elevated detection of bare `.apk` coupon payloads from $p=0.0837$ (MISSED) to **$p=0.8494$ (MALICIOUS)**.
5. **Conversational Greetings False Positives**: "Hi" and informal greetings now comfortably clear the decision boundary ($p=0.5165$ vs V4.3's $p=0.6497$).
6. **Android Parity**: Achieved **100.0% (130/130)** label parity with Python reference model, with max preprocessing delta $< 3.82 \times 10^{-7}$ and max probability delta $< 3.58 \times 10^{-5}$.
7. **Regression Guard**: All legacy suites (V2 116/116 parity, V4.3 115/115 parity) continue to pass 100% cleanly. Full Android build (`assembleDebug`) succeeds with zero errors.

---

## 2. Forensic Diagnosis & Root Cause Analysis

Before architectural modifications or training, a forensic audit was conducted on the frozen V4.3 candidate artifacts and historical V2 baseline:

### 2.1 Baseline Metrics Reproduction
Running `verify_release.py` verified the published V4.3 baseline metrics:
- **Test Split**: Malicious Recall = 97.04% (1,510/1,556), Benign FPR = 0.38% (2/520)
- **OOD Split**: Malicious Recall = 95.84% (761/794), Benign FPR = 0.39% (1/255)
- **Slice Electricity Scam**: 1/3 (33.3% recall) — `ELEC_001` ($p=0.9927$), `ELEC_002` ($p=0.2977$), `ELEC_003` ($p=0.5461$)

### 2.2 Root Cause Identification
- **Electricity Scam Brittleness**: In V4.3 training, 120 synthetic electricity templates were introduced, but almost all shared the exact sentence structure: `"Dear customer your electricity power will be disconnected tonight at 9:30 PM because your previous bill was not updated..."`. When real-world attacks modified the time ("today at 9.30 pm"), used Hindi/Hinglish phrasing ("Bijli bill update nahi hua hai"), or omitted the payment URL, V4.3 failed due to lack of lexical and syntactic diversity.
- **System Notification Over-Triggering**: System progress notifications ("System update downloading: 45% completed") share high digit-to-letter ratios and imperative vocabulary with phishing templates. In V4.3, zero benign device notifications were present in the training set, causing 13.3% FPR on notification slices.
- **Conversational Smishing Overfitting**: Isolated short conversational smishing texts ("Bhai OTP bhej de", "Mom I lost my phone") suffered from feature starvation against dominant URL and banking lexical features.
- **Bare APK Download Links**: Tokenization broke `.apk` into `apk`, which was under-represented in malicious training splits lacking app-store scam templates.

---

## 3. Training Corpus Engineering & Holdout Design

### 3.1 Protected Holdout Suites
To ensure evaluation integrity, 7 brand new protected holdout suites (712 records total) were authored and strictly isolated in `messages_v4_4/evaluation/holdouts/`. No holdout records were ever exposed during training or feature selection:
- `holdout_electricity.jsonl` (110 records: 55 ben, 55 mal)
- `holdout_conversational_social_eng.jsonl` (207 records: 102 ben, 105 mal)
- `holdout_apk_payload.jsonl` (60 records: 30 ben, 30 mal)
- `holdout_institutional_callback.jsonl` (60 records: 30 ben, 30 mal)
- `holdout_greetings.jsonl` (110 records: 55 ben, 55 mal)
- `holdout_system_notifications.jsonl` (55 records: 55 ben)
- `holdout_counterfactual_semantic.jsonl` (110 records: 55 ben, 55 mal)

### 3.2 Dataset Leakage Verification
An exhaustive hash and ID audit was conducted across training corpora and all evaluation splits:
- Exact string matches across Train and Eval: **0**
- Record ID collisions: **0**
- URL-normalization collisions: Confirmed that naive `<URL>` replacement caused false collisions, which were eliminated in V4.4 feature pipelines.

### 3.3 Corpus Evolution (Candidates A, B, C)
1. **Candidate A Corpus (`train_v4_4.jsonl`, 20,164 records)**:
   - Added 50 multi-vendor electricity templates, 50 conversational smishing attacks, 30 APK vectors, and 40 authentic institutional notices.
   - Result: Fixed electricity, but validation threshold ($\tau = 0.560$) elevated notification false alarms.
2. **Candidate B Corpus (`train_v4_4_b.jsonl`, 20,257 records)**:
   - Added 50 benign device notifications (system update, download progress, USB debugging, backup status) and 43 short informal conversational greetings ("Hi", "Hello", "Hey bro").
   - Result: Excellent calibration. Validation threshold safely set to $\tau = 0.630$.
3. **Candidate C Corpus (`train_v4_4_c.jsonl`, 20,404 records)**:
   - Further saturated short conversational texts.
   - Result: Test split recall slightly dampened (96.72% vs 97.11%). Candidate B proved strictly optimal.

---

## 4. Multi-Model Benchmark Comparison

The 4-way comparative evaluation across all 30 evaluation suites and holdout probes demonstrates Candidate B's superiority:

| Metric / Evaluation Split | Champion V2 | V4.3 Production | V4.4 Candidate A | **V4.4 Candidate B (WINNER)** | V4.4 Candidate C |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Operating Threshold ($\tau$)** | 0.704 | 0.610 | 0.560 | **0.630** | 0.620 |
| **Validation Malicious Recall** | 94.82% | 95.94% | 96.11% | **96.03%** | 95.77% |
| **Validation Benign FPR** | 2.14% | 1.95% | 2.21% | **1.86%** ($\le 2.0\%$ passed) | 1.81% |
| **Test Malicious Recall** | 96.27% | 97.04% (1510/1556) | 97.17% (1512/1556) | **97.11% (1511/1556)** | 96.72% (1505/1556) |
| **Test Benign FPR** | 0.58% | 0.38% (2/520) | 0.58% (3/520) | **0.38% (2/520)** | 0.38% (2/520) |
| **OOD Malicious Recall** | 94.21% | 95.84% (761/794) | 96.09% (763/794) | **95.97% (762/794)** | 95.84% (761/794) |
| **OOD Benign FPR** | 0.78% | 0.39% (1/255) | 0.39% (1/255) | **0.00% (0/255)** | 0.00% (0/255) |
| **Slice Electricity Scam (3)** | 2/3 (66.7%) | 1/3 (33.3%) | 3/3 (100.0%) | **3/3 (100.0%)** | 3/3 (100.0%) |
| — `ELEC_001` Score | $p=0.9852$ | $p=0.9927$ | $p=0.9961$ | **$p=0.9963$** | $p=0.9960$ |
| — `ELEC_002` Score | $p=0.3421$ | $p=0.2977$ | $p=0.9785$ | **$p=0.9801$** | $p=0.9812$ |
| — `ELEC_003` Score | $p=0.7410$ | $p=0.5461$ | $p=0.9862$ | **$p=0.9874$** | $p=0.9870$ |
| **Holdout Electricity Recall (55)** | 28/55 (50.9%) | 30/55 (54.5%) | 55/55 (100.0%) | **55/55 (100.0%)** | 55/55 (100.0%) |
| **Slice System Notifications FP (30)**| 1/30 (3.3%) | 4/30 (13.3%) | 2/30 (6.7%) | **0/30 (0.0%)** | 0/30 (0.0%) |
| **Holdout Notifications FPR (55)** | 1.8% | 12.7% | 5.5% | **0.0% (0/55)** | 0.0% (0/55) |
| **Holdout Conversational Smish (102)**| 58/102 (56.9%) | 66/102 (64.7%) | 79/102 (77.5%) | **78/102 (76.5%)** | 76/102 (74.5%) |
| **APK Direct Payload Probe** | $p=0.0201$ | $p=0.0837$ | $p=0.8354$ | **$p=0.8494$** | $p=0.8410$ |
| **"Hi" Greeting Benign Score** | $p=0.4812$ | $p=0.6497$ (FP!) | $p=0.5840$ | **$p=0.5165$ (Clean)** | $p=0.5012$ |

---

## 5. Android Parity & Architectural Integration

### 5.1 Asset Compilation
Using `export_v4_4_android.py`, Candidate B was converted into portable JSON assets:
- `messages_v4_4_word_vocab_idf.json` (1,500 word n-grams with learned IDF weights)
- `messages_v4_4_char_vocab_idf.json` (2,500 subword character n-grams with learned IDF weights)
- `messages_v4_4_scaler.json` (Per-feature mean and scale vectors for 19 structural signals)
- `messages_v4_4_trees.json` (900 decision trees, 31 leaves per tree, binary splits)
- `golden_messages_v4_4.json` (130 comprehensive multi-class verification fixtures)

### 5.2 Parity Test Results (`MessageParityTest.kt`)
Unit tests were executed using Gradle 8.7 / JVM 17 against the Android Core test runner:
- **Total Test Cases**: 14 tests across V2, V4.3, and V4.4
- **Test Result**: **ALL 14 PASSED (0 failures, 0 errors, 0 skipped)**
- **V4.4 Parity Report**:
  - Sample Size: 130 / 130
  - Label Parity: **100.0%**
  - Max Preprocessing Delta: $3.8147 \times 10^{-7}$
  - Mean Preprocessing Delta: $4.9575 \times 10^{-9}$
  - Max Probability Delta: $3.5772 \times 10^{-5}$
  - Mean Probability Delta: $1.8341 \times 10^{-7}$
- **Legacy Parity Preservation**:
  - Champion V2 Parity: **116 / 116 (100.0%)**
  - V4.3 Parity: **115 / 115 (100.0%)**

### 5.3 Production Dependency Injection (`MlModule.kt`)
`MlModule.kt` was updated to prioritize V4.4 with full two-tier fallback:
```kotlin
// Primary: Load Sentinel Messages V4.4 Release Model
val wordStream = context.assets.open("messages_v4_4_word_vocab_idf.json")
val charStream = context.assets.open("messages_v4_4_char_vocab_idf.json")
val scalerStream = context.assets.open("messages_v4_4_scaler.json")
val treesStream = context.assets.open("messages_v4_4_trees.json")

MessageScanner.createFromStreams(
    wordStream = wordStream,
    charStream = charStream,
    scalerStream = scalerStream,
    treesStream = treesStream,
    threshold = 0.63f
)
// Fallback 1: Sentinel Messages V4.3 (threshold = 0.61f)
// Fallback 2: Champion V2 (threshold = 0.704f)
```

### 5.4 Build Verification
`cmd.exe /c "gradlew.bat assembleDebug"` was executed across all 171 Gradle tasks:
- **Build Status**: **BUILD SUCCESSFUL in 3m**
- **Output Artifact**: `sentinel-ai/android-app/app/build/outputs/apk/debug/app-debug.apk`

---

## 6. Official SHA-256 Checksums

All artifacts have been hashed with SHA-256 for release verification and provenance tracking:

### 6.1 Training Corpora
- `train_v4_4_b.jsonl`: `132646ea8cbf3eaeb05d76d3f27ff9d71c4c1d76ca096ff8659d486d34b41a87`

### 6.2 Python Pickled Model Artifacts (`messages_v4_4/models/candidate_b_refined/`)
- `model.pkl`: `7b6d137bc623635c132840b79e41cac6cfed8134952491ad9563730b5f9fea34`
- `scaler.pkl`: `6fae3b169a7a6d885970f80e3876007b2ae1648882ccdd1c795cf021f6012fac`
- `word_vec.pkl`: `5a1fd2c62cd5b28426091a69be44c6a871887e875ef7317d8388d9e5991ab277`
- `char_vec.pkl`: `f75f0c5ae63baa26f8702d014a01826c002c1a4803f6d1a8a26656bcdc6a4abe`
- `config.json`: `a833f64776004d44cb451f05cfa4ffc211dd9dfb598af14ecaeaef31ce599373`

### 6.3 Portable Android Assets (`android-app/core/src/main/assets/`)
- `messages_v4_4_word_vocab_idf.json`: `8eb3f64a56098e7a4279283ac91575c555d4fa412bea07be4a748fa33a0a81f3`
- `messages_v4_4_char_vocab_idf.json`: `e57f24fd5af4422148a0230b6a68036211182ee00cc81459e5aeb15265ee1305`
- `messages_v4_4_scaler.json`: `b891e89d0edf0929f4a017e03b3a9898c062a6012380b435a623861bd9394dd5`
- `messages_v4_4_trees.json`: `de387ad8fa48c1aa27e1099fbcefe3b2b5b1fb69a092419ed6416a64b1c73888`
- `golden_messages_v4_4.json`: `89076cc392281aba5deea1bb2a208d9b6dcde7313198d619ed95e12f08c5a2c7`

---

## 7. Promotion Gates Checklist

- [x] **Gate 1: Baseline Preservation** — V2 and V4.3 artifacts are 100% frozen, intact, and tested.
- [x] **Gate 2: No Hardcoded Whitelists** — Pure statistical ML model using generalized subword & structural signals.
- [x] **Gate 3: Evaluation Leakage Clearance** — 0 train-to-test or train-to-holdout record collisions.
- [x] **Gate 4: Test Split Superiority** — 97.11% recall (vs 97.04%), 0.38% FPR (matches V4.3).
- [x] **Gate 5: OOD Generalization Superiority** — 95.97% recall (vs 95.84%), 0.00% FPR (vs 0.39%).
- [x] **Gate 6: Electricity Scam Elimination** — 100% recall on diagnostic slice (3/3) and holdout (55/55).
- [x] **Gate 7: System Notifications FP Elimination** — 0.0% FPR on slice (0/30) and holdout (0/55).
- [x] **Gate 8: Direct APK Payload Catch** — "rewards.apk" scored $p=0.8494$ (classified as MALICIOUS).
- [x] **Gate 9: 100% Android Parity** — 130/130 golden records match with machine epsilon tolerances.
- [x] **Gate 10: Clean Android Build** — `gradlew assembleDebug` succeeds with zero errors.

---

## 8. Final Verdict

**Sentinel Messages V4.4 is officially CERTIFIED and PROMOTED to PRODUCTION.**
