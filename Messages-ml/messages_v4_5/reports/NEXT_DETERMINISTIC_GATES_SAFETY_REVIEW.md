# SENTINEL MESSAGES — DETERMINISTIC SECURITY GATES SAFETY & PRECISION AUDIT

**Document ID**: `SENTINEL-DETERMINISTIC-GATES-SAFETY-2026-09-24`  
**Author**: Lead ML/Security Architecture & Safety Engineer  
**Date**: September 24, 2026  
**Status**: AUDIT COMPLETED — EMPIRICAL EVALUATION ONLY  
**Primary Directive**: Analysis Only (No training, no model creation, no corpus modification, no Android modification, no production modification, no experiment execution).  
**Protected Benchmark**: Sentinel Messages V4.3 Candidate-D ($\tau = 0.6100$, 4,019 dimensions).

---

## 1. Executive Summary & Critical Audit Decision

Following the rejection of the asymmetric semantic sieve architecture (where $G = 35$ unprotected malicious messages halted deployment), an exhaustive empirical safety audit was conducted to evaluate whether **deterministic post-inference upgrade-only security gates** could be safely deployed on top of frozen Sentinel V4.3.

Three candidate upgrade-only gates were evaluated across 21 distinct evaluation sources ($N = 4,471$ benchmark records):
1. **Candidate Gate A**: `.apk` payload / attachment extension gate.
2. **Candidate Gate B**: Normalized `<URL>` token consistency gate.
3. **Candidate Gate C**: Toll-free (`1800`) / callback coercive fraud pattern gate.

### DECISION:
$$\mathbf{B \text{ — } DETERMINISTIC \text{ } GATES \text{ } NOT \text{ } JUSTIFIED}$$

### Core Empirical Reasons for Decision B:
1. **Gate B (`<URL>`) is an Unsafe Academic Dataset Artifact**:
   - The token `<URL>` appears with 100% malicious/spam purity in `test.jsonl` ($N=742$) and `ood.jsonl` ($N=354$) **exclusively because academic researchers (ACM IMC 2025) pre-redacted URLs** in malicious collections while benign collections (Mendeley, UCI) were unredacted P2P texts.
   - At Android runtime, incoming messages contain raw URLs (`https://...`), never the string `"<URL>"`.
   - In production, upgrading any message with a URL to `MALICIOUS` would produce catastrophic false alarms on legitimate banking notices, delivery updates, and ride receipts.
   - On the primary test set, Gate B falsely escalates 36 `SPAM` messages to `MALICIOUS` ($S \to M$ rises from 90 to 126). **Gate B is explicitly rejected.**
2. **Gate C (`1800` Callback + Coercion) is Non-Functional on Datasets and Unsafe in Production**:
   - Due to dataset normalization to `<PHONE>`, `re_1800` matches **0 messages** in Primary TEST, OOD, Clean OOD, and Real Mobile Simulation.
   - Evaluating `(phone_token OR 1800) + coercion` matches 39 messages in Primary TEST, but **all 39 are already detected as MALICIOUS by V4.3** (0 recoveries).
   - In production, legitimate banking security alerts routinely pair coercion/urgency terms with official 1800 numbers (e.g., in `slice_hard_negatives.jsonl`: *"We noticed a login attempt... block your NetBanking immediately by calling our 24x7 customer care at 18002026161"*). Gate C would flag legitimate bank fraud alerts as attacks. **Gate C is explicitly rejected.**
3. **Gate A (`.apk`) Lacks Distributional Evidence and Target Need**:
   - Literal `.apk` matches **0 messages** in Primary TEST, **0 messages** in Primary OOD, **0 messages** in Clean OOD, and **0 messages** in Real Mobile Simulation.
   - In the dedicated `holdout_apk_payload.jsonl` suite ($N=60$), **frozen V4.3 already detects 30 / 30 (100.0%) of the malicious APK payloads** due to its subword morpheme and suspicious TLD features.
   - Across the entire repository, Gate A recovers exactly **1 single message** in a synthetic benchmark slice (`slice_institutional_partnerships.jsonl`).
   - A hardcoded heuristic that touches 0 test/OOD records and addresses a problem where V4.3 already achieves 100.0% holdout recall does not justify architectural gate deployment.

---

## 2. Datasets Inspected & Exact Distributions

The audit evaluated 21 distinct dataset files covering all processed splits, benchmark slices, holdouts, and device simulation suites:

| Dataset Identifier | File Path | Total Rows | BENIGN | SPAM | MALICIOUS | Evaluation Purpose |
|:---|:---|:---:|:---:|:---:|:---:|:---|
| **Primary TEST** | `data/processed/test.jsonl` | 2,264 | 520 | 188 | 1,556 | Authoritative frozen test benchmark |
| **Primary OOD** | `data/processed/ood.jsonl` | 1,132 | 255 | 83 | 794 | Out-of-distribution evaluation split |
| **Clean OOD** | Filtered `ood.jsonl` (zero train overlap) | 1,075 | 249 | 79 | 747 | Strict non-contaminated OOD split |
| **Real Mobile Simulation** | `6sep/simulation/SIMULATION_CASES.jsonl` | 294 | 291 | 0 | 3 | Real-world device interaction traces |
| **Holdout APK Payload** | `messages_v4_4/evaluation/holdouts/holdout_apk_payload.jsonl` | 60 | 30 | 0 | 30 | Sideloaded APK payload suite |
| **Holdout Conversational** | `messages_v4_4/evaluation/holdouts/holdout_conversational_social_eng.jsonl` | 207 | 105 | 0 | 102 | Conversational & social engineering |
| **Holdout Counterfactual** | `messages_v4_4/evaluation/holdouts/holdout_counterfactual_semantic.jsonl` | 110 | 55 | 0 | 55 | Advisory warnings vs attacks |
| **Holdout Electricity** | `messages_v4_4/evaluation/holdouts/holdout_electricity.jsonl` | 110 | 55 | 0 | 55 | Utility bill scams vs receipts |
| **Holdout Greetings** | `messages_v4_4/evaluation/holdouts/holdout_greetings.jsonl` | 110 | 55 | 0 | 55 | P2P greetings vs greeting lures |
| **Holdout Institutional** | `messages_v4_4/evaluation/holdouts/holdout_institutional_callback.jsonl` | 60 | 30 | 0 | 30 | Official notifications vs callbacks |
| **Holdout Notifications** | `messages_v4_4/evaluation/holdouts/holdout_system_notifications.jsonl` | 55 | 55 | 0 | 0 | Pure benign Android notifications |
| **Benchmark Banking Scam** | `data/benchmarks/slice_banking_scam.jsonl` | 3 | 0 | 0 | 3 | High-risk banking smishing |
| **Benchmark Electricity Scam**| `data/benchmarks/slice_electricity_scam.jsonl` | 3 | 0 | 0 | 3 | Power disconnection smishing |
| **Benchmark Hard Negatives** | `data/benchmarks/slice_hard_negatives.jsonl` | 4 | 4 | 0 | 0 | High-urgency legitimate alerts |
| **Benchmark Hinglish** | `data/benchmarks/slice_hinglish_smishing.jsonl` | 3 | 0 | 0 | 3 | Code-mixed threats |
| **Benchmark Institutional** | `data/benchmarks/slice_institutional_partnerships.jsonl` | 32 | 16 | 0 | 16 | Co-branded messages |
| **Benchmark Legit Banking** | `data/benchmarks/slice_legit_banking.jsonl` | 3 | 3 | 0 | 0 | Legitimate transactional banking |
| **Benchmark Legit Delivery**| `data/benchmarks/slice_legit_delivery.jsonl` | 3 | 3 | 0 | 0 | Legitimate delivery updates |
| **Benchmark Legit OTP** | `data/benchmarks/slice_legit_otp.jsonl` | 5 | 5 | 0 | 0 | Legitimate authentication OTPs |
| **Benchmark OTP Theft** | `data/benchmarks/slice_otp_theft.jsonl` | 4 | 0 | 0 | 4 | Credential harvesting smishing |
| **Synthetic Fixtures** | `data/benchmarks/synthetic_pipeline_fixtures.jsonl` | 16 | 7 | 2 | 7 | Pipeline regression fixtures |

---

## 3. Candidate Gate A: APK / Payload Gate Audit

### 3.1 Pattern Definition:
```python
RE_APK = re.compile(r"\.apk\b", re.IGNORECASE)
```

### 3.2 Audit Findings Across Sources:
Every available dataset in the repository was audited for occurrences of `.apk`:

| Source | Total Rows | Total `.apk` Matches | BENIGN `.apk` | SPAM `.apk` | MALICIOUS `.apk` | V4.3 Prediction on Matches |
|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **Primary TEST** | 2,264 | **0** | 0 | 0 | 0 | N/A (0 occurrences) |
| **Primary OOD** | 1,132 | **0** | 0 | 0 | 0 | N/A (0 occurrences) |
| **Clean OOD** | 1,075 | **0** | 0 | 0 | 0 | N/A (0 occurrences) |
| **Real Mobile Sim** | 294 | **0** | 0 | 0 | 0 | N/A (0 occurrences) |
| **Holdout APK Payload** | 60 | **30** | 0 | 0 | 30 | **MALICIOUS: 30 / 30 (100.0%)** |
| **Holdout Conversational**| 207 | **3** | 0 | 0 | 3 | **MALICIOUS: 3 / 3 (100.0%)** |
| **Holdout Counterfactual**| 110 | **3** | 0 | 0 | 3 | **MALICIOUS: 3 / 3 (100.0%)** |
| **Holdout Electricity** | 110 | **1** | 0 | 0 | 1 | **MALICIOUS: 1 / 1 (100.0%)** |
| **Holdout Greetings** | 110 | **5** | 0 | 0 | 5 | **MALICIOUS: 5 / 5 (100.0%)** |
| **Bench Banking Scam** | 3 | **1** | 0 | 0 | 1 | **MALICIOUS: 1 / 1 (100.0%)** |
| **Bench Institutional** | 32 | **1** | 0 | 0 | 1 | **BENIGN: 1 / 1 (Missed Detection)** |
| **Synthetic Fixtures** | 16 | **1** | 0 | 0 | 1 | **MALICIOUS: 1 / 1 (100.0%)** |
| **Training (train.jsonl)**| 15,855 | **3** | 0 | 0 | 3 | MALICIOUS: 3 / 3 |

### 3.3 Representation in Holdout APK Payload:
The dedicated suite `holdout_apk_payload.jsonl` contains 60 records:
- **30 Malicious Records**: Every record contains an explicit `.apk` download URL hosted on a suspicious TLD (`.top`, `.xyz`, `.live`, `.cc`, `.site`).
  - Example (`apk_0031`): `"Download our official partner rewards app at rewards.apk: http://partner-rewards.top/rewards.apk"`
  - V4.3 correctly detects **30 out of 30 as MALICIOUS (100.0% recall)**.
- **30 Benign Records**: Every record promotes legitimate mobile apps via the official Google Play Store or Apple App Store.
  - Example (`apk_0001`): `"You can download our app from Google Play Store: https://play.google.com/store/apps/details?id=com.sentinel.ai"`
  - None of these 30 benign records contain the string `.apk`.
  - V4.3 flags 6 of these 30 records as false alarms due to generic URL features ($\text{FPR} = 20.00\%$).
  - **Crucial Finding**: Gate A does not alter any prediction in `holdout_apk_payload.jsonl` because V4.3 already caught 100% of the malicious rows.

### 3.4 The Single Recovered Sample in Benchmark Institutional:
Across all 21 sources, Gate A alters exactly one prediction:
- **Record ID**: `v3_audit_malicious_6384897348100801684` in `slice_institutional_partnerships.jsonl`
- **Text**: `"College announcement: Faculty must install this .apk for new campus laptops next week."`
- **Ground Truth**: `MALICIOUS`
- **V4.3 Baseline**: $P(\text{B}) = 0.7250, P(\text{S}) = 0.0228, P(\text{M}) = 0.2523 \implies P(\text{nb}) = 0.2750 < 0.610 \to$ **`BENIGN`** (False Negative).
- **Gate A Effect**: Upgrades to `MALICIOUS`, raising benchmark recall from $12/16$ (75.00%) to $13/16$ (81.25%).

### 3.5 Evaluation of the Four APK Questions:
1. *Is literal `.apk` itself sufficiently specific to justify an unconditional MALICIOUS upgrade?*  
   In consumer mobile communication, `.apk` is strongly indicative of sideloading malware. However, literal `.apk` in isolation does not distinguish between malicious distribution and developer/peer discussions (`"Here is the release build app-debug.apk"`).
2. *Are there benign legitimate APK references?*  
   While none exist in the academic benchmark datasets, real-world Android power users, developers, and corporate MDM channels discuss `.apk` files without malicious intent.
3. *Is the current APK holdout representative enough to support a gate?*  
   **No.** The holdout is synthetic and conflates `.apk` with suspicious TLDs (`.top`, `.xyz`). Because V4.3 already catches 30/30 of those messages via TLD and subword morpheme signals, the holdout does not demonstrate a production blindspot that requires a deterministic gate.
4. *Is the gate merely fixing a known benchmark artifact, or does it represent a real security vector?*  
   The gate affects zero messages in TEST, zero in OOD, zero in Clean OOD, and zero in Real Mobile Simulation. It exclusively repairs 1 synthetic fixture.

---

## 4. Candidate Gate B: Normalized URL Token Audit

### 4.1 Token Distributions Across Splits:
An audit was conducted on all tokenized placeholders created during dataset preparation:

| Token | Primary TEST ($N=2,264$) | Primary OOD ($N=1,132$) | Clean OOD ($N=1,075$) | Train Corpus ($N=10,683$) |
|:---|:---:|:---:|:---:|:---:|
| `<URL>` | 742 (0 B, 73 S, 669 M) | 354 (0 B, 39 S, 315 M) | 336 (0 B, 39 S, 297 M) | 4,934 (3 B, 378 S, 4,553 M) |
| `<PHONE>` | 53 (0 B, 19 S, 34 M) | 36 (0 B, 8 S, 28 M) | 33 (0 B, 5 S, 28 M) | 483 (3 B, 140 S, 340 M) |
| `<PHONE_NUMBER>` | 215 (0 B, 13 S, 202 M) | 86 (0 B, 3 S, 83 M) | 80 (0 B, 3 S, 77 M) | 1,432 (0 B, 67 S, 1,365 M) |
| `<NUM>` | 552 (72 B, 111 S, 369 M) | 287 (25 B, 47 S, 215 M) | 274 (25 B, 43 S, 206 M) | 3,724 (507 B, 646 S, 2,571 M) |
| `<NUM_CODE>` | 200 (20 B, 50 S, 130 M) | 102 (13 B, 21 S, 68 M) | 98 (13 B, 20 S, 65 M) | 1,448 (191 B, 291 S, 966 M) |
| `<DATE_TIME>` | 711 (0 B, 49 S, 662 M) | 335 (0 B, 19 S, 316 M) | 308 (0 B, 19 S, 289 M) | 4,693 (0 B, 301 S, 4,392 M) |

### 4.2 Forensic Answers to Questions A through E:

#### A. Would an `<URL> => MALICIOUS` rule create benign false positives?
**Yes, severely in production.**  
In the offline test set, `<URL>` appears in 0 benign messages only because the benign corpus consists of personal P2P SMS from 2011/2022 (e.g. *"K go and sleep well"*, *"No management puzzeles"*). In real mobile ecosystems, legitimate messages continuously contain URLs:
- Order and courier tracking: `https://swiggy.is4.in/...`, `https://amzn.in/...`, `https://shiprocket.co/...`
- Transaction receipts & utility bills: `https://billdesk.io/...`, `https://bescom.org/...`
- App links & password resets: `https://play.google.com/...`
An unconditional URL upgrade rule would flag every legitimate message with a link as malicious.

#### B. Would it merely reproduce a dataset preprocessing artifact?
**Yes, entirely.**  
The 100% absence of `<URL>` in test benign data is an artifact of dataset composition. The malicious messages were sourced from the ACM IMC 2025 paper (*Fishing for Smishing*), where researchers pre-redacted URLs to `<URL>` in their raw CSV (`final_dataset_output.csv`). The benign messages were drawn from Mendeley, which had no URL redactions.

#### C. Can token presence be reliably distinguished from a real raw URL at production inference?
**No.**  
`<URL>` is an offline academic notation. Real user SMS and notifications contain raw strings like `https://bit.ly/3xY` or `www.bank-login.cc`. Real production text never contains the 5-character string `"<URL>"`.

#### D. Does the Android/runtime pipeline preserve or normalize these tokens?
**No.**  
Direct inspection of `android-app/core/src/main/java/com/sentinel/ai/core/ml/messages/MessageFeatureExtractor.kt` confirms that Android receives raw notification text and applies regex:
```kotlin
private val RE_URL = Pattern.compile("https?://\\S+|www\\.\\S+", Pattern.CASE_INSENSITIVE)
```
Android never performs pre-tokenization replacement to `<URL>`.

#### E. Is there a principled production-safe version of this gate?
**No.**  
In Sentinel's Android architecture, URL security is the exclusive jurisdiction of `UrlScanner` (URL-ML Champion V8) and the `RiskFusionEngine`, which inspect domain reputation, TLS characteristics, and hosting infrastructure. Hardcoding an upgrade rule in the text ML classifier breaks this separation of concerns.

**CONCLUSION ON GATE B: EXPLICITLY REJECTED.**

---

## 5. Candidate Gate C: Toll-Free / Callback Audit

### 5.1 Pattern Definitions:
```python
RE_1800 = re.compile(r"\b1800[-\s]?\d{3}[-\s]?\d{3,4}\b|\b1800\d{6,7}\b", re.IGNORECASE)
RE_LANDLINE = re.compile(r"\b0\d{2,4}[-\s]?\d{6,8}\b", re.IGNORECASE)
RE_COERCION = re.compile(r"\b(blocked|suspended|cut|disconnect|legal action|penalty|fraud department|deactivated|court|police|arrest|fir|warrant)\b", re.IGNORECASE)
```

### 5.2 Audit Findings on Phone Patterns:
1. **Raw Regex Ineffectiveness**:
   - `RE_1800` matches **0 messages** in Primary TEST, **0 messages** in Primary OOD, and **0 messages** in Clean OOD.
   - `RE_LANDLINE` matches **0 messages** in Primary TEST, OOD, and Clean OOD.
   - All phone numbers were pre-tokenized to `<PHONE>` or `<PHONE_NUMBER>`.
2. **Coercion + Phone Token Evaluation**:
   - Primary TEST contains 39 messages matching `(RE_1800 OR phone_token) AND RE_COERCION`.
   - **All 39 messages are already detected as MALICIOUS by Sentinel V4.3.**
   - Primary OOD contains 15 messages matching the pattern; **all 15 are already detected as MALICIOUS by V4.3**.
   - Clean OOD contains 13 messages matching the pattern; **all 13 are already detected as MALICIOUS by V4.3**.
   - **Empirical Recovery Count**: Gate C recovers **0 missed malicious messages**.

### 5.3 Lethal Production False Positive Risk:
In India, legitimate financial institutions, government bodies, and utilities send urgent security notices containing official 1800 numbers:
- **SBI**: `1800-11-2211`
- **HDFC Bank**: `1800-202-6161`
- **ICICI Bank**: `1800-1080`
- **UIDAI**: `1800-300-1947`

In `slice_hard_negatives.jsonl`, a legitimate bank fraud alert states:
> `"Security Alert: We noticed a login attempt from an unrecognized device in London. If this was not you, block your NetBanking immediately by calling our 24x7 customer care at 18002026161."`

Under Gate C, the presence of `18002026161` paired with `block` / `immediately` would force an upgrade to `MALICIOUS`, creating a high-severity false positive on authentic security warnings.

**CONCLUSION ON GATE C: EXPLICITLY REJECTED.**

---

## 6. Upgrade-Only Regression Analysis

All candidate configurations were replayed across the 21 evaluation suites against frozen Sentinel V4.3:

| Suite Name | Metric | Frozen V4.3 Baseline | Gate A Only (APK) | Gate B Only (URL Tok) | Gate C Only (Phone+Coerc) | All Gates (A+B+C) |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| **Primary TEST** ($N=2,264$) | Malicious Recall | 1,510 / 1,556 (97.04%) | 1,510 / 1,556 (97.04%) | 1,519 / 1,556 (97.62%) | 1,510 / 1,556 (97.04%) | 1,519 / 1,556 (97.62%) |
| | Benign FPR | 2 / 520 (0.38%) | 2 / 520 (0.38%) | 2 / 520 (0.38%) | 2 / 520 (0.38%) | 2 / 520 (0.38%) |
| | Spam $\to$ Malicious | 90 / 188 (47.87%) | 90 / 188 (47.87%) | **126 / 188 (67.02%)** | 90 / 188 (47.87%) | **126 / 188 (67.02%)** |
| **Primary OOD** ($N=1,132$) | Malicious Recall | 761 / 794 (95.84%) | 761 / 794 (95.84%) | 766 / 794 (96.47%) | 761 / 794 (95.84%) | 766 / 794 (96.47%) |
| | Benign FPR | 1 / 255 (0.39%) | 1 / 255 (0.39%) | 1 / 255 (0.39%) | 1 / 255 (0.39%) | 1 / 255 (0.39%) |
| | Spam $\to$ Malicious | 31 / 83 (37.35%) | 31 / 83 (37.35%) | **54 / 83 (65.06%)** | 31 / 83 (37.35%) | **54 / 83 (65.06%)** |
| **Clean OOD** ($N=1,075$) | Malicious Recall | 715 / 747 (95.72%) | 715 / 747 (95.72%) | 719 / 747 (96.25%) | 715 / 747 (95.72%) | 719 / 747 (96.25%) |
| | Benign FPR | 1 / 249 (0.40%) | 1 / 249 (0.40%) | 1 / 249 (0.40%) | 1 / 249 (0.40%) | 1 / 249 (0.40%) |
| | Spam $\to$ Malicious | 31 / 79 (39.24%) | 31 / 79 (39.24%) | **54 / 79 (68.35%)** | 31 / 79 (39.24%) | **54 / 79 (68.35%)** |
| **Real Mobile Simulation** | Malicious Recall | 3 / 3 (100.0%) | 3 / 3 (100.0%) | 3 / 3 (100.0%) | 3 / 3 (100.0%) | 3 / 3 (100.0%) |
| | Benign FPR | 14 / 291 (4.81%) | 14 / 291 (4.81%) | 14 / 291 (4.81%) | 14 / 291 (4.81%) | 14 / 291 (4.81%) |
| **Holdout APK Payload** | Malicious Recall | 30 / 30 (100.0%) | 30 / 30 (100.0%) | 30 / 30 (100.0%) | 30 / 30 (100.0%) | 30 / 30 (100.0%) |
| | Benign FPR | 6 / 30 (20.00%) | 6 / 30 (20.00%) | 6 / 30 (20.00%) | 6 / 30 (20.00%) | 6 / 30 (20.00%) |
| **Holdout Conversational**| Malicious Recall | 66 / 102 (64.71%) | 66 / 102 (64.71%) | 66 / 102 (64.71%) | 66 / 102 (64.71%) | 66 / 102 (64.71%) |
| | Benign FPR | 6 / 105 (5.71%) | 6 / 105 (5.71%) | 6 / 105 (5.71%) | 6 / 105 (5.71%) | 6 / 105 (5.71%) |
| **Holdout Counterfactual** | Malicious Recall | 46 / 55 (83.64%) | 46 / 55 (83.64%) | 46 / 55 (83.64%) | 46 / 55 (83.64%) | 46 / 55 (83.64%) |
| | Benign FPR | 22 / 55 (40.00%) | 22 / 55 (40.00%) | 22 / 55 (40.00%) | 22 / 55 (40.00%) | 22 / 55 (40.00%) |
| **Benchmark Institutional**| Malicious Recall | 12 / 16 (75.00%) | **13 / 16 (81.25%)** | 12 / 16 (75.00%) | 12 / 16 (75.00%) | **13 / 16 (81.25%)** |
| | Benign FPR | 1 / 16 (6.25%) | 1 / 16 (6.25%) | 1 / 16 (6.25%) | 1 / 16 (6.25%) | 1 / 16 (6.25%) |

### Observations on Upgrades:
- **Zero New Benign $\to$ Malicious Upgrades on TEST/OOD**: Because neither `.apk`, `<URL>`, nor `1800` appeared in the benign test or OOD splits, no new benign test false positives were registered on offline files.
- **Spam $\to$ Malicious Distortion**: Gate B causes massive class boundary corruption. In Primary TEST, 36 spam messages are upgraded to malicious (+40.0% increase in spam misclassification). In Clean OOD, 23 spam messages are escalated to malicious (+74.2% increase).
- **Inability to Address Known Vulnerabilities**: None of the gates improve performance on conversational fraud ($64.71\%$), electricity smishing ($54.55\%$), or counterfactual semantic warnings ($83.64\%$).

---

## 7. Production Representation Audit

A complete audit of the Android runtime codebase (`sentinel-ai`) was conducted to trace how messages are processed:

```
Incoming Message Event (SmsReceiver / NotificationListener)
  │
  ▼
NotificationAnalysisInput(messageText: String, sender: String?)
  │
  ├──► TextNormalizer.analyzeAndNormalize(messageText)
  │      └── Extracts script, homoglyphs, casing, length. (NO TOKEN REDACTION)
  │
  ├──► MessageScanner.scan(messageText)
  │      └── MessageFeatureExtractor.extractV43Features(messageText)
  │            ├── RE_URL.matcher(rawText)  [https?://\S+|www\.\S+]
  │            └── RE_PHONE.matcher(rawText) [(?:+91|0)?[6-9]\d{9}]
  │      └── DualTfidfVectorizer.transform(word + char)
  │      └── MultiClassTreeEvaluator.predictProba()
  │      └── MessageAdjudicator.adjudicate(threshold = 0.610f)
  │
  ├──► NotificationThreatAnalyzer Heuristic Pipeline
  │      ├── UrlScanner.scan(candidateUrls)  [URL-ML Champion V8]
  │      ├── Shortened URL & IP URL indicators
  │      ├── OTP solicitation vs negation heuristics
  │      └── Urgency & financial keyword extraction
  │
  ▼
DefaultRiskFusionEngine.fuse(evidenceList)
  ├── Vector clustering (Payload vs Intent vs Context)
  ├── Contextual trust dampening
  ├── Cross-vector compounding
  └── Final RiskLevel (GREEN, YELLOW, RED, CRITICAL)
```

### Production Runtime Inconsistencies:
1. **Pre-tokenized Tokens Do Not Exist in Android**:
   - The Android runtime passes real message text directly to `MessageScanner`. It never introduces tokens like `<URL>`, `<PHONE>`, `<NUM>`, or `<DATE_TIME>`.
   - Any gate written against `<URL>` or `<PHONE>` would be dead code on an actual Android device.
2. **URL Logic Belongs to URL-ML, Not Text Heuristics**:
   - Android already extracts all embedded URLs in `NotificationThreatAnalyzer` (lines 185–286) and feeds them to `UrlScanner` (URL-ML Champion V8) with safe-brand domain gating.
   - Forcing text-level URL upgrade gates contradicts Android's multi-agent architecture and bypasses URL-ML's calibrated safety models.

---

## 8. Final Decision & Synthesis

### Selected Decision:
$$\mathbf{B \text{ — } DETERMINISTIC \text{ } GATES \text{ } NOT \text{ } JUSTIFIED}$$

### Justification Summary:
- **Gate B (`<URL>`)**: Fails production representation audit. It exploits an academic dataset artifact and causes significant spam-to-malicious distortion while threatening catastrophic false alarms on real Android devices.
- **Gate C (`1800` Callback)**: Fails empirical recovery audit (0 recoveries across TEST, OOD, and Clean OOD) and creates unacceptable false positive risks against legitimate bank fraud alerts.
- **Gate A (`.apk`)**: Fails target necessity. Sentinel V4.3 already catches 100.0% (30/30) of malicious APK payloads in the dedicated holdout, and the pattern matches 0 records in Primary TEST, OOD, Clean OOD, and Real Mobile Simulation.

---

## 9. Limitations & Prohibitions

1. **Frozen Production Benchmark Maintained**:  
   Sentinel Messages V4.3 Candidate-D remains the authoritative, bit-for-bit immutable production baseline.
2. **No Model Training**:  
   No model weights, trees, or scalers have been modified or trained.
3. **No Android Code Alteration**:  
   `sentinel-ai/` remains completely untouched.
4. **No Gate Implementation**:  
   In compliance with the directive, no deterministic gates are implemented or promoted into production.

---

**Audit Completed**: September 24, 2026  
**Status**: Safety Review Complete — Deterministic Gates Rejected — Analysis Halted.
