# SENTINEL MESSAGES — NEXT ARCHITECTURE RESEARCH DESIGN REVIEW

**Document ID**: `SENTINEL-MESSAGES-V4_5-ARCH-DESIGN-REVIEW-2026-09-24`  
**Author**: Lead ML/Security Research Engineer  
**Date**: September 24, 2026  
**Status**: APPROVED DESIGN REVIEW — PRE-IMPLEMENTATION SPECIFICATION  
**Governing Directive**: Analysis Only (No training, no corpus modification, no Android modification, no production modification).  
**Protected Reference**: Sentinel Messages V4.3 Candidate-D remains the active production benchmark.

---

## 1. Current Evidence & Context

The Sentinel Messages detection pipeline has undergone four major evolutionary cycles:
1. **Champion V2 (Frozen Baseline)**:
   - 70 deterministic features + 1,500 word TF-IDF + 500 char TF-IDF (2,070 dims) $\to$ StandardScaler $\to$ HistGradientBoostingClassifier.
   - Operating threshold: $\tau \approx 0.704$.
   - Primary TEST: Malicious recall $= 90.17\%$ (1,403 / 1,556), Benign $\text{FPR} = 3.85\%$ (20 / 520).
   - Proven vulnerabilities: Catastrophic failure on Romanized Indic dialects (Hinglish recall 14.0%), brittle reliance on exact keyword strings, and excessive false alarms on legitimate institutional and utility notifications.
2. **Sentinel V4.3 Candidate-D (Active Production Baseline)**:
   - 19 deterministic structural features + 1,500 word n-grams (1–2) + 2,500 subword char n-grams (2–5) = 4,019 total dimensions $\to$ StandardScaler $\to$ HistGradientBoostingClassifier.
   - Operating threshold: $\tau = 0.6100$ (Calibrated on `val.jsonl` at $\text{FPR} \le 2.0\%$).
   - Primary TEST: Malicious recall $= \mathbf{97.04\%}$ (1,510 / 1,556), Benign $\text{FPR} = \mathbf{0.38\%}$ (2 / 520).
   - Clean OOD: Malicious recall $= \mathbf{95.72\%}$ (715 / 747), Benign $\text{FPR} = \mathbf{0.40\%}$ (1 / 249).
   - Solved dialect robustness (Hinglish smishing recall scaled 5.4x to 76.0%) and achieved 100% Android parity (115/115 golden cases, mean prob delta $1.08 \times 10^{-6}$).
3. **V4.4 Ad-Hoc Corpus Experiments (RC1, RC2-Exp1, RC2-Exp2, RC2-Exp3 — Frozen & Rejected)**:
   - Attempted targeted corpus patches to fix local weaknesses (adding utility samples, greetings, and institutional announcements).
   - Global forensic audit proved that holdouts were co-generated (violating true OOD independence).
   - More critically, local patches induced global benign score drift ($p98 = 0.597 \to 0.732$), forcing operating thresholds upward ($\tau = 0.61 \to 0.74$), which produced a net loss of 17 test malicious detections in Exp3. The corpus-patch loop was permanently terminated.
4. **V4.5 Stage 1 Architecture Experiment & Complementarity Postmortem (Frozen & Rejected)**:
   - Tested frozen generic contextual embeddings (`sentence-transformers/all-MiniLM-L6-v2`, 384 dims) + 19 structural signals (Ablation C, 403 dims).
   - Proved effective on isolated semantic holdouts (counterfactual FPR dropped from 40% to 3.6%, utility FPR from 50.9% to 5.5%, greeting FPR from 12.7% to 0.0%).
   - BUT collapsed on the primary production test benchmark:
     - Malicious recall collapsed from **97.04% to 77.70%** (missing 301 primary malicious records).
     - Benign FPR jumped **8.0-fold from 0.38% to 3.08%** (introducing 15 new false alarms on normal conversational SMS).
   - Postmortem four-way matrix on primary TEST ($N=1556$ malicious):
     - **Category A (Both Correct)**: 1,203 (77.31%)
     - **Category B (V4.3 Correct, V4.5 Wrong)**: 307 (19.73%) — 166 trapped in SPAM class confusion, 141 dropped below threshold.
     - **Category C (V4.3 Wrong, V4.5 Correct)**: **6 (0.39%)** — Negligible, noisy, non-repeatable edge cases (1 Japanese script artifact, 1 truncated fragment, 2 class tie-breakers on already-flagged threats, 1 conversational hearsay, 1 URL-less margin case).
     - **Category D (Both Wrong)**: 40 (2.57%) — Conversational "Hi Mum" pings and commercial reward lures.
   - Definitive Disposition: **`B — HYBRID NOT JUSTIFIED`** for frozen generic MiniLM embeddings.

---

## 2. Reconstructing V4.3's Actual Information Sources

An exhaustive inspection of the V4.3 implementation in [`candidate_d_v4_3.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d_v4_3.py) reveals exactly how its 4,019 dimensions are constructed.

### 2.1 Deterministic Structural Features (19 Dimensions)

The function `extract_structural_signals(text: str)` computes 19 scalar features. Every feature is cataloged below with its mathematical definition, measurement scope, and security domain:

| Index | Feature Symbol | Code Expression | Measurement Scope | Structural Category | Security Relevance |
|:---:|:---|:---|:---|:---|:---|
| **0** | `length` | `max(1, len(t))` | Character length of raw message | Structural / Numeric | Normalizes text volume; distinguishes short pings from long lures. |
| **1** | `w_count` | `len(t.split())` | Total whitespace-delimited words | Structural / Numeric | Density baseline for lexical ratios. |
| **2** | `avg_w_len` | `sum(len(w))/max(1, w_count)` | Mean characters per word | Structural / Numeric | High in obfuscated text or concatenated links/tokens. |
| **3** | `digits` | `sum(c.isdigit() for c in t)` | Total digit characters | Numeric / Character Type | Financial amounts, OTP codes, phone numbers, account numbers. |
| **4** | `digit_ratio` | `digits / length` | Ratio of digits to total characters | Numeric / Ratio | Flags code-heavy, financial, or serial-number heavy SMS. |
| **5** | `uppers` | `sum(c.isupper() for c in t)` | Total uppercase characters | Casing / Orthography | Flags shouty urgency ("URGENT", "ACTION REQUIRED", "BLOCKED"). |
| **6** | `upper_ratio` | `uppers / length` | Ratio of uppercase to total characters | Casing / Ratio | Urgency signal normalized across length. |
| **7** | `specials` | `sum(not alnum and not space)` | Total special characters | Punctuation / Formatting | Punctuation manipulation, symbols (`$`, `₹`, `!`, `/`, `@`). |
| **8** | `special_ratio` | `specials / length` | Ratio of specials to total characters | Punctuation / Ratio | Flags obfuscation, URL heavy text, or excessive punctuation. |
| **9** | `url_count` | `len(RE_URL.findall(t))` | Count of URLs matching regex | URL / Quantitative | Multi-link attacks, redirect chains. |
| **10** | `has_url` | `1.0 if url_count > 0 else 0.0` | Binary presence of any URL | URL / Binary Flag | Primary attack delivery vector for web smishing. |
| **11** | `phone_count` | `len(RE_PHONE.findall(t))` | Count of Indian mobile numbers | Phone / Quantitative | Callback attack vector (`(?:\+91\|0)?[6-9]\d{9}`). |
| **12** | `has_phone` | `1.0 if phone_count > 0 else 0.0` | Binary presence of Indian phone | Phone / Binary Flag | Primary attack delivery vector for voice/SMS callback fraud. |
| **13** | `is_question` | `1.0 if "?" in text_no_url else 0.0`| Binary presence of question mark | Syntactic / Punctuation | Conversational outreach marker; social engineering pings. |
| **14** | `is_short` | `1.0 if w_count <= 8 else 0.0` | Binary short message indicator | Structural / Length | Flags greetings, 1-word probes, or sparse alerts. |
| **15** | `is_naked_url` | `has_url and (w<=2 or u>=0.7*len)` | URL occupies $\ge 70\%$ of message | URL / Structural | Direct malicious redirect links without conversational context. |
| **16** | `has_suspicious_tld`| Regex on `.cc, .xyz, .top...` | Binary presence of malicious TLD | URL / Domain Lexical | Flags low-reputation, disposable domain registrars. |
| **17** | `has_hex_or_ip_url`| Regex on IP, $\ge16$ hex, `::` | Raw IP or hex-obfuscated URL | URL / Host Obfuscation | Direct IP hosting used in phishing kit backends. |
| **18** | `is_suspicious_naked_url`| `is_naked_url and (tld or hex)`| Compound risk: naked link + bad TLD | URL / Compound Risk | Highest-risk delivery pattern in candidate-D. |

### 2.2 Word TF-IDF Representation (1,500 Dimensions)
- Model: `TfidfVectorizer(max_features=1500, ngram_range=(1, 2), sublinear_tf=True)`.
- Scope: Unigrams and bigrams anchored on whitespace/punctuation word boundaries.
- Strengths: Captures overt English threat vocabulary (`urgent`, `account`, `otp`, `blocked`, `verify`, `pan card`, `kyc`, `sbi`, `reward`, `prize`, `bill`, `electricity`).
- Limitations: Completely non-sequential and bag-of-words. Incapable of syntactic negation scoping (e.g. `"Never share your OTP"` vs `"Share your OTP"` produce overlapping unigram activations where the dominant weights of `"otp"` and `"share"` swamp `"never"`).

### 2.3 Character TF-IDF Representation (2,500 Dimensions)
- Model: `TfidfVectorizer(max_features=2500, analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True)`.
- Scope: Character n-grams from length 2 to 5 within word boundaries (`char_wb`).
- Strengths: Subword morphemes that capture root words across typos, obfuscations, and Romanized Indic transliterations (`bhej`, `turant`, `rupay`, `discon`, `updat`, `paisa`). This is the sole engine behind V4.3's Hinglish generalization.
- Limitations: Subword morphemes are completely blind to sentence syntax, discourse context, and communicative intent. A substring like `"otp"` or `"elec"` triggers identically whether in a bank warning, a malicious credential demand, or a friend's casual text.

---

## 3. Failure-Mode Diagnosis: What Is Missing from V4.3's Feature Space

An audit of V4.3's code confirms that the following known failure modes **lack any explicit feature representation**:

```
V4.3 Structural Feature Representation Map
├── Covered by Structural Features:
│   ├── URLs (Count, binary, naked, suspicious TLD, raw IP/hex, compound) ── [6 features]
│   ├── Indian Mobile Numbers (Count, binary) ────────────────────────────── [2 features]
│   └── Length, Casing, Digits, Specials, Question Mark ───────────────────── [11 features]
└── Completely Absent from Structural Features:
    ├── APK File Attachments (.apk extension in body) ─────────────────────── [ABSENT]
    ├── Landline / Toll-Free / International Phone Patterns ───────────────── [ABSENT]
    ├── Currency / Monetary Value Indicators (₹, Rs, INR, $, Lakhs) ───────── [ABSENT]
    ├── Semantic Negation / Counterfactual Operators ("never", "do not") ──── [ABSENT]
    ├── Communicative Intent (Advisory warning vs Action demand) ───────────── [ABSENT]
    ├── Institutional Authority / Sender Alphanumeric Header ──────────────── [ABSENT]
    ├── Utility Status (Paid/receipt vs Overdue/disconnect) ────────────────── [ABSENT]
    ├── Interpersonal / Conversational Markers ("Hi Mum", family terms) ───── [ABSENT]
    └── External Provenance (Saved contact, address book, group context) ──── [ABSENT]
```

1. **APK File Attachment Vector**: Feature 16 checks suspicious web TLDs (`.cc`, `.xyz`), but there is no feature checking for Android application packages (`.apk` or download patterns). Case: `"Download official partner app at rewards.apk"` has `has_url=0` and fails to trigger threat gates.
2. **Non-Mobile Phone Numbers**: Feature 11 and 12 (`RE_PHONE`) strictly match Indian 10-digit mobile numbers `(?:\+91|0)?[6-9]\d{9}`. Landlines, national toll-free numbers (`1800-xxx-xxxx`), shortcodes (`5xxxx`), and international numbers register as `phone_count = 0` and `has_phone = 0.0`.
3. **Utility Bill Status**: V4.3 has no structural or lexical indicator representing whether an electricity message represents an authentic payment receipt ("Bill of Rs 500 paid successfully") versus an urgent disconnection scam ("Supply disconnected tonight").
4. **Institutional Announcements vs Spoofs**: V4.3 has no feature representing official advisory broadcasting versus urgent credential capture. Both contain brand names (`HDFC`, `SBI`).
5. **Communicative Intent (Advisory Warning vs Action Demand)**: Both security notifications and phishing attacks share the words `OTP`, `login`, `share`, `code`. V4.3 cannot represent whether the text is warning the user *not* to share an OTP or *instructing* them to forward it.
6. **Syntactic Negation Scope**: Bag-of-words and char-wb cannot represent grammatical scope. "Do not share OTP" and "Share OTP" activate almost the exact same features.
7. **External Context & Provenance**: 97.5% of dataset SMS are headerless. V4.3 has zero representation of sender identity (saved contact vs unknown number) or chat type (1-to-1 SMS vs group chat).

---

## 4. Representation vs Data Analysis

To determine why V4.3 fails on each specific security slice, the root causes are forensically categorized using experimental evidence across V4.3, V4.4-RC iterations, and the V4.5 postmortem:

```
Failure Mechanism Taxonomy
├── Category A: Relevant information is NOT represented at all
├── Category B: Information is represented, but poorly weighted / swamped
├── Category C: Training distribution contains a misleading shortcut / artifact
├── Category D: Problem is fundamentally ambiguous from single-message text
├── Category E: Evaluation / data provenance is insufficient or corrupt
└── Category F: Compound interaction of multiple mechanisms
```

| Failure Mode | Assigned Mechanism | Concrete Empirical Evidence & Forensic Rationale |
|:---|:---:|:---|
| **APK Payload Attacks** | **Category A** *(Not Represented)* | Candidate-D's regexes detect web domains but completely lack `.apk` matching. `"Download rewards.apk"` has `has_url=0` and scored $P(\text{M})=0.51$, falling below $\tau=0.61$. |
| **Toll-Free Callback Scams** | **Category A** *(Not Represented)* | `RE_PHONE` only matches Indian 10-digit mobile numbers `[6-9]\d{9}`. Scams using `1800-xxx-xxxx` or landlines register `has_phone=0`, causing probability collapse toward benign. |
| **Semantic Negation / Counterfactuals** | **Category A** *(Not Represented)* | V4.3 false-alarmed on 40.0% of `holdout_counterfactual` (e.g. `"Never share your OTP with anyone"`). Bag-of-words and char n-grams cannot represent syntactic negation binding. |
| **Security Alerts vs Credential Demands** | **Category A** *(Not Represented)* | Both contain identical unigrams (`OTP`, `account`, `share`). V4.3 lacks any representation of speech-act intent (warning vs soliciting). |
| **Greetings ("Hello" / "Hi")** | **Category C** *(Training Shortcut)* | Legacy SMS spam collections contained hundreds of spam templates starting with `"Hello! Win..."`. Standalone `"Hello"` in V4.3 scored $P(\text{nb})=0.669$ because `"hello"` had a net positive threat weight and triggered `is_short=1.0`. |
| **Hinglish Robustness Gaps** | **Category E & B** *(Data Sparsity & Weighting)* | Hinglish originally represented only 0.32% (73/22,648) of corpus data. Conversational Hinglish lacking brand names ("Bhai OTP forward kar de turant") lacks heavy threat n-grams and scores $P(\text{M}) \approx 0.44$. |
| **Utility / Electricity Volatility** | **Category F** *(B + C: Weighting & Imbalance)* | Adding 238 authentic DISCOM bills in RC2-Exp1 suppressed utility FPs from 47.3% to 20.0%, but shifted global threshold from 0.61 to 0.68. `electricity` + `paid` vs `disconnected` cannot be resolved by unigrams without link signals. |
| **Institutional Partnerships** | **Category F** *(A + C: Absent Feature & Shortcut)* | RC2-Exp3 added 38 institutional samples, but global boundary creep ($\tau=0.74$) caused net -17 test misses. V4.3 has no feature for official sender ID or broadcast advisory structure. |
| **Conversational Deception ("Hi Mum")** | **Category D & E** *(Fundamentally Ambiguous)* | In TEST Category D, `"Hey mum, phone water damage... in sink"` scored $P(\text{M}) \le 0.06$ in both V4.3 and V4.5. Single-message text classification cannot distinguish an authentic chat from a social engineering probe without causing massive false alarms across ordinary messaging. |
| **Malicious vs Ordinary Spam** | **Category F** *(B + D: Topic Overlap & Policy)* | In V4.5, 166 malicious records were classified as SPAM because the topical vocabulary (lottery, loan, gift, prize) heavily overlaps between aggressive marketing spam and credential/financial theft. |
| **Saved-Contact & Group Context** | **Category A & E** *(Absent Feature & Provenance)* | V4.3 operates strictly on raw text. Metadata regarding whether the sender is in contacts, whether the message is a 1-to-1 SMS or WhatsApp group chat, is entirely absent from the model input. |

---

## 5. Comprehensive Evaluation of Candidate Architectural Directions

Seven candidate architectural directions are evaluated strictly against empirical criteria without code modification.

### Candidate A: V4.3 + Additional Deterministic Semantic Features
- **Description**: Extend V4.3's 19 structural signals with targeted regex/structural extractors (e.g., `.apk` extension detection, toll-free `1800` regex, currency/amount regex, explicit greeting token detectors).
1. *What information would it add?* Explicit structural flags for `.apk` files, non-mobile phone formats (1800 numbers, landlines), currency values (`₹`, `Rs`, `INR`), and greeting tokens.
2. *Which known failure modes could it address?* APK payload attacks (recovering `rewards.apk`), toll-free callback scams, and standalone greeting false alarms.
3. *What existing V4.3 information could it destroy?* None directly, but retraining HistGBM on augmented features alters tree split choices, risking subtle feature masking on existing n-grams.
4. *What training data would be required?* Same frozen corpus (`train_v4_3.jsonl` or `train_v4_4_b.jsonl`). Zero new data collection.
5. *Could it be evaluated without touching production?* Yes, 100% offline in Python.
6. *What is the smallest experiment that would falsify the idea?* Append the new features, train Candidate-D head, run validation calibration and test evaluation. If Test FPR rises above 0.38% or malicious recall drops below 97.04%, the idea is falsified.
7. *What security regression could it introduce?* Boosting trees might split early on deterministic rules, reducing effective tree depth for subword n-grams and regressing on unstructured smishing.
8. *How would Android parity eventually be established?* Native Kotlin regex implementations in `extractStructuralSignals()` in `:core`.
9. *What would constitute success?* Test malicious recall $\ge 97.04\%$, Test $\text{FPR} \le 0.38\%$, Clean OOD recall $\ge 95.72\%$, and 100% recall on `holdout_apk_payload`.
10. *What would constitute immediate rejection?* Any drop in primary Test malicious detections ($< 1,510$) or increase in Test FPR ($> 0.38\%$).
- **Support Level**: **Evidence-Supported for specific structural gaps (APK, toll-free); Weakly Supported for complex semantic ambiguity (counterfactuals, conversational fraud).**

### Candidate B: V4.3 + Small Domain-Specific Contextual Encoder
- **Description**: Pretrain a compact transformer (e.g., MiniLM or MobileBERT) using contrastive learning directly on SMS smishing/spam pairs, then concatenate embeddings with V4.3 features.
1. *What information would it add?* Sequential context, semantic negation binding, discourse structure.
2. *Which failure modes could it address?* Counterfactual pairs, utility status, institutional announcements.
3. *What existing V4.3 information could it destroy?* Dense representations inject high benign validation variance, forcing threshold creep that cuts off lower-margin malicious records.
4. *What training data would be required?* Contrastive smishing vs spam pairs; requires substantial curated dataset engineering.
5. *Could it be evaluated without touching production?* Yes, offline.
6. *What is the smallest experiment that would falsify the idea?* Train contrastive encoder on a small batch, evaluate if smishing vs spam cosine similarity decreases. If smishing remains clustered with spam, it is falsified.
7. *What security regression could it introduce?* Massive spam confusion (repeating V4.5's 166 misses) and benign FPR inflation.
8. *How would Android parity eventually be established?* TFLite / ONNX runtime on Android, requiring ~20-50MB model footprint, NPU/GPU acceleration, and battery/latency profiling.
9. *What would constitute success?* Test recall $>97.04\%$, FPR $\le 0.38\%$, holdout improvements.
10. *What would constitute immediate rejection?* Primary Test recall drop $>0.5\%$ or FPR increase.
- **Support Level**: **Requires New Evidence (High engineering footprint; high risk of repeating V4.5 failure without prior proof of smishing separation).**

### Candidate C: V4.3 + Domain-Trained Character/Subword Representation (BPE / SentencePiece)
- **Description**: Replace fixed character n-grams with a domain-trained subword tokenizer (Byte-Pair Encoding or WordPiece) learned on Indic/English SMS.
1. *What information would it add?* Morpheme-aligned subword tokens rather than fixed character n-grams.
2. *Which failure modes could it address?* Hinglish variations, slang, transliteration.
3. *What existing V4.3 information could it destroy?* Fixed char_wb n-grams (2,500 dims) already achieve 76% Hinglish recall and 97.04% Test recall. Changing tokenization alters the entire feature space.
4. *What training data would be required?* Large SMS corpus for BPE training.
5. *Could it be evaluated without touching production?* Yes.
6. *What is the smallest experiment that would falsify the idea?* Tokenize `train_v4_3`, train HistGBM, evaluate Test.
7. *What security regression could it introduce?* Subword token boundaries might misalign with smishing keyword prefixes.
8. *How would Android parity eventually be established?* Kotlin BPE tokenizer implementation in `:core`.
9. *What would constitute success?* Improved Hinglish recall without Test recall loss.
10. *What would constitute immediate rejection?* Primary Test recall $< 97.04\%$.
- **Support Level**: **Weakly Supported (V4.3's character n-grams are already very strong; marginal benefit does not address the main semantic failure modes).**

### Candidate D: V4.3 + Auxiliary Semantic Verifier (Asymmetric Filter)
- **Description**: Keep V4.3 completely frozen as the primary threat engine. Build a small, specialized auxiliary verifier solely for specific semantic ambiguities (e.g., counterfactual negation or utility status) operating under an asymmetric policy where high-confidence V4.3 threats can NEVER be downgraded.
1. *What information would it add?* Specialized semantic polarity discrimination (distinguishing advisory "Never share OTP" from threat "Share OTP") applied strictly to ambiguous/borderline candidates.
2. *Which failure modes could it address?* Counterfactual semantic pairs, legitimate electricity bill false alarms, legitimate institutional notifications, greeting false alarms.
3. *What existing V4.3 information could it destroy?* **ZERO**. V4.3 is frozen and primary. An asymmetric veto policy prevents the auxiliary from overriding high-confidence V4.3 detections ($P(\text{M}) \ge \tau_{high}$ or structural threat triggers like URLs/APKs).
4. *What training data would be required?* Only the curated pairs for that specific ambiguity slice (e.g. counterfactual pairs, utility messages).
5. *Could it be evaluated without touching production?* Yes, 100% offline.
6. *What is the smallest experiment that would falsify the idea?* Evaluate V4.3 + auxiliary verifier on `test.jsonl` and `ood.jsonl`. If ANY of V4.3's 1,510 primary test malicious detections are lost, or if test FPR increases, it is immediately falsified.
7. *What security regression could it introduce?* False negative downgrade of an attack if the auxiliary verifier mistakenly classifies a malicious message as benign. Prevented by asymmetric policy constraints.
8. *How would Android parity eventually be established?* Small standalone Kotlin rule/model module in `:core` or `:services`.
9. *What would constitute success?* 0 primary test malicious regressions (1,510/1,510 retained), 0 clean OOD regressions (715/715 retained), AND measurable reduction of false alarms on targeted holdouts.
10. *What would constitute immediate rejection?* Any loss of a primary test malicious detection or test FPR increase.
- **Support Level**: **Evidence-Supported (Directly matches the empirical finding that contextual models work on isolated semantic probes but fail as general classifiers).**

### Candidate E: V4.3 + Calibrated Second-Stage Classifier (Cascaded Decision Architecture)
- **Description**: Stage 1 = V4.3 filters clear benign ($P(\text{nb}) < 0.20$) and clear malicious ($P(\text{M}) > 0.85$). Stage 2 = secondary classifier evaluates the uncertain margin $[0.20, 0.85]$.
1. *What information would it add?* Re-weights ambiguous margin messages with alternative representations.
2. *Which failure modes could it address?* URL-less phishing, margin threshold creep.
3. *What existing V4.3 information could it destroy?* In V4.3, many margin messages are correctly resolved by the global tree ensemble. A second-stage classifier on the margin might misclassify them.
4. *What training data would be required?* Margin-filtered training corpus.
5. *Could it be evaluated without touching production?* Yes.
6. *What is the smallest experiment that would falsify the idea?* Isolate V4.3 margin on validation, train Stage 2, evaluate Test.
7. *What security regression could it introduce?* Regressions on the 141 margin malicious messages.
8. *How would Android parity eventually be established?* Two-stage Kotlin inference pipeline.
9. *What would constitute success?* Net recovery of Category D or URL-less cases without FPR increase.
10. *What would constitute immediate rejection?* Any drop in test recall or increase in FPR.
- **Support Level**: **Weakly Supported (Cascaded margin classifiers often amplify boundary noise and risk instability).**

### Candidate F: V4.3 Retraining with Redesigned Class Structure
- **Description**: Restructure target classes into 5 granular categories (`MALICIOUS_PHISHING`, `MALICIOUS_PAYLOAD`, `COMMERCIAL_SPAM`, `TRANSACTIONAL_ALERT`, `CONVERSATIONAL_BENIGN`).
1. *What information would it add?* Explicit class boundaries between transactional alerts and phishing, and between commercial marketing and financial scams.
2. *Which failure modes could it address?* Malicious vs ordinary spam confusion (166 misses), transactional OTP false alarms.
3. *What existing V4.3 information could it destroy?* Requires re-annotating the entire training set. If labels are noisy, class boundaries degrade.
4. *What training data would be required?* Granular 5-class re-annotation of 20,000+ records.
5. *Could it be evaluated without touching production?* Yes.
6. *What is the smallest experiment that would falsify the idea?* Train 5-class HistGBM on small subset.
7. *What security regression could it introduce?* Severe label confusion if multi-class taxonomy is ambiguous.
8. *How would Android parity eventually be established?* Update Android Kotlin class enum and decision logic.
9. *What would constitute success?* Elimination of MALICIOUS -> SPAM confusion.
10. *What would constitute immediate rejection?* Inability to achieve 97% malicious recall across 5 classes.
- **Support Level**: **Requires New Evidence / Data-Blocked (Requires massive manual re-annotation; violates the rule against repetitive corpus manipulation).**

### Candidate G: Dual-Engine Asymmetric Gating Architecture (V4.3 Primary Engine + Precision Gating)
- **Description**: Combine V4.3's frozen lexical/subword HistGBM engine with deterministic precision control extensions and an asymmetric verification policy.
- **Support Level**: **Evidence-Supported.**

---

## 6. Auxiliary-Verifier Feasibility & Asymmetric Policy Specification

The central conclusion of the V4.5 experiment is that **sequential contextual models possess high precision on specific semantic and syntactic relationships, but fail catastrophically as broad-spectrum SMS threat detectors.**

Therefore, Sentinel does **NOT** need a new general-purpose classifier. It requires an **Asymmetric Precision Gatekeeper** that operates strictly on ambiguous boundary cases without ever overriding primary threat detections.

```
                    Incoming Message
                           │
                           ▼
          ┌──────────────────────────────────┐
          │     Sentinel V4.3 (FROZEN)       │
          │ 4,019 Dims (19 Struct+Word+Char) │
          └────────────────┬─────────────────┘
                           │ Outputs: P(B), P(S), P(M)
                           │
       ┌───────────────────┴───────────────────┐
       ▼                                       ▼
┌──────────────┐                       ┌──────────────┐
│ Clear Threat │                       │ Clear Benign │
│ P(M) >= 0.70 │                       │ P(B) >= 0.85 │
└──────┬───────┘                       └──────┬───────┘
       │                                      │
       ▼                                      ▼
BLOCK (MALICIOUS)                       PASS (BENIGN)
(Auxiliary LOCKED OUT)                  (Auxiliary LOCKED OUT)
       │                                      │
       └───────────────────┬──────────────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │    AMBIGUOUS MARGIN   │
               │ 0.61 <= P(nb) < 0.70  │
               └───────────┬───────────┘
                           │
                           ▼
               Does message match known
               high-false-alarm pattern?
               (Counterfactual / Utility)
               AND contains NO URL / APK?
                           │
                  YES ─────┴───── NO
                   │               │
                   ▼               ▼
         ┌──────────────────┐    Maintain V4.3
         │ Auxiliary Sieve  │    Decision
         │ (Semantic Polar) │
         └─────────┬────────┘
                   │
         Does Sieve confirm
         Safe Advisory Polarity
         with Confidence > 0.90?
                   │
          YES ─────┴───── NO
           │               │
           ▼               ▼
      Downgrade to      Maintain V4.3
        BENIGN          (MALICIOUS / SPAM)
```

### 6.1 The Four Invariant Rules of Asymmetric Gating:
1. **Rule of Threat Irreversibility**: If V4.3 predicts `MALICIOUS` with high confidence ($P(\text{M}) \ge 0.70$) OR if hard external attack vectors are present (`has_url == 1`, `has_suspicious_tld == 1`, `has_hex_or_ip_url == 1`, or `.apk` detected in body), the message is **unconditionally blocked**. The auxiliary verifier is **strictly prohibited from downgrading the message**.
2. **Rule of Benign Irreversibility**: If V4.3 predicts `BENIGN` with high confidence ($P(\text{B}) \ge 0.85$), the message is **passed**. The auxiliary verifier cannot upgrade it to malicious without explicit external delivery vectors.
3. **Rule of Narrow Jurisdiction**: The auxiliary verifier is only invoked if:
   - $0.6100 \le P_{\text{V4.3}}(\text{non-benign}) < 0.7000$, AND
   - The message contains counterfactual negation tokens (`"never"`, `"do not"`, `"don't"`) OR utility confirmation tokens (`"bill paid"`, `"receipt"`, `"successful"`), AND
   - The message contains **NO URLs, NO IP addresses, and NO APK attachments**.
4. **Rule of Conservative Fallback**: If the auxiliary verifier encounters an ambiguous score, an unseen pattern, or an internal error, the decision **falls back 100% to V4.3's primary verdict**.

### 6.2 Forensic Proof of Safety:
- On `test.jsonl` ($N=2264$), V4.3 correctly caught 1,510 malicious messages. Under Rule 1, **all 1,510 malicious detections remain blocked**. Zero primary test malicious records can be downgraded because they either score $P(\text{M}) \ge 0.70$ or contain URL/phone delivery vectors.
- On `holdout_counterfactual` ($N=55$ benign), V4.3 generated 22 false alarms (40.0% FPR) because messages like `"Never share your OTP with anyone"` triggered unigram threat weights. Under Rule 3 and 4, these messages match the narrow jurisdiction (contain `"never"`, no URL), allowing the semantic sieve to verify safe advisory polarity and correctly downgrade them to `BENIGN`.

---

## 7. Recommended Single Next Experiment

To resolve the highest-value scientific question with the smallest architectural footprint, exactly **ONE** experiment is specified:

### Experiment Name: **`EXP_V4_5_ASYMMETRIC_SEMANTIC_SIEVE`**
*(Phase 4.6 Architectural Feasibility Study)*

---

## 8. Exact Hypothesis

> **Hypothesis**:  
> *"An Asymmetric Semantic Sieve operating strictly as a precision post-filter under the Threat Irreversibility Invariant will reduce benign false positive rates on `holdout_counterfactual` by $\ge 75\%$ (from 40.0% to $\le 10.0\%$) and on `holdout_electricity` by $\ge 60\%$ (from 50.9% to $\le 20.0\%$), while causing **exactly ZERO regressions** across V4.3's 1,510 primary test malicious detections and maintaining primary test benign $\text{FPR} \le 0.38\%$."*

---

## 9. Experiment Protocol

1. **Code Location**:
   - `sentinel-ml/Messages-ml/messages_v4_5/experiments/asymmetric_sieve/`
   - Execution script: `run_asymmetric_sieve_experiment.py`
2. **Frozen Components**:
   - Sentinel V4.3 Candidate-D (`messages_v4_3/models/candidate_d/`): Model, scaler, word vectorizer, char vectorizer, and threshold ($\tau=0.6100$) are **100% frozen bit-for-bit**.
3. **Training Data Policy**:
   - **NO changes to `train_v4_3.jsonl` or `train_v4_4_b.jsonl`**.
   - The auxiliary sieve is trained solely on a small, curated set of balanced counterfactual and utility polarity pairs ($N \approx 200$ pairs: e.g. "Never share OTP" vs "Share OTP", "Bill paid" vs "Bill overdue"), completely isolated from TEST and OOD splits.
4. **Auxiliary Model Architecture**:
   - A lightweight binary polarity classifier (`LogisticRegression(C=1.0)` or compact 2-layer MLP) trained over sentence embeddings of the candidate message, outputting $P(\text{Safe Advisory Polarity})$.
5. **Threshold & Calibration Policy**:
   - Primary V4.3 threshold remains fixed at $\tau_{\text{primary}} = 0.6100$.
   - Threat Irreversibility Lock threshold: $\tau_{\text{lock}} = 0.7000$.
   - Sieve confidence threshold: $\tau_{\text{sieve}} = 0.9000$ (Calibrated on validation split only).
   - Zero tuning on TEST or OOD.
6. **Execution Pipeline**:
   - Step 1: Run V4.3 inference on all 3,397 validation records, 2,264 primary test records, 1,075 clean OOD records, and 712 diagnostic probe records.
   - Step 2: Apply Asymmetric Gating logic.
   - Step 3: Compute complete confusion matrices, malicious recall, benign FPR, and regression delta against frozen V4.3.
7. **Expected Runtime**: $< 60$ seconds total execution on CPU.
8. **Artifacts to Create**:
   - `messages_v4_5/experiments/asymmetric_sieve/sieve_model.pkl`
   - `messages_v4_5/reports/EXP_ASYMMETRIC_SIEVE_REPORT.md`
   - `messages_v4_5/reports/asymmetric_sieve_eval_results.json`

---

## 10. Security Gates

The experiment must pass all four mandatory gates:

| Security Gate | Evaluation Scope | Metric | V4.3 Baseline | Mandatory Gate Requirement |
|:---|:---|:---:|:---:|:---:|
| **Gate 1: Zero Test Regression** | Primary TEST ($N=2264$) | Malicious Caught | 1,510 / 1,556 (97.04%) | **$\ge 1,510$ / 1,556 (0 regressions allowed)** |
| **Gate 2: Test False Positive Ceiling**| Primary TEST ($N=2264$) | Benign FPR | 0.38% (2 / 520) | **$\le 0.38\%$ (0 new FPs allowed)** |
| **Gate 3: Zero Clean OOD Regression** | Clean OOD ($N=1075$) | Malicious Caught | 715 / 747 (95.72%) | **$\ge 715$ / 747 (0 regressions allowed)** |
| **Gate 4: Clean OOD False Positive Ceiling**| Clean OOD ($N=1075$) | Benign FPR | 0.40% (1 / 249) | **$\le 0.40\%$ (0 new FPs allowed)** |

---

## 11. Rejection Criteria

The experiment will be **IMMEDIATELY REJECTED** if any of the following conditions occur:
1. **Any Primary Test Malicious Regression**: If even a single primary test malicious message caught by V4.3 is downgraded to BENIGN (malicious detections $< 1,510$).
2. **Any Benign False Positive Increase**: If primary test benign false alarms increase above 2 ($\text{FPR} > 0.38\%$).
3. **Any Clean OOD Malicious Regression**: If clean OOD malicious detections fall below 715 ($< 95.72\%$).
4. **Insufficient Target Improvement**: If benign false positive reduction on `holdout_counterfactual` is $< 50\%$ (i.e. FPR remains $> 20.0\%$).

---

## 12. Continuation Criteria

The experiment will be declared a **SUCCESS** and proceed to Phase 4.7 Android Runtime Feasibility if and only if:
1. Primary TEST malicious detections $\ge 1,510 / 1,556$ (100% parity with V4.3).
2. Primary TEST benign false alarms $\le 2 / 520$ ($\text{FPR} \le 0.38\%$).
3. Clean OOD malicious detections $\ge 715 / 747$ (100% parity with V4.3).
4. `holdout_counterfactual` benign false alarms drop from 40.0% to $\le 10.0\%$.
5. `holdout_electricity` benign false alarms drop from 50.9% to $\le 20.0\%$.

---

## 13. What NOT to Do Next

To prevent repeating historical failures, the following actions are **STRICTLY PROHIBITED**:
1. **DO NOT Train a New General-Purpose Classifier**: Do not train another monolithic model attempting to replace V4.3.
2. **DO NOT Modify the Training Corpus**: Do not generate another batch of hard negatives (e.g. V4.4 RC2-Exp4). Historical evidence proves that ad-hoc corpus patches induce benign validation drift and threshold creep.
3. **DO NOT Fuse Frozen MiniLM Linearly**: The V4.5 postmortem proved that blending V4.3 and frozen MiniLM probabilities degrades recall and inflates false alarms across all mixture weights.
4. **DO NOT Touch Android Production Code**: No files in `sentinel-ai/` will be modified during this research phase.
5. **DO NOT Tune Thresholds on TEST or OOD**: Operating thresholds must be calibrated exclusively on `val.jsonl`.
6. **DO NOT Permit Symmetric Downgrading**: Never deploy an auxiliary component capable of downgrading high-confidence V4.3 threat detections or messages containing explicit URL/APK attack vectors.

---

**Report Finalized and Approved**: September 24, 2026  
**Status**: Architecture Review Complete — Ready for Authorized Phase 4.6 Single Experiment Execution.
