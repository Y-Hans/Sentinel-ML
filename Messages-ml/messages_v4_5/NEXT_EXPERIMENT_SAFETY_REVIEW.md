# SENTINEL MESSAGES — NEXT EXPERIMENT SAFETY & PROVENANCE AUDIT REVIEW

**Document ID**: `SENTINEL-SAFETY-REVIEW-V4_5-2026-09-24`  
**Author**: Lead ML/Security Architecture & Safety Engineer  
**Date**: September 24, 2026  
**Status**: AUDIT COMPLETED — THREAT IRREVERSIBILITY INVARIANT FALSIFIED FOR ORIGINAL DESIGN  
**Primary Directive**: Analysis Only (No training, no model creation, no corpus modification, no Android modification, no production modification).  
**Protected Benchmark**: Sentinel Messages V4.3 Candidate-D ($\tau = 0.6100$, 4,019 dimensions).

---

## 1. Executive Summary & Critical Safety Finding

A rigorous empirical audit was conducted over all **1,510 primary test malicious messages correctly detected by Sentinel V4.3** to verify the central invariant of the proposed asymmetric sieve architecture:

> *"Claimed Invariant: All 1,510 malicious TEST detections caught by V4.3 are protected against downgrade by either $P(\text{MALICIOUS}) \ge 0.70$ or explicit attack-vector features (`has_url`, `has_phone`, `has_suspicious_tld`, `has_hex_or_ip_url`, `has_apk`)."*

### THE CLAIMED INVARIANT IS EMPIRICALLY FALSE:
- **Exact Protection Audit Result**:
  - Protected by $P(\text{MALICIOUS}) \ge 0.70$: **1,475 records (97.68%)**
  - Protected by V4.3 raw URL regex: **0 records (0.00%)** *(due to dataset token normalization to `<URL>`)*
  - Protected by V4.3 raw phone regex: **0 records (0.00%)** *(due to dataset token normalization to `<PHONE>`)*
  - Protected by suspicious TLD regex: **3 records (0.20%)**
  - Protected by APK regex: **0 records (0.00%)**
  - **COUNT G (NOT PROTECTED BY ANY PROPOSED IRREVERSIBLE MECHANISM): 35 RECORDS (2.32%)**

### MANDATORY SAFETY STOP:
Per Section 1 of the Safety Directive:
> *"The final G count MUST be exactly zero before any sieve experiment is allowed. If $G > 0$: STOP. Do not execute the sieve. Instead revise the architecture so those records are protected."*

Because **$G = 35 > 0$**, the execution of any semantic sieve experiment is **STRICTLY HALTED**. 

Among these 35 unprotected malicious records is message `MSG_SRC_IMC25_FISHING_SMISHING_0019838` with text **`"Paid Successfully"`** ($P(\text{M}) = 0.6227, P(\text{B}) = 0.3600$). Under the proposed sieve architecture, a semantic utility/payment verifier evaluating this message would classify it as a benign payment confirmation and **downgrade an authentic malicious attack to BENIGN**, introducing a catastrophic primary test regression.

---

## 2. Threat Irreversibility Audit & Exact Protection Counts

Every one of the 1,510 malicious messages caught by V4.3 in `data/processed/test.jsonl` was audited against the proposed irreversible protection rules:

| Category | Protection Mechanism | Description | Count | % of V4.3 Detections | Protection Status |
|:---:|:---|:---|:---:|:---:|:---:|
| **A** | **High Threat Confidence** | $P(\text{MALICIOUS}) \ge 0.7000$ | **1,475** | **97.68%** | Robustly Protected |
| **B** | **Raw URL Regex** | V4.3 `has_url == 1.0` (`https?://\S+\|www\.\S+`) | **0** | **0.00%** | **INEFFECTIVE (Dataset is Normalized)** |
| **C** | **Raw Phone Regex** | V4.3 `has_phone == 1.0` (`(?:\+91\|0)?[6-9]\d{9}`) | **0** | **0.00%** | **INEFFECTIVE (Dataset is Normalized)** |
| **D** | **Suspicious TLD / IP** | V4.3 `has_suspicious_tld` or `has_hex_or_ip_url` | **3** | **0.20%** | Robustly Protected |
| **E** | **APK File Extension** | Regex match on `\.apk\b` in raw text | **0** | **0.00%** | Unmatched in margin pool |
| **F** | **Multiple Mechanisms** | Satisfies $\ge 2$ protection rules simultaneously | **3** | **0.20%** | Robustly Protected |
| **G** | **UNPROTECTED MARGIN** | **Satisfies ZERO proposed protection rules** | **35** | **2.32%** | **FATAL BREACH: $G > 0$** |

```
1,510 V4.3 Malicious Primary TEST Detections
├── Protected by P(M) >= 0.70 ──────────────── 1,475 (97.68%)
├── Protected by Suspicious TLD Regex ────────     3  (0.20%)
└── Count G: UNPROTECTED AT-RISK MARGIN ──────    35  (2.32%)  <-- VIOLATES SAFETY GATE
```

---

## 3. Deep Forensic Audit of the 35 Unprotected Malicious Detections

The 35 records falling into Count G have $0.6100 \le P(\text{non-benign}) < 0.7000$ and register $0.0$ on V4.3's structural URL and phone features. They divide into three distinct threat vectors:

### 3.1 Group G.1: Hidden URLs Masked by Dataset Tokenization ($N = 12$)
These attacks delivered web smishing payloads, but because the evaluation corpus was pre-tokenized with `<URL>`, V4.3's `RE_URL` (`https?://`) did not fire. The model caught them exclusively through Word TF-IDF (`"url"` feature) and Character TF-IDF:
1. `MSG_SRC_IMC25_FISHING_SMISHING_0006481`: `"Free Msg: Your bill is paid for <DATE_TIME>. Thanks, here's a little gift for you: <URL>"` ($P(\text{M}) = 0.5600, P(\text{S}) = 0.4393, P(\text{nb}) = 0.9993$)
2. `MSG_SRC_IMC25_FISHING_SMISHING_0022321`: `"Let's chat on WhatsApp! It's a fast, simple, and secure app... Get it at <URL>"` ($P(\text{M}) = 0.6635, P(\text{nb}) = 0.9944$)
3. `MSG_SRC_IMC25_FISHING_SMISHING_0007422`: `"Pay $<NUM> for full vehicle insurance... Hurry and click: <URL> Reply END to unsubscribe"` ($P(\text{M}) = 0.6018, P(\text{nb}) = 0.9988$)
4. `MSG_SRC_IMC25_FISHING_SMISHING_0006678`: `"(__coinbase__) <URL> You just got [<NUM> b.t.c]"` ($P(\text{M}) = 0.6421, P(\text{nb}) = 0.9969$)
5. `MSG_SRC_IMC25_FISHING_SMISHING_0014117`: `"GlaxoSmithKline ... FSCS Protected Min £25k ... <URL> REGISTER HERE NOW."` ($P(\text{M}) = 0.6915, P(\text{nb}) = 0.9996$)
6. `MSG_SRC_IMC25_FISHING_SMISHING_0007568`: `"<URL>: <DATE_TIME> to vote in CA Primary Election... Find a ballot dropbox: <URL>"` ($P(\text{M}) = 0.5492, P(\text{nb}) = 0.9996$)

### 3.2 Group G.2: Hidden Callback Numbers Masked by Dataset Tokenization ($N = 7$)
These attacks delivered voice/SMS callback fraud. Because phone numbers were normalized to `<PHONE>` or `<PHONE_NUMBER>`, V4.3's `RE_PHONE` did not fire. They were caught solely through subwords (`"call"`, `"phone"`, `"pobox"`):
1. `MSG_SRC_IMC25_FISHING_SMISHING_0018607`: `"Dear customer congratulation you are lucky winner... Helpline number-<PHONE_NUMBER> Toll free number - <DATE_TIME>"` ($P(\text{M}) = 0.6859, P(\text{nb}) = 0.9999$)
2. `MSG_SRC_MENDELEY_SMISHING_2022_0001093`: `"<NUM> free text msgs. Just text ok to <NUM_CODE> a or call <PHONE> nd we'll credit your account"` ($P(\text{M}) = 0.6009, P(\text{nb}) = 0.9992$)
3. `MSG_SRC_MENDELEY_SMISHING_2022_0004410`: `"You have won a guaranteed £<NUM> award... call free on <PHONE> (<NUM>+) <NUM> stop getstop..."` ($P(\text{M}) = 0.5348, P(\text{nb}) = 0.9992$)
4. `MSG_SRC_IMC25_FISHING_SMISHING_0018675`: `"Welcome To <NAMED_ENTITY> Lucky Winner... Help Center:- <PHONE_NUMBER>"` ($P(\text{M}) = 0.6831, P(\text{nb}) = 0.9997$)
5. `MSG_SRC_MENDELEY_SMISHING_2022_0005483`: `"This weeks SavaMob member offers are now accessible. Just call <PHONE> for details!..."` ($P(\text{M}) = 0.6089, P(\text{nb}) = 0.9972$)
6. `MSG_SRC_MENDELEY_SMISHING_2022_0000414`: `"Loans for any purpose even if you have Bad Credit! Call NoWorriesLoans.com on <PHONE>"` ($P(\text{M}) = 0.6100, P(\text{nb}) = 0.9923$)
7. `MSG_SRC_MENDELEY_SMISHING_2022_0003808`: `"Last chance claim discount vouchers-Text YES to <NUM_CODE> now! SavaMob offers mobile T Cs <PHONE>"` ($P(\text{M}) = 0.5474, P(\text{nb}) = 0.9981$)

### 3.3 Group G.3: Critical URL-less & Phone-less Threats ($N = 16$)
These attacks contain **neither URLs nor phone numbers** in any form (raw or tokenized). They rely entirely on social engineering, coercive panic, or conversational fraud:
1. **`MSG_SRC_IMC25_FISHING_SMISHING_0019838`**:
   - *Text*: `"Paid Successfully"`
   - *V4.3*: $P(\text{B}) = 0.3600, P(\text{S}) = 0.0173, P(\text{M}) = 0.6227 \implies P(\text{nb}) = 0.6400 \to$ **`MALICIOUS`**
   - *Lethal Vulnerability*: An auxiliary utility/payment verifier evaluating this message will classify `"Paid Successfully"` as a legitimate transaction confirmation receipt and **downgrade it to BENIGN**.
2. **`MSG_SRC_IMC25_FISHING_SMISHING_0010411`**:
   - *Text*: `"Payment not done sir yet company will start legal action your aadhar card pan card will be blocked"`
   - *V4.3*: $P(\text{B}) = 0.3319, P(\text{S}) = 0.0017, P(\text{M}) = 0.6664 \implies P(\text{nb}) = 0.6681 \to$ **`MALICIOUS`**
   - *Lethal Vulnerability*: Coercive extortion without a link. V4.3 correctly catches this via legal panic keywords, but $P(\text{M}) = 0.6664 < 0.70$.
3. **`MSG_SRC_IMC25_FISHING_SMISHING_0007615`**:
   - *Text*: `"Order-ID <NUM_CODE> Hello. The delivery guy was at your door. We missed you. Inform us when we can come back today"`
   - *V4.3*: $P(\text{B}) = 0.3029, P(\text{S}) = 0.0291, P(\text{M}) = 0.6680 \to$ **`MALICIOUS`**
4. **`MSG_SRC_IMC25_FISHING_SMISHING_0007324`**:
   - *Text*: `"Hey 👋 Am an artist If you don’t mind one of your picture could be my inspiring muse... You will totally get paid for it as well as a bonus..."`
   - *V4.3*: $P(\text{B}) = 0.3254, P(\text{S}) = 0.0381, P(\text{M}) = 0.6366 \to$ **`MALICIOUS`**
5. **`MSG_SRC_IMC25_FISHING_SMISHING_0018029`**:
   - *Text*: `"ARE YOU SAFE FROM SMS HIJACK ATTACKS?"`
   - *V4.3*: $P(\text{B}) = 0.3165, P(\text{S}) = 0.0133, P(\text{M}) = 0.6701 \to$ **`MALICIOUS`**
6. **`MSG_SRC_IMC25_FISHING_SMISHING_0022319`**:
   - *Text*: `"A while back you put a request for info on refinance on your home. I wanted to check back in. Would it be ok to email you a quote? Reply STOP to opt out"`
   - *V4.3*: $P(\text{B}) = 0.1728, P(\text{S}) = 0.1589, P(\text{M}) = 0.6683 \to$ **`MALICIOUS`**

---

## 4. Phone & Vector Vulnerability Analysis

The assumption that `has_phone == 1.0` acts as a reliable protection invariant is **empirically disproven**:

1. **Format Blindness in V4.3 Regex**:
   - V4.3 extracts phone presence via `RE_PHONE = re.compile(r"(?:\+91|0)?[6-9]\d{9}")`.
   - In `test.jsonl` ($N = 2,264$), **exactly ZERO messages match `RE_PHONE`**.
   - Exactly **268 messages** contain normalized `<PHONE>` or `<PHONE_NUMBER>` tokens.
   - Any rule that checks `st_test[12] == 1.0` to prevent downgrading callback scams evaluates to `False` across 100% of normalized test messages.
2. **Real-World Infrastructure Blindness**:
   - `RE_PHONE` strictly requires Indian 10-digit mobile numbers starting with 6–9.
   - It has **zero coverage** for:
     - National Toll-Free Numbers (`1800-xxx-xxxx` or `1800xxxxxx`)
     - State Landline Numbers (`011-xxxxxxx`, `022-xxxxxxx`, `080-xxxxxxx`)
     - Shortcode Callback Numbers (`5xxxx`, `56767`)
     - International Callback Scams (`+1`, `+44`, `+234`)
3. **Phone-Only Threats at Marginal Probabilities**:
   - Seven malicious records caught by V4.3 have $P(\text{MALICIOUS}) < 0.70$ and rely on phone callbacks.
   - **Conclusion**: Phone numbers are an active attack vector, but V4.3's current structural phone feature cannot be used as an immutable safety shield.

---

## 5. Sieve Training-Data Provenance Specification

To prevent repeating the V4.4 contamination failure (where holdouts and training patches were co-generated), a formal provenance specification has been drafted and locked at:

**[`messages_v4_5/experiments/asymmetric_sieve/PROVENANCE_SPEC.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/messages_v4_5/experiments/asymmetric_sieve/PROVENANCE_SPEC.md)**

### Mandatory Provenance Controls:
1. **Zero Contamination from Protected Splits**:
   - Absolute ban on reading, sampling, paraphrasing, or mutating messages from `test.jsonl`, `ood.jsonl`, or any of the 7 diagnostic holdout suites.
2. **Authorized Public Source Regimes**:
   - Public regulatory consumer alerts (RBI Kehta Hai, TRAI advisory notices).
   - Publicly published DISCOM tariff schedules and receipt templates (TANGEDCO, BESCOM, MSEDCL).
3. **Automated Mathematical Isolation Gates**:
   - Exact String Overlap: Exactly **0** collisions.
   - Aggressive Normalized Overlap: Exactly **0** collisions.
   - Word Token Jaccard Similarity Ceiling: $\max_{e} J(s, e) < 0.70$ against all evaluation records.
   - MinHash LSH Character 5-Gram Overlap: Zero shared buckets with protected evaluation sets.
   - ID Collision Check: Format `MSG_SIEVE_AUTHORED_2026_{INDEX:06d}` with zero namespace overlap.
4. **Volume Control**: Dataset volume is capped at $150 \le N_{\text{pairs}} \le 300$ ($300 \le N_{\text{rows}} \le 600$).

---

## 6. Splitting the Semantic Problem: Advisory vs Utility

The proposal to train a single semantic verifier covering both advisory counterfactuals and utility legitimacy is **rejected**. They represent disjoint linguistic and structural tasks:

```
Disjoint Semantic Tasks
├── Verifier A: Speech-Act Communicative Polarity (Advisory vs Solicitation)
│   ├── Target: Prohibitive security warnings ("Never share OTP") vs Phishing demands ("Send OTP")
│   ├── Input Domain: Explicit security/credential terminology (OTP, password, PIN, login)
│   └── Safety Invariant: MUST contain ZERO external delivery vectors (No URLs, no phone callbacks)
└── Verifier B: Transactional Settlement Polarity (Settlement vs Coercion)
    ├── Target: Completed settlement receipts ("Bill paid successfully") vs Disconnection threats ("Cut tonight")
    ├── Input Domain: Account statements, delivery confirmations, electricity bills
    └── Safety Risk: HIGH (Attacks like "Paid Successfully" mimic settlement confirmations as bait)
```

### 6.1 Specification for Verifier A (Speech-Act Communicative Polarity)
- **Input**: Message containing credential tokens (`otp`, `pin`, `password`, `code`).
- **Target Label**: Binary `ADVISORY_PROHIBITION` vs `ACTION_DEMAND`.
- **Dangerous Failure Mode**: Phishing lures disguised as advisories (e.g. `"Never share your OTP with anyone, except at our official portal: http://fake.cc"`).
- **Mandatory Precondition**: Verifier A is **locked out** if the message contains ANY URL (`has_url == 1` or `<URL>`) or ANY phone callback vector.

### 6.2 Specification for Verifier B (Transactional Settlement Polarity)
- **Input**: Message containing utility terms (`electricity`, `bill`, `meter`, `power`).
- **Target Label**: `SETTLED_RECEIPT` vs `ACTION_PENDING_DISCONNECTION`.
- **Dangerous Failure Mode**: Fake receipt smishing (e.g. `"Paid Successfully"`, or `"Your bill of Rs 500 is paid. View invoice: [URL]"`).
- **Mandatory Precondition**: Verifier B is **locked out** unless verified against an authentic alphanumeric sender header (e.g., `VK-BESCOM`, `TNEB-PR`). Because 97.5% of dataset messages are headerless, **Verifier B cannot be safely deployed on headerless SMS without introducing regressions.**

---

## 7. Analysis of the Flawed "Safe Advisory Polarity" Label

The review confirms that **"Safe Advisory Polarity" is not a scientifically valid ground-truth label**:
- "Safe" is an operational risk policy decision, not a linguistic feature.
- A text can be linguistically advisory while serving as adversarial bait:
  - *"Advisory Bait"*: `"Never share your password with unauthorized callers. Update your security profile at [Link]."`
- Conversely, an attack can omit all action verbs:
  - *"Coercive Assertion"*: `"Payment not done sir yet company will start legal action your aadhar card pan card will be blocked"`
- **Required Redesign**: If a verifier is trained, its label must represent **explicit syntactic imperative polarity** (e.g. `NEGATIVE_IMPERATIVE_PROHIBITION`: grammatical presence of negated directive verbs scoping credential objects without disjunctive clauses).

---

## 8. Why Deterministic Security-Vector Extensions Must Come First

Before training any machine learning verifier, the review analyzed whether V4.3's structural blind spots can be solved as **Deterministic Post-Inference Security Gates without retraining V4.3**:

### 8.1 The Pure Upgrade Invariant:
A post-inference deterministic gate operates under a unidirectional logic:
$$\hat{y}_{\text{final}} = \begin{cases} \text{MALICIOUS} & \text{if } \text{GateTriggered}(x) \\ \hat{y}_{\text{V4.3}}(x) & \text{otherwise} \end{cases}$$

### 8.2 Mathematical Proof of Zero Regression:
1. Because the deterministic gate can **ONLY UPGRADE** a non-malicious prediction (`BENIGN` or `SPAM`) to `MALICIOUS`, it **CAN NEVER DOWNGRADE** any of V4.3's 1,510 primary test malicious detections.
2. The count of unprotected malicious records is **mathematically $G = 0$**.
3. Primary TEST malicious detections have a guaranteed mathematical floor:
   $$\text{Malicious Caught} \ge 1,510 / 1,556 \quad (97.04\%)$$

### 8.3 Structural Vectors Solved Immediately:
1. **APK Payload Gate**:
   - Trigger: `re.search(r"\.apk\b", text, re.I)`.
   - Effect: Upgrades `"Download our official partner rewards app at rewards.apk"` directly to `MALICIOUS`.
   - Test FPR Impact: **0 new false positives** (audit confirmed 0 benign test messages contain `.apk`).
2. **Normalized URL Token Consistency Gate**:
   - Trigger: Presence of `<URL>` when V4.3 raw regex evaluated to 0.
3. **Toll-Free Callout Callback Gate**:
   - Trigger: Presence of `1800` toll-free pattern combined with coercive action words (`call immediately`, `suspended`, `penalty`).

---

## 9. Revised Architectural Options

| Architecture Option | Description | Regression Risk | Implementation Complexity | Recommendation Status |
|:---|:---|:---:|:---:|:---:|
| **Option A: Deterministic Security-Vector Gates** | Post-inference upgrade gates on frozen V4.3 for APK, toll-free, and token consistency. | **ZERO ($G = 0$ Guaranteed)** | Minimal (Pure Python, $<50$ lines) | **STRONGLY RECOMMENDED AS NEXT STEP** |
| **Option B: Speech-Act Polarity Verifier (A)** | Gated auxiliary verifier for counterfactual warnings, locked against downgrading V4.3 threats. | Low (if $G=0$ enforced) | Moderate (Requires authored corpus) | Deferred pending Option A baseline |
| **Option C: Utility Settlement Verifier (B)** | Gated auxiliary verifier for utility bills. | High (Susceptible to fake receipt bait) | High (Requires header metadata) | **REJECTED ON HEADERLESS SMS** |
| **Option D: Combined Semantic Sieve** | Original combined sieve design. | **UNACCEPTABLE ($G = 35$)** | High | **PERMANENTLY REJECTED** |
| **Option E: No Experiment** | Maintain V4.3 without changes. | Zero | Zero | Suboptimal (Leaves APK gap unclosed) |

---

## 10. The Single Recommended Next Experiment

Based on undeniable empirical evidence, the **SINGLE** authorized experiment to perform next is:

### Experiment Name: **`EXP_V4_5_DETERMINISTIC_SECURITY_GATES`**
*(Phase 4.6 Structural Precision Gate Evaluation)*

---

## 11. Exact Experiment Specification

1. **Exact Hypothesis**:  
   > *"Deploying deterministic post-inference upgrade gates (for `.apk` payload extensions, normalized URL consistency, and toll-free callback fraud patterns) on top of the frozen Sentinel V4.3 classifier without retraining will recover missed APK attacks (improving `holdout_apk_payload` recall to 100.0%) while maintaining **exactly 1,510 / 1,556 primary test malicious detections (0 regressions)**, primary test benign $\text{FPR} \le 0.38\%$ (0 new false alarms), and Clean OOD recall $\ge 95.72\%$."*
2. **Code Location**:  
   `sentinel-ml/Messages-ml/messages_v4_5/experiments/deterministic_gates/`  
   Script: `run_deterministic_gates_experiment.py`
3. **Training Data**:  
   **ZERO TRAINING DATA REQUIRED**. No model is trained; no corpus is generated or modified.
4. **Architecture & Frozen State**:  
   - Primary: Sentinel V4.3 Candidate-D (`messages_v4_3/models/candidate_d/`) is **100% frozen bit-for-bit**.
   - Gate Logic:
     ```python
     def evaluate_deterministic_gates(text, v43_pred, v43_probs):
         # Rule 1: APK Payload Detection
         if re.search(r"\.apk\b", text, re.IGNORECASE):
             return "MALICIOUS", "TRIGGER_APK_PAYLOAD"
         
         # Rule 2: Toll-Free Coercive Callback Detection
         has_toll_free = bool(re.search(r"\b1800\d{6,7}\b|\b1800[-\s]\d{3}[-\s]\d{3,4}\b", text, re.IGNORECASE))
         has_coercion = bool(re.search(r"\b(blocked|suspended|cut|disconnect|legal action|penalty|fraud department)\b", text, re.IGNORECASE))
         if has_toll_free and has_coercion:
             return "MALICIOUS", "TRIGGER_TOLL_FREE_COERCION"
         
         # Unmodified Fallback to V4.3
         return v43_pred, "V4.3_PRIMARY"
     ```
5. **Evaluation Protocol**:  
   Full execution across `test.jsonl` ($N=2,264$), `ood.jsonl` ($N=1,132$), Clean OOD ($N=1,075$), and all 7 targeted holdout suites ($N=712$).

---

## 12. Exact Rejection Gates

The experiment will be **IMMEDIATELY REJECTED** if:
1. Primary TEST malicious detections fall below **1,510 / 1,556** (any regression from V4.3).
2. Primary TEST benign false alarms increase above **2 / 520** ($\text{FPR} > 0.38\%$).
3. Clean OOD malicious detections fall below **715 / 747** ($< 95.72\%$).
4. Clean OOD benign false alarms increase above **1 / 249** ($\text{FPR} > 0.40\%$).

---

## 13. What Remains Strictly Forbidden

1. **NO Semantic Sieve Execution**: Sieve execution is prohibited until deterministic vectors are fully closed.
2. **NO Downgrade of V4.3 Threat Detections**: High-confidence threats and messages matching primary threat criteria remain permanently locked against downgrading.
3. **NO Training Corpus Modifications**: No ad-hoc hard-negative additions.
4. **NO Retraining of V4.3**: Model weights and scaler remain bit-for-bit immutable.
5. **NO Production or Android Modification**: Zero changes to `sentinel-ai/`.

---

**Report Finalized and Approved**: September 24, 2026  
**Status**: Safety Audit Complete — Sieve Halted — Deterministic Gate Experiment Authorized.
