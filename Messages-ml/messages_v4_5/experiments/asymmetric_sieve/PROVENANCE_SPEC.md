# DATASET PROVENANCE & ISOLATION SPECIFICATION: AUXILIARY SEMANTIC SIEVE

**Document ID**: `SENTINEL-PROVENANCE-SPEC-SIEVE-2026-09-24`  
**Status**: APPROVED SPECIFICATION — PRE-DATASET GENERATION GATE  
**Target Component**: Auxiliary Semantic Sieve / Precision Gatekeeper (Phase 4.6+)  
**Governing Rule**: Strict Data Isolation (Zero leakage from TEST, OOD, or Protected Diagnostic Suites).  

---

## 1. Purpose & Historical Motivation

Previous experiments in Sentinel Messages (specifically V4.4 Candidate B and RC2 iterations) suffered from **co-generated holdouts and template leakage**:
- Diagnostic holdouts and training additions were generated during the same research cycle by prompt-based mutation, resulting in aggressive normalized overlaps (810 URL-normalized overlaps, 1,245 aggressive-normalized overlaps, 9,831 Jaccard $\ge 0.85$ pairs).
- Apparent holdout independence was overstated, creating a false impression of Out-of-Distribution (OOD) generalization.

To guarantee that any future semantic verifier or auxiliary component is evaluated with uncompromised scientific validity, this specification establishes the **mandatory data provenance, generation, isolation, and audit protocols** before a single training sample may be created or ingested.

---

## 2. Permitted and Prohibited Source Datasets

### 2.1 Strictly PROHIBITED Sources (Zero Ingestion, Zero Mutation):
1. **Primary TEST Split (`data/processed/test.jsonl`)**:
   - Cryptographic SHA-256: `988ca27e6c283c683b516ad0f531aa7728aa0aa37e8c3b6f00e9efbb1ddda787` ($N = 2,264$).
   - **Rule**: Absolutely forbidden from reading, copying, paraphrasing, back-translating, or mutating.
2. **Primary OOD Split (`data/processed/ood.jsonl`)**:
   - Cryptographic SHA-256: `34cd57b5252fcc6f5c8ecbe6ad76ffb68c783dbad8c65f80b2d3587e91d575c3` ($N = 1,132$).
   - **Rule**: Absolutely forbidden.
3. **Protected Diagnostic Holdout Suites (`messages_v4_4/evaluation/holdouts/`)**:
   - `holdout_apk_payload.jsonl` ($N=60$)
   - `holdout_conversational_social_eng.jsonl` ($N=207$)
   - `holdout_counterfactual_semantic.jsonl` ($N=110$)
   - `holdout_electricity.jsonl` ($N=110$)
   - `holdout_greetings.jsonl` ($N=110$)
   - `holdout_institutional_callback.jsonl` ($N=60$)
   - `holdout_system_notifications.jsonl` ($N=110$)
   - **Rule**: These 7 files are **Permanent Benchmark Fixtures**. No sample in the sieve dataset may be derived from, aligned with, or prompted from these files.

### 2.2 Permitted Source Domains (Newly Authored Corpus):
1. **Public Domain Regulatory Disclosures**:
   - Reserve Bank of India (RBI) official consumer protection circulars and Kehta Hai public safety campaigns.
   - Telecom Regulatory Authority of India (TRAI) official advisory guidelines.
   - Authentic DISCOM consumer tariff circulars and bill formats publicly published on state electricity board portals (e.g., BESCOM, TANGEDCO, MSEDCL, Tata Power).
2. **Independent Synthetic Authoring Protocol**:
   - All synthetic pairs must be authored by an independent generator that has **never accessed** the protected evaluation splits.

---

## 3. Authoring Process & Counterfactual Pair Construction

The auxiliary verifier targets specific linguistic phenomena (e.g. communicative speech-act polarity). Therefore, samples must be constructed as **minimal counterfactual pairs**:

### 3.1 Structural Contrastive Pair Rule:
Every training instance must consist of a paired tuple:
$$(x_{\text{advisory}}, x_{\text{threat}})$$
Where $x_{\text{advisory}}$ and $x_{\text{threat}}$ share identical lexical entities, numbers, and brand terms, but differ strictly in their communicative polarity.

#### Example Counterfactual Tuple (Credential Security):
- **Base Subject**: Bank One-Time Password advisory.
- **Shared Entities**: `"HDFC Bank"`, `"OTP"`, `"A/C XX1042"`, `"netbanking"`.
- **Advisory Variant ($x_{\text{advisory}}$)**:
  `"HDFC Bank: OTP for netbanking login is 948210. Valid for 5 mins. NEVER share this OTP with anyone, including bank staff."`
- **Threat Variant ($x_{\text{threat}}$)**:
  `"HDFC Bank: OTP for netbanking login is 948210. Forward this code immediately to +919822334455 to prevent account suspension."`

#### Example Counterfactual Tuple (Utility Status):
- **Base Subject**: State electricity bill notification.
- **Shared Entities**: `"BESCOM"`, `"Consumer ID 0948219"`, `"Rs 1,420"`, `"Bill"`.
- **Closed Receipt Variant ($x_{\text{confirmation}}$)**:
  `"BESCOM: Payment of Rs 1,420 for Consumer ID 0948219 received successfully on 18-Sep. Transaction ID: 994821. Thank you."`
- **Urgent Disconnection Variant ($x_{\text{threat}}$)**:
  `"BESCOM Alert: Payment of Rs 1,420 for Consumer ID 0948219 is overdue. Power will be disconnected tonight at 9 PM. Call officer 9811223344."`

---

## 4. Label Ontology & Granular Target Taxonomy

The flawed concept of a monolithic `"Safe Advisory Polarity"` label is replaced with a **formal speech-act taxonomy**:

```
Sieve Semantic Ontology
├── 1. ADVISORY_PROHIBITION (Label 0)
│   └── Explicit imperative prohibiting credential sharing without redirection
├── 2. TRANSACTION_CONFIRMATION (Label 1)
│   └── Past-tense confirmation of completed payment, delivery, or statement
├── 3. ACTION_DEMAND_THREAT (Label 2)
│   └── Urgent solicitation of credentials, codes, callbacks, or external action
└── 4. UNRESOLVED_AMBIGUOUS (Label 3)
    └── Mixed signals, promotional bait, or ambiguous conversational text
```

**Security Invariant**: The auxiliary sieve may only issue a downgrade recommendation if the model predicts `ADVISORY_PROHIBITION` or `TRANSACTION_CONFIRMATION` with calibrated probability $P \ge 0.9500$. Any sample scoring in `ACTION_DEMAND_THREAT` or `UNRESOLVED_AMBIGUOUS` falls back unconditionally to V4.3's primary threat determination.

---

## 5. Mandatory Automated Leakage & Contamination Gates

Before any newly authored dataset `train_sieve.jsonl` can be loaded by an experiment, it must pass a 5-step automated audit script (`audit_sieve_provenance.py`):

### 5.1 Exact String Collision Gate:
$$\{x_{\text{train}}\} \cap (\{x_{\text{test}}\} \cup \{x_{\text{ood}}\} \cup \{x_{\text{holdouts}}\}) = \emptyset$$
- **Threshold**: Exactly **0** collisions allowed. Any exact match results in instant dataset invalidation.

### 5.2 Aggressive Normalized Collision Gate:
Normalize text via lowercasing, stripping punctuation, masking URLs (`<URL>`), masking phone numbers (`<PHONE>`), and masking numbers (`<NUM>`):
$$\text{NormAggressive}(x_{\text{train}}) \cap \text{NormAggressive}(x_{\text{eval}}) = \emptyset$$
- **Threshold**: Exactly **0** normalized collisions allowed.

### 5.3 Token Jaccard Similarity Ceiling:
For every sample $s \in \text{train\_sieve}$ and every sample $e \in \text{protected\_eval}$:
$$J(s, e) = \frac{|T(s) \cap T(e)|}{|T(s) \cup T(e)|}$$
Where $T(\cdot)$ is the set of word tokens:
- **Threshold**: $\max_{e} J(s, e) < 0.70$.
- Any pair exhibiting $J(s, e) \ge 0.70$ must be logged and discarded.

### 5.4 Character 5-Gram MinHash LSH Overlap Gate:
- Run MinHash Locality-Sensitive Hashing with 128 permutations across character 5-grams.
- Any cluster containing both a training sieve record and a protected evaluation record results in automated rejection.

### 5.5 Entity ID Collision Gate:
- Unique message IDs in `train_sieve.jsonl` must follow the format:
  `MSG_SIEVE_AUTHORED_2026_{INDEX:06d}`
- Exactly **0** ID collisions with any historical corpus (`SRC_IMC25`, `SRC_MENDELEY`, `SRC_UCI`, `EXP_*`).

---

## 6. Sieve Dataset Size and Volume Controls

- **Total Allowed Sieve Volume**: $150 \le N_{\text{pairs}} \le 300$ ($300 \le N_{\text{rows}} \le 600$).
- **Rationale**: A targeted semantic gatekeeper must not be a massive, uncurated corpus that introduces broad lexical noise. It must be a compact, mathematically balanced set of precision calibration points.
- **Split Ratio**:
  - 70% Training (`sieve_train.jsonl`)
  - 30% Internal Sieve Validation (`sieve_val.jsonl`)
  - **Zero overlap** with any Sentinel benchmark split.

---

**Specification Approved**: September 24, 2026  
**Enforcement Authority**: Lead ML & Security Architecture Lead
