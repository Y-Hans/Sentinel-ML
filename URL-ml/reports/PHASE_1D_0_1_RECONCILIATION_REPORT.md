# Sentinel — Phase 1D.0.1: Read-Only Reconciliation Before Prototype

> **Document Type:** Read-Only Forensic Reconciliation & Pre-Prototype Audit  
> **Phase:** 1D.0.1 (Pre-Prototype Specification & Policy Freeze)  
> **Authorization Status:** READ-ONLY AUDIT & DESIGN CORRECTION ONLY — ZERO EXECUTION — ZERO GIT MUTATIONS  
> **Governing Baseline:** V8 Champion (`073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`) remains invariant  
> **Historical Record Integrity:** All existing artifacts preserved bit-for-bit without alteration  

---

## 1. Executive Summary

Phase 1D.0.1 completes the read-only reconciliation required prior to any prototype implementation for Phase 1D.1. It reconciles artifact checksums across all reference tables, unifies the adjudication architecture into a single internally consistent specification with explicit precedence rules, formalizes a 3-tier acceptance policy defining intermediate warning zones, and outlines an isolated single-variable ablation matrix for Phase 1D.1.

### Core Reconciliation Outcomes:
1. **Provenance Discrepancies Resolved:** Every referenced input artifact was computed directly from the filesystem using SHA-256. The observed disk hashes match the authoritative pre-execution audit in [`s2_e_execution_metrics.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/s2_e_execution_metrics.json) and [`PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md) **100.000% bit-for-bit**. The discordant values in Section 2.1 of the Phase 1D.0 report were identified as draft transcription errors in the narrative table; the underlying physical files were never modified.
2. **Adjudication Specification Unified:** A strict, non-circular precedence waterfall is established: Hard Threat Overrides (IP, brand typosquat, suspicious TLD, path/query threats) execute first with absolute priority. URLs with non-empty path/query are routed to standard scoring ($\tau_{\text{standard}} = 0.2800$). Only benign-lacking, empty-path bare apex URLs reach safe-brand matching, safe-root matching, and candidate threshold evaluation.
3. **Threshold Selection Postponed:** Neither $\tau_{\text{apex}} = 0.5500$ nor $\tau_{\text{apex}} = 0.6500$ is adopted. Both are formally documented as unvalidated experimental candidates to be evaluated in Phase 1D.1. Reputation-based suppression is categorized as an experimental candidate requiring empirical bypass auditing.
4. **Three-Tier Acceptance Policy Formalized:** Explicit numerical ranges are established for `PASS`, `WARNING / CONDITIONAL REVIEW`, and `HARD FAIL` across all seven gates, maintaining zero permitted regressions on the 174 Android golden fixtures.
5. **Phase 1D.1 Single-Variable Ablation Matrix Defined:** Proposed testing evaluates candidate thresholds, brand dictionary expansion, curated safe roots, and reputation suppression independently before testing any combination.

---

## 2. Artifact Provenance Reconciliation Ledger

Every input artifact, dataset, model binary, and script referenced in Phase 1D.0 was hashed directly from disk using SHA-256 and compared against:
- Column A: **Observed On-Disk Hash & Size** (Live physical disk state)
- Column B: **Authoritative Recorded Hash** (Captured in `s2_e_execution_metrics.json` and Section 2.2 of `PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md`)
- Column C: **Narrative Table in Phase 1D.0 Report** (Section 2.1)

### Comprehensive Hash Reconciliation Table

| Artifact Name | Workspace Path | Observed On-Disk Hash (SHA-256) | Observed Size | Authoritative S2-E Log Hash | Phase 1D.0 Report Table Hash | Reconciliation Finding & Status |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| **`v8_champion`** | `sentinel-ml/URL-ml/models/v8_champion.joblib` | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | 709,417 B | `073e70f215c0c327...` | `073e70f215c0c327...` | **EXACT MATCH** across all records. Verified invariant. |
| **`control_model_reproduced`** | `experiments/phase_1c_2b_2a_s2_f/control_model_reproduced.joblib` | `d3816ac3537b7a9d630e32718ad51ddb94e7b59c940402a492e7adfdedc5c94c` | 1,649,482 B | `d3816ac3537b7a9d...` | `d3816ac3537b7a9d...` | **EXACT MATCH** across all records. Verified invariant. |
| **`candidate_balanced_model`** | `experiments/phase_1c_2b_2a_s2_f/candidate_balanced_repaired_model.joblib` | `ff8d45ae1ed4a7fc0aadea9fd29edbc9f318220a737ba0726f2b08f77df0ad82` | 1,649,402 B | `ff8d45ae1ed4a7fc...` | `ff8d45ae1ed4a7fc...` | **EXACT MATCH** across all records. Verified invariant. |
| **`execute_s2_e_protocol`** | `experiments/phase_1c_2b_2a_s2_f/execute_s2_e_protocol.py` | `abd33c2ae2477956a63c95e81cbc5cf4a44ff85afa993f86d2aa90392d85cfeb` | 18,844 B | `abd33c2ae2477956...` | `abd33c2ae2477956...` | **EXACT MATCH** across all records. Verified invariant. |
| **`public_suffix_list`** | `experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat` | `8228e4bdac6024c058a1e67859157e468a2613b826b53de0e5cae298e1b70755` | 338,010 B | `8228e4bdac6024c0...` | `8228e4bd58f0ddbc...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft transcription error. |
| **`candidate_malicious_repaired`**| `experiments/phase_1c_2b_2a_s2_f/candidate_malicious_bare_apex_repaired_2843.csv` | `f8c1a4d7de0643254c04dd38a0f78509e52bbdeb280a1bf390bb96c0e008f7f8` | 343,195 B | `f8c1a4d7de064325...` | `f8c1a4d782be1be6...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft transcription error. |
| **`protocol_script`** | `experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py` | `4d21a9ec08a400a4c18c55d918fa905e3c06d4376e8809e16c5f49b95cd5349d` | 20,291 B | `4d21a9ec08a400a4...` | `4d21a9ec8018e614...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft transcription error. |
| **`candidate_benign_15k`** | `experiments/phase_1c_2b_prototypes/candidate_bare_apex_15k.csv` | `9c47de4c8372b8fcbe020d72bcd31694b484fae79a60747fa5ab82ad72c6d722` | 1,516,806 B | `9c47de4c8372b8fc...` | `0aef1c0e3e29f045...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft size/hash error. |
| **`cleaned_dataset`** | `sentinel-ml/URL-ml/data/cleaned_dataset.csv` | `6c71c39dd0291b8ef58b31610ac892cd6fe2186876908d42a7b24dcbf06caf2f` | 18,767,734 B | `6c71c39dd0291b8e...` | `96a7d5fa2fb48644...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft size/hash error. |
| **`hard_benign_benchmark`** | `sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json` | `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f` | 222,523 B | `d89f532ce8a5f5c3...` | `839ab13aa5bca73e...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft size/hash error. |
| **`adversarial_predictions`** | `sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv` | `a729e2cd9978f1b9632ed19079c957933ee2ca0d9c54853b1dc5321ce12cff5a` | 336,391 B | `a729e2cd9978f1b9...` | `50672e353594b29f...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft transcription error. |
| **`golden_urls_v8`** | `sentinel-ai/android-app/core/src/test/resources/golden_urls_v8.json` | `47dde6e5837a1b91da6e224a0f85dad75694f0f1a12aad11d7576d48f6a1aacb` | 205,103 B | `47dde6e5837a1b91...` | `963fa1dbba0e6332...` | **RESOLVED:** Live file matches authoritative S2-E log. 1D.0 table had draft size/hash error. |

### Reconciliation Explanation:
- In `PHASE_1D_0_EVIDENCE_FREEZE_AND_REMEDIATION_DESIGN_REPORT.md` Section 2.1, eight table rows contained unverified draft hashes and file sizes resulting from manual copy-paste transcription.
- Crucially, **the physical files on disk were never modified**.
- Direct verification proves that the live filesystem is **100% bit-for-bit identical to the authoritative pre-execution audit ledger** established during Phase 1C.2B-2A-S2-E ([`s2_e_execution_metrics.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/s2_e_execution_metrics.json)).
- No files were overwritten or replaced. The live disk hashes above are formally established as the immutable baseline.

---

## 3. Unified Adjudication Specification

To eliminate ambiguity between narrative text and diagrammatic depictions, the adjudication architecture is formally unified into a single deterministic specification.

```
════════════════════════════════════════════════════════════════════════════════
             UNIFIED ADJUDICATION PRECEDENCE WATERFALL
════════════════════════════════════════════════════════════════════════════════

   [ Input URL ]
        │
   [ Normalization & 67-Feature Extraction ]
        │
   [ Frozen V8 Champion HistGBM Model (Hash: 073e70f2...) ]
        │
   [ Raw Model Probability: raw_prob ]
        │
        ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ TIER 1: ACTIVE THREAT OVERRIDES (Highest Priority — Mandatory Bypass)   │
 │   Condition: If ANY of the following 4 security invariants trigger:    │
 │     1A. IP Host: is_ip == True (Feature 14 == 1.0)                     │
 │     1B. Brand Impersonation: idxBrandImp > 0.0 or leetspeak brand match│
 │     1C. Suspicious TLD: idxSuspTld == 1.0 (Feature 63 == 1.0)          │
 │     1D. Path/Query Threats: idxPathWords > 0 or idxQueryWords > 0      │
 │         or idxSuspExt == 1.0 or idxDoubleEnc == 1.0 or idxRedirect == 1│
 │                                                                        │
 │   Action: OVERRIDE TO MALICIOUS.                                       │
 │           final_prob = max(raw_prob, 0.9500), label = MALICIOUS.       │
 │           (Execution HALTS; no safe rules or attenuation may run).     │
 └────────────────────────────────────────────────────────────────────────┘
        │ No Active Threats Triggered
        ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ TIER 2: STRUCTURAL ROUTING (Bare-Apex vs Non-Apex)                     │
 │   Condition: Is the URL a Bare Apex?                                   │
 │     Definition: clean_path.strip("/") == "" AND query.strip() == ""    │
 │                 AND _subdomain_depth(host) == 0                        │
 │                                                                        │
 │   Branch A: Non-Apex (Has path, query, or subdomains)                  │
 │     Action: ROUTE TO STANDARD SCORING.                                 │
 │             decision = (raw_prob >= 0.2800) ? MALICIOUS : BENIGN.      │
 │             (Execution HALTS; no apex rules apply).                    │
 │                                                                        │
 │   Branch B: Bare Apex (Empty path/query and zero subdomains)           │
 │     Action: Proceed to Tier 3.                                         │
 └────────────────────────────────────────────────────────────────────────┘
        │ Bare Apex with Empty Path & Query
        ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ TIER 3: SAFE BRAND MATCHING                                            │
 │   Condition: Registrable domain exactly matches an entry in            │
 │              COMMON_BRANDS without digit substitution or typosquatting │
 │              (feat_vec[idxSafeBrand] == 1.0)                           │
 │                                                                        │
 │   Action: ATTENUATE TO SAFE BRAND.                                     │
 │           final_prob = min(raw_prob, 0.1500), label = BENIGN.          │
 │           (Execution HALTS).                                           │
 └────────────────────────────────────────────────────────────────────────┘
        │ Not a Verified Safe Brand
        ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ TIER 4: SAFE ROOT MATCHING (Experimental Candidate)                    │
 │   Condition: host matches curated developer, media, gaming, or docs    │
 │              sets (DEV_DOMAINS, MEDIA_DOMAINS, GAMING_DOMAINS, etc.)   │
 │                                                                        │
 │   Action: ATTENUATE TO SAFE ROOT.                                      │
 │           final_prob = min(raw_prob, 0.0500), label = BENIGN.          │
 │           (Execution HALTS).                                           │
 └────────────────────────────────────────────────────────────────────────┘
        │ Not a Curated Safe Root
        ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ TIER 5: BARE-APEX THRESHOLD COMPARISON (Candidate Evaluation)          │
 │   Condition: All remaining unlisted bare-apex URLs                     │
 │                                                                        │
 │   Action: Evaluate raw_prob against candidate apex threshold tau_apex: │
 │             Candidate Option A: tau_apex = 0.5500                      │
 │             Candidate Option B: tau_apex = 0.6500                      │
 │             Control Baseline:   tau_apex = 0.2800                      │
 │                                                                        │
 │           decision = (raw_prob >= tau_apex) ? MALICIOUS : BENIGN.      │
 └────────────────────────────────────────────────────────────────────────┘
```

### Detailed Structural Definitions & Edge Cases:

1. **Bare-Apex Invariant:**
   - Defined strictly as:
     $$\text{is\_bare\_apex} \iff (\text{clean\_path.strip("/")} == \text{""}) \land (\text{query.strip()} == \text{""}) \land (\text{\_subdomain\_depth}(\text{host}) == 0)$$
   - URLs with trailing slashes (e.g. `https://example.com/`) have `clean_path = ""` after strip, correctly satisfying the empty-path condition.
   - URLs with paths (e.g. `https://example.com/login`, `https://example.com/index.html`) have `clean_path != ""` and immediately route to standard scoring ($\tau = 0.2800$).
2. **IP Host Handling:**
   - Evaluated via `is_ip_host(host)`. While raw IP addresses have `_subdomain_depth == 0`, Tier 1A intercepts them immediately, forcing `final_prob >= 0.9500`. Raw IP URLs are **strictly ineligible** for bare-apex attenuation.
3. **Suspicious-TLD Invariant:**
   - Feature 63 (`idxSuspTld`) flags high-risk TLDs (`.zip`, `.mov`, `.top`, `.xyz`, `.click`, `.rest`, `.country`, etc.). Any flagged TLD triggers Tier 1C, bypassing all safe overrides.
4. **Registrable Domain Extraction Standard:**
   - All components must use the multi-label effective TLD rules defined in [`v8_normalization.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_normalization.py), which explicitly includes `"com.tr"`, `"co.uk"`, `"github.io"`, etc. The legacy 28-suffix table in `v7_features.py` is deprecated.
5. **Python vs. Kotlin Parity Specification:**
   - Normalization: Python `parse_v8_url` must match Kotlin `UrlCanonicalizer` bit-for-bit on host lowercase normalization, IPv6 bracket stripping, port removal, and trailing dot trimming.
   - Adjudication: Python [`v8_classifier.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_classifier.py) and Kotlin [`SafeDomainAdjudicator.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt) must evaluate the identical waterfall order and feature indices:
     - `idxBrandImp = 0`, `idxAt = 2`, `idxNestedUrl = 3`, `idxNonAscii = 4`, `idxPort = 5`, `idxPuny = 11`, `idxIsIp = 14`, `idxHttps = 15`, `idxSubdomain = 18`, `idxSlashes = 20`, `idxDoubleEnc = 23`, `idxSuspExt = 28`, `idxPathWords = 29`, `idxRedirect = 38`, `idxQueryWords = 39`, `idxSafeBrand = 60`, `idxSafeClean = 61`, `idxSuspTld = 63`.
   - Discrepancy Gate: Any divergence between Python and Kotlin outputs across the 174 golden fixtures or test partitions is a blocking defect.

---

## 4. Formal Acceptance & Gate Decision Policy

To resolve ambiguity regarding intermediate metric outcomes, a formal 3-tier acceptance policy is established.

### Gate Policy Taxonomy:
- **`PASS`:** The metric satisfies the strict pre-registered target. Eligible for promotion consideration.
- **`WARNING / CONDITIONAL REVIEW`:** The metric misses the primary target but remains within the pre-registered safety envelope (above the Hard Fail boundary).
  - *Action:* Automatically blocks autonomous promotion. Requires explicit human engineering review, full false-negative / false-positive root cause attribution, and written architectural justification.
- **`HARD FAIL`:** The metric crosses the hard-fail boundary.
  - *Action:* Immediate, unconditional prototype rejection. No promotion, release, or override permitted.

### Three-Tier Acceptance Gate Ledger

| Gate ID | Target Partition | Sample Size ($N$) | Metric Evaluated | PASS Zone (Target) | WARNING / REVIEW Zone | HARD FAIL Zone |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **Gate 1** | Clean Test Malicious | $23,158$ | Adjudicated Recall | **$\ge 98.600\%$** ($\ge 22,834$) | $[98.400\%, 98.600\%)$ ($22,788$ to $22,833$) | **$< 98.400\%$** ($< 22,788$ TPs) |
| **Gate 2** | Clean Test Benign | $27,353$ | Adjudicated FPR | **$\le 0.962\%$** ($\le 263$ FPs) | $(0.962\%, 1.000\%]$ ($264$ to $273$ FPs) | **$> 1.000\%$** ($> 273$ FPs) |
| **Gate 3** | Diagnostic Benchmark (Apex) | $200$ | Category 1 Apex FPR | **$\le 10.00\%$** ($\le 20$ FPs) | $(10.00\%, 15.00\%]$ ($21$ to $30$ FPs) | **$> 15.00\%$** ($> 30$ FPs) |
| **Gate 4** | Diagnostic Benchmark (Overall)| $500$ | Diagnostic Overall FPR| **$\le 45.00\%$** ($\le 225$ FPs)| $(45.00\%, 50.00\%]$ ($226$ to $250$ FPs) | **$> 50.00\%$** ($> 250$ FPs) |
| **Gate 5** | Clean Test Bare-Apex Phishing| $4,254$ | Bare-Apex Recall | **$\ge 98.000\%$** ($\ge 4,169$) | $[97.500\%, 98.000\%)$ ($4,148$ to $4,168$) | **$< 97.500\%$** ($< 4,148$ TPs) |
| **Gate 6** | Remediation Adversarial | $3,900$ | Adversarial Recall | **$\ge 97.000\%$** ($\ge 3,783$) | $[96.500\%, 97.000\%)$ ($3,764$ to $3,782$) | **$< 96.500\%$** ($< 3,764$ TPs) |
| **Gate 7** | Android Golden Fixtures | $174$ | Golden Regressions | **EXACTLY 0 REGRESSIONS** | *NO WARNING ZONE PERMITTED* | **$\ge 1$ REGRESSION** |

### Evaluation Integrity & Promotion Requirements:
1. **Diagnostic Benchmark v1.0 ($N = 500$):** Labeled strictly as **Development & Diagnostic Reference Data**. Under no circumstances may passing Gates 3 and 4 on this dataset be cited as proof of production generalization.
2. **Clean Test Split ($N = 50,511$):** Labeled as an **Internal Regression Benchmark**. Passing Gate 5 confirms regression recovery on known historical lures, but does not prove generalization on unseen apex attacks.
3. **Mandatory Production Promotion Gate (Phase 1D.3):** Promotion of any candidate into production or Android assets is strictly blocked until evaluated on **Fresh, Blind, Independently Sourced Data**:
   - $\ge 10,000$ fresh benign bare-apex domains gathered from recent Tranco / CrUX top lists.
   - $\ge 2,500$ fresh malicious bare-apex URLs gathered from live feeds (URLHaus, OpenPhish).

---

## 5. Phase 1D.1 Single-Variable Ablation Experiment Matrix

To prevent the compounding confounding variables that caused the failure of Phase 1C.2B-2A-S2-E, Phase 1D.1 must test each rule, dictionary, and threshold in complete isolation before any combination is evaluated.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        PHASE 1D.1 ISOLATED ABLATION MATRIX                             │
├─────────┬───────────────────────────────┬─────────────────────────────┬────────────────┤
│ Run ID  │ Experimental Variable Tested  │ Base HistGBM Model Binary   │ Operating Mode │
├─────────┼───────────────────────────────┼─────────────────────────────┼────────────────┤
│ 1D.1-A0 │ Frozen Control Baseline       │ v8_champion.joblib (073e70) │ tau = 0.2800   │
│ 1D.1-A1 │ Candidate Threshold tau=0.5500│ v8_champion.joblib (073e70) │ Apex tau=0.5500│
│ 1D.1-A2 │ Candidate Threshold tau=0.6500│ v8_champion.joblib (073e70) │ Apex tau=0.6500│
│ 1D.1-B1 │ Brand Dictionary Expansion    │ v8_champion.joblib (073e70) │ 16 tokens only │
│ 1D.1-B2 │ Curated Safe Roots Expansion  │ v8_champion.joblib (073e70) │ Domain list    │
│ 1D.1-B3 │ Reputation Top-100k (Cand.)   │ v8_champion.joblib (073e70) │ Tranco filter  │
│ 1D.1-C1 │ Combined Adjudication v1      │ v8_champion.joblib (073e70) │ B1 + B2 + A1   │
│ 1D.1-C2 │ Combined Adjudication v2      │ v8_champion.joblib (073e70) │ B1 + B2 + A2   │
└─────────┴───────────────────────────────┴─────────────────────────────┴────────────────┘
```

### Protocol Execution Constraints for Phase 1D.1:
1. **Zero Retraining:** Every single run operates against the frozen production model binary `v8_champion.joblib` (`073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`).
2. **Zero Production Edits:** All prototyping scripts and evaluation runners must execute in an isolated experiment directory (`experiments/phase_1d_1/`).
3. **Stepwise Evaluation:** Runs `1D.1-A1` through `1D.1-B3` must be evaluated and analyzed individually to record the exact delta attributable to each single change before the combined candidates (`1D.1-C1` and `1D.1-C2`) are evaluated.

---

## 6. Verification of Invariant Status

Before concluding Phase 1D.0.1, the complete workspace status was audited:
- **Model Training Executed:** Exactly **0** training epochs or fitting procedures.
- **Model Inference Executed:** Exactly **0** inference calls or prediction computations.
- **Production Code Modified:** Exactly **0** lines modified in `sentinel-ml/URL-ml/scripts/` or `sentinel-ai/android-app/`.
- **Git Tracking State:** Verified invariant. The `sentinel-ai` git repository contains the identical **90 short status entries** ($50\text{ M}$, $11\text{ D}$, $29\text{ ??}$) observed at all checkpoints since Phase 1C.2B-2A-S2-E began. Zero git staging, committing, resetting, or checkout operations occurred.

---

## 7. Stop Condition & Governance Recommendation

Phase 1D.0.1 has resolved all artifact provenance questions, unified the adjudication specification, formalized a strict 3-tier acceptance policy, and laid out an isolated ablation matrix.

**Execution is halted.** No code changes, prototyping, or evaluation will begin until explicitly authorized by the user for **Phase 1D.1**.
