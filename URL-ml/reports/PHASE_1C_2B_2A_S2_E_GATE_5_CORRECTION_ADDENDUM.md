# Sentinel — Phase 1C.2B-2A-S2-E: Gate 5 Correction and Forensic Reconciliation Addendum

> **Document Type:** Read-Only Forensic Addendum to Phase 1C.2B-2A-S2-E  
> **Status:** **`CORRECTED — FAIL`** *(Under read-only model binary inference)* / **`UNVERIFIABLE WITHOUT NEW INFERENCE`** *(Under strict on-disk prediction artifact isolation)*  
> **Candidate Final Decision:** **`REJECTED — NOT PROMOTED`**  
> **Governing Baseline:** V8 Champion (`073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`) remains invariant  
> **Historical Record Integrity:** All prior reports ([`PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md) and [`PHASE_1C_2B_2A_S2_E_CLOSURE_AUDIT_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1C_2B_2A_S2_E_CLOSURE_AUDIT_REPORT.md)) are strictly preserved without alteration.

---

## 1. Executive Summary & Governance Status

This forensic addendum resolves the Phase 1C.2B-2A-S2-E Gate 5 evaluation discrepancy identified during the read-only closure audit.

```
════════════════════════════════════════════════════════════════════════════════
             GATE 5 STATUS: CORRECTED — FAIL (HARD FAIL)
            OVERALL CANDIDATE DECISION: REJECTED — NOT PROMOTED
════════════════════════════════════════════════════════════════════════════════
```

### Key Reconciliations Established:
1. **Gate 5 Denominator Distortion Explained:** The protocol script evaluated `_subdomain_depth` on the parsed `parent_domain` rather than `host`. Because `parent_domain` is already an effective top-level domain plus one label (eTLD+1), its subdomain depth is always $0$, unintentionally inflating the evaluation set from the intended bare-apex malicious cohort to almost the entirety of the malicious test set ($N = 23,078$ out of $23,158$).
2. **Resolution of $N = 4,254$ vs $N = 4,217$:** The 37-record discrepancy is mathematically proven to stem from a dictionary divergence between `v8_normalization.TWO_LABEL_SUFFIXES` (33 suffixes, which includes `"com.tr"`) and `v7_features.TWO_LABEL_SUFFIXES` (28 suffixes, which omitted `"com.tr"`). All 37 differing URLs are `.com.tr` bare-apex phishing domains. Under authoritative V8 normalization (used in Track A), the true intended bare-apex cohort size is **$N = 4,254$**. Under legacy V7 feature extractor helper logic, it is **$N = 4,217$**.
3. **Dual Verification of Gate 5 Outcome:**
   - **Strict Saved-Artifact Rule:** Because per-URL probability arrays were deleted from memory before serializing `s2_e_execution_metrics.json`, no raw test prediction CSV exists on disk. From saved serialized predictions alone, Gate 5 is **`UNVERIFIABLE WITHOUT NEW INFERENCE`**.
   - **Read-Only Model Binary Forensic Inference:** Executing read-only inference with the frozen, unaltered model binaries (`control_model_reproduced.joblib`, `candidate_balanced_repaired_model.joblib`, and `v8_champion.joblib`) reveals that Candidate A1 achieves only **$93.912\%$ recall** ($3,995 / 4,254$) on the intended cohort, suffering a $-4.114\text{ pp}$ recall loss ($+175$ false negatives) against C0 / V8 ($98.025\%$).
   - Because $93.912\% < 95.00\%$, Candidate A1 **fails Gate 5 as a HARD_FAIL** under both cohort definitions.
4. **Resolution of 100 vs 174 Golden Fixtures:** The Android golden fixture file [`golden_urls_v8.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/test/resources/golden_urls_v8.json) contains exactly **174** URLs ($88$ benign, $86$ malicious). All 174 were evaluated during S2-E ($85 \text{ TN} + 3 \text{ FP} + 5 \text{ FN} + 81 \text{ TP} = 174$), producing exactly **8 regressions** ($3 \text{ FP} + 5 \text{ FN}$). The conversational mention of "100 golden URLs" was an errant transcription slip conflating "100% parity" with the fixture count.

---

## 2. Root Cause of Gate 5 Denominator Distortion

In [`run_balanced_experiment_protocol_repaired.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/run_balanced_experiment_protocol_repaired.py#L424-L428), Gate 5 was constructed as follows:

```python
# Protocol line 424:
apex_mask = np.array([
    _subdomain_depth(parse_v8_url(u).parent_domain or "") == 0 and y_test[i] == 1 
    for i, u in enumerate(test_urls)
])
sub_apex_urls = [test_urls[i] for i in range(len(test_urls)) if apex_mask[i]]
y_sub_apex = y_test[apex_mask]
X_sub_apex = X_test[apex_mask]
m_res["test_subgroup_malicious_apex"] = evaluate_model_on_corpus(clf, sub_apex_urls, y_sub_apex, X_sub_apex)
```

### Forensic Analysis of the Mask Implementation:
1. `parse_v8_url(u).parent_domain` extracts the registrable domain (e.g., `evil.example.com` $\rightarrow$ `example.com`).
2. `_subdomain_depth(host)` computes:
   $$\text{depth} = \max(0, \text{len}(\text{labels}) - \text{suffix\_size} - 1)$$
3. When passed `parent_domain` (`example.com`), $\text{len}(\text{labels}) = 2$ and $\text{suffix\_size} = 1$, giving $2 - 1 - 1 = 0$.
4. Consequently, `_subdomain_depth(parent_domain)` evaluates to $0$ for **every valid domain**, regardless of how many subdomains the original URL possessed.
5. Out of the $23,158$ malicious URLs in `test_df`, exactly $23,078$ had a non-empty `parent_domain` (the remaining $80$ were malformed URLs or raw IP addresses without a registrable domain).
6. Thus, Gate 5 was evaluated against almost the entire malicious test partition ($N = 23,078$) instead of the intended bare-apex subgroup.

---

## 3. Discrepancy Resolution: $N = 4,254$ vs $N = 4,217$

During preflight and prior phases, two different cohort numbers appeared in documentation:
- Preflight & Track A reports: $N = 4,254$
- Closure audit forensic check: $N = 4,217$
- Discrepancy: Exactly **37 URLs** ($4,254 - 4,217 = 37$).

### Source Data and Implementation Audit:
A full comparison of the two filtering expressions on the frozen `test_df` ($50,511$ rows, $23,158$ malicious) was performed:

| Expression | Code Location | Resulting Count |
| :--- | :--- | :---: |
| `len(parse_v8_url(u).subdomain_labels) == 0 and y_test[i] == 1` | `run_track_a_experiment.py` (Line 268) | **$4,254$** |
| `_subdomain_depth(parse_v8_url(u).host) == 0 and y_test[i] == 1` | `v7_features.py` helper applied to host | **$4,217$** |

### Root Cause of the 37-URL Divergence:
Isolating the 37 differing URLs revealed that **100% of them belong to the Turkish second-level country-code TLD (`.com.tr`)**:
- Example 1: `http://haydi-bakalim-900tl-kampanyamiz-online.com.tr/`
- Example 2: `http://acikdenizv4.com.tr/`
- Example 3: `https://fiz.com.tr/.polski/.dpdpl/card.php`
- Example 4: `https://monotime.com.tr/bconline/`
- Example 5: `https://noodleking.com.tr/wells/auth/login/present.php`

```
Differing suffixes breakdown: {'com.tr': 37}
Total differing URLs: 37
```

### Explaining the Mechanism:
- In [`v8_normalization.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_normalization.py#L22-L28), `TWO_LABEL_SUFFIXES` contains 33 multi-label public suffixes, explicitly including `"com.tr"`. For `acikdenizv4.com.tr`, `parse_v8_url` identifies `com.tr` as a 2-label suffix, sets `parent_domain = "acikdenizv4.com.tr"`, finds `host == parent_domain`, and assigns `subdomain_labels = []` (length 0). This correctly identifies it as a **bare-apex domain**.
- In [`v7_features.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v7_features.py#L35-L40), `TWO_LABEL_SUFFIXES` was an older hardcoded table of 28 suffixes that **omitted** `"com.tr"`. Consequently, `_suffix_size` returned $1$ instead of $2$. For `acikdenizv4.com.tr` (3 labels), `_subdomain_depth` computed $3 - 1 - 1 = 1$, misclassifying the apex domain as having a subdomain.

### Intended Cohort Determination:
The project's architectural normalization standard is V8 Normalization ([`v8_normalization.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_normalization.py)). Therefore:
- The authoritative intended bare-apex denominator is **$N = 4,254$**.
- The value $4,217$ is an artifact of using the legacy V7 feature extractor helper with an incomplete suffix list.
- Both cohorts were evaluated to ensure total transparency.

---

## 4. Side-by-Side Metric Reconciliation

### 4.1 Saved Prediction Artifacts vs. Model Binary Inference
- **Saved Predictions Check:** In `execute_s2_e_protocol.py` (lines 295 & 377), `del cand_res["_raw_probs"]` and `del cand_res["_final_probs"]` were executed prior to saving `s2_e_execution_metrics.json`. No standalone URL-level prediction file for the test split was persisted to disk. Under strict artifact-only governance, Gate 5 is **`UNVERIFIABLE WITHOUT NEW INFERENCE`**.
- **Frozen Binary Inference:** To satisfy forensic completeness, read-only inference was executed in memory using the frozen, unaltered model binaries saved in `experiments/phase_1c_2b_2a_s2_f/`:
  - Control Model C0: `control_model_reproduced.joblib` (`d3816ac3...`)
  - Candidate Model A1: `candidate_balanced_repaired_model.joblib` (`ff8d45ae...`)
  - Frozen V8 Champion: `v8_champion.joblib` (`073e70f2...`)

### 4.2 Comprehensive Side-by-Side Comparison

| Metric / Cohort | Original Reported (Errant Mask) | Corrected Intended Cohort (V8 Normalization) | Corrected Legacy Cohort (V7 Host Helper) | Pre-Registered Gate 5 Specification |
| :--- | :---: | :---: | :---: | :---: |
| **Cohort Definition** | `_subdomain_depth(parent_domain)==0` | `len(subdomain_labels)==0` | `_subdomain_depth(host)==0` | Test bare-apex phishing URLs |
| **Cohort Size ($N$)** | **$23,078$** | **$4,254$** | **$4,217$** | Expected $N = 4,254$ |
| **V8 Champion TPs (Recall)** | $22,760$ ($98.622\%$) | $4,170$ ($98.025\%$) | $4,138$ ($98.127\%$) | Baseline: $98.025\%$ ($4,170$) |
| **C0 Control TPs (Recall)** | $22,760$ ($98.622\%$) | $4,170$ ($98.025\%$) | $4,138$ ($98.127\%$) | 100% baseline parity |
| **Candidate A1 TPs (Recall)** | $22,514$ ($97.556\%$) | $3,995$ ($93.912\%$) | $3,963$ ($93.977\%$) | **Target:** $\ge 96.00\%$ ($\ge 4,084$)<br>**Hard Fail:** $< 95.00\%$ ($< 4,042$) |
| **Candidate False Negatives** | $564$ | **$259$** | **$254$** | Pre-reg limit: $\le 170$ FNs |
| **New FNs vs C0 Baseline** | $+246$ | **$+175$** | **$+175$** | Candidate misses 175 more apex URLs |
| **$\Delta \text{Recall}$ (Cand vs C0)** | $-1.066\text{ pp}$ | **$-4.114\text{ pp}$** | **$-4.150\text{ pp}$** | Severe degradation |
| **Raw Prob Recall (Pre-Adj)** | $97.508\%$ ($22,503 / 23,078$) | $93.865\%$ ($3,993 / 4,254$) | $93.929\%$ ($3,961 / 4,217$) | Pre-adjudication raw score |
| **Gate 5 Verdict** | *Errant execution ($97.56\%$)* | **HARD_FAIL** ($93.91\% < 95.00\%$) | **HARD_FAIL** ($93.98\% < 95.00\%$) | **`CORRECTED — FAIL`** |

### 4.3 Trajectory Across Candidate Iterations:
- **Baseline V8 / C0:** $4,170 / 4,254 = \mathbf{98.025\%}$ ($84$ FNs)
- **Track A Candidate (Benign-only 15k):** $3,916 / 4,254 = \mathbf{92.055\%}$ ($338$ FNs, $+254$ new FNs)
- **Candidate A1 (Balanced S2-E):** $3,995 / 4,254 = \mathbf{93.912\%}$ ($259$ FNs, $+175$ new FNs)
- **Analysis:** While Candidate A1 recovered 79 true positives compared to Track A ($3,995$ vs $3,916$), it remains severely degraded compared to production baseline V8 ($-4.114\text{ pp}$ recall loss, missing 175 additional real malicious bare-apex URLs). It fails the pre-registered Gate 5 hard threshold ($95.00\%$) by **$1.088$ percentage points**.

---

## 5. Resolution of 100-versus-174 Golden Fixture Wording

Task 6 requested resolving the wording discrepancy regarding 100 versus 174 golden fixtures:

1. **Authoritative Fixture File Audit:**
   - File: [`android-app/core/src/test/resources/golden_urls_v8.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/test/resources/golden_urls_v8.json)
   - Size: 61,041 bytes
   - Total JSON items: Exactly **174 records**
   - Class breakdown: **88 Benign URLs**, **86 Malicious URLs**
2. **Evaluation Metrics JSON Audit:**
   - In `s2_e_execution_metrics.json`:
     ```json
     "golden_fixtures": {
       "adjudicated_scores": {
         "n_total": 174,
         "n_benign": 88,
         "n_malicious": 86,
         "tn": 85,
         "fp": 3,
         "fn": 5,
         "tp": 81
       },
       "regressions_count": 8
     }
     ```
   - Total samples: $85 + 3 + 5 + 81 = 174$.
   - Regressions: $3 \text{ FP} + 5 \text{ FN} = 8$ regressions out of **174** ($4.60\%$ regression error rate).
3. **Origin of "100":**
   - In conversational summaries, the phrase "8 regressions out of 100 golden URLs" appeared as a human typographical slip conflating "100% parity target" with the sample size.
   - All written report tables ([`PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1C_2B_2A_S2_E_EXPERIMENT_REPORT.md#L122) and [`PHASE_1C_2B_2A_S2_R_RECONCILIATION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1C_2B_2A_S2_R_RECONCILIATION_REPORT.md#L179)) correctly documented $N = 174$. The ground truth fixture count is conclusively **174**.

---

## 6. Final Comprehensive Gate Matrix (Corrected)

| Gate | Description | Denominator ($N$) | Pre-Reg Target | C0 Control | Candidate A1 | Corrected Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Gate 1** | Clean Test Malicious Recall | $23,158$ | $\ge 98.200\%$ | $98.605\%$ | $97.543\%$ | **HARD_FAIL** |
| **Gate 2** | Clean Test Benign FPR | $27,353$ | $\le 1.000\%$ | $0.962\%$ | $0.885\%$ | **PASS** |
| **Gate 3** | Benchmark v1.0 Bare-Apex FPR | $200$ | $\le 6.00\%$ | $100.00\%$ | $14.50\%$ | **HARD_FAIL** |
| **Gate 4** | Benchmark v1.0 Overall FPR | $500$ | $\le 46.00\%$ | $84.00\%$ | $39.20\%$ | **PASS** |
| **Gate 5** | **Test Bare-Apex Phishing Recall** | **$4,254$** | **$\ge 96.00\%$** | **$98.025\%$** | **$93.912\%$** | **HARD_FAIL** *(Corrected)* |
| **Gate 6** | Remediation Adversarial Recall | $3,900$ | $\ge 96.50\%$ | $97.051\%$ | $96.513\%$ | **PASS** |
| **Gate 7** | Android Golden Parity | $174$ | $0$ regressions | $0$ regressions | $8$ regressions | **HARD_FAIL** |

---

## 7. Required Governance Conclusion

Under the pre-registered protocol evaluation criteria and the forensic evidence:

```
════════════════════════════════════════════════════════════════════════════════
GATE 5 VERDICT:
  - Artifact-only rule: UNVERIFIABLE WITHOUT NEW INFERENCE
  - Read-only model binary inference: CORRECTED — FAIL (93.912% < 95.000% Hard Fail)

OVERALL CANDIDATE VERDICT:
  REJECTED — NOT PROMOTED (Invariant)
════════════════════════════════════════════════════════════════════════════════
```

1. **Gate 5 Status:** Candidate A1 achieved **$93.912\%$ recall** on the $4,254$ bare-apex phishing cohort, severely violating the pre-registered Gate 5 target ($\ge 96.00\%$) and falling into the Hard Fail zone ($< 95.00\%$). Under model binary inference, Gate 5 is conclusively **`CORRECTED — FAIL`**.
2. **Production Impact:** Correcting Gate 5 further solidifies the rejection of Candidate A1. The balanced bare-apex candidate failed 4 out of 7 pre-registered gates (Gates 1, 3, 5, and 7).
3. **Model Promotion Status:** Candidate A1 is **REJECTED — NOT PROMOTED**.
4. **Production Baseline:** Champion V8 (`073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`) remains the sole authorized production model.
5. **Phase Status:** Complete. Awaiting further stakeholder authorization.
