# Sentinel — Phase 1D.1-A0/A1/A2: Isolated Apex-Threshold Prototype Report

> **Document Type:** Isolated Stage 1 Experiment Report  
> **Phase:** 1D.1-A0/A1/A2 (Isolated Bare-Apex Threshold Policy Evaluation)  
> **Status:** **STAGE 1 COMPLETE — APEX THRESHOLD MODULATION ALONE PROVEN INSUFFICIENT**  
> **Governing Baseline:** V8 Champion (`073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`) remains invariant  
> **Experiment Directory:** `sentinel-ml/URL-ml/experiments/phase_1d_1/`  
> **Git Tracking State:** Verified invariant (90 short status entries, zero git mutations)  

---

## 1. Executive Summary & Core Empirical Verdict

Phase 1D.1-A0/A1/A2 evaluated the isolated effect of modulating the operating threshold specifically for bare-apex URLs with empty paths and queries ($\tau_{\text{apex}} = 0.5500$ in A1, $\tau_{\text{apex}} = 0.6500$ in A2), compared directly against the frozen V8 Champion control baseline ($\tau = 0.2800$ in A0). 

To eliminate confounding variables, **zero model retraining, zero brand-dictionary changes, zero safe-root whitelists, and zero heuristic overrides were introduced**. All three policies operated on the exact same frozen probability predictions produced by the unaltered V8 Champion model binary.

```
════════════════════════════════════════════════════════════════════════════════
                     PHASE 1D.1 STAGE 1 CORE VERDICT:
     NAIVE APEX THRESHOLD MODULATION ALONE FAILS TO RESOLVE BARE-APEX FPS
════════════════════════════════════════════════════════════════════════════════
```

### The Primary Empirical Discoveries:
1. **Benign Bare-Apex Probability Saturation:**
   The fundamental reason threshold shifting fails is that V8 Champion's raw probabilities on legitimate bare-apex domains do not cluster near the decision boundary ($\tau = 0.2800$). Across the 200 hard-benign bare-apex benchmark domains:
   - The **median predicted probability is $0.9367$** (mean: $0.9161$).
   - **$73.5\%$ of legitimate domains (147 / 200)** receive probabilities $\ge 0.9000$.
   - **$98.5\%$ of legitimate domains (197 / 200)** receive probabilities $\ge 0.6500$.
   - Raising $\tau_{\text{apex}}$ to $0.5500$ (A1) or $0.6500$ (A2) eliminates **only 3 false positives out of 200** (`auth0.io`, `theverge.com`, `archive.org`), leaving a catastrophic **$98.50\%$ false-positive rate** (Gate 3 Hard Fail).
2. **Immediate Malicious Recall Degradation:**
   While threshold shifting fails to suppress benign false positives, it immediately degrades malicious recall on real bare-apex phishing lures:
   - **Policy A1 ($\tau_{\text{apex}} = 0.5500$):** Misses 1 phishing lure in Clean Test (`https://irsstimuluscheckeligibility.site`, $p = 0.5180$) and misses 3 phishing attacks in the Adversarial split, pushing Gate 6 into `WARNING_REVIEW` ($96.974\%$).
   - **Policy A2 ($\tau_{\text{apex}} = 0.6500$):** Misses 3 phishing lures in Clean Test (`irsstimuluscheckeligibility.site`, `lnicioerlineaennpresasscoltiaperu.com`, `spk-kundenserrvice-prozess.de`), pushing Gate 1 ($98.592\%$) and Gate 5 ($97.955\%$) into `WARNING_REVIEW`.
   - **Gate 7 Hard Fail under A2:** A2 causes **1 regression on the Android Golden Fixtures** (`https://github.com`, $p = 0.5674$, which flips from malicious to benign), triggering an immediate Hard Fail.
3. **Strategic Conclusion:**
   Adjusting the scalar decision threshold in the absence of domain-level entity or reputation signals is mathematically incapable of separating bare-apex domains. This definitively validates the Phase 1D.0 architecture: false-positive reduction requires **Tier 3 (Safe Brand Matching)** and **Tier 4 (Curated Safe Roots)** rather than threshold manipulation.

---

## 2. Input and Output Provenance Ledger

### 2.1 Input File Verification
Before running inference, all input files were hashed and confirmed against authoritative records:

| Artifact Name | Path | Size | SHA-256 Checksum | Verification Status |
| :--- | :--- | :---: | :--- | :---: |
| **`v8_champion`** | `sentinel-ml/URL-ml/models/v8_champion.joblib` | 709,417 B | `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58` | **VERIFIED INVARIANT** |
| **`cleaned_dataset`** | `sentinel-ml/URL-ml/data/cleaned_dataset.csv` | 18,767,734 B | `6c71c39dd0291b8ef58b31610ac892cd6fe2186876908d42a7b24dcbf06caf2f` | **VERIFIED** |
| **`hard_benchmark`** | `sentinel-ml/URL-ml/data/hard_benign_benchmark_500.json` | 222,523 B | `d89f532ce8a5f5c35251622cc80dacdcf1318bda62cbf45d88deb6ba7456520f` | **VERIFIED** |
| **`adv_predictions`** | `sentinel-ml/URL-ml/reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv` | 336,391 B | `a729e2cd9978f1b9632ed19079c957933ee2ca0d9c54853b1dc5321ce12cff5a` | **VERIFIED** |
| **`golden_urls_v8`** | `sentinel-ai/android-app/core/src/test/resources/golden_urls_v8.json` | 205,103 B | `47dde6e5837a1b91da6e224a0f85dad75694f0f1a12aad11d7576d48f6a1aacb` | **VERIFIED** |

### 2.2 Output Artifacts Created in `experiments/phase_1d_1/`
All evaluation results and frozen probability arrays were serialized to disk:

| Output Artifact | Size | SHA-256 Checksum | Description |
| :--- | :---: | :--- | :--- |
| **`clean_test_predictions_v8.csv`** | 3,642,657 B | `e6018a61afba840f6e5b047df1323f1c0e1d3fa580f322bae4877e0a694d7351` | Complete URL-level raw and adjudicated predictions ($N = 50,511$) |
| **`benchmark_predictions_v8.csv`** | 53,807 B | `eb3b78d1b7bf3b16f9ce69e91c82a2140eae6bffd9702b9d339c4e66addf0498` | Benchmark v1.0 raw and adjudicated predictions with categories ($N = 500$) |
| **`adversarial_predictions_v8.csv`**| 304,486 B | `2c6a3be102d24d03b85b18477247544d236f0318b0a6ce5510b2318d9bcfc891` | Adversarial split predictions ($N = 3,900$) |
| **`golden_predictions_v8.csv`** | 16,341 B | `07c89fcaf178ba5ada532ca821439769b0dac41c8b568f8f49772332dd26cd3c` | Android golden fixtures predictions ($N = 174$) |
| **`decision_changes_a0_a1_a2.csv`** | 1,984 B | `76ed055e957eca1c1c0f4d733b7132f94939a7fb1cb478fc4c822c38ef025d42` | Complete audit of all 12 decision flips across all corpora |
| **`phase_1d_1_a0_a1_a2_metrics.json`**| 27,166 B | `330c1ddadeaff23883a54960ba0b869b7bce3bc7fe31329f7cb2ce94741e1b8a` | Machine-readable metrics, confusion matrices, and gate verdicts |
| **`run_phase_1d_1_a0_a1_a2.py`** | 30,343 B | `89217bf8e22a0ab955032abecfc079e04a6fbc845196323ec04e0390c6d8978b` | Standalone executable evaluation runner script |

---

## 3. Policy Specification & Bare-Apex Qualification

The evaluation compared three deterministic policies using identical frozen probabilities:

```
┌────────────────────────────────────────────────────────────────────────┐
│ A0 (Control Baseline):                                                 │
│   All URLs evaluate at standard threshold: tau = 0.2800.                │
├────────────────────────────────────────────────────────────────────────┤
│ A1 (Candidate 1):                                                      │
│   • Qualified Bare Apex: tau_apex = 0.5500                             │
│   • All other URLs:      tau_std  = 0.2800                             │
├────────────────────────────────────────────────────────────────────────┤
│ A2 (Candidate 2):                                                      │
│   • Qualified Bare Apex: tau_apex = 0.6500                             │
│   • All other URLs:      tau_std  = 0.2800                             │
└────────────────────────────────────────────────────────────────────────┘
```

### Exact Bare-Apex Qualification Filter:
Under V8 Normalization ([`v8_normalization.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_normalization.py)), a URL qualifies for candidate bare-apex thresholding if and only if **all five conditions are met**:
1. **IP Host Exclusion:** `p.is_ip == False` and `feat_vec[idx_is_ip] == 0.0`. (IP hosts are strictly excluded).
2. **Suspicious TLD Exclusion:** `feat_vec[idx_susp_tld] == 0.0` and `tld not in SUSPICIOUS_TLDS`. (High-risk TLDs like `.zip`, `.mov`, `.top`, `.xyz` are strictly excluded).
3. **Empty Clean Path:** `p.clean_path.strip("/") == ""`. (Any path segment routes the URL to standard $\tau = 0.2800$).
4. **Empty Query:** `p.query.strip() == ""`. (Any query string routes the URL to standard $\tau = 0.2800$).
5. **Zero Subdomain Depth:** `len(p.subdomain_labels) == 0`. (Uses authoritative multi-label public suffix normalization including `.com.tr`, `.co.uk`, `.github.io`).

---

## 4. Master Evaluation Results & Pre-Registered Gate Status

All metrics evaluated against the formal 3-tier acceptance policy established in Phase 1D.0.1:

| Gate ID | Target Partition | Size ($N$) | Evaluation Metric | Policy A0 Baseline (tau=0.28) | Policy A1 Candidate (tau=0.55) | Policy A2 Candidate (tau=0.65) | Gate Policy Criteria |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| **Gate 1** | Clean Test Malicious | $23,158$ | Recall | **$98.605\%$** ($22,835$) <br>**PASS** | **$98.601\%$** ($22,834$) <br>**PASS** | **$98.592\%$** ($22,832$) <br>**WARNING_REVIEW** | Target: $\ge 98.600\%$<br>Warn: $[98.400\%, 98.600\%)$<br>Fail: $< 98.400\%$ |
| **Gate 2** | Clean Test Benign | $27,353$ | FPR | **$0.962\%$** ($263$) <br>**PASS** | **$0.962\%$** ($263$) <br>**PASS** | **$0.962\%$** ($263$) <br>**PASS** | Target: $\le 0.962\%$<br>Warn: $(0.962\%, 1.000\%]$<br>Fail: $> 1.000\%$ |
| **Gate 3** | Benchmark (Bare Apex) | $200$ | Category 1 FPR | **$100.00\%$** ($200$) <br>**HARD_FAIL** | **$98.50\%$** ($197$) <br>**HARD_FAIL** | **$98.50\%$** ($197$) <br>**HARD_FAIL** | Target: $\le 10.00\%$<br>Warn: $(10.00\%, 15.00\%]$<br>Fail: $> 15.00\%$ |
| **Gate 4** | Benchmark (Overall) | $500$ | Overall FPR | **$84.00\%$** ($420$) <br>**HARD_FAIL** | **$83.40\%$** ($417$) <br>**HARD_FAIL** | **$83.40\%$** ($417$) <br>**HARD_FAIL** | Target: $\le 45.00\%$<br>Warn: $(45.00\%, 50.00\%]$<br>Fail: $> 50.00\%$ |
| **Gate 5** | Test Phishing Apex | $4,254$ | Bare-Apex Recall | **$98.025\%$** ($4,170$) <br>**PASS** | **$98.002\%$** ($4,169$) <br>**PASS** | **$97.955\%$** ($4,167$) <br>**WARNING_REVIEW** | Target: $\ge 98.000\%$<br>Warn: $[97.500\%, 98.000\%)$<br>Fail: $< 97.500\%$ |
| **Gate 6** | Remediation Adversarial | $3,900$ | Adversarial Recall | **$97.051\%$** ($3,785$) <br>**PASS** | **$96.974\%$** ($3,782$) <br>**WARNING_REVIEW** | **$96.923\%$** ($3,780$) <br>**WARNING_REVIEW** | Target: $\ge 97.000\%$<br>Warn: $[96.500\%, 97.000\%)$<br>Fail: $< 96.500\%$ |
| **Gate 7** | Android Golden Fixtures | $174$ | Regressions | **0 Regressions** <br>**PASS** | **0 Regressions** <br>**PASS** | **1 Regression** <br>**HARD_FAIL** | Target: 0 regressions<br>Fail: $\ge 1$ regression |
| **OVERALL**| **Pre-Registered Verdict**| — | — | **HARD_FAIL** (Gates 3, 4) | **HARD_FAIL** (Gates 3, 4) | **HARD_FAIL** (Gates 3, 4, 7) | Any Hard Fail blocks promotion |

---

## 5. Comprehensive Audit of All 12 Decision Changes

Every single URL across all evaluation datasets where A1 or A2 produced a different binary prediction from A0 is documented below:

### Complete Decision Changes Ledger (`decision_changes_a0_a1_a2.csv`)

| Dataset | Record ID | Target URL | True Label | Raw Prob | A0 (tau=0.28) | A1 (tau=0.55) | A2 (tau=0.65) | Impact of Policy A1 | Impact of Policy A2 |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| **Clean Test** | `test_41235` | `https://lnicioerlineaennpresasscoltiaperu.com` | MALICIOUS | `0.5541` | MALICIOUS | MALICIOUS | **BENIGN** | No Change | **TP Lost (New FN)** |
| **Clean Test** | `test_43347` | `https://spk-kundenserrvice-prozess.de` | MALICIOUS | `0.5603` | MALICIOUS | MALICIOUS | **BENIGN** | No Change | **TP Lost (New FN)** |
| **Clean Test** | `test_49963` | `https://irsstimuluscheckeligibility.site` | MALICIOUS | `0.5180` | MALICIOUS | **BENIGN** | **BENIGN** | **TP Lost (New FN)** | **TP Lost (New FN)** |
| **Benchmark** | `bench_037` | `https://auth0.io` | BENIGN | `0.5386` | MALICIOUS | **BENIGN** | **BENIGN** | **FP Eliminated** | **FP Eliminated** |
| **Benchmark** | `bench_148` | `https://theverge.com` | BENIGN | `0.4796` | MALICIOUS | **BENIGN** | **BENIGN** | **FP Eliminated** | **FP Eliminated** |
| **Benchmark** | `bench_160` | `https://archive.org` | BENIGN | `0.4842` | MALICIOUS | **BENIGN** | **BENIGN** | **FP Eliminated** | **FP Eliminated** |
| **Adversarial**| `adv_3002` | `HTTPS://SABADONOAPPMAGAZINE.COM/` | MALICIOUS | `0.3252` | MALICIOUS | **BENIGN** | **BENIGN** | **TP Lost (New FN)** | **TP Lost (New FN)** |
| **Adversarial**| `adv_3112` | `HTTP://SHEINAAPP.COM` | MALICIOUS | `0.6216` | MALICIOUS | MALICIOUS | **BENIGN** | No Change | **TP Lost (New FN)** |
| **Adversarial**| `adv_3137` | `HTTP://SMARTDAPPSAUTHONLINE.COM` | MALICIOUS | `0.4387` | MALICIOUS | **BENIGN** | **BENIGN** | **TP Lost (New FN)** | **TP Lost (New FN)** |
| **Adversarial**| `adv_3186` | `HTTP://ETHEREUM-CHE.COM` | MALICIOUS | `0.6478` | MALICIOUS | MALICIOUS | **BENIGN** | No Change | **TP Lost (New FN)** |
| **Adversarial**| `adv_3241` | `HTTP://LAVOZDELOSCENTAUROS.COM/` | MALICIOUS | `0.4473` | MALICIOUS | **BENIGN** | **BENIGN** | **TP Lost (New FN)** | **TP Lost (New FN)** |
| **Golden Fix** | `v8_gold_0014`| `https://github.com` | MALICIOUS* | `0.5674` | MALICIOUS | MALICIOUS | **BENIGN** | No Change (Pass) | **Regression (Hard Fail)**|

*\*Note on `v8_gold_0014`:* In the Android golden fixture `golden_urls_v8.json`, `https://github.com` captures baseline V8's raw model output ($p = 0.5674 \ge 0.28$) as a regression baseline. When A2 sets $\tau_{\text{apex}} = 0.6500$, `github.com` flips from malicious to benign, triggering a regression against the frozen golden baseline.

---

## 6. Detailed Analysis of the Probability Saturation Phenomenon

To explain why moving the threshold to $0.5500$ and $0.6500$ eliminated only 3 false positives out of 200 in Benchmark v1.0, we analyzed the exact distribution of V8 Champion's predicted probabilities on the 200 Category 1 bare-apex domains:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│         BENCHMARK V1.0 BARE-APEX (N = 200) PROBABILITY DISTRIBUTION            │
├──────────────────────────────────────────────────────┬─────────────────────────┤
│ Metric                                               │ Value                   │
├──────────────────────────────────────────────────────┼─────────────────────────┤
│ Minimum Probability                                  │ 0.4796 (theverge.com)   │
│ 25th Percentile                                      │ 0.8976                  │
│ Median Probability                                   │ 0.9367                  │
│ 75th Percentile                                      │ 0.9532                  │
│ Maximum Probability                                  │ 0.9880                  │
│ Mean Probability                                     │ 0.9161                  │
├──────────────────────────────────────────────────────┼─────────────────────────┤
│ Count with Probability < 0.2800 (Clean at Baseline)  │ 0 / 200 (0.0%)          │
│ Count with Probability < 0.5500 (Cleaned by A1)      │ 3 / 200 (1.5%)          │
│ Count with Probability < 0.6500 (Cleaned by A2)      │ 3 / 200 (1.5%)          │
│ Count with Probability < 0.8000                      │ 9 / 200 (4.5%)          │
│ Count with Probability >= 0.9000 (Saturated Threat)  │ 147 / 200 (73.5%)       │
└──────────────────────────────────────────────────────┴─────────────────────────┘
```

### Forensic Takeaways:
1. **The Feature Extractor Blind Spot:**
   When a URL has no subdomains (`NoOfSubDomain == 0`), no path words (`PathSuspiciousWords == 0`), and no query words (`QuerySuspiciousWords == 0`), HistGBM relies heavily on `HostEntropy`, `DomainLength`, and `SpecialCharRatio`. Because many legitimate domain names have lengths between 8 and 18 characters and Shannon entropy between $3.0$ and $3.8$, the gradient boosted trees assign them the exact same leaf values as bare-apex phishing lures.
2. **Asymmetry of Shifting Thresholds:**
   Because 147 out of 200 benign apex domains have probabilities $> 0.9000$, raising the decision threshold to $0.5500$ or $0.6500$ captures almost none of the benign false positives ($1.5\%$ reduction), but it immediately begins eating into malicious recall by dropping legitimate phishing lures whose probabilities fall in the $0.50 - 0.65$ range.
3. **Proof of Architecture:**
   This empirical finding conclusively proves that **threshold modulation alone is dead on arrival**. The solution cannot be a simple scalar adjustment; it **requires deterministic entity and reputation recognition** (Tier 3 Brand Dictionaries and Tier 4 Safe Root Adjudication).

---

## 7. Conclusions, Recommendations, and Stop Condition

### Key Conclusions:
1. **Both A1 and A2 are REJECTED as standalone solutions.** Neither policy comes remotely close to passing Gate 3 (Apex FPR remains $98.50\%$, far exceeding the $\le 10.00\%$ target).
2. **Policy A2 is Strictly Disqualified:** A2 causes 3 false negatives on real test phishing lures, induces 5 false negatives on adversarial attacks, and violates Gate 7 by breaking golden fixture parity.
3. **Threshold Baseline Established:** A threshold of $\tau_{\text{apex}} = 0.5500$ preserves golden fixture parity (0 regressions) and retains $98.002\%$ recall on bare-apex phishing ($4,169 / 4,254$), but is useless without dictionary and safe-root overrides.

### Next Authorized Step (Phase 1D.1 Stage 2):
In accordance with the pre-registered ablation matrix:
- **Phase 1D.1-B1:** Test the **16-token Brand Dictionary Expansion** in isolation on frozen V8 predictions.
- **Phase 1D.1-B2:** Test the **Curated Safe Roots Expansion** (developer, gaming, media, docs) in isolation.
- **Phase 1D.1-B3:** Test the **Reputation Filter (Top-100k Tranco)** in isolation.

### Execution Stop Condition:
In strict compliance with user instructions:
- Zero model training occurred.
- Zero production code was altered.
- Zero Git mutations occurred.
- **Execution is halted.** We await explicit user authorization before proceeding to Phase 1D.1 Stage 2 (B1 / B2 / B3).
