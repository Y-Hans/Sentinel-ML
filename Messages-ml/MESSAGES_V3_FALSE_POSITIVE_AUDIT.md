# Messages V3 False Positive Forensic Audit & Remediation

## 1. Overview & Root Cause Analysis
The "Risk score: 93 / 100" false positive for the HP partnership announcement is rooted in the frozen V2 ML model structure combined with inadequate V3 dampeners. 

- **V2 Output:** P(BENIGN) = 34.49%, P(SUSPICIOUS) = 20.73%, P(MALICIOUS) = 44.78%, `P(Non-benign) = 65.51%`.
- **TF-IDF Trigger:** The model heavily penalized semantic overlap with scam keywords ("requested", "soon", "regards", "new").
- **Risk Mapping to 93:** The final risk score of 93/100 is generated downstream through mathematical scaling mapping probabilities near the decision boundary ($\tau=0.704$): `(0.6551 / 0.704) * 100 = ~93.05`.
- **Missing Dampener:** The `ContextualAdjudicator.kt` contained benign dampeners (e.g. for standalone greetings or system progress) but lacked one for institutional announcements, and critically, the dampeners were previously restricted only to cases where $P(Malicious) \le 0.75$, allowing high-confidence false positives to bypass correction entirely.

## 2. Implemented Fix
We updated `ContextualAdjudicator.kt` in the Android repository to include a specialized `INSTITUTIONAL_DAMPENING` heuristic. This dampener evaluates for the presence of $\ge 2$ institutional keywords (e.g. "campus", "partnered with", "university", "faculty", "dear students", "procure"). 
Crucially, this dampener is applied globally to elevated scores but is strictly overriden by:
- Hard URL presence
- Identified threats (OTP theft, KYC phishing, Malware downloads, Extortion)
- Urgent threat overrides (e.g., "immediately", "urgent", "action required")
- Financial fraud requests (e.g., "pay", "fee", "transfer")
- Credential theft requests (e.g., "password", "login details")

All V2 artifacts (`champion_v2_model.pkl`, `champion_v2_scaler.pkl`, etc.) remained **frozen** and unmodified. No brand whitelists were used.

## 3. Benchmark Results

### Institutional Suite Evaluation
We created a 32-message hard-negative benchmark suite (`slice_institutional_partnerships.jsonl`) pairing legitimate campus/institutional announcements against malicious imitations.

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Legit N | 16 | 16 | 0 |
| Legit FPR | 37.50% | 0.00% | -37.50% |
| Malicious N | 16 | 16 | 0 |
| Malicious Recall | 81.25% | 81.25% | 0.00% |

*The original failing HP announcement now evaluates to P(Non-benign) = 0.1500 (Risk Score: 21), safely classifying it as BENIGN.*

### Overall V3 Benchmark Metrics (Validation Set N=3,397)
| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| Overall FPR | 2.48% | 2.48% | 0.00% |
| Overall Recall | 96.49% | 96.37% | -0.12% |
| OTP Recall | 100.0% | 100.0% | 0.00% |
| KYC Recall | 100.0% | 100.0% | 0.00% |

*(A negligible 0.12% drop in broad spam recall occurred due to generalized scam messages coincidentally matching $\ge 2$ academic vocabulary terms, an acceptable tradeoff for eradicating a 37.5% FPR category without model retraining.)*

## 4. Final Recommendation
The contextual dampening fix is robust, effectively neutralizing institutional false positives while preserving strict boundaries against financial fraud, credential theft, and malicious URLs. The fix has been integrated into `ContextualAdjudicator.kt`. The V3 architecture is verified and recommended for continued deployment, provided future iterations incorporate this institutional dimension natively in V3 Single-Stage ML retraining.
