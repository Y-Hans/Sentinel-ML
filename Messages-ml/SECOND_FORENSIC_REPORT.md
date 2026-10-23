# Second ML Forensic Report

Scope: sentinel-ml/Messages-ml only. No training, data edits, threshold changes, V2/V4.3 artifact changes, or Android work.

## Evidence-status summary

- **VERIFIED:** frozen artifact architecture/hashes and full-dataset metadata were checked directly.
- **REPRODUCED:** V4.3 VAL/TEST/OOD predictions, aggregate composition, per-group error counts, class probabilities, VAL-only reliability diagnostics, training keyword/source distributions, and twenty authored counterfactual probes.
- **INFERENCE:** data/source skew is real; the dominant actionable failure pattern in observed classifications is a high-confidence SPAM/MALICIOUS boundary failure on promotional/commercial-spam rows. The full diagnosis is multi-layer.
- **UNKNOWN:** true human label correctness, temporal/real-world generalization, causal feature contributions on natural messages, and whether more representative data alone would remedy the class boundary.

## Seven final questions

1. **Is source/data skew actually demonstrated? — YES (VERIFIED).** TEST: IMC25 1,649/2,264 (72.84%), Mendeley 568 (25.09%); OOD: IMC25 818/1,132 (72.26%), Mendeley 274 (24.20%). BENIGN TEST is mostly Mendeley (479/520); MALICIOUS TEST mostly IMC25 (1,518/1,556). TEST/OOD language flag Hinglish is 3 records each. V4.3 train is 64.11% MALICIOUS.
2. **Is three-class SPAM/MALICIOUS confusion a major bottleneck? — YES (REPRODUCED).** TEST has 90/188 SPAM→MALICIOUS (47.9%) and 22 MALICIOUS→SPAM; OOD 31/83 (37.3%) and 16. The 90/31 errors all fall under PROMOTIONAL / COMMERCIAL_SPAM metadata and have median P(M) about .786/.783, with P(non-benign) near .999. This is not a threshold problem.
3. **Is representation failure demonstrated? — PARTLY (VERIFIED/REPRODUCED, bounded).** Candidate-D lacks explicit intent, source-authenticity, callback, APK, or negation-scope features, and held-out raw URL/phone features are zero because values were placeholder-normalized. A controlled authored OTP/delivery-code pair reverses or fails absolute labels. Broader natural-data representation failure as the main root cause remains UNKNOWN.
4. **Is label-semantic inconsistency demonstrated? — YES AT THE ANNOTATION SCHEMA; SECURITY MISLABELS NOT PROVEN.** The schema/taxonomy does not accept 20 distinct primary_type values used on 3,817 training rows (2,177 B /1,640 M); source_type has 4,154 out-of-enum rows, and the controlled additions omit threat_vectors. The corpus also has 1,232 MALICIOUS promotional-word hits and 714 BENIGN security-word hits. No human relabeling was performed, so incorrect security labels are not proven.
5. **Is thresholding the main problem? — NO (INFERENCE from reproduced score paths).** Threshold policy accounts for 24 TEST and 17 OOD MALICIOUS→BENIGN errors whose maximum P(non-benign) remains below .61. It does not account for 90/31 SPAM→MALICIOUS or 22/16 MALICIOUS→SPAM, all of which are above threshold.
6. **Is there evidence that more training data alone will solve this? — NO.** There is no causal evidence for volume alone. V4.4 historical targeted additions reportedly improved probes while worsening global metrics; that history cautions against treating more examples as a remedy. Future data design must improve independent source/label coverage, not merely increase N.
7. **What single technical hypothesis now has the strongest evidence? — INFERENCE.** V4.3 learns a strong non-benign signal but an unstable three-class boundary where promotional/commercial-spam rows are often mapped to MALICIOUS; class/source associations, nonconforming controlled-addition labels, and lack of explicit action-intent/transaction-channel features make the SPAM/MALICIOUS distinction unreliable. The cross-source 90/31 error concentration under one target category is the strongest model-error evidence.

## Decision

# G. MULTI-LAYER PROBLEM

**Why:** source/class skew is quantitatively demonstrated (TEST/OOD source mixes, TRAIN label balance and language coverage); the dominant three-class error is high-confidence and category-specific; input representation omits normalized intent and raw URL/phone cues in held-out files; the MALICIOUS→BENIGN component is partly threshold-gated; and class-label semantics are underdocumented. No single threshold or capacity explanation accounts for all of these. This is a layered diagnosis, not proof every layer is equally causal.

Decision work is analysis only. No candidate experiment or model recommendation is made. Supporting artifacts: DATASET_COMPOSITION_AUDIT.json, ERROR_STRATIFICATION.md, CLASS_CONFUSION_ANALYSIS.md, LABEL_SEMANTICS_AUDIT.md, COUNTERFACTUAL_METHOD_AUDIT.md.
