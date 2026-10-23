# Messages V4 forensic baseline

**Date:** 2026-09-14  
**Decision:** `V4_NOT_STARTED_DATA_REQUIRED`  
**Production decision:** retain the frozen Messages V2 artifact; do not promote V3 or a new V4 candidate.

## Evidence inventory

The current Messages V2 artifact is intact. Its SHA-256 values are:

| Artifact | SHA-256 |
| --- | --- |
| `champion_v2_model.pkl` | `d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887` |
| `champion_v2_scaler.pkl` | `6b5ecf4e4df650494b87e659a2479141d88fc28fa6f05fcbe09d2d5fe50fe999` |
| `champion_v2_tfidf_word.pkl` | `b1244fba45db377986d2ba1b25c525051c6e2552e103c11676cfdc05da3f1495` |
| `champion_v2_tfidf_char.pkl` | `19308b9e48529704127d8102e54ec844681c2310dcc3d71d2a5d5bd33fdd4701` |

The scaler hash is the on-disk authority. The previously documented mismatch is a registry typo, not an artifact defect.

V2 is the 3-class `HistGradientBoostingClassifier` over 70 deterministic features, 1,500 word TF-IDF features and 500 `char_wb` TF-IDF features, standardized to 2,070 dimensions. The canonical non-benign decision threshold is `0.704`.

The processed corpus reports 22,648 records: 15,855 train, 3,397 validation, 2,264 test and 1,132 OOD. Its own quality report records 99.59% English/Latin, only 73 Hinglish examples (0.32%), and 97.48% headerless/unknown senders. Those proportions are insufficient to substantiate the target robustness claims for Indian conversational traffic, provider headers, or multilingual deployment.

## Historical reconstruction and contradictions

1. The corrected V2 evaluation report gives electricity-scam recall of **2/3 (66.7%)**, not 100%.
2. The HP institutional message produces `P(non-benign)=0.6551`; its reported risk 93 is the UI mapping `round(0.6551 / 0.704 * 100)`, not evidence that its classifier threshold was crossed.
3. The September candidate campaign ended in `NO_MODEL_READY` / `DATASET_REMEDIATION_REQUIRED`: the selected HN-safe point had 86.96% test malicious recall, 88.69% OOD malicious recall, and 79.19% on the original credential-request label population, below the unchanged 80% gate. The credential audit says only 27 of the 2,302 examples are conservatively verified malicious; 1,656 are ambiguous. That gate cannot be repaired by tuning or synthetic examples.
4. The V3 “promotion” document conflicts with its own machine-readable audits. Its 520-case Hinglish suite records V3 two-stage recall 87.12%, not the claimed complete solution. More importantly, the trusted-context audit records 10/25 saved-contact malicious-URL cases as safe (40%). Therefore “no active bypass” in the same report only means the misses were attributed to the base model; it does not make the end-to-end system release-safe.
5. `sentinel_db` and `sentinel_db(1)` are distinct byte sequences, but neither opens as SQLite. Recovered/reconstructed databases are also malformed. Existing recovery output records a 294-record interpretation (291 messages, 3 URLs), whereas historical narrative claims about 335 records cannot be independently reproduced from the original database bytes. This data is protected evaluation evidence only until provenance and label recovery are completed.

## Root cause and release blockers

The evidence supports a combined data and representation failure: the V2 feature space learns surface/morphology and campaign lexicon, while legitimate technical, institutional and Hinglish conversation is nearly absent from the training distribution. The V3 response is an unproven policy layer with fixed lexical escalation/dampening. It cannot establish semantic generalization and has documented attack escapes.

The following release gates are blocked:

| Gate | Result | Basis |
| --- | --- | --- |
| V2 identity | pass | hashes above |
| Regression schema integrity | pass | 40 Messages-ML tests pass after taxonomy alignment |
| Corrected electricity replay | fail for V4 release | V2 = 2/3; no independently verified V4 |
| Hinglish robustness | fail | V3 520-case audit has 67 V2 misses and 67 V3 misses |
| Trusted/saved malicious URL protection | fail | V3 audit: 15/25 block, 10/25 safe |
| Source/template holdout | not established | existing partitions are not a deployment-source holdout |
| Device-history provenance/leakage | not established | original databases are corrupt |
| Android V4 equivalence/performance | not applicable | no V4 artifact may be exported honestly |

## Required data before V4 training

1. Independently adjudicate the 2,302 credential-request records, preserving source, annotator, rationale, and confidence. Separate verified malicious, benign, anti-phishing and ambiguous records before using any of them in a gate.
2. Recover or export the original device database from a healthy device/backup. Assign immutable record identifiers and adjudications; never train on its protected replay set.
3. Collect independently sourced, non-synthetic benign messages for technical/security notifications, delivery PINs, bank/OTP notices, provider links, academic/institutional notices, Indian service headers, and collaboration chat.
4. Collect independently sourced malicious pairs for the same families, including saved-contact/group/account-takeover scenarios and Indian-language/Hinglish fraud. Keep provider/template-disjoint test and source-holdout partitions.
5. Add a pre-registered release protocol: exact/normalized/template leakage checks, source/template/provider holdouts, counterfactual pairs, stable calibration, and Android parity before any model is eligible.

No V2 artifact, Android asset, threshold, or production model was changed by this forensic phase.
