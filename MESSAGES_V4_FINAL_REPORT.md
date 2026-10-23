# Messages V4 final report

## Executive summary

**Verdict: DATA_REQUIRED — no Messages V4 release candidate exists.** A truthful V4 cannot be trained or promoted from the available evidence without repeating the prior errors: fitting ambiguous labels, tuning to protected false positives, or hiding semantic gaps behind rules. V2 remains the only frozen artifact; V3 remains experimental.

## V2 baseline, V3 history, and root cause

V2 uses 70 deterministic features plus word/character TF-IDF (2,070 features total), a scaler and a 3-class HistGBM. Its frozen artifact hashes and exact forensic findings are in [MESSAGES_V4_FORENSIC_BASELINE.md](MESSAGES_V4_FORENSIC_BASELINE.md). V2 has demonstrated false positives on institutional and technical/Hinglish content and only 2/3 recall on the corrected electricity replay.

The V3 two-stage proposal did not retrain a semantically robust model: it retained V2 and added contextual lexical rules. Its own trusted-context audit includes 10 safe outcomes out of 25 saved-contact malicious-URL examples. The 520-case Hinglish audit reports 87.12% V3 recall, leaving 67 missed attacks. It must not replace V2.

The root cause is training-distribution and representation mismatch: highly English, headerless campaign data and deterministic surface features are not evidence of reliable intent discrimination across the target Indian conversational, technical and provider-shift distributions.

## Dataset and leakage audit

The canonical processed corpus has 22,648 records, group-aware partitioning and a documented zero in-corpus template overlap. That does not establish absence of deployment leakage: the source/domain/template variety is limited, the simulation databases are corrupt, and the 2,302-record credential metric is materially ambiguous (27 verified malicious, 1,656 ambiguous according to its audit). Existing device history is excluded from V4 training and remains protected pending recovery/provenance.

The permanent benchmark schema was corrected to recognize the already-present `INSTITUTIONAL_ANNOUNCEMENT`, `SCAM`, `PHISHING`, and `OTP_THEFT` taxonomy labels. `python -m pytest sentinel-ml\\Messages-ml\\tests -q --cache-clear` now passes 40 tests.

## V4 design, training, calibration, and Android integration

None was performed because the data gate failed before experimentation. Consequently there is no V4 model, feature configuration, calibration, threshold, exported Android artifact, GPU usage, artifact size, latency measurement, or Android equivalence result to report. Reporting any such value would fabricate a release candidate.

The pre-registered V4 design after data remediation is: use source/template-grouped, provenance-preserving train/validation/test/holdout partitions; compare text representations against an ablated deterministic baseline; evaluate calibration and security families before selecting a threshold; export only the selected model through the existing Kotlin runtime; and require Python/Kotlin feature, probability, class, risk, and final-policy parity.

## Measured comparison

| Metric | V2 | V3 | V4 |
| --- | ---: | ---: | ---: |
| Corrected electricity recall | 66.7% (2/3) | not independently reproducible as 100% | not trained |
| Hinglish attack recall (520-suite) | 62.88% | 87.12% | not trained |
| Saved-contact malicious-URL block rate | not separately measured | 60.0% (15/25) | not trained |
| Credential population recall | 79.19% in prior HN-safe campaign | not established | not trained |
| Source/template holdout | not established | not established | not established |
| Android equivalence | V2 assets exist | rule parity only | not applicable |

## Security analysis and rollback

Do not deploy contextual rules as a substitute for model evidence; saved, trusted, group, or institutional context must never downgrade a clear threat. Retain V2 exactly as frozen, with hashes recorded in the forensic baseline. Do not overwrite the V2 pickle or Android assets. If a V3 policy layer is enabled in a development build, disable it to roll back to the V2 classifier path; it is not a V4 replacement.

## Data-required plan

The concrete collection, adjudication, protected-evaluation, and release protocol is in [MESSAGES_V4_FORENSIC_BASELINE.md](MESSAGES_V4_FORENSIC_BASELINE.md). V4 work may resume only after those gates are satisfied and the resulting corpus is independently audited for leakage and annotation quality.
