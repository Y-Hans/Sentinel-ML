# Experiment Report — V4.3 Forensic Reproduction and Next Experiment Gate

Date: 2026-09-30. This report distinguishes completed read-only reproduction from a candidate model experiment.

## Completed: frozen baseline reproduction

- **Status: REPRODUCED.** Frozen V4.3 candidate-D pickles loaded directly and evaluated on the actual repository VAL/TEST/OOD JSONL files at tau=.61.
- **Artifacts:** SHA-256 hashes and estimator/vectorizer dimensions are recorded in PROJECT_ML_DOSSIER.md and reproduction.json.
- **Results:** VAL 2222/2316 malicious recall, 16/807 benign FP; TEST 1510/1556, 2/520; OOD 761/794, 1/255. Confusion matrices match stored candidate metrics exactly.
- **Error records:** all TEST and OOD errors are exported with text, source metadata, probability, structural vector, URL/phone flags, and top active lexical features. Evaluation files and frozen artifacts were not changed.
- **No threshold tuning:** tau remained .61. No new training or evaluation data were added.

## Candidate-changing experiment decision

**REPRODUCED diagnostic perturbations:** scripts/probe_counterfactuals_v43.py evaluates ten manually constructed text pairs and writes counterfactual_probes.json. They suggest greeting lexical sensitivity, weak OTP polarity response, and utility phone-associated flips in tested strings. These authored probes are diagnostic, not independent validation.

**Selected experiment family: F — data redesign. Designed, not run.**

- **One hypothesis:** headline metrics and reported weak slices are materially confounded by training/evaluation source composition and uncertain label semantics; a source-held-out, adjudicated collection will reveal the real error distribution before model changes.
- **One main variable:** data source/adjudication regime. Keep features, classifier, threshold, runtime and frozen V4.3 parent unchanged for this experiment.
- **Immutable parent:** V4.3 Candidate-D files, hashes in the dossier.
- **Independent evaluation strategy:** collect new real Indian SMS/WhatsApp samples from sources not used in any current corpus; have security reviewers independently label B/S/M and resolve disagreements before unblinding model predictions. Hold out by collection source and time, and audit exact, normalized, URL-normalized, template, Jaccard, ID, sender and semantic overlap against all train corpora. Do not use synthetic or co-authored examples as primary evidence.
- **Success criterion:** first establish a usable independent baseline with label agreement and provenance; then a later single-variable model candidate must improve a preregistered target category on this fixed clean evaluation set without lowering aggregate malicious recall or exceeding benign FPR policy, and without material spam↔malicious regression. Threshold stays fixed for this data experiment.
- **Failure criterion:** data independence or adjudication cannot be established, source-only effects explain the apparent gain, or the baseline reveals no stable, repeatable failure cluster. If so, stop and do not expand the corpus/model.
- **Why not train now:** there is no sufficiently independent, source-diverse, naturally occurring and adjudicated corpus in the inspected tree. Training against existing diagnostics or V4.4 co-generated holdouts would repeat the contamination mechanism. An APK gate, lexicon patch, new threshold, or another hard-negative expansion has no defensible independent success criterion today.

## Status

**No candidate model was trained. No new model artifact exists.** The completed experiment is a read-only reproduction and error export, not a model improvement claim. Proceed only after a qualifying independent corpus is available.
