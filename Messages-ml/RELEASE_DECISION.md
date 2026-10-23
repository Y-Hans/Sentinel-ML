# ML Release Decision

Date: 2026-09-30

## Decision

**Retain frozen V4.3 Candidate-D as the existing ML reference. Do not promote any new candidate.** This is a research decision and does not independently certify current Android production assets.

## Basis

- **REPRODUCED** V4.3 VAL/TEST/OOD headline counts exactly match the stored report at tau=.61.
- **VERIFIED** frozen artifacts have consistent dimensions and class order; 111 iterations align with configured early stopping.
- **VERIFIED** evaluation coverage has material limitations: sources are concentrated in public corpora, Hinglish and script-specific held-out counts are tiny, and several target slices contain only 3–32 examples.
- **REPRODUCED** spam↔malicious confusion is substantial even where benign FPR is low.
- **HISTORICAL** V4.4 was held after forensic corrections; RC2 target tuning caused global regressions. V4.5 MiniLM and asymmetric sieve reports reject those particular candidates.
- **UNKNOWN** contemporary field performance, source-level label validity, full leakage independence, current calibration, and current Android parity.

## Release implications

- V4.3 remains frozen and unmodified in this investigation.
- V2 and all protected evaluation files remain untouched.
- No V4.4/V4.5 artifact is promoted.
- No Android files/assets were inspected or modified in this pass; Android is downstream and there is no qualifying new ML candidate to integrate.
- This decision does not resolve the product's policy for suspicious spam versus malicious messages.

## Gate to reconsider

Reconsider ML candidate work only after an independently sourced and adjudicated dataset is available, with source/time holdout and near-duplicate/provenance checks beyond exact text. Then define a single-variable experiment with fixed V4.3 parent, fixed threshold, paired error review, and explicit no-regression rules.
