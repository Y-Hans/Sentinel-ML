# Root Cause Analysis — Sentinel Message Security ML

Date: 2026-09-30. Evidence labels use the dossier convention: VERIFIED, REPRODUCED, HISTORICAL, INFERENCE, UNKNOWN.

## Conclusion

**INFERENCE — dominant cause:** multiple interacting issues, led by training/evaluation data quality and source/coverage shift, then three-class confusion and representation limits. Evidence does not support a classifier-capacity or threshold-first intervention.

## Evidence

1. **REPRODUCED — headline baseline:** V4.3 at tau=.61 gets VAL 2222/2316 malicious (95.94%) and 16/807 benign FP (1.98%); TEST 1510/1556 (97.04%) and 2/520 (0.38%); OOD 761/794 (95.84%) and 1/255 (0.39%). Direct outputs and exact error records are in messages_v4_3/evaluation/reproduction_20260930/.
2. **VERIFIED — source concentration:** 72.8% TEST and 72.3% OOD rows come from one public research source; source mix is nearly identical across these evaluation splits. Their “OOD” status therefore does not establish unseen-source transfer.
3. **VERIFIED — target-language evidence is inadequate:** train marks 1,797/19,672 Hinglish, but TEST has 3 and OOD 3; actual Devanagari count is 15 TEST and 4 OOD. These sample sizes cannot support claims about language-family performance.
4. **VERIFIED — label/source shortcut risk:** among train rows containing “hello”, 265/336 are MALICIOUS. TEST/OOD errors include short greetings and ordinary-looking conversational/service messages labeled MALICIOUS. They may represent poisoning/social engineering or source-label/taxonomy noise; this was not adjudicated.
5. **REPRODUCED — three-class confusion:** TEST has 90 SPAM→MALICIOUS and 22 MALICIOUS→SPAM in addition to 46 malicious FNs; OOD has 31 and 16. Binary “non-benign” scores hide this failure dimension.
6. **VERIFIED — utility prior skew:** electricity occurs in 422 training rows: 339 M /82 B /1 S. “Bijli” appears in 81 rows: 53 M /28 B. The difference is compatible with wording sensitivity driven by source/class priors and limited benign natural coverage.
7. **VERIFIED — representation limits:** 19 handcrafted features encode URL shape and phone presence, not threat intent, negation scope, callback semantics, sender authenticity, APK/download context, or linguistic family. TF-IDF bigrams and character grams can encode local cues but are not compositional models.
8. **HISTORICAL — targeted hard-negative costs:** V4.4 RC2 forensic report documents increasing validation threshold from .63 to .74, TEST losses and malicious→spam confusion after sequential targeted corpus patches. This cautions against “add examples until slice improves.”
9. **HISTORICAL — alternative architecture evidence:** frozen MiniLM performed worse globally; asymmetric sieve produced no unique independent detections on its reported set. This does not rule out all transformer or contextual methods.
10. **UNKNOWN — causal contribution:** no fresh controlled perturbation sweep was run in this pass. Reported word counts are not feature attributions. The actual causal effect of replacing only a provider, institution, greeting token, URL, phone, negation, punctuation, or English/Hinglish wording remains unknown.

## Differential diagnosis by failure family

| Family | Evidence-based leading explanation | Confidence |
|---|---|---|
| Electricity / utility | Source/class prior plus scarce diverse benign DISCOM wording; target suite too small | INFERENCE, moderate |
| Greetings | Strong contextual token skew and possible source-label taxonomy contamination | INFERENCE, moderate; token causality UNKNOWN |
| Hinglish | Undercoverage in independent evaluation and distribution shift; script counts are tiny | INFERENCE, high |
| Institutional/campus | Genuine behavior/channel/destination discrimination; benign/malicious share institution names | INFERENCE; independent observations UNKNOWN |
| Callback/phone | Presence-only feature cannot encode intent, number class or legitimacy | VERIFIED, high |
| APK/software | No explicit structural feature; lexical signal may work when surrounding cues exist | VERIFIED; production miss rate UNKNOWN |
| Security alert / OTP negation | Local n-grams represent some negation, but no robust scope/compositional mechanism | VERIFIED/INFERENCE; causal failure rate UNKNOWN |
| Spam vs malicious | Substantial symmetric class confusion under current labels and threshold | REPRODUCED, high |
| Threshold | .61 reproduces; cannot fix label errors/source shift or 3-way confusion | REPRODUCED + INFERENCE |
| Android mismatch | Not investigated; no ML candidate currently warrants integration work | UNKNOWN, downstream |

## Bottleneck ranking

1. **A data quality / label semantics — INFERENCE, high priority.**
2. **B coverage and source shift — VERIFIED evidence; dominant.**
3. **H evaluation design — VERIFIED evidence; current source and language limitations.**
4. **E class confusion — REPRODUCED.**
5. **C representation — VERIFIED gaps, but contribution not isolated.**
6. **D missing deterministic security features — several missing, but no causal deployment-sized blindspot established.**
7. **F threshold/calibration — threshold reproduced; independent calibration UNKNOWN.**
8. **G post-processing — not part of this inference path; relevance UNKNOWN.**
9. **I Android/runtime mismatch — not relevant until candidate passes ML gates.**

## What would falsify this diagnosis

**REPRODUCED diagnostic probe:** hand-authored pairs yielded bare “Hello” .991 non-benign, “Hello.” .804, and “Hi” .650; the OTP polarity pair remained MALICIOUS with only a .05 score change. Provider/institution swaps barely moved scores, while URL insertion raised score in one context. The utility phone pair flipped BENIGN→MALICIOUS, but also changed words and the phone structural feature. See counterfactual_probes.json. These are mechanism hints, not independent evaluation evidence.

An independently sourced, human-adjudicated, source-held-out collection with substantial natural Hinglish/utility/institution/callback cases that shows stable labels and similar V4.3 performance would weaken the data/source diagnosis. If a single controlled representation feature then recovers repeatable natural errors with no paired regression, representation becomes the stronger bottleneck. Do not infer this from authored probes.
