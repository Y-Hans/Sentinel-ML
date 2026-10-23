# Simulation baseline results — NOT RUN


Evidence vocabulary: **OBSERVED** = inspected/computed in this pass; **REPORTED** = earlier document or user statement, not reproduced here; **ASSUMED** = proposed design, hypothesis, or conditional calculation, not measured behavior.

**Disposition: STOPPED AT PREFLIGHT. Neither simulation nor sealed final exam was frozen. No model inference, training, calibration, threshold change, export, promotion, Android execution, or Phase 2–7 implementation occurred.** The requested zero-overlap and evidence sufficiency conditions were not met. These are blocker/conditional-design documents, not completed baseline results or an approval-ready training authorization.

## Execution scope and availability

**OBSERVED:** model executions = 0, inference rows = 0, bootstrap replicates = 0, calibration fits = 0, threshold modifications = 0. The Part A freeze prerequisite failed. Raw and adjudicated outputs are unavailable for every row below; this means NOT MEASURED, never 0 errors or 0 recall.

| Track / baseline | OBSERVED artifact availability | Raw / adjudicated deployment results |
|---|---|---|
| Messages V2 champion | Canonical four pickles in `sentinel-ml/6sep/messages/final/`; duplicate artifact copies inventoried | NOT RUN / NOT RUN |
| Messages V4.3 Candidate-D | Four pickles in `messages_v4_3/models/candidate_d/` | NOT RUN / NOT RUN |
| Messages V4.4 | A, B, C and RC2 experiment 1/2/3 model/vectorizer/scaler artifacts present | Each variant NOT RUN / NOT RUN |
| Messages V4.5 | Ablation A/C classifiers, C HGB, structural scaler and auxiliary next-architecture artifact present; embedding dependency closure not validated | Each variant NOT RUN / NOT RUN |
| URL V7 | Joblib and portable JSON present | NOT RUN / NOT RUN |
| URL V8 raw; V8 + adjudication | Joblib, portable JSON, Python adjudicator source present | NOT RUN / NOT RUN |
| Installed Beta 2.0.1; unsigned 2.1.0 | APK files inventoried and hashed; historical pull linkage unresolved | Python model/adjudicator approximation NOT RUN; exact APK runtime requires authorization |

**OBSERVED:** alerts/1,000 benign, alerts/user/day, PPV, recall, bootstrap CIs, per-language/script/channel/group/form/popularity/family rates, reliability/ECE, threshold-sensitivity curves and worst-error rankings are all NOT ESTIMABLE from this pass. No new worst-case predictions are claimed. N=0 is not decision-grade. A reference report cannot fill these cells as OBSERVED.

## Conditional measurement specification — ASSUMED

Freeze endpoints before running: model thresholded non-benign score, raw malicious classification, adjudicated warning, adjudicated block; preserve three-class Messages probabilities and spam errors. Store raw score, final probability, label, policy branch, original/canonical URL and linkage ID. Adjudicator-mutated values need not be calibrated probabilities; assess calibration of the model separately and label policy outputs decision scores where appropriate. “As shipped” Python approximation must bind to APK asset/source identity and list unsupported metadata; Kotlin fusion/severity/Gradle or device confirmation **requires authorization**.

For attack prevalence p, sensitivity r, benign FPR f:

* false alerts/1,000 benign = 1000 f;
* PPV(p) = p r / [p r + (1-p) f]; undefined if denominator zero;
* false alerts/user/day = V(1-p)f; total alerts/day = V[(1-p)f+pr].

Use the frozen scenario weights from the design. Recall reweighting assumes class-conditional segment distribution is stable; campaign shifts violate it. Spam rates require a third term rather than relabeling spam benign or malicious opportunistically. For unique user alerts, join URL/message events and dedup before counting.

Use 2,000 stratified cluster-bootstrap replicates (seed fixed pre-run), resampling independent users/days and template/domain components, propagating f/r jointly to PPV and daily burden. Publish 95% intervals, component counts and effective sample sizes; use binomial upper bounds for zero-event cells because a bootstrap of zero cannot prove zero risk. Flag every cell with <30 labeled rows in either relevant class as not decision-grade; also reject sparse independent-component counts. Calibration: validation-fixed probability bins, weighted test reliability curves/ECE/Brier/log loss with deployment prior adjustment clearly separated from unadjusted scores. Threshold sensitivity: a predeclared diagnostic grid around existing frozen thresholds, with no chosen replacement and no held-out threshold optimization. Keep validation/test/exam roles separate.

## Reported comparison and disagreement ledger — not reproduced

| Status | Claims retained side by side | Interpretation / unresolved evidence |
|---|---|---|
| REPORTED vs REPORTED | User: first pull m1 V4/V7, next two V2/V8; master plan: historical 562 V2/V7, unsigned V4.3/V8 | Need hash-linked per-pull installation provenance; neither selected as fact |
| OBSERVED vs REPORTED | Replay union-normalized overlap 9/294; history 6/562; master §5 says 6/294 and 0/562 | Different normalization/training universes may explain discrepancy; present pass does not clear individual models |
| OBSERVED vs REPORTED | Candidate-D train file 19,672; its model-source docstring says 19,070 | Manifest and measured count agree on 19,672; docstring discrepancy retained |
| REPORTED vs REPORTED | Master §3 Candidate-D TEST recall 1510/1556, benign FPR 2/520; VAL 2222/2316 and 16/807; OOD 761/794 and 1/255 | Different populations, not interchangeable deployment estimates; no reproduction here |
| REPORTED vs REPORTED | Master §3 OOD 95.84%; V4.5 architecture report clean OOD baseline 95.72% on 747 attacks | Distinct full/clean denominators, not a numerical average |
| REPORTED vs REPORTED | V4.4 earlier system-notification FPR 0/55; final forensic audit 25/55 (45.5%) | Historical audit retracts earlier claim; neither rerun here |
| REPORTED vs REPORTED | V4.4 release says zero collisions; final audit reports 601 normalized rows / 263 keys for B and 598/261 for V4.3 | Exact-string versus normalized/template criteria; no general zero-leakage claim allowed |
| REPORTED vs REPORTED | V4.5 provenance audit says strict leakage rejected despite 307 aggressive-normalized collisions and 5 TEST near-duplicate pairs | Exact-string independence does not satisfy requested grouped-template independence |
| REPORTED vs REPORTED | Master calls source starvation primary; SECOND_FORENSIC_REPORT emphasizes TEST 90/188 and OOD 31/83 spam→malicious errors, underdocumented semantics and source skew | Different failure slices; architectural causality remains unproven |
| REPORTED vs REPORTED | Master V8 schemeless Instagram p=.982; Oct 21 integration report schemeless p=.001 after canonicalization, explicit HTTP .982 | Runtime version/input-form difference; no claim current APK reproduces old failure |
| REPORTED vs REPORTED | URL reconciliation: earlier 4248/4254=99.853%; corrected cohort 4170/4254=98.025%; qualified empty-path 681/682=99.853% | Cohort conflation reported; retain all figures with denominators |
| REPORTED vs REPORTED | URL earlier benign denominator 43,027; reconciliation 42,941 total, 42,937 unique URLs, 42,643 hosts, 40,845 domains | Fixture class accounting and unit distinctions reported |
| REPORTED vs REPORTED | Hard-benign historical draft 304/500=60.8%; reconciliation V8 419/500 raw=83.8%, 420/500 adjudicated=84% | Reference only, not replayed, not deployment FPR or gate-setting data |
| REPORTED vs REPORTED | Master parity gate N=500; integration URL parity 174/174; hard-benign N=500 | Three distinct populations; never substitute one denominator for another |
| REPORTED vs REPORTED | Master Phase 5 cold-start <15 ms; Gate 9 latency <20 ms/RAM<50 MB | Different/underdefined latency endpoints; proposed plan separates cold/warm endpoints |
| REPORTED vs REPORTED | V4.5 report calls V4.3 sole production; user says later V2/V8 | Report date/deployment state differs; release metadata required |

**REPORTED:** V4.4 final audit utility false alarms 26/55 and institutional recall 9/16 versus V4.3 12/16; V4.5 TEST recall 77.70% and FPR 3.08% versus V4.3 97.04%/0.38%. Institutional N=16 per attack cell is not decision-grade. These are earlier report claims, not measurements of the requested simulation.

**OBSERVED limitation:** comparison covers the master plan and the specific source documents in `reference_hashes.json`. It is not an exhaustive reconciliation of every historical report; that requirement remains unfinished because execution stopped. No report conflict was silently resolved by picking the favorable number.

## Commands and environment

**OBSERVED:** working directory for every command was the workspace root printed in `environment.json`; Windows PowerShell, Python executable/version/platform recorded there. Scripts use only Python standard library; `-B` prevents bytecode writes; no project module/model unpickled or imported. Exact substantive commands, counts, exit codes and input/output hashes are in `SIMULATION_RUN_EVIDENCE.md` and the adjacent JSON files. Expected SQLite/codec failures are caught and recorded as diagnostic results; the scripts themselves exited 0. No package installation or network access occurred.
