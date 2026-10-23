# Simulation baseline results


Date: October 22, 2026 (Asia/Calcutta). Scope: analysis, frozen-model inference and development design only.

Evidence labels: **OBSERVED** = computed or inspected in this run; **REPORTED** = historical/user claim not established here; **ASSUMED** = scenario/design choice; **PROVISIONAL** = inference conditional on unreviewed labels, authored cases or salvage. Observing a stored label is not observing its correctness. Null/NA means not estimable, never zero errors. No candidate training, model/calibrator fitting, model export, promotion, frozen-threshold change, Kotlin/Gradle/Android execution or Git mutation was performed.

## Reproduction gate

**OBSERVED:** Messages uses Python 3.14.4 / numpy 2.5.2 / sklearn 1.9.0; URL uses its venv Python 3.11.15 / numpy 2.4.6 / sklearn 1.9.0. Cache tags include Messages cpython-314 and cpython-311; the selected 3.14 interpreter is supported by Candidate-D cache provenance and exact reproduction, not proof of the historical training environment. All eight Messages pickle bundles and both URL joblibs loaded; their recorded unpickle warning lists are empty. No portable fallback was needed. A portable evaluator exists for a load failure; it was not used to substitute favorable results.

| Messages model | Frozen τ | TEST FP/benign | TEST malignant-class correct/attack | TEST spam→malicious | OOD spam→malicious |
| --- | --- | --- | --- | --- | --- |
| Messages_V2 | 0.704 | 20/520 | 1403/1556 | 39/188 | 14/83 |
| Messages_V4.3 | 0.61 | 2/520 | 1510/1556 | 90/188 | 31/83 |
| Messages_V4.4_candidate_a_corrected | 0.56 | 3/520 | 1510/1556 | 84/188 | 28/83 |
| Messages_V4.4_candidate_b_refined | 0.63 | 2/520 | 1511/1556 | 88/188 | 30/83 |
| Messages_V4.4_candidate_c_balanced | 0.63 | 3/520 | 1505/1556 | 86/188 | 30/83 |
| Messages_V4.4_rc2_experiment_1 | 0.68 | 3/520 | 1507/1556 | 87/188 | 34/83 |
| Messages_V4.4_rc2_experiment_2 | 0.68 | 3/520 | 1503/1556 | 88/188 | 33/83 |
| Messages_V4.4_rc2_experiment_3 | 0.74 | 2/520 | 1494/1556 | 85/188 | 29/83 |

**OBSERVED:** V4.3 exactly reproduces 1510/1556, 2/520 at τ=.61, TEST spam→malicious 90/188 (median pM=.786366), OOD spam→malicious 31/83. V2 current text-only feature pipeline produces 1403/1556 and 20/520, whereas September 6 report says 1402/1556 and 10/520. Same model identity does not ensure identical feature/sender/source pipeline; original version closure remains unresolved. The current inference follows the repo's benchmark_v2 text-only `sender_header=None` contract. This discrepancy is retained, not repaired by threshold selection.

| URL clean TEST model/path | TP/attack | FP/benign | Recall | FPR |
| --- | --- | --- | --- | --- |
| URL_V7 raw | 22880/23158 | 267/27353 | 98.800% | 0.976% |
| URL_V7 adjudicated | 22869/23158 | 267/27353 | 98.752% | 0.976% |
| URL_V8 raw | 22825/23158 | 207/27353 | 98.562% | 0.757% |
| URL_V8 adjudicated | 22835/23158 | 263/27353 | 98.605% | 0.962% |
| URL_V8 adjudicated_without_url_strings | 22825/23158 | 207/27353 | 98.562% | 0.757% |

**OBSERVED:** clean split reconstruction uses repository domain_group, GroupShuffleSplit .4/seed42 then .5/seed43, label inversion, frozen feature extraction and models; test N=50,511. Exact argv/cwd, runtime, exit codes, split counts and index hash are in `url_reproduction_only_v2.command.json`/`urls_reproduction.json`. The old `reproduce_v7_champion.py` was read but not executed because it fits and overwrites models. New inference-only code reproduces its split without training. On the 174 comparison fixtures, current features/raw probabilities match exactly; final probability maximum difference is about 2.954e−8. This is parity reference evidence, not truth or a gate-tuning outcome.

| URL historical HARD model/path | TP/attack | FP/benign | Recall | FPR |
| --- | --- | --- | --- | --- |
| URL_V7 raw | 815/841 | 82/1959 | 96.908% | 4.186% |
| URL_V7 adjudicated | 815/841 | 9/1959 | 96.908% | 0.459% |
| URL_V8 raw | 810/841 | 66/1959 | 96.314% | 3.369% |
| URL_V8 adjudicated | 832/841 | 66/1959 | 98.930% | 3.369% |

**OBSERVED:** this HARD source is `hard_dataset.csv` N=2,800, distinct from the protected 500 hard-benign URLs. It was evaluated as an additional reproduction reference after the clean reproduction gate; no gate/model choice depended on it.

## Simulation: raw versus adjudicated

**OBSERVED predictions / PROVISIONAL accuracy:** 8,040 message prediction rows (8 models×1005 events), 204 URL rows (2×102). Messages raw means class argmax; adjudication means frozen p(non-benign) threshold then max(spam,malicious), not Kotlin contact/group/fusion policy. URL raw means base probability at frozen τ; adjudication uses the current Python V7 gating or V8 URL-aware adjudicator. These current-source wrappers are not guaranteed historically shipped policy versions. Exact APK runtime execution was neither needed nor attempted; it requires separate authorization.

**PROVISIONAL main conditional table:** Messages uses all 816 available assumed/provisional benign and 72 authored attack events; URLs use 11 assumed-benign/5 authored attacks. Excluded unknown labels remain in denominator counts and alert-rate files. These challenge estimates are not real deployment rates.

| Model / path | FP / available benign | TP / authored attack (any alert) | Alerts / 1,000 benign | FPR bootstrap 95% CI | Recall bootstrap 95% CI |
| --- | --- | --- | --- | --- | --- |
| Messages_V2 raw | 19/816 | 8/72 | 23.284 | [0.269%, 8.147%] | [11.111%, 11.111%] |
| Messages_V2 adjudicated | 18/816 | 4/72 | 22.059 | [0.158%, 8.358%] | [0.000%, 11.111%] |
| Messages_V4.3 raw | 44/816 | 36/72 | 53.922 | [2.433%, 12.565%] | [44.444%, 55.556%] |
| Messages_V4.3 adjudicated | 24/816 | 32/72 | 29.412 | [0.478%, 9.406%] | [44.444%, 44.444%] |
| Messages_V4.4_candidate_a_corrected raw | 82/816 | 52/72 | 100.490 | [4.789%, 23.033%] | [44.444%, 100.000%] |
| Messages_V4.4_candidate_a_corrected adjudicated | 59/816 | 52/72 | 72.304 | [3.871%, 15.451%] | [44.444%, 100.000%] |
| Messages_V4.4_candidate_b_refined raw | 68/816 | 56/72 | 83.333 | [3.007%, 19.509%] | [55.556%, 100.000%] |
| Messages_V4.4_candidate_b_refined adjudicated | 33/816 | 52/72 | 40.441 | [1.124%, 10.576%] | [44.444%, 100.000%] |
| Messages_V4.4_candidate_c_balanced raw | 92/816 | 52/72 | 112.745 | [4.622%, 25.567%] | [55.556%, 88.889%] |
| Messages_V4.4_candidate_c_balanced adjudicated | 53/816 | 48/72 | 64.951 | [2.504%, 15.387%] | [44.444%, 88.889%] |
| Messages_V4.4_rc2_experiment_1 raw | 73/816 | 52/72 | 89.461 | [3.912%, 19.760%] | [44.444%, 100.000%] |
| Messages_V4.4_rc2_experiment_1 adjudicated | 31/816 | 48/72 | 37.990 | [0.915%, 10.000%] | [44.444%, 88.889%] |
| Messages_V4.4_rc2_experiment_2 raw | 88/816 | 52/72 | 107.843 | [4.245%, 24.328%] | [44.444%, 100.000%] |
| Messages_V4.4_rc2_experiment_2 adjudicated | 27/816 | 52/72 | 33.088 | [0.901%, 8.769%] | [44.444%, 100.000%] |
| Messages_V4.4_rc2_experiment_3 raw | 70/816 | 52/72 | 85.784 | [3.880%, 15.623%] | [44.444%, 100.000%] |
| Messages_V4.4_rc2_experiment_3 adjudicated | 22/816 | 52/72 | 26.961 | [0.566%, 7.712%] | [44.444%, 100.000%] |
| URL_V7 raw | 6/11 | 4/5 | 545.455 | [33.333%, 100.000%] | [33.333%, 100.000%] |
| URL_V7 adjudicated | 5/11 | 4/5 | 454.545 | [22.222%, 100.000%] | [33.333%, 100.000%] |
| URL_V8 raw | 6/11 | 4/5 | 545.455 | [30.750%, 100.000%] | [33.333%, 100.000%] |
| URL_V8 adjudicated | 6/11 | 5/5 | 545.455 | [33.333%, 100.000%] | [100.000%, 100.000%] |

**PROVISIONAL label-status table (adjudicated):**

| Model | Label status | Labeled benign / attack | FP / TP | All-row alert rate |
| --- | --- | --- | --- | --- |
| Messages_V2 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 46.154% |
| Messages_V2 | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 18 / 0 | 2.542% |
| Messages_V2 | SYNTHETIC_AUTHORED | 108 / 72 | 0 / 4 | 2.222% |
| Messages_V4.3 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 41.880% |
| Messages_V4.3 | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 8 / 0 | 1.130% |
| Messages_V4.3 | SYNTHETIC_AUTHORED | 108 / 72 | 16 / 32 | 26.667% |
| Messages_V4.4_candidate_a_corrected | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 48.718% |
| Messages_V4.4_candidate_a_corrected | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 35 / 0 | 4.944% |
| Messages_V4.4_candidate_a_corrected | SYNTHETIC_AUTHORED | 108 / 72 | 24 / 52 | 42.222% |
| Messages_V4.4_candidate_b_refined | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 30.769% |
| Messages_V4.4_candidate_b_refined | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 13 / 0 | 1.836% |
| Messages_V4.4_candidate_b_refined | SYNTHETIC_AUTHORED | 108 / 72 | 20 / 52 | 40.000% |
| Messages_V4.4_candidate_c_balanced | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 30.769% |
| Messages_V4.4_candidate_c_balanced | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 25 / 0 | 3.531% |
| Messages_V4.4_candidate_c_balanced | SYNTHETIC_AUTHORED | 108 / 72 | 28 / 48 | 42.222% |
| Messages_V4.4_rc2_experiment_1 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 25.641% |
| Messages_V4.4_rc2_experiment_1 | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 7 / 0 | 0.989% |
| Messages_V4.4_rc2_experiment_1 | SYNTHETIC_AUTHORED | 108 / 72 | 24 / 48 | 40.000% |
| Messages_V4.4_rc2_experiment_2 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 29.060% |
| Messages_V4.4_rc2_experiment_2 | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 7 / 0 | 0.989% |
| Messages_V4.4_rc2_experiment_2 | SYNTHETIC_AUTHORED | 108 / 72 | 20 / 52 | 40.000% |
| Messages_V4.4_rc2_experiment_3 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 22.222% |
| Messages_V4.4_rc2_experiment_3 | PROVISIONAL_BENIGN_UNREVIEWED | 708 / 0 | 6 / 0 | 0.847% |
| Messages_V4.4_rc2_experiment_3 | SYNTHETIC_AUTHORED | 108 / 72 | 16 / 52 | 37.778% |
| URL_V7 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 26.190% |
| URL_V7 | SYNTHETIC_AUTHORED | 11 / 5 | 5 / 4 | 56.250% |
| URL_V7 | SYNTHETIC_UNRESOLVED | 0 / 0 | 0 / 0 | 100.000% |
| URL_V8 | NEEDS_REVIEW | 0 / 0 | 0 / 0 | 38.095% |
| URL_V8 | SYNTHETIC_AUTHORED | 11 / 5 | 6 / 5 | 68.750% |
| URL_V8 | SYNTHETIC_UNRESOLVED | 0 / 0 | 0 / 0 | 100.000% |

**PROVISIONAL natural-message burden:**

| Model/path | Alerts / provisional benign | Alerts / 1,000 benign | False alerts/day at .1% attacks, V=300 | Bootstrap 95% CI/day |
| --- | --- | --- | --- | --- |
| Messages_V2 raw | 19/708 | 26.836 | 8.043 | [0.900, 32.042] |
| Messages_V2 adjudicated | 18/708 | 25.424 | 7.619 | [0.643, 32.957] |
| Messages_V4.3 raw | 20/708 | 28.249 | 8.466 | [4.381, 16.579] |
| Messages_V4.3 adjudicated | 8/708 | 11.299 | 3.386 | [1.226, 11.102] |
| Messages_V4.4_candidate_a_corrected raw | 42/708 | 59.322 | 17.779 | [10.010, 33.731] |
| Messages_V4.4_candidate_a_corrected adjudicated | 35/708 | 49.435 | 14.816 | [8.285, 30.275] |
| Messages_V4.4_candidate_b_refined raw | 28/708 | 39.548 | 11.853 | [3.632, 17.146] |
| Messages_V4.4_candidate_b_refined adjudicated | 13/708 | 18.362 | 5.503 | [1.833, 9.253] |
| Messages_V4.4_candidate_c_balanced raw | 36/708 | 50.847 | 15.239 | [4.738, 27.049] |
| Messages_V4.4_candidate_c_balanced adjudicated | 25/708 | 35.311 | 10.583 | [2.814, 23.133] |
| Messages_V4.4_rc2_experiment_1 raw | 29/708 | 40.960 | 12.276 | [6.514, 24.379] |
| Messages_V4.4_rc2_experiment_1 adjudicated | 7/708 | 9.887 | 2.963 | [0.803, 6.279] |
| Messages_V4.4_rc2_experiment_2 raw | 32/708 | 45.198 | 13.546 | [5.133, 22.109] |
| Messages_V4.4_rc2_experiment_2 adjudicated | 7/708 | 9.887 | 2.963 | [0.534, 5.576] |
| Messages_V4.4_rc2_experiment_3 raw | 34/708 | 48.023 | 14.392 | [4.671, 21.569] |
| Messages_V4.4_rc2_experiment_3 adjudicated | 6/708 | 8.475 | 2.540 | [0.805, 6.587] |

**ASSUMED transported message projections / authored-only URL projections:** Messages rows below transport authored attack recall to provisional natural benign FPR; URL rows use authored FPR/recall because natural URL truth is absent. Each scenario assumes stable class-conditional rates; no measured deployment precision is claimed. Every cell is not decision-grade, especially two message attack families or five URL attack domains. Degenerate bootstrap intervals must be read with cluster counts/zero-event bounds in JSON.

| Model/path | Assumed attack prevalence | PPV [bootstrap 95% CI] | Recall [bootstrap 95% CI] | False alerts/day | Total alerts/day |
| --- | --- | --- | --- | --- | --- |
| Messages_V2 raw | 0.100% | 0.413% [0.104%, 3.375%] | 11.111% [11.111%, 11.111%] | 8.043 | 8.076 |
| Messages_V2 raw | 1.000% | 4.014% [1.039%, 26.058%] | 11.111% [11.111%, 11.111%] | 7.970 | 8.304 |
| Messages_V2 raw | 5.000% | 17.892% [5.187%, 64.742%] | 11.111% [11.111%, 11.111%] | 7.648 | 9.315 |
| Messages_V2 adjudicated | 0.100% | 0.218% [0.000%, 3.224%] | 5.556% [0.000%, 11.111%] | 7.619 | 7.636 |
| Messages_V2 adjudicated | 1.000% | 2.160% [0.000%, 25.159%] | 5.556% [0.000%, 11.111%] | 7.551 | 7.718 |
| Messages_V2 adjudicated | 5.000% | 10.315% [0.000%, 63.657%] | 5.556% [0.000%, 11.111%] | 7.246 | 8.079 |
| Messages_V4.3 raw | 0.100% | 1.741% [0.903%, 3.447%] | 50.000% [44.444%, 55.556%] | 8.466 | 8.616 |
| Messages_V4.3 raw | 1.000% | 15.167% [8.425%, 26.483%] | 50.000% [44.444%, 55.556%] | 8.390 | 9.890 |
| Messages_V4.3 raw | 5.000% | 48.229% [32.404%, 65.242%] | 50.000% [44.444%, 55.556%] | 8.051 | 15.551 |
| Messages_V4.3 adjudicated | 0.100% | 3.788% [1.225%, 11.133%] | 44.444% [44.444%, 44.444%] | 3.386 | 3.520 |
| Messages_V4.3 adjudicated | 1.000% | 28.434% [11.122%, 55.834%] | 44.444% [44.444%, 44.444%] | 3.356 | 4.689 |
| Messages_V4.3 adjudicated | 5.000% | 67.429% [39.468%, 86.820%] | 44.444% [44.444%, 44.444%] | 3.220 | 9.887 |
| Messages_V4.4_candidate_a_corrected raw | 0.100% | 1.204% [0.480%, 2.313%] | 72.222% [44.444%, 100.000%] | 17.779 | 17.995 |
| Messages_V4.4_candidate_a_corrected raw | 1.000% | 10.951% [4.644%, 19.284%] | 72.222% [44.444%, 100.000%] | 17.619 | 19.785 |
| Messages_V4.4_candidate_a_corrected raw | 5.000% | 39.053% [20.240%, 55.454%] | 72.222% [44.444%, 100.000%] | 16.907 | 27.740 |
| Messages_V4.4_candidate_a_corrected adjudicated | 0.100% | 1.441% [0.524%, 2.916%] | 72.222% [44.444%, 100.000%] | 14.816 | 15.032 |
| Messages_V4.4_candidate_a_corrected adjudicated | 1.000% | 12.859% [5.044%, 23.256%] | 72.222% [44.444%, 100.000%] | 14.682 | 16.849 |
| Messages_V4.4_candidate_a_corrected adjudicated | 5.000% | 43.468% [21.676%, 61.225%] | 72.222% [44.444%, 100.000%] | 14.089 | 24.922 |
| Messages_V4.4_candidate_b_refined raw | 0.100% | 1.931% [1.022%, 6.791%] | 77.778% [55.556%, 100.000%] | 11.853 | 12.086 |
| Messages_V4.4_candidate_b_refined raw | 1.000% | 16.573% [9.434%, 42.371%] | 77.778% [55.556%, 100.000%] | 11.746 | 14.079 |
| Messages_V4.4_candidate_b_refined raw | 5.000% | 50.862% [35.181%, 79.300%] | 77.778% [55.556%, 100.000%] | 11.271 | 22.938 |
| Messages_V4.4_candidate_b_refined adjudicated | 0.100% | 3.788% [1.620%, 11.007%] | 72.222% [44.444%, 100.000%] | 5.503 | 5.720 |
| Messages_V4.4_candidate_b_refined adjudicated | 1.000% | 28.434% [14.246%, 55.518%] | 72.222% [44.444%, 100.000%] | 5.453 | 7.620 |
| Messages_V4.4_candidate_b_refined adjudicated | 5.000% | 67.429% [46.398%, 86.672%] | 72.222% [44.444%, 100.000%] | 5.233 | 16.066 |
| Messages_V4.4_candidate_c_balanced raw | 0.100% | 1.402% [0.692%, 3.872%] | 72.222% [55.556%, 88.889%] | 15.239 | 15.456 |
| Messages_V4.4_candidate_c_balanced raw | 1.000% | 12.547% [6.570%, 28.901%] | 72.222% [55.556%, 88.889%] | 15.102 | 17.268 |
| Messages_V4.4_candidate_c_balanced raw | 5.000% | 42.777% [26.815%, 67.929%] | 72.222% [55.556%, 88.889%] | 14.492 | 25.325 |
| Messages_V4.4_candidate_c_balanced adjudicated | 0.100% | 1.855% [0.723%, 6.065%] | 66.667% [44.444%, 88.889%] | 10.583 | 10.783 |
| Messages_V4.4_candidate_c_balanced adjudicated | 1.000% | 16.016% [6.843%, 39.447%] | 66.667% [44.444%, 88.889%] | 10.487 | 12.487 |
| Messages_V4.4_candidate_c_balanced adjudicated | 5.000% | 49.842% [27.680%, 77.243%] | 66.667% [44.444%, 88.889%] | 10.064 | 20.064 |
| Messages_V4.4_rc2_experiment_1 raw | 0.100% | 1.734% [0.669%, 3.552%] | 72.222% [44.444%, 100.000%] | 12.276 | 12.493 |
| Messages_V4.4_rc2_experiment_1 raw | 1.000% | 15.118% [6.367%, 27.096%] | 72.222% [44.444%, 100.000%] | 12.165 | 14.332 |
| Messages_V4.4_rc2_experiment_1 raw | 5.000% | 48.133% [26.161%, 65.947%] | 72.222% [44.444%, 100.000%] | 11.674 | 22.507 |
| Messages_V4.4_rc2_experiment_1 adjudicated | 0.100% | 6.323% [2.555%, 19.065%] | 66.667% [44.444%, 88.889%] | 2.963 | 3.163 |
| Messages_V4.4_rc2_experiment_1 adjudicated | 1.000% | 40.515% [20.921%, 70.388%] | 66.667% [44.444%, 88.889%] | 2.936 | 4.936 |
| Messages_V4.4_rc2_experiment_1 adjudicated | 5.000% | 78.017% [57.956%, 92.529%] | 66.667% [44.444%, 88.889%] | 2.818 | 12.818 |
| Messages_V4.4_rc2_experiment_2 raw | 0.100% | 1.574% [0.691%, 5.038%] | 72.222% [44.444%, 100.000%] | 13.546 | 13.762 |
| Messages_V4.4_rc2_experiment_2 raw | 1.000% | 13.897% [6.560%, 34.866%] | 72.222% [44.444%, 100.000%] | 13.424 | 15.590 |
| Messages_V4.4_rc2_experiment_2 raw | 5.000% | 45.682% [26.784%, 73.609%] | 72.222% [44.444%, 100.000%] | 12.881 | 23.715 |
| Messages_V4.4_rc2_experiment_2 adjudicated | 0.100% | 6.814% [2.847%, 30.400%] | 72.222% [44.444%, 100.000%] | 2.963 | 3.180 |
| Messages_V4.4_rc2_experiment_2 adjudicated | 1.000% | 42.458% [22.822%, 81.505%] | 72.222% [44.444%, 100.000%] | 2.936 | 5.103 |
| Messages_V4.4_rc2_experiment_2 adjudicated | 5.000% | 79.359% [60.641%, 95.827%] | 72.222% [44.444%, 100.000%] | 2.818 | 13.651 |
| Messages_V4.4_rc2_experiment_3 raw | 0.100% | 1.483% [0.679%, 5.187%] | 72.222% [44.444%, 100.000%] | 14.392 | 14.609 |
| Messages_V4.4_rc2_experiment_3 raw | 1.000% | 13.188% [6.457%, 35.568%] | 72.222% [44.444%, 100.000%] | 14.263 | 16.429 |
| Messages_V4.4_rc2_experiment_3 raw | 5.000% | 44.182% [26.451%, 74.201%] | 72.222% [44.444%, 100.000%] | 13.686 | 24.520 |
| Messages_V4.4_rc2_experiment_3 adjudicated | 0.100% | 7.860% [2.764%, 23.583%] | 72.222% [44.444%, 100.000%] | 2.540 | 2.756 |
| Messages_V4.4_rc2_experiment_3 adjudicated | 1.000% | 46.261% [22.293%, 75.689%] | 72.222% [44.444%, 100.000%] | 2.517 | 4.684 |
| Messages_V4.4_rc2_experiment_3 adjudicated | 5.000% | 81.770% [59.916%, 94.193%] | 72.222% [44.444%, 100.000%] | 2.415 | 13.249 |
| URL_V7 raw | 0.100% | 0.147% [0.055%, 0.275%] | 80.000% [33.333%, 100.000%] | 16.347 | 16.371 |
| URL_V7 raw | 1.000% | 1.460% [0.557%, 2.703%] | 80.000% [33.333%, 100.000%] | 16.200 | 16.440 |
| URL_V7 raw | 5.000% | 7.166% [2.835%, 12.644%] | 80.000% [33.333%, 100.000%] | 15.545 | 16.745 |
| URL_V7 adjudicated | 0.100% | 0.176% [0.050%, 0.388%] | 80.000% [33.333%, 100.000%] | 13.623 | 13.647 |
| URL_V7 adjudicated | 1.000% | 1.747% [0.503%, 3.780%] | 80.000% [33.333%, 100.000%] | 13.500 | 13.740 |
| URL_V7 adjudicated | 5.000% | 8.478% [2.564%, 16.990%] | 80.000% [33.333%, 100.000%] | 12.955 | 14.155 |
| URL_V8 raw | 0.100% | 0.147% [0.056%, 0.279%] | 80.000% [40.000%, 100.000%] | 16.347 | 16.371 |
| URL_V8 raw | 1.000% | 1.460% [0.562%, 2.750%] | 80.000% [40.000%, 100.000%] | 16.200 | 16.440 |
| URL_V8 raw | 5.000% | 7.166% [2.863%, 12.844%] | 80.000% [40.000%, 100.000%] | 15.545 | 16.745 |
| URL_V8 adjudicated | 0.100% | 0.183% [0.100%, 0.299%] | 100.000% [100.000%, 100.000%] | 16.347 | 16.377 |
| URL_V8 adjudicated | 1.000% | 1.818% [1.000%, 2.941%] | 100.000% [100.000%, 100.000%] | 16.200 | 16.500 |
| URL_V8 adjudicated | 5.000% | 8.800% [5.000%, 13.636%] | 100.000% [100.000%, 100.000%] | 15.545 | 17.045 |

## Overlap, segments, calibration and failures

**PROVISIONAL:** all-model raw/adjudicated all/without-overlap/overlap-only metrics and intervals are in `metrics_summary.jsonl`. Selected no-drop comparisons:

| Model/path | Scope | FP/benign | TP/attack |
| --- | --- | --- | --- |
| Messages_V4.3 raw | without_overlap | 44/803 | 36/72 |
| Messages_V4.3 raw | overlap_only | 0/13 | 0/0 |
| Messages_V4.3 adjudicated | without_overlap | 24/803 | 32/72 |
| Messages_V4.3 adjudicated | overlap_only | 0/13 | 0/0 |
| URL_V8 raw | without_overlap | 4/4 | 2/3 |
| URL_V8 raw | overlap_only | 2/7 | 2/2 |
| URL_V8 adjudicated | without_overlap | 4/4 | 3/3 |
| URL_V8 adjudicated | overlap_only | 2/7 | 2/2 |

**OBSERVED:** `segment_metrics.jsonl` contains 988 raw/adjudicated cells across language/script, channel, conversation, family, label_status, overlap, pull and URL form/domain/popularity. Every cell includes class/cluster counts, uncertainty and not_decision_grade=true; the absence of decision-grade evidence is not hidden by aggregation. V4.3's without-overlap sample still has 24/803 conditional benign errors and 32/72 any-alert attack detections, showing the authored failure pattern is not removed by the overlap screen. URL V8 without-overlap has only 4 benign/3 attack cases: insufficient for a novel-domain safety claim.

**OBSERVED:** `calibration_reliability.jsonl` provides reliability-bin curves, ECE and Brier for all labeled, natural-provisional and authored scopes, with raw sample weighting and each assumed prevalence. `threshold_sensitivity.jsonl` lists diagnostic grid outcomes around the locked thresholds, never a selected alternative. `security_metrics_summary.jsonl` and `security_segment_metrics.jsonl` provide a second Messages endpoint requiring MALICIOUS class, rather than any spam/security alert. Its companion calibration/sensitivity files retain the same p(non-benign) diagnostic score; they are not p(M)-specific calibration or a new operating policy. Do not compare any-alert synthetic recall directly to historical three-class malicious recall.

**PROVISIONAL:** `failure_cluster_evidence.jsonl` gives every observed label-conditional error cluster and both FP/FN examples; `worst_failures.jsonl` ranks up to 30 failures/model/path, with score, script, label_status and overlap. Examples, current V8 adjudication: Ahmedabad government portal ≈.999928, Paytm ≈.956639, IRCTC ≈.887285, Tata Power billpay ≈.738310, bare `instagram.com` ≈.609370. Their assumed-benign labels are authored, not newly externally verified. The same fixture with explicit HTTPS or www can follow different structural paths, so neither old parser diagnosis nor a claimed universal canonicalization fix is assumed.

**OBSERVED:** 13,536 row-level logged/current comparisons and 80 per-pull/model/path summaries are recorded. They compare logged non-green app outcomes against model-only alerts, not truth. URL parent-message risk is not necessarily a URL verdict; group/contact/fusion effects and salvage corruption confound attribution. Counts/IDs/predictions/explanations are retained in `logged_comparison.jsonl`. No agreement score resolves the generation conflict.

## Preserved disagreements

| Status | Conflicting figures/claims | Disposition |
| --- | --- | --- |
| OBSERVED vs REPORTED | V2 current 20/520 FPs, 1403/1556 malicious correct; 6sep baseline 10/520 and 1402/1556 | Feature/sender/source version closure unresolved; do not choose favorable report |
| OBSERVED and REPORTED | V4.3 1510/1556, 2/520, spam→M 90/188 and 31/83 | Reproduced exactly in current environment |
| OBSERVED vs REPORTED | source_type out-of-schema 4047 now vs second forensic 4154; primary_type 3817 across 20 values now | Current schema enum and train hash retained; earlier denominator/schema definition unresolved |
| OBSERVED vs REPORTED | V7 clean adjudicated 98.752%/.976%, hard .459%; V8 current URL-aware 98.605%/.962%, hard 3.369%; older V8 report 98.68%/1.17%, hard .36% | Different raw/gating/URL-aware policy and report versions; no averaging or assertion historically equivalent |
| OBSERVED | V8 with URLs 22835 TP/263 FP; no-URL fallback 22825 TP/207 FP | Different callable paths in same frozen wrapper; both reported explicitly |
| OBSERVED vs REPORTED | 68 malicious,1 spam,0 benign Devanagari and 0 nonASCII char tokens now; earlier blackout 92% | Coverage gap reproduced, exact 92% not claimed for new authored texts |
| OBSERVED vs REPORTED | 21-corpus new simulation overlap 28/1005 and 66/102 URL source-domain flags; prior 9/294 and6/562 | New sampling/normalization/corpus scope; not comparable row denominators; tags retained |
| REPORTED | User three-pull mapping vs master installed V2/V7 and unsigned V4.3/V8 | UNRESOLVED per pull despite APK asset identity |
| REPORTED | V4.4 historical system FPR0/55 vs forensic25/55; zero exact collisions vs601 normalized rows | Historical audit retracts favorable claim; current study does not certify old holdouts independent |
| REPORTED | V4.5 77.70% TEST recall/3.08% FPR vs V4.3 97.04%/.38%; source audit says strict leakage rejection despite307 aggressive collisions | Historical reference only; Step7 named baselines exclude V4.5; embedding/classifier closure not certified here |
| REPORTED | URL reconciliation earlier4248/4254=99.853 vs4170/4254=98.025;681/682=99.853 separate cohort | Cohort conflation retained, not redefined |
| REPORTED | Hard-benign draft304/500=60.8 vs419 raw/420 adjudicated; benign total43027 vs42941 | Comparison-only historical disagreement; 500 not scored/tuned in this pass |
| REPORTED | Master parityN500 vs174 URL fixtures; cold-start<15ms vs Gate9<20ms | Different fixtures/endpoints; no Android execution or hardware conclusion |
| OBSERVED | New salvage568 October archive candidates vs older562 record recovery, only154 exact keys match | Snapshot/byte recovery differences unresolved; no complete-row claim |

**OBSERVED limitation:** this ledger covers the specifically cited reports/hashes, not a claim of an exhaustive audit of every historical document. New inferences are reproducible, label correctness remains provisional, and no present simulation supports approving release today.
