# Stage 0 — Hinglish probe results

Date: October 22, 2026 (Asia/Calcutta). **Verdict under the unchanged pre-registered rules: “Recall is also a problem” for all eight text-only frozen models. False positives are not the only observed problem.** This is a single-author synthetic stress probe; it does not measure real-world prevalence or prove real-world attack recall. A synthetic failure is informative; a pass would not certify field performance.

Evidence labels: **OBSERVED** means executed/inspected here; **ASSUMED** means generator intent/label or design choice; **REPORTED** means historical claim; **PROVISIONAL** means an interpretation relying on unreviewed synthetic labels. No training, GPU request, threshold change, calibration fit, export, source/model overwrite, Android/Kotlin/Gradle execution, link fetch or DNS resolution occurred. Neither datasets_v5 nor user_data was opened. The set is frozen as an exam and must not enter later training/tuning.

## 1. Primary answer: MALICIOUS only, SPAM never alerts

**OBSERVED decisions / ASSUMED labels:** 480 malicious, 480 benign, 120 spam Hinglish rows; 120 malicious and 120 benign English twins. Text-only inference uses sender=None and the original frozen p(non-benign) threshold followed by the spam/malicious class decision. Positive=final MALICIOUS, never SPAM. Raw three-class probabilities/argmax and final class are retained separately; this is not a new threshold policy or an Android fused-alert claim.

| Model | Attack recall / Wilson 95% | Benign false alerts / Wilson 95% | Spam false alerts / Wilson 95% | Misses → BENIGN / SPAM | Pre-registered verdict |
| --- | --- | --- | --- | --- | --- |
| V2 | 115/480 (24.0%; [20.4%, 28.0%]) | 95/480 (19.8%; [16.5%, 23.6%]) | 12/120 (10.0%; [5.8%, 16.7%]) | 358 / 7 | Recall is also a problem |
| V4.3 | 207/480 (43.1%; [38.8%, 47.6%]) | 87/480 (18.1%; [14.9%, 21.8%]) | 20/120 (16.7%; [11.1%, 24.3%]) | 273 / 0 | Recall is also a problem |
| V4.4_candidate_a_corrected | 314/480 (65.4%; [61.1%, 69.5%]) | 203/480 (42.3%; [38.0%, 46.8%]) | 39/120 (32.5%; [24.8%, 41.3%]) | 166 / 0 | Recall is also a problem |
| V4.4_candidate_b_refined | 279/480 (58.1%; [53.7%, 62.5%]) | 144/480 (30.0%; [26.1%, 34.2%]) | 24/120 (20.0%; [13.8%, 28.0%]) | 201 / 0 | Recall is also a problem |
| V4.4_candidate_c_balanced | 257/480 (53.5%; [49.1%, 58.0%]) | 131/480 (27.3%; [23.5%, 31.4%]) | 27/120 (22.5%; [15.9%, 30.8%]) | 223 / 0 | Recall is also a problem |
| V4.4_rc2_experiment_1 | 170/480 (35.4%; [31.3%, 39.8%]) | 71/480 (14.8%; [11.9%, 18.2%]) | 20/120 (16.7%; [11.1%, 24.3%]) | 310 / 0 | Recall is also a problem |
| V4.4_rc2_experiment_2 | 182/480 (37.9%; [33.7%, 42.3%]) | 72/480 (15.0%; [12.1%, 18.5%]) | 20/120 (16.7%; [11.1%, 24.3%]) | 298 / 0 | Recall is also a problem |
| V4.4_rc2_experiment_3 | 128/480 (26.7%; [22.9%, 30.8%]) | 53/480 (11.0%; [8.5%, 14.2%]) | 15/120 (12.5%; [7.7%, 19.6%]) | 352 / 0 | Recall is also a problem |

**OBSERVED:** V4.3 detects207/480=43.125%, misses273, all classified BENIGN. V2 detects115/480=23.958%, misses365 (358BENIGN,7SPAM). Best text-only point recall is V4.4 CandidateA314/480=65.417%, while it falsely alerts on203/480 benign and39/120 spam rows. Spam-never-alerts does not rescue these attacks: the misses are overwhelmingly below the benign boundary, not merely assigned to spam. No single model is chosen or promoted from these results.

**PROPOSED rules applied without revision:** FP-main requires lower95% overall recall≥.90, no N≥30family pointrecall<.80 and paired-English gap≤5points. Recall-also if pointrecall<.85 OR≥3families below.80 OR paired-English gap>10points. Otherwise mixed/inconclusive. All eight text-only models satisfy the recall-also condition through overall recall; family and twin gaps also trigger it. Exact Boolean rule inputs are in verdicts.json.

| Model | Families below80% (N≥30) | Paired English−Hinglish gap, points | Recall lower95% |
| --- | --- | --- | --- |
| V2 | 12 | 20.83 | 20.4% |
| V4.3 | 12 | 32.50 | 38.8% |
| V4.4_candidate_a_corrected | 12 | 15.83 | 61.1% |
| V4.4_candidate_b_refined | 11 | 20.83 | 53.7% |
| V4.4_candidate_c_balanced | 12 | 18.33 | 49.1% |
| V4.4_rc2_experiment_1 | 12 | 32.50 | 31.3% |
| V4.4_rc2_experiment_2 | 12 | 40.00 | 33.7% |
| V4.4_rc2_experiment_3 | 12 | 42.50 | 22.9% |

## 2. Family breakdown

**OBSERVED / PROVISIONAL:** each family has40Hinglish attacks. Cells give detected/N,pointrecall andWilson95%; these are row-level synthetic intervals, not independent-population evidence. Near templates are capped, but shared frames/translation ancestry still correlate rows.

| Family | V2 | V4.3 | V4.4_candidate_a_corrected | V4.4_candidate_b_refined | V4.4_candidate_c_balanced | V4.4_rc2_experiment_1 | V4.4_rc2_experiment_2 | V4.4_rc2_experiment_3 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| APK_install_lure | 8/40 (20.0%; [10.5%, 34.8%]) | 20/40 (50.0%; [35.2%, 64.8%]) | 29/40 (72.5%; [57.2%, 83.9%]) | 31/40 (77.5%; [62.5%, 87.7%]) | 29/40 (72.5%; [57.2%, 83.9%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 20/40 (50.0%; [35.2%, 64.8%]) | 14/40 (35.0%; [22.1%, 50.5%]) |
| OTP_coercion | 6/40 (15.0%; [7.1%, 29.1%]) | 23/40 (57.5%; [42.2%, 71.5%]) | 27/40 (67.5%; [52.0%, 79.9%]) | 21/40 (52.5%; [37.5%, 67.1%]) | 21/40 (52.5%; [37.5%, 67.1%]) | 19/40 (47.5%; [32.9%, 62.5%]) | 20/40 (50.0%; [35.2%, 64.8%]) | 16/40 (40.0%; [26.3%, 55.4%]) |
| SIM_telecom_KYC | 7/40 (17.5%; [8.7%, 31.9%]) | 24/40 (60.0%; [44.6%, 73.7%]) | 31/40 (77.5%; [62.5%, 87.7%]) | 30/40 (75.0%; [59.8%, 85.8%]) | 30/40 (75.0%; [59.8%, 85.8%]) | 25/40 (62.5%; [47.0%, 75.8%]) | 22/40 (55.0%; [39.8%, 69.3%]) | 20/40 (50.0%; [35.2%, 64.8%]) |
| UPI_collect_refund | 26/40 (65.0%; [49.5%, 77.9%]) | 17/40 (42.5%; [28.5%, 57.8%]) | 29/40 (72.5%; [57.2%, 83.9%]) | 27/40 (67.5%; [52.0%, 79.9%]) | 23/40 (57.5%; [42.2%, 71.5%]) | 10/40 (25.0%; [14.2%, 40.2%]) | 12/40 (30.0%; [18.1%, 45.4%]) | 5/40 (12.5%; [5.5%, 26.1%]) |
| bank_KYC_block | 9/40 (22.5%; [12.3%, 37.5%]) | 26/40 (65.0%; [49.5%, 77.9%]) | 31/40 (77.5%; [62.5%, 87.7%]) | 33/40 (82.5%; [68.1%, 91.3%]) | 29/40 (72.5%; [57.2%, 83.9%]) | 23/40 (57.5%; [42.2%, 71.5%]) | 24/40 (60.0%; [44.6%, 73.7%]) | 17/40 (42.5%; [28.5%, 57.8%]) |
| challan_tax_government | 6/40 (15.0%; [7.1%, 29.1%]) | 9/40 (22.5%; [12.3%, 37.5%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 13/40 (32.5%; [20.1%, 48.0%]) | 12/40 (30.0%; [18.1%, 45.4%]) | 8/40 (20.0%; [10.5%, 34.8%]) | 7/40 (17.5%; [8.7%, 31.9%]) | 5/40 (12.5%; [5.5%, 26.1%]) |
| courier_customs_fee | 21/40 (52.5%; [37.5%, 67.1%]) | 16/40 (40.0%; [26.3%, 55.4%]) | 28/40 (70.0%; [54.6%, 81.9%]) | 25/40 (62.5%; [47.0%, 75.8%]) | 28/40 (70.0%; [54.6%, 81.9%]) | 19/40 (47.5%; [32.9%, 62.5%]) | 17/40 (42.5%; [28.5%, 57.8%]) | 15/40 (37.5%; [24.2%, 53.0%]) |
| electricity_gas_callback | 5/40 (12.5%; [5.5%, 26.1%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 27/40 (67.5%; [52.0%, 79.9%]) | 22/40 (55.0%; [39.8%, 69.3%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 10/40 (25.0%; [14.2%, 40.2%]) | 11/40 (27.5%; [16.1%, 42.8%]) | 10/40 (25.0%; [14.2%, 40.2%]) |
| friend_impersonation_money | 9/40 (22.5%; [12.3%, 37.5%]) | 17/40 (42.5%; [28.5%, 57.8%]) | 27/40 (67.5%; [52.0%, 79.9%]) | 22/40 (55.0%; [39.8%, 69.3%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 13/40 (32.5%; [20.1%, 48.0%]) | 14/40 (35.0%; [22.1%, 50.5%]) | 10/40 (25.0%; [14.2%, 40.2%]) |
| job_task_fee | 4/40 (10.0%; [4.0%, 23.1%]) | 19/40 (47.5%; [32.9%, 62.5%]) | 28/40 (70.0%; [54.6%, 81.9%]) | 23/40 (57.5%; [42.2%, 71.5%]) | 24/40 (60.0%; [44.6%, 73.7%]) | 14/40 (35.0%; [22.1%, 50.5%]) | 19/40 (47.5%; [32.9%, 62.5%]) | 9/40 (22.5%; [12.3%, 37.5%]) |
| loan_app_threat | 10/40 (25.0%; [14.2%, 40.2%]) | 10/40 (25.0%; [14.2%, 40.2%]) | 21/40 (52.5%; [37.5%, 67.1%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 12/40 (30.0%; [18.1%, 45.4%]) | 4/40 (10.0%; [4.0%, 23.1%]) | 5/40 (12.5%; [5.5%, 26.1%]) | 1/40 (2.5%; [0.4%, 12.9%]) |
| prize_lottery | 4/40 (10.0%; [4.0%, 23.1%]) | 8/40 (20.0%; [10.5%, 34.8%]) | 18/40 (45.0%; [30.7%, 60.2%]) | 14/40 (35.0%; [22.1%, 50.5%]) | 13/40 (32.5%; [20.1%, 48.0%]) | 7/40 (17.5%; [8.7%, 31.9%]) | 11/40 (27.5%; [16.1%, 42.8%]) | 6/40 (15.0%; [7.1%, 29.1%]) |

## 3. Channel, URL-like text, density, noise and length

**OBSERVED:** below are all requested attack-recall slices, text-only, with their denominators/intervals. `PROBE_BREAKDOWNS.csv` and `probe_breakdowns.jsonl` additionally include benign andspam false-alert rates, three-way confusion, everypersona/batch andall/unflagged source-overlap versions. N<30 is explicitly “indicative only.” A cell with N≥30 is still a synthetic, correlated diagnostic, not automatically real-world decision-grade evidence.

| Model | Axis | Value | Attack recall / Wilson95% |
| --- | --- | --- | --- |
| V2 | channel_style | SMS | 72/240 (30.0%; [24.6%, 36.1%]) |
| V2 | channel_style | WhatsApp | 43/240 (17.9%; [13.6%, 23.3%]) |
| V2 | has_url | false | 35/288 (12.2%; [8.9%, 16.4%]) |
| V2 | has_url | true | 80/192 (41.7%; [34.9%, 48.7%]) |
| V2 | hinglish_density | heavy | 39/160 (24.4%; [18.4%, 31.6%]) |
| V2 | hinglish_density | light | 41/160 (25.6%; [19.5%, 32.9%]) |
| V2 | hinglish_density | medium | 35/160 (21.9%; [16.2%, 28.9%]) |
| V2 | noise_level | clean | 24/96 (25.0%; [17.4%, 34.5%]) |
| V2 | noise_level | missing_vowels | 14/96 (14.6%; [8.9%, 23.0%]) |
| V2 | noise_level | mixed_case | 41/96 (42.7%; [33.3%, 52.7%]) |
| V2 | noise_level | texting_abbrev | 19/96 (19.8%; [13.1%, 28.9%]) |
| V2 | noise_level | typos | 17/96 (17.7%; [11.4%, 26.5%]) |
| V2 | length_bin | long_31_plus | 23/187 (12.3%; [8.3%, 17.8%]) |
| V2 | length_bin | medium_16_30 | 57/199 (28.6%; [22.8%, 35.3%]) |
| V2 | length_bin | short_5_15 | 35/94 (37.2%; [28.1%, 47.3%]) |
| V4.3 | channel_style | SMS | 117/240 (48.8%; [42.5%, 55.0%]) |
| V4.3 | channel_style | WhatsApp | 90/240 (37.5%; [31.6%, 43.8%]) |
| V4.3 | has_url | false | 75/288 (26.0%; [21.3%, 31.4%]) |
| V4.3 | has_url | true | 132/192 (68.8%; [61.9%, 74.9%]) |
| V4.3 | hinglish_density | heavy | 66/160 (41.2%; [33.9%, 49.0%]) |
| V4.3 | hinglish_density | light | 82/160 (51.2%; [43.6%, 58.9%]) |
| V4.3 | hinglish_density | medium | 59/160 (36.9%; [29.8%, 44.6%]) |
| V4.3 | noise_level | clean | 43/96 (44.8%; [35.2%, 54.7%]) |
| V4.3 | noise_level | missing_vowels | 34/96 (35.4%; [26.6%, 45.4%]) |
| V4.3 | noise_level | mixed_case | 52/96 (54.2%; [44.2%, 63.8%]) |
| V4.3 | noise_level | texting_abbrev | 43/96 (44.8%; [35.2%, 54.7%]) |
| V4.3 | noise_level | typos | 35/96 (36.5%; [27.5%, 46.4%]) |
| V4.3 | length_bin | long_31_plus | 40/187 (21.4%; [16.1%, 27.8%]) |
| V4.3 | length_bin | medium_16_30 | 92/199 (46.2%; [39.4%, 53.2%]) |
| V4.3 | length_bin | short_5_15 | 75/94 (79.8%; [70.6%, 86.7%]) |
| V4.4_candidate_a_corrected | channel_style | SMS | 166/240 (69.2%; [63.1%, 74.7%]) |
| V4.4_candidate_a_corrected | channel_style | WhatsApp | 148/240 (61.7%; [55.4%, 67.6%]) |
| V4.4_candidate_a_corrected | has_url | false | 161/288 (55.9%; [50.1%, 61.5%]) |
| V4.4_candidate_a_corrected | has_url | true | 153/192 (79.7%; [73.4%, 84.8%]) |
| V4.4_candidate_a_corrected | hinglish_density | heavy | 106/160 (66.2%; [58.6%, 73.1%]) |
| V4.4_candidate_a_corrected | hinglish_density | light | 108/160 (67.5%; [59.9%, 74.3%]) |
| V4.4_candidate_a_corrected | hinglish_density | medium | 100/160 (62.5%; [54.8%, 69.6%]) |
| V4.4_candidate_a_corrected | noise_level | clean | 61/96 (63.5%; [53.6%, 72.5%]) |
| V4.4_candidate_a_corrected | noise_level | missing_vowels | 65/96 (67.7%; [57.8%, 76.2%]) |
| V4.4_candidate_a_corrected | noise_level | mixed_case | 68/96 (70.8%; [61.1%, 79.0%]) |
| V4.4_candidate_a_corrected | noise_level | texting_abbrev | 64/96 (66.7%; [56.8%, 75.3%]) |
| V4.4_candidate_a_corrected | noise_level | typos | 56/96 (58.3%; [48.3%, 67.7%]) |
| V4.4_candidate_a_corrected | length_bin | long_31_plus | 91/187 (48.7%; [41.6%, 55.8%]) |
| V4.4_candidate_a_corrected | length_bin | medium_16_30 | 143/199 (71.9%; [65.2%, 77.6%]) |
| V4.4_candidate_a_corrected | length_bin | short_5_15 | 80/94 (85.1%; [76.5%, 90.9%]) |
| V4.4_candidate_b_refined | channel_style | SMS | 147/240 (61.3%; [55.0%, 67.2%]) |
| V4.4_candidate_b_refined | channel_style | WhatsApp | 132/240 (55.0%; [48.7%, 61.2%]) |
| V4.4_candidate_b_refined | has_url | false | 152/288 (52.8%; [47.0%, 58.5%]) |
| V4.4_candidate_b_refined | has_url | true | 127/192 (66.1%; [59.2%, 72.5%]) |
| V4.4_candidate_b_refined | hinglish_density | heavy | 89/160 (55.6%; [47.9%, 63.1%]) |
| V4.4_candidate_b_refined | hinglish_density | light | 103/160 (64.4%; [56.7%, 71.4%]) |
| V4.4_candidate_b_refined | hinglish_density | medium | 87/160 (54.4%; [46.6%, 61.9%]) |
| V4.4_candidate_b_refined | noise_level | clean | 54/96 (56.2%; [46.3%, 65.7%]) |
| V4.4_candidate_b_refined | noise_level | missing_vowels | 49/96 (51.0%; [41.2%, 60.8%]) |
| V4.4_candidate_b_refined | noise_level | mixed_case | 73/96 (76.0%; [66.6%, 83.5%]) |
| V4.4_candidate_b_refined | noise_level | texting_abbrev | 56/96 (58.3%; [48.3%, 67.7%]) |
| V4.4_candidate_b_refined | noise_level | typos | 47/96 (49.0%; [39.2%, 58.8%]) |
| V4.4_candidate_b_refined | length_bin | long_31_plus | 85/187 (45.5%; [38.5%, 52.6%]) |
| V4.4_candidate_b_refined | length_bin | medium_16_30 | 130/199 (65.3%; [58.5%, 71.6%]) |
| V4.4_candidate_b_refined | length_bin | short_5_15 | 64/94 (68.1%; [58.1%, 76.6%]) |
| V4.4_candidate_c_balanced | channel_style | SMS | 130/240 (54.2%; [47.8%, 60.4%]) |
| V4.4_candidate_c_balanced | channel_style | WhatsApp | 127/240 (52.9%; [46.6%, 59.1%]) |
| V4.4_candidate_c_balanced | has_url | false | 127/288 (44.1%; [38.5%, 49.9%]) |
| V4.4_candidate_c_balanced | has_url | true | 130/192 (67.7%; [60.8%, 73.9%]) |
| V4.4_candidate_c_balanced | hinglish_density | heavy | 78/160 (48.8%; [41.1%, 56.4%]) |
| V4.4_candidate_c_balanced | hinglish_density | light | 97/160 (60.6%; [52.9%, 67.9%]) |
| V4.4_candidate_c_balanced | hinglish_density | medium | 82/160 (51.2%; [43.6%, 58.9%]) |
| V4.4_candidate_c_balanced | noise_level | clean | 49/96 (51.0%; [41.2%, 60.8%]) |
| V4.4_candidate_c_balanced | noise_level | missing_vowels | 42/96 (43.8%; [34.3%, 53.7%]) |
| V4.4_candidate_c_balanced | noise_level | mixed_case | 74/96 (77.1%; [67.7%, 84.4%]) |
| V4.4_candidate_c_balanced | noise_level | texting_abbrev | 51/96 (53.1%; [43.2%, 62.8%]) |
| V4.4_candidate_c_balanced | noise_level | typos | 41/96 (42.7%; [33.3%, 52.7%]) |
| V4.4_candidate_c_balanced | length_bin | long_31_plus | 73/187 (39.0%; [32.3%, 46.2%]) |
| V4.4_candidate_c_balanced | length_bin | medium_16_30 | 118/199 (59.3%; [52.4%, 65.9%]) |
| V4.4_candidate_c_balanced | length_bin | short_5_15 | 66/94 (70.2%; [60.3%, 78.5%]) |
| V4.4_rc2_experiment_1 | channel_style | SMS | 98/240 (40.8%; [34.8%, 47.1%]) |
| V4.4_rc2_experiment_1 | channel_style | WhatsApp | 72/240 (30.0%; [24.6%, 36.1%]) |
| V4.4_rc2_experiment_1 | has_url | false | 63/288 (21.9%; [17.5%, 27.0%]) |
| V4.4_rc2_experiment_1 | has_url | true | 107/192 (55.7%; [48.7%, 62.6%]) |
| V4.4_rc2_experiment_1 | hinglish_density | heavy | 52/160 (32.5%; [25.7%, 40.1%]) |
| V4.4_rc2_experiment_1 | hinglish_density | light | 66/160 (41.2%; [33.9%, 49.0%]) |
| V4.4_rc2_experiment_1 | hinglish_density | medium | 52/160 (32.5%; [25.7%, 40.1%]) |
| V4.4_rc2_experiment_1 | noise_level | clean | 34/96 (35.4%; [26.6%, 45.4%]) |
| V4.4_rc2_experiment_1 | noise_level | missing_vowels | 24/96 (25.0%; [17.4%, 34.5%]) |
| V4.4_rc2_experiment_1 | noise_level | mixed_case | 57/96 (59.4%; [49.4%, 68.7%]) |
| V4.4_rc2_experiment_1 | noise_level | texting_abbrev | 30/96 (31.2%; [22.9%, 41.1%]) |
| V4.4_rc2_experiment_1 | noise_level | typos | 25/96 (26.0%; [18.3%, 35.6%]) |
| V4.4_rc2_experiment_1 | length_bin | long_31_plus | 37/187 (19.8%; [14.7%, 26.1%]) |
| V4.4_rc2_experiment_1 | length_bin | medium_16_30 | 75/199 (37.7%; [31.2%, 44.6%]) |
| V4.4_rc2_experiment_1 | length_bin | short_5_15 | 58/94 (61.7%; [51.6%, 70.9%]) |
| V4.4_rc2_experiment_2 | channel_style | SMS | 101/240 (42.1%; [36.0%, 48.4%]) |
| V4.4_rc2_experiment_2 | channel_style | WhatsApp | 81/240 (33.8%; [28.1%, 39.9%]) |
| V4.4_rc2_experiment_2 | has_url | false | 68/288 (23.6%; [19.1%, 28.8%]) |
| V4.4_rc2_experiment_2 | has_url | true | 114/192 (59.4%; [52.3%, 66.1%]) |
| V4.4_rc2_experiment_2 | hinglish_density | heavy | 54/160 (33.8%; [26.9%, 41.4%]) |
| V4.4_rc2_experiment_2 | hinglish_density | light | 69/160 (43.1%; [35.7%, 50.9%]) |
| V4.4_rc2_experiment_2 | hinglish_density | medium | 59/160 (36.9%; [29.8%, 44.6%]) |
| V4.4_rc2_experiment_2 | noise_level | clean | 33/96 (34.4%; [25.6%, 44.3%]) |
| V4.4_rc2_experiment_2 | noise_level | missing_vowels | 29/96 (30.2%; [21.9%, 40.0%]) |
| V4.4_rc2_experiment_2 | noise_level | mixed_case | 60/96 (62.5%; [52.5%, 71.5%]) |
| V4.4_rc2_experiment_2 | noise_level | texting_abbrev | 33/96 (34.4%; [25.6%, 44.3%]) |
| V4.4_rc2_experiment_2 | noise_level | typos | 27/96 (28.1%; [20.1%, 37.8%]) |
| V4.4_rc2_experiment_2 | length_bin | long_31_plus | 38/187 (20.3%; [15.2%, 26.7%]) |
| V4.4_rc2_experiment_2 | length_bin | medium_16_30 | 83/199 (41.7%; [35.1%, 48.7%]) |
| V4.4_rc2_experiment_2 | length_bin | short_5_15 | 61/94 (64.9%; [54.8%, 73.8%]) |
| V4.4_rc2_experiment_3 | channel_style | SMS | 74/240 (30.8%; [25.3%, 36.9%]) |
| V4.4_rc2_experiment_3 | channel_style | WhatsApp | 54/240 (22.5%; [17.7%, 28.2%]) |
| V4.4_rc2_experiment_3 | has_url | false | 42/288 (14.6%; [11.0%, 19.1%]) |
| V4.4_rc2_experiment_3 | has_url | true | 86/192 (44.8%; [37.9%, 51.9%]) |
| V4.4_rc2_experiment_3 | hinglish_density | heavy | 42/160 (26.2%; [20.0%, 33.6%]) |
| V4.4_rc2_experiment_3 | hinglish_density | light | 48/160 (30.0%; [23.4%, 37.5%]) |
| V4.4_rc2_experiment_3 | hinglish_density | medium | 38/160 (23.8%; [17.8%, 30.9%]) |
| V4.4_rc2_experiment_3 | noise_level | clean | 25/96 (26.0%; [18.3%, 35.6%]) |
| V4.4_rc2_experiment_3 | noise_level | missing_vowels | 16/96 (16.7%; [10.5%, 25.4%]) |
| V4.4_rc2_experiment_3 | noise_level | mixed_case | 47/96 (49.0%; [39.2%, 58.8%]) |
| V4.4_rc2_experiment_3 | noise_level | texting_abbrev | 27/96 (28.1%; [20.1%, 37.8%]) |
| V4.4_rc2_experiment_3 | noise_level | typos | 13/96 (13.5%; [8.1%, 21.8%]) |
| V4.4_rc2_experiment_3 | length_bin | long_31_plus | 21/187 (11.2%; [7.5%, 16.6%]) |
| V4.4_rc2_experiment_3 | length_bin | medium_16_30 | 62/199 (31.2%; [25.1%, 37.9%]) |
| V4.4_rc2_experiment_3 | length_bin | short_5_15 | 45/94 (47.9%; [38.1%, 57.9%]) |

**OBSERVED failure pattern:** V4.3 URL-less recall75/288=26.042%, URL-like132/192=68.750%; V2 URL-less35/288=12.153%, URL-like80/192=41.667%. Both fail without a link, not just on benign false alarms. **PROVISIONAL caution:** has_url marks defangedhxxps/.invalid tokens; the legacyhttp(s)/www regex need not recognize them as URLs. Do not describe this as a clean true-HTTPS-versus-no-URL experiment or infer an exact deployed-feature mechanism. No post-score rewrite was made to fix this confound. Callback numbers use fictionalNANP55501xx rather than Indian mobile-format numbers, which can affect legacy phone features. Report these safe-syntax/geographic limitations before extrapolation.

## 4. Paired English twins and English TEST

**OBSERVED:** the paired comparison uses only each row's own English twin, not all480Hinglish against120English. 120random scenario pairs were selected before scores (seed202610220), adding both malicious andbenign English translations. Language/translation/noise artifacts remain possible; no pure causal-language claim is made. Each rate hasWilson95%; paired discordant outcomes/texts are in paired_English_comparisons.jsonl.

| Model | Matched malicious Hinglish recall | Same-scenario English recall | English−Hinglish gap, points | English-only / Hinglish-only detections |
| --- | --- | --- | --- | --- |
| V2 | 29/120 (24.2%; [17.4%, 32.6%]) | 54/120 (45.0%; [36.4%, 53.9%]) | 20.83 | 30 / 5 |
| V4.3 | 48/120 (40.0%; [31.7%, 48.9%]) | 87/120 (72.5%; [63.9%, 79.7%]) | 32.50 | 45 / 6 |
| V4.4_candidate_a_corrected | 76/120 (63.3%; [54.4%, 71.4%]) | 95/120 (79.2%; [71.1%, 85.5%]) | 15.83 | 25 / 6 |
| V4.4_candidate_b_refined | 66/120 (55.0%; [46.1%, 63.6%]) | 91/120 (75.8%; [67.4%, 82.6%]) | 20.83 | 31 / 6 |
| V4.4_candidate_c_balanced | 62/120 (51.7%; [42.8%, 60.4%]) | 84/120 (70.0%; [61.3%, 77.5%]) | 18.33 | 28 / 6 |
| V4.4_rc2_experiment_1 | 36/120 (30.0%; [22.5%, 38.7%]) | 75/120 (62.5%; [53.6%, 70.6%]) | 32.50 | 42 / 3 |
| V4.4_rc2_experiment_2 | 36/120 (30.0%; [22.5%, 38.7%]) | 84/120 (70.0%; [61.3%, 77.5%]) | 40.00 | 51 / 3 |
| V4.4_rc2_experiment_3 | 24/120 (20.0%; [13.8%, 28.0%]) | 75/120 (62.5%; [53.6%, 70.6%]) | 42.50 | 56 / 5 |

**OBSERVED paired benign controls:**

| Model | Hinglish false-alert rate | English twin false-alert rate | English−Hinglish false-alert points |
| --- | --- | --- | --- |
| V2 | 24/120 (20.0%; [13.8%, 28.0%]) | 32/120 (26.7%; [19.6%, 35.2%]) | 6.67 |
| V4.3 | 16/120 (13.3%; [8.4%, 20.6%]) | 62/120 (51.7%; [42.8%, 60.4%]) | 38.33 |
| V4.4_candidate_a_corrected | 42/120 (35.0%; [27.1%, 43.9%]) | 80/120 (66.7%; [57.8%, 74.5%]) | 31.67 |
| V4.4_candidate_b_refined | 34/120 (28.3%; [21.0%, 37.0%]) | 67/120 (55.8%; [46.9%, 64.4%]) | 27.50 |
| V4.4_candidate_c_balanced | 28/120 (23.3%; [16.7%, 31.7%]) | 53/120 (44.2%; [35.6%, 53.1%]) | 20.83 |
| V4.4_rc2_experiment_1 | 14/120 (11.7%; [7.1%, 18.6%]) | 48/120 (40.0%; [31.7%, 48.9%]) | 28.33 |
| V4.4_rc2_experiment_2 | 17/120 (14.2%; [9.0%, 21.5%]) | 56/120 (46.7%; [38.0%, 55.6%]) | 32.50 |
| V4.4_rc2_experiment_3 | 14/120 (11.7%; [7.1%, 18.6%]) | 47/120 (39.2%; [30.9%, 48.1%]) | 27.50 |

**OBSERVED English TEST comparison:** fullTEST reproduces the requiredV4.3 target1510/1556 and2/520before anyprobe inference. English-only uses metadata language en/English, with actual denominators below; it is not mislabeled as the fullTEST. TEST/OOD language count/hash evidence is report_input_counts.json; both contain3hinglish-tagged records. TEST is an older different scenario/source distribution, not a matched language control.

| Model | TEST scope | Attack detections / N | Recall | Benign MALICIOUS alerts / N | Spam MALICIOUS alerts / N |
| --- | --- | --- | --- | --- | --- |
| V2 | TEST_all | 1403/1556 | 90.2% | 20/520 | 39/188 |
| V2 | TEST_English_metadata | 1399/1551 | 90.2% | 20/519 | 39/188 |
| V4.3 | TEST_all | 1510/1556 | 97.0% | 2/520 | 90/188 |
| V4.3 | TEST_English_metadata | 1506/1551 | 97.1% | 2/519 | 90/188 |
| V4.4_candidate_a_corrected | TEST_all | 1510/1556 | 97.0% | 2/520 | 84/188 |
| V4.4_candidate_a_corrected | TEST_English_metadata | 1505/1551 | 97.0% | 2/519 | 84/188 |
| V4.4_candidate_b_refined | TEST_all | 1511/1556 | 97.1% | 1/520 | 88/188 |
| V4.4_candidate_b_refined | TEST_English_metadata | 1506/1551 | 97.1% | 1/519 | 88/188 |
| V4.4_candidate_c_balanced | TEST_all | 1505/1556 | 96.7% | 2/520 | 86/188 |
| V4.4_candidate_c_balanced | TEST_English_metadata | 1500/1551 | 96.7% | 2/519 | 86/188 |
| V4.4_rc2_experiment_1 | TEST_all | 1507/1556 | 96.9% | 3/520 | 87/188 |
| V4.4_rc2_experiment_1 | TEST_English_metadata | 1502/1551 | 96.8% | 3/519 | 87/188 |
| V4.4_rc2_experiment_2 | TEST_all | 1503/1556 | 96.6% | 2/520 | 88/188 |
| V4.4_rc2_experiment_2 | TEST_English_metadata | 1498/1551 | 96.6% | 2/519 | 88/188 |
| V4.4_rc2_experiment_3 | TEST_all | 1494/1556 | 96.0% | 1/520 | 85/188 |
| V4.4_rc2_experiment_3 | TEST_English_metadata | 1489/1551 | 96.0% | 1/519 | 85/188 |

**PROVISIONAL:** text-only paired English gains span15.833–42.5points, with all eight above the10point recall-also threshold. The English synthetic controls can also be harder than EnglishTEST; therefore this study finds both language sensitivity and scenario/style shift, not solely one causal defect.

## 5. Condition 2: sender-header metadata (V2 only)

**OBSERVED:** onlyV2's feature pipeline accepts sender_header. V4.3andV4.4 extract text-only structural signals, so no fake condition2 is created by prepending metadata. SMS headers are fictionalDLT-shaped labels (e.g.AD-NAVBNK), not verified sender identity. Compare the sameSMS-style Hinglish rows, not alltext rows againsttheSMSsubset:

| Model / condition | SMS malicious recall | SMS benign false alerts | SMS spam false alerts |
| --- | --- | --- | --- |
| V2/text_only | 72/240 (30.0%; [24.6%, 36.1%]) | 47/240 (19.6%; [15.1%, 25.1%]) | 6/60 (10.0%; [4.7%, 20.1%]) |
| V2/SMS_with_sender_header | 7/240 (2.9%; [1.4%, 5.9%]) | 4/240 (1.7%; [0.6%, 4.2%]) | 0/60 (0.0%; [0.0%, 6.0%]) |

**OBSERVED:** with sender metadataV2 detects7/240Hinglish SMS attacks(2.917%) while falsely alerting on4/240benign and0/60spam. This supports investigating learned sender-trust sensitivity; it does not prove a real sender-authentication bypass or an Android runtime defect. Headers are invented, and this is frozen Python feature behavior only. Condition2 verdict andEnglish pairing are separately recorded; it also satisfies recall-also. No threshold was changed.

## 6. Three-way confusion, raw output and overlap controls

**OBSERVED:** matrix order true rows/predicted columns=BENIGN,SPAM,MALICIOUS. The MALICIOUS-only endpoint remains constant. Complete per-model raw probabilities/final classes are probe_predictions.jsonl; raw-argmax metrics are raw_argmax_metrics.jsonl, not substituted for the locked operating result.

| Model / condition | BENIGN row B/S/M | SPAM row B/S/M | MALICIOUS row B/S/M |
| --- | --- | --- | --- |
| V2/text_only | [380, 5, 95] | [92, 16, 12] | [358, 7, 115] |
| V2/SMS_with_sender_header | [236, 0, 4] | [60, 0, 0] | [233, 0, 7] |
| V4.3/text_only | [393, 0, 87] | [100, 0, 20] | [273, 0, 207] |
| V4.4_candidate_a_corrected/text_only | [277, 0, 203] | [81, 0, 39] | [166, 0, 314] |
| V4.4_candidate_b_refined/text_only | [336, 0, 144] | [96, 0, 24] | [201, 0, 279] |
| V4.4_candidate_c_balanced/text_only | [349, 0, 131] | [93, 0, 27] | [223, 0, 257] |
| V4.4_rc2_experiment_1/text_only | [409, 0, 71] | [100, 0, 20] | [310, 0, 170] |
| V4.4_rc2_experiment_2/text_only | [408, 0, 72] | [100, 0, 20] | [298, 0, 182] |
| V4.4_rc2_experiment_3/text_only | [427, 0, 53] | [105, 0, 15] | [352, 0, 128] |

**OBSERVED:** source audit covers79text-bearing corpus/report sources,23classifiedtraining sources. Conservative report examples count as past exposure; source paths/hashes, parser errors and normalization are in corpus_audit_manifest.json. No normalized-exact/tokenJaccard≥.85 cross-corpus overlaps were flagged. Eight intraprobe near edges form components ofsize2(max), within the3rowcap. No post-score filtering is used for the primary verdict.

| Model | Scope | Hinglish recall | Benign false-alert rate | Spam false-alert rate |
| --- | --- | --- | --- | --- |
| V2 | all | 115/480 (24.0%; [20.4%, 28.0%]) | 95/480 (19.8%; [16.5%, 23.6%]) | 12/120 (10.0%; [5.8%, 16.7%]) |
| V2 | without_corpus_overlap | 115/480 (24.0%; [20.4%, 28.0%]) | 95/480 (19.8%; [16.5%, 23.6%]) | 12/120 (10.0%; [5.8%, 16.7%]) |
| V2 | without_intra_near_duplicates | 111/470 (23.6%; [20.0%, 27.7%]) | 95/474 (20.0%; [16.7%, 23.9%]) | 12/120 (10.0%; [5.8%, 16.7%]) |
| V4.3 | all | 207/480 (43.1%; [38.8%, 47.6%]) | 87/480 (18.1%; [14.9%, 21.8%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.3 | without_corpus_overlap | 207/480 (43.1%; [38.8%, 47.6%]) | 87/480 (18.1%; [14.9%, 21.8%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.3 | without_intra_near_duplicates | 201/470 (42.8%; [38.4%, 47.3%]) | 85/474 (17.9%; [14.7%, 21.6%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_candidate_a_corrected | all | 314/480 (65.4%; [61.1%, 69.5%]) | 203/480 (42.3%; [38.0%, 46.8%]) | 39/120 (32.5%; [24.8%, 41.3%]) |
| V4.4_candidate_a_corrected | without_corpus_overlap | 314/480 (65.4%; [61.1%, 69.5%]) | 203/480 (42.3%; [38.0%, 46.8%]) | 39/120 (32.5%; [24.8%, 41.3%]) |
| V4.4_candidate_a_corrected | without_intra_near_duplicates | 306/470 (65.1%; [60.7%, 69.3%]) | 198/474 (41.8%; [37.4%, 46.3%]) | 39/120 (32.5%; [24.8%, 41.3%]) |
| V4.4_candidate_b_refined | all | 279/480 (58.1%; [53.7%, 62.5%]) | 144/480 (30.0%; [26.1%, 34.2%]) | 24/120 (20.0%; [13.8%, 28.0%]) |
| V4.4_candidate_b_refined | without_corpus_overlap | 279/480 (58.1%; [53.7%, 62.5%]) | 144/480 (30.0%; [26.1%, 34.2%]) | 24/120 (20.0%; [13.8%, 28.0%]) |
| V4.4_candidate_b_refined | without_intra_near_duplicates | 273/470 (58.1%; [53.6%, 62.5%]) | 141/474 (29.7%; [25.8%, 34.0%]) | 24/120 (20.0%; [13.8%, 28.0%]) |
| V4.4_candidate_c_balanced | all | 257/480 (53.5%; [49.1%, 58.0%]) | 131/480 (27.3%; [23.5%, 31.4%]) | 27/120 (22.5%; [15.9%, 30.8%]) |
| V4.4_candidate_c_balanced | without_corpus_overlap | 257/480 (53.5%; [49.1%, 58.0%]) | 131/480 (27.3%; [23.5%, 31.4%]) | 27/120 (22.5%; [15.9%, 30.8%]) |
| V4.4_candidate_c_balanced | without_intra_near_duplicates | 251/470 (53.4%; [48.9%, 57.9%]) | 129/474 (27.2%; [23.4%, 31.4%]) | 27/120 (22.5%; [15.9%, 30.8%]) |
| V4.4_rc2_experiment_1 | all | 170/480 (35.4%; [31.3%, 39.8%]) | 71/480 (14.8%; [11.9%, 18.2%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_1 | without_corpus_overlap | 170/480 (35.4%; [31.3%, 39.8%]) | 71/480 (14.8%; [11.9%, 18.2%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_1 | without_intra_near_duplicates | 164/470 (34.9%; [30.7%, 39.3%]) | 69/474 (14.6%; [11.7%, 18.0%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_2 | all | 182/480 (37.9%; [33.7%, 42.3%]) | 72/480 (15.0%; [12.1%, 18.5%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_2 | without_corpus_overlap | 182/480 (37.9%; [33.7%, 42.3%]) | 72/480 (15.0%; [12.1%, 18.5%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_2 | without_intra_near_duplicates | 176/470 (37.4%; [33.2%, 41.9%]) | 70/474 (14.8%; [11.9%, 18.2%]) | 20/120 (16.7%; [11.1%, 24.3%]) |
| V4.4_rc2_experiment_3 | all | 128/480 (26.7%; [22.9%, 30.8%]) | 53/480 (11.0%; [8.5%, 14.2%]) | 15/120 (12.5%; [7.7%, 19.6%]) |
| V4.4_rc2_experiment_3 | without_corpus_overlap | 128/480 (26.7%; [22.9%, 30.8%]) | 53/480 (11.0%; [8.5%, 14.2%]) | 15/120 (12.5%; [7.7%, 19.6%]) |
| V4.4_rc2_experiment_3 | without_intra_near_duplicates | 122/470 (26.0%; [22.2%, 30.1%]) | 51/474 (10.8%; [8.3%, 13.9%]) | 15/120 (12.5%; [7.7%, 19.6%]) |

**PROVISIONAL audit limits:** a zero lexical-overlap screen does not certify semantic/template independence, true human-label validity or all historical provenance. Excluded config/model/cache/prohibited/sealed paths are enumerated by the audit rules; text-bearing records in supportedformats were audited without opening datasets_v5/user_data oranysealedexam. Design was fixed before generation; setfinalhash was recorded before inference. The original andallunflagged metrics remain immutable.

## 7. Label QA and user review

**OBSERVED:** a separate content-only deterministic blind process read opaque text/channel/header/language fields without expected,family,pair fields. It assigned all1320labels and disagreed with80author labels. This is file-level blindness, not independenthumanreview: the same author knows the grammar and its rule classifier is fallible. Disagreements are retained inblind_disagreements.csv with rationale; no expected label was changed to improve scores.

**OBSERVED:** REVIEW_SAMPLE.csv contains202unique rows: the seeded50malicious,50benign,25spam Hinglish sample plus everyblinddisagreement not already sampled. user_agree/user_note remainblank. Read the benign/spam intent boundaries, legitimate deliveryPIN handoff, verifiedfriend moneycases, loan/recovery threats, noisyshortmessages andall disagreementrationales before deciding label correctness. Mark wrong intended labels explicitly. No user review has arrived, so corrected_user_review scope currentlyexcludeszero rows and equalsoriginal; it is not a verified correction. A futureuser review mustcreate aNEWexclusion/analysisartifact; retainthisoriginal frozen exam unchanged.

## 8. Twenty-five worst misses and false alerts per model

**OBSERVED decisions / ASSUMED labels:** worst_25_misses_per_model.csv ranksHinglishmaliciousfalse negatives byascendingpM; worst_25_false_alerts_per_model.csv ranksbenign/spamalerts bydescendingpM,withtext,expected/finalclass,family,style,density,noise,lengthandprobabilities. They hold25/condition when enough errors exist, otherwiseallavailableerrors,neverfabricatedexamples. Tablesbelowgive representative rows; theCSVfiles containthecomplete requestedper-model lists,includingcondition2.

| Model | Worst miss example | Predicted | pM |
| --- | --- | --- | --- |
| V2 | Mujhe Login team ke naam ka sandesh samajhna tha. login atka hua dikh raha hai. Jo baat likhi hai woh yeh: jo OTP aaya use mujhe forward kar do. +1-202-555-0134 🙂 | BENIGN | 0.00786561152845452 |
| V4.3 | Aaj bahut kaam tha, poora din messages dekhne ka mauka nahi mila. Ab dekha ki part time ka offer mila hai. Baar baar poochhne ki jagah yahin bata raha hoon: job confirm karne ko security deposit meri UPI par bhejo. | BENIGN | 0.004137739556533017 |
| V4.4_candidate_a_corrected | Aaj bahut kaam tha, poora din messages dekhne ka mauka nahi mila. Ab dekha ki part time ka offer mila hai. Baar baar poochhne ki jagah yahin bata raha hoon: job confirm karne ko security deposit meri UPI par bhejo. | BENIGN | 0.01107600438724604 |
| V4.4_candidate_b_refined | Aaj bahut kaam tha, poora din messages dekhne ka mauka nahi mila. Ab dekha ki part time ka offer mila hai. Baar baar poochhne ki jagah yahin bata raha hoon: job confirm karne ko security deposit meri UPI par bhejo. | BENIGN | 0.013750227087374797 |
| V4.4_candidate_c_balanced | Subah se ghar ke kaam mein laga tha isliye ab message bhej raha hoon. tumhara naam lucky draw mein nikla h. Tumhare liye poora sandarbh bata diya; baat ko dhyan se samajhkar winning amount ke liye card CVV agent ko batao. | BENIGN | 0.012810852433540462 |
| V4.4_rc2_experiment_1 | Aaj bahut kaam tha, poora din messages dekhne ka mauka nhi mila. Ab dekha ki the winner certificate is ready h. Baar baar poochhne ki jagah yahin bata raha hoon: lottery tax abhi private UPI par bhar do phir paisa milega. | BENIGN | 0.008424697419455812 |
| V4.4_rc2_experiment_2 | Aaj bahut kaam tha, poora din messages dekhne ka mauka nhi mila. Ab dekha ki the winner certificate is ready h. Baar baar poochhne ki jagah yahin bata raha hoon: lottery tax abhi private UPI par bhar do phir paisa milega. | BENIGN | 0.005394184407404388 |
| V4.4_rc2_experiment_3 | Aaj bahut kaam tha, poora din messages dekhne ka mauka nhi mila. Ab dekha ki the winner certificate is ready h. Baar baar poochhne ki jagah yahin bata raha hoon: lottery tax abhi private UPI par bhar do phir paisa milega. | BENIGN | 0.003475941646849296 |

| Model | Worst false-alert example | Expected | pM |
| --- | --- | --- | --- |
| V2 | Adarniya grahak, failed payment ka paisa lautna hai. Aapke liye nirdesh: refund tumhare account mein credit ho chuka hai. hxxps://UPI-collect-refund-06.invalid/case/106 | BENIGN | 0.9782268091511827 |
| V4.3 | purane saved number par call karke identity cnfrm kar lena, kripya. hxxps://friend-impersonation-money-05.invalid/case/105 | BENIGN | 0.9786650843812086 |
| V4.4_candidate_a_corrected | Arre dost, mujhe abhi yeh mila: a friend urgently needs money hai. Main isi liye message kar raha hoon; purane saved number par call karke identity confirm kar lena. +1-202-555-0190 | BENIGN | 0.9909919094856431 |
| V4.4_candidate_b_refined | verification poori hui; savings account chalu hai, kripya. hxxps://bank-KYC-block-05.invalid/case/105 | BENIGN | 0.9794602216097957 |
| V4.4_candidate_c_balanced | verification poori hui; savings account chalu hai, kripya. hxxps://bank-KYC-block-05.invalid/case/105 | BENIGN | 0.9860414298413905 |
| V4.4_rc2_experiment_1 | Beta jab kaam se fursat mile tab yeh padhna. I am contacting you from a new number hai. Maine jitna samjha uske hisab se naye UPI par paisa bhejne se pehle voice call mein verify kiya. +1-202-555-0105 | BENIGN | 0.9825401986661212 |
| V4.4_rc2_experiment_2 | Beta jab kaam se fursat mile tab yeh padhna. I am contacting you from a new number hai. Maine jitna samjha uske hisab se naye UPI par paisa bhejne se pehle voice call mein verify kiya. +1-202-555-0105 | BENIGN | 0.9804467013905168 |
| V4.4_rc2_experiment_3 | verification poori hui; savings account chalu hai, kripya. hxxps://bank-KYC-block-05.invalid/case/105 | BENIGN | 0.9807392962042325 |

## 9. The87.1%lead and earlier intentionalHinglish tests

**REPORTED master §6.2:** V2Hinglish smishing recall87.1%,67missesoutof520. **OBSERVED source attribution:** `7sep_messages_v3/reports/HINGLISH_520_ATTACK_AUDIT.json` embeds520attack records in detailed_eval,13categories×40,with p_v2/v2_detected andp_v3_ts/v3_ts_detected. It reportsV2=327/520=62.885% andV3two-stage=453/520=87.115%(67misses). Thus87.1%belongs toV3two-stageinthat source,notV2. These oldresults areREPORTED,not newly reproduced; originalauthoring/tool/environment provenance oftheembedded520 isnotcertified. Hashes,recordschema andcategorycounts are historical_87_1_lead.json.

**REPORTED older report:** HINGLISH_ROBUSTNESS_REPORT.md describesa100rowslice with50maliciousV2recall14%=7/50,anda separate80semanticpair study. Its data sourcebench_hinglish_robustness.jsonl existsandwascounted/hashed. Therefore“neverintentionallytested”isnottrueforV2intheexistingrepository; that doesnotdiminishthevalueofthisnewimmutableprobeorproveallcurrentvariantsweretestedpreviously. MasterV2TEST94.2%alsoconflictswiththecurrenttext-onlyreproduction; neitheris silentlyusedastheother'sbaseline. Do notmixV3deterministicpolicyescalation,oldV2features,fullTEST,andnewHinglishcontrolcohorts.

## 10. Five informative patterns and disposition

1. **OBSERVED / PROVISIONAL:** all eighttext-onlyrecallsare23.96–65.42%,eachbelow85%;thefalse-positive-onlyhypothesisfails undertheregisteredrules. PairedEnglishimprovementis15.83–42.5points,withscenario/styleandtranslationcaveats.
2. **OBSERVED / PROVISIONAL:** URL-lessattacksareparticularlyweak(V4.3=75/288,V2=35/288),includingcallbackandreply-onlyfamilies. DefangedURL/nonnativephone-formatlimitationsmeanthestructuralcomparisonisdiagnostic,notanequivalentdeploymentsimulation.
3. **OBSERVED:** missesmostlybecomeBENIGN,notSPAM(V4.3all273;V2=358of365). Spam-never-alertsdoesnotexplainawaythoselowrecalls.
4. **OBSERVED / PROVISIONAL:** V2SMSsenderheadersdriveattackdetectiondownto7/240;same-rowtext-onlycomparisonisgivenabove. Learnedmetadata/trustfeaturesneedinvestigation; thisisnotproofaboutrealverifiedsendersorAndroidpolicy.
5. **OBSERVED / PROVISIONAL:** falsealertsremainmaterialtoo(V4.3=87/480benign,20/120spam;CandidateA=203/480benign). Candidatechangestradeoffrecallandbenign/spamalerts;thisexamdoesnotauthorizeaselectedmodel,thresholdtweakortraining.

**STOP:** Stage0iscompleteafterthefinalintegrity/evidencechecks. Recallisalsoamaterialproblemforthefrozenreference models,sothecontinuationconditiondoesnotpermitstartingStage1. TheuserhasalsosaidStage1willbeprovidedafterStage0. Waitforuserreview/instruction; donotrequestGPU,train,finetune,tuneagainstthisexam,copyittotrainingdata,orstartasprintimplementation.
