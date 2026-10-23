# Probe v2 results

OBSERVED frozen-model inference / ASSUMED synthetic labels / PROVISIONAL real-world interpretation. Models and thresholds unchanged. This set is single-author, with reused family contexts and benign contrasts; it is not independent natural traffic. English twins share scenarios. Row-level Wilson intervals do not account for template correlation. No labels came from scores.

| Model | v2 recall, Wilson95 | benign false alerts | spam false alerts | English pair gap | Verdict |
|---|---|---|---|---|---|
| V2 | 453/600 = 75.5% [71.9, 78.8] | 264/400 = 66.0% [61.2, 70.5] | 38/100 = 38.0% [29.1, 47.8] | 8.7 pp | Recall is also a problem |
| V4.3 | 494/600 = 82.3% [79.1, 85.2] | 197/400 = 49.2% [44.4, 54.1] | 14/100 = 14.0% [8.5, 22.1] | 13.3 pp | Recall is also a problem |
| V4.4_candidate_a_corrected | 569/600 = 94.8% [92.8, 96.3] | 280/400 = 70.0% [65.3, 74.3] | 27/100 = 27.0% [19.3, 36.4] | 2.0 pp | False positives are the main problem |
| V4.4_candidate_b_refined | 504/600 = 84.0% [80.9, 86.7] | 238/400 = 59.5% [54.6, 64.2] | 13/100 = 13.0% [7.8, 21.0] | 10.7 pp | Recall is also a problem |
| V4.4_candidate_c_balanced | 477/600 = 79.5% [76.1, 82.5] | 203/400 = 50.7% [45.9, 55.6] | 13/100 = 13.0% [7.8, 21.0] | 12.7 pp | Recall is also a problem |
| V4.4_rc2_experiment_1 | 431/600 = 71.8% [68.1, 75.3] | 172/400 = 43.0% [38.2, 47.9] | 7/100 = 7.0% [3.4, 13.7] | 17.3 pp | Recall is also a problem |
| V4.4_rc2_experiment_2 | 415/600 = 69.2% [65.4, 72.7] | 181/400 = 45.2% [40.4, 50.1] | 10/100 = 10.0% [5.5, 17.4] | 18.0 pp | Recall is also a problem |
| V4.4_rc2_experiment_3 | 384/600 = 64.0% [60.1, 67.7] | 152/400 = 38.0% [33.4, 42.8] | 7/100 = 7.0% [3.4, 13.7] | 22.0 pp | Recall is also a problem |

## V1 confound diagnostics

OBSERVED paired text transformation; changing URL/phone tokens simultaneously cannot identify each causal contribution. Active subset is chosen by the previous same-author rule classifier, not verified truth; selection bias favors recognizable attacks. Do not call its complement cue-free.

| Model | v1 all attacks | v1 normalized | v1 active-pattern subset |
|---|---|---|---|
| V2 | 115/480 = 24.0% [20.4, 28.0] | 199/480 = 41.5% [37.1, 45.9] | 101/434 = 23.3% [19.5, 27.5] |
| V4.3 | 207/480 = 43.1% [38.8, 47.6] | 220/480 = 45.8% [41.4, 50.3] | 190/434 = 43.8% [39.2, 48.5] |
| V4.4_candidate_a_corrected | 314/480 = 65.4% [61.1, 69.5] | 367/480 = 76.5% [72.5, 80.0] | 290/434 = 66.8% [62.3, 71.1] |
| V4.4_candidate_b_refined | 279/480 = 58.1% [53.7, 62.5] | 347/480 = 72.3% [68.1, 76.1] | 255/434 = 58.8% [54.1, 63.3] |
| V4.4_candidate_c_balanced | 257/480 = 53.5% [49.1, 58.0] | 346/480 = 72.1% [67.9, 75.9] | 233/434 = 53.7% [49.0, 58.3] |
| V4.4_rc2_experiment_1 | 170/480 = 35.4% [31.3, 39.8] | 290/480 = 60.4% [56.0, 64.7] | 154/434 = 35.5% [31.1, 40.1] |
| V4.4_rc2_experiment_2 | 182/480 = 37.9% [33.7, 42.3] | 304/480 = 63.3% [58.9, 67.5] | 167/434 = 38.5% [34.0, 43.1] |
| V4.4_rc2_experiment_3 | 128/480 = 26.7% [22.9, 30.8] | 248/480 = 51.7% [47.2, 56.1] | 112/434 = 25.8% [21.9, 30.1] |

## Integrity and limits

OBSERVED V4.3 reproduction gate: 1510/1556 and 2/520 benign any-nonbenign. All raw probabilities and final MALICIOUS-only alerts are in probe_predictions.jsonl. Full TEST vs English metadata confusion is in English_TEST_baselines.json. No sender headers were fed. The first score-free validator failed on benign channel balance; repair_manifest.json records metadata-only correction, with draft preserved. Frozen dataset and design are under frozen/; freeze_manifest.json commits hashes before scores.

OBSERVED user review marks: 0; excluded explicit wrong marks: 0. REVIEW_SAMPLE_v2.csv contains a class-stratified random sample 60/40/20 without enrichment. More than 5% wrong requires a new set before trusting this one; exactly 6/120 is 5%, 7/120 exceeds it. Do not tune on either probe. Invented 9000000NNN patterns match the regex but are not proven unallocated. URLs are reserved .invalid, never fetched, neutral and lacking scenario words. Synthetic .invalid URLs still differ from deployment.

OBSERVED all/no-overlap and user-corrected counts: probe_summary.jsonl; cross-corpus evidence: corpus_audit_manifest.json, overlap_tags.jsonl. Excluding overlap is sensitivity analysis, not a guarantee of source independence. Worst25 misses and25 false alerts per model are in worst_failures.csv.

## All requested v2 cells

| Model | Axis | Cell | Recall Wilson95 | B+S false alerts Wilson95 | Interpretation |
|---|---|---|---|---|---|
| V2 | family | APK_install_lure | 39/50 = 78.0% [64.8, 87.2] | 26/33 = 78.8% [62.2, 89.3] | synthetic descriptive |
| V2 | family | OTP_coercion | 37/50 = 74.0% [60.4, 84.1] | 11/33 = 33.3% [19.8, 50.4] | synthetic descriptive |
| V2 | family | SIM_telecom_KYC | 35/50 = 70.0% [56.2, 80.9] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V2 | family | UPI_collect_refund | 42/50 = 84.0% [71.5, 91.7] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V2 | family | bank_KYC_block | 33/50 = 66.0% [52.2, 77.6] | 24/33 = 72.7% [55.8, 84.9] | synthetic descriptive |
| V2 | family | challan_tax_government | 39/50 = 78.0% [64.8, 87.2] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V2 | family | courier_customs_fee | 45/50 = 90.0% [78.6, 95.7] | 28/33 = 84.8% [69.1, 93.3] | synthetic descriptive |
| V2 | family | electricity_gas_callback | 30/50 = 60.0% [46.2, 72.4] | 18/33 = 54.5% [38.0, 70.2] | synthetic descriptive |
| V2 | family | friend_impersonation_money | 30/50 = 60.0% [46.2, 72.4] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V2 | family | job_task_fee | 40/50 = 80.0% [67.0, 88.8] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V2 | family | loan_app_threat | 43/50 = 86.0% [73.8, 93.0] | 27/33 = 81.8% [65.6, 91.4] | synthetic descriptive |
| V2 | family | prize_lottery | 40/50 = 80.0% [67.0, 88.8] | 19/33 = 57.6% [40.8, 72.8] | synthetic descriptive |
| V2 | family | promotion_no_secret | 0/0; unavailable | 38/100 = 38.0% [29.1, 47.8] | indicative only |
| V2 | family | safe_OTP_transaction | 0/0; unavailable | 0/4 = 0.0% [0.0, 49.0] | indicative only |
| V2 | has_url | false | 126/240 = 52.5% [46.2, 58.7] | 54/188 = 28.7% [22.7, 35.6] | synthetic descriptive |
| V2 | has_url | true | 327/360 = 90.8% [87.4, 93.4] | 248/312 = 79.5% [74.7, 83.6] | synthetic descriptive |
| V2 | channel_style | SMS | 226/300 = 75.3% [70.2, 79.9] | 151/250 = 60.4% [54.2, 66.3] | synthetic descriptive |
| V2 | channel_style | WhatsApp | 227/300 = 75.7% [70.5, 80.2] | 151/250 = 60.4% [54.2, 66.3] | synthetic descriptive |
| V2 | length_bin | 16_30 | 253/329 = 76.9% [72.1, 81.1] | 107/154 = 69.5% [61.8, 76.2] | synthetic descriptive |
| V2 | length_bin | 6_15 | 200/271 = 73.8% [68.3, 78.7] | 195/346 = 56.4% [51.1, 61.5] | synthetic descriptive |
| V2 | noise_level | clean | 104/120 = 86.7% [79.4, 91.6] | 82/105 = 78.1% [69.3, 84.9] | synthetic descriptive |
| V2 | noise_level | missing_vowels | 105/120 = 87.5% [80.4, 92.3] | 80/105 = 76.2% [67.2, 83.3] | synthetic descriptive |
| V2 | noise_level | mixed_case | 105/120 = 87.5% [80.4, 92.3] | 47/93 = 50.5% [40.6, 60.5] | synthetic descriptive |
| V2 | noise_level | texting_abbrev | 118/120 = 98.3% [94.1, 99.5] | 86/105 = 81.9% [73.5, 88.1] | synthetic descriptive |
| V2 | noise_level | typos | 21/120 = 17.5% [11.7, 25.3] | 7/92 = 7.6% [3.7, 14.9] | synthetic descriptive |
| V2 | generator_batch | colloquial_adviser | 57/75 = 76.0% [65.2, 84.2] | 44/65 = 67.7% [55.6, 77.8] | synthetic descriptive |
| V2 | generator_batch | formal_desk | 56/75 = 74.7% [63.8, 83.1] | 29/63 = 46.0% [34.3, 58.2] | synthetic descriptive |
| V2 | generator_batch | friend | 65/79 = 82.3% [72.4, 89.1] | 40/64 = 62.5% [50.3, 73.3] | synthetic descriptive |
| V2 | generator_batch | household | 56/78 = 71.8% [61.0, 80.6] | 27/59 = 45.8% [33.7, 58.3] | synthetic descriptive |
| V2 | generator_batch | hurried_texter | 52/71 = 73.2% [61.9, 82.1] | 35/61 = 57.4% [44.9, 69.0] | synthetic descriptive |
| V2 | generator_batch | merchant | 56/73 = 76.7% [65.8, 84.9] | 40/61 = 65.6% [53.0, 76.3] | synthetic descriptive |
| V2 | generator_batch | student | 56/77 = 72.7% [61.9, 81.4] | 42/67 = 62.7% [50.7, 73.3] | synthetic descriptive |
| V2 | generator_batch | terse_service | 55/72 = 76.4% [65.4, 84.7] | 45/60 = 75.0% [62.8, 84.2] | synthetic descriptive |
| V2 | hinglish_density | heavy | 167/222 = 75.2% [69.1, 80.4] | 127/188 = 67.6% [60.6, 73.8] | synthetic descriptive |
| V2 | hinglish_density | medium | 286/378 = 75.7% [71.1, 79.7] | 175/312 = 56.1% [50.5, 61.5] | synthetic descriptive |
| V4.3 | family | APK_install_lure | 44/50 = 88.0% [76.2, 94.4] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.3 | family | OTP_coercion | 44/50 = 88.0% [76.2, 94.4] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.3 | family | SIM_telecom_KYC | 47/50 = 94.0% [83.8, 97.9] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.3 | family | UPI_collect_refund | 44/50 = 88.0% [76.2, 94.4] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.3 | family | bank_KYC_block | 43/50 = 86.0% [73.8, 93.0] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V4.3 | family | challan_tax_government | 35/50 = 70.0% [56.2, 80.9] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.3 | family | courier_customs_fee | 47/50 = 94.0% [83.8, 97.9] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.3 | family | electricity_gas_callback | 29/50 = 58.0% [44.2, 70.6] | 7/33 = 21.2% [10.7, 37.8] | synthetic descriptive |
| V4.3 | family | friend_impersonation_money | 45/50 = 90.0% [78.6, 95.7] | 20/33 = 60.6% [43.7, 75.3] | synthetic descriptive |
| V4.3 | family | job_task_fee | 42/50 = 84.0% [71.5, 91.7] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.3 | family | loan_app_threat | 38/50 = 76.0% [62.6, 85.7] | 13/33 = 39.4% [24.7, 56.3] | synthetic descriptive |
| V4.3 | family | prize_lottery | 36/50 = 72.0% [58.3, 82.5] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.3 | family | promotion_no_secret | 0/0; unavailable | 14/100 = 14.0% [8.5, 22.1] | indicative only |
| V4.3 | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.3 | has_url | false | 207/240 = 86.2% [81.3, 90.0] | 81/188 = 43.1% [36.2, 50.2] | synthetic descriptive |
| V4.3 | has_url | true | 287/360 = 79.7% [75.3, 83.6] | 130/312 = 41.7% [36.3, 47.2] | synthetic descriptive |
| V4.3 | channel_style | SMS | 261/300 = 87.0% [82.7, 90.3] | 94/250 = 37.6% [31.8, 43.7] | synthetic descriptive |
| V4.3 | channel_style | WhatsApp | 233/300 = 77.7% [72.6, 82.0] | 117/250 = 46.8% [40.7, 53.0] | synthetic descriptive |
| V4.3 | length_bin | 16_30 | 272/329 = 82.7% [78.2, 86.4] | 97/154 = 63.0% [55.1, 70.2] | synthetic descriptive |
| V4.3 | length_bin | 6_15 | 222/271 = 81.9% [76.9, 86.0] | 114/346 = 32.9% [28.2, 38.1] | synthetic descriptive |
| V4.3 | noise_level | clean | 74/120 = 61.7% [52.7, 69.9] | 38/105 = 36.2% [27.6, 45.7] | synthetic descriptive |
| V4.3 | noise_level | missing_vowels | 101/120 = 84.2% [76.6, 89.6] | 42/105 = 40.0% [31.1, 49.6] | synthetic descriptive |
| V4.3 | noise_level | mixed_case | 115/120 = 95.8% [90.6, 98.2] | 73/93 = 78.5% [69.1, 85.6] | synthetic descriptive |
| V4.3 | noise_level | texting_abbrev | 112/120 = 93.3% [87.4, 96.6] | 51/105 = 48.6% [39.2, 58.0] | synthetic descriptive |
| V4.3 | noise_level | typos | 92/120 = 76.7% [68.3, 83.3] | 7/92 = 7.6% [3.7, 14.9] | synthetic descriptive |
| V4.3 | generator_batch | colloquial_adviser | 62/75 = 82.7% [72.6, 89.6] | 26/65 = 40.0% [29.0, 52.1] | synthetic descriptive |
| V4.3 | generator_batch | formal_desk | 63/75 = 84.0% [74.1, 90.6] | 23/63 = 36.5% [25.7, 48.9] | synthetic descriptive |
| V4.3 | generator_batch | friend | 68/79 = 86.1% [76.8, 92.0] | 28/64 = 43.8% [32.3, 55.9] | synthetic descriptive |
| V4.3 | generator_batch | household | 66/78 = 84.6% [75.0, 91.0] | 29/59 = 49.2% [36.8, 61.6] | synthetic descriptive |
| V4.3 | generator_batch | hurried_texter | 60/71 = 84.5% [74.3, 91.1] | 26/61 = 42.6% [31.0, 55.1] | synthetic descriptive |
| V4.3 | generator_batch | merchant | 54/73 = 74.0% [62.9, 82.7] | 25/61 = 41.0% [29.5, 53.5] | synthetic descriptive |
| V4.3 | generator_batch | student | 60/77 = 77.9% [67.5, 85.7] | 30/67 = 44.8% [33.5, 56.6] | synthetic descriptive |
| V4.3 | generator_batch | terse_service | 61/72 = 84.7% [74.7, 91.2] | 24/60 = 40.0% [28.6, 52.6] | synthetic descriptive |
| V4.3 | hinglish_density | heavy | 175/222 = 78.8% [73.0, 83.7] | 79/188 = 42.0% [35.2, 49.2] | synthetic descriptive |
| V4.3 | hinglish_density | medium | 319/378 = 84.4% [80.4, 87.7] | 132/312 = 42.3% [37.0, 47.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | APK_install_lure | 44/50 = 88.0% [76.2, 94.4] | 22/33 = 66.7% [49.6, 80.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | OTP_coercion | 49/50 = 98.0% [89.5, 99.6] | 29/33 = 87.9% [72.7, 95.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | SIM_telecom_KYC | 48/50 = 96.0% [86.5, 98.9] | 26/33 = 78.8% [62.2, 89.3] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | UPI_collect_refund | 47/50 = 94.0% [83.8, 97.9] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | bank_KYC_block | 50/50 = 100.0% [92.9, 100.0] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | challan_tax_government | 47/50 = 94.0% [83.8, 97.9] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | courier_customs_fee | 50/50 = 100.0% [92.9, 100.0] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | electricity_gas_callback | 44/50 = 88.0% [76.2, 94.4] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | friend_impersonation_money | 50/50 = 100.0% [92.9, 100.0] | 26/33 = 78.8% [62.2, 89.3] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | job_task_fee | 50/50 = 100.0% [92.9, 100.0] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | loan_app_threat | 49/50 = 98.0% [89.5, 99.6] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | prize_lottery | 41/50 = 82.0% [69.2, 90.2] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | family | promotion_no_secret | 0/0; unavailable | 27/100 = 27.0% [19.3, 36.4] | indicative only |
| V4.4_candidate_a_corrected | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_candidate_a_corrected | has_url | false | 232/240 = 96.7% [93.6, 98.3] | 99/188 = 52.7% [45.5, 59.7] | synthetic descriptive |
| V4.4_candidate_a_corrected | has_url | true | 337/360 = 93.6% [90.6, 95.7] | 208/312 = 66.7% [61.3, 71.7] | synthetic descriptive |
| V4.4_candidate_a_corrected | channel_style | SMS | 293/300 = 97.7% [95.3, 98.9] | 149/250 = 59.6% [53.4, 65.5] | synthetic descriptive |
| V4.4_candidate_a_corrected | channel_style | WhatsApp | 276/300 = 92.0% [88.4, 94.6] | 158/250 = 63.2% [57.1, 68.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | length_bin | 16_30 | 315/329 = 95.7% [93.0, 97.4] | 128/154 = 83.1% [76.4, 88.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | length_bin | 6_15 | 254/271 = 93.7% [90.2, 96.0] | 179/346 = 51.7% [46.5, 57.0] | synthetic descriptive |
| V4.4_candidate_a_corrected | noise_level | clean | 109/120 = 90.8% [84.3, 94.8] | 68/105 = 64.8% [55.3, 73.2] | synthetic descriptive |
| V4.4_candidate_a_corrected | noise_level | missing_vowels | 110/120 = 91.7% [85.3, 95.4] | 64/105 = 61.0% [51.4, 69.7] | synthetic descriptive |
| V4.4_candidate_a_corrected | noise_level | mixed_case | 120/120 = 100.0% [96.9, 100.0] | 81/93 = 87.1% [78.8, 92.5] | synthetic descriptive |
| V4.4_candidate_a_corrected | noise_level | texting_abbrev | 118/120 = 98.3% [94.1, 99.5] | 77/105 = 73.3% [64.2, 80.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | noise_level | typos | 112/120 = 93.3% [87.4, 96.6] | 17/92 = 18.5% [11.9, 27.6] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | colloquial_adviser | 71/75 = 94.7% [87.1, 97.9] | 39/65 = 60.0% [47.9, 71.0] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | formal_desk | 69/75 = 92.0% [83.6, 96.3] | 37/63 = 58.7% [46.4, 70.0] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | friend | 78/79 = 98.7% [93.2, 99.8] | 39/64 = 60.9% [48.7, 71.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | household | 73/78 = 93.6% [85.9, 97.2] | 37/59 = 62.7% [50.0, 73.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | hurried_texter | 70/71 = 98.6% [92.4, 99.8] | 42/61 = 68.9% [56.4, 79.1] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | merchant | 69/73 = 94.5% [86.7, 97.8] | 34/61 = 55.7% [43.3, 67.5] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | student | 70/77 = 90.9% [82.4, 95.5] | 42/67 = 62.7% [50.7, 73.3] | synthetic descriptive |
| V4.4_candidate_a_corrected | generator_batch | terse_service | 69/72 = 95.8% [88.5, 98.6] | 37/60 = 61.7% [49.0, 72.9] | synthetic descriptive |
| V4.4_candidate_a_corrected | hinglish_density | heavy | 208/222 = 93.7% [89.7, 96.2] | 113/188 = 60.1% [53.0, 66.8] | synthetic descriptive |
| V4.4_candidate_a_corrected | hinglish_density | medium | 361/378 = 95.5% [92.9, 97.2] | 194/312 = 62.2% [56.7, 67.4] | synthetic descriptive |
| V4.4_candidate_b_refined | family | APK_install_lure | 41/50 = 82.0% [69.2, 90.2] | 22/33 = 66.7% [49.6, 80.2] | synthetic descriptive |
| V4.4_candidate_b_refined | family | OTP_coercion | 46/50 = 92.0% [81.2, 96.8] | 24/33 = 72.7% [55.8, 84.9] | synthetic descriptive |
| V4.4_candidate_b_refined | family | SIM_telecom_KYC | 38/50 = 76.0% [62.6, 85.7] | 26/33 = 78.8% [62.2, 89.3] | synthetic descriptive |
| V4.4_candidate_b_refined | family | UPI_collect_refund | 42/50 = 84.0% [71.5, 91.7] | 20/33 = 60.6% [43.7, 75.3] | synthetic descriptive |
| V4.4_candidate_b_refined | family | bank_KYC_block | 45/50 = 90.0% [78.6, 95.7] | 19/33 = 57.6% [40.8, 72.8] | synthetic descriptive |
| V4.4_candidate_b_refined | family | challan_tax_government | 41/50 = 82.0% [69.2, 90.2] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.4_candidate_b_refined | family | courier_customs_fee | 48/50 = 96.0% [86.5, 98.9] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.4_candidate_b_refined | family | electricity_gas_callback | 35/50 = 70.0% [56.2, 80.9] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_candidate_b_refined | family | friend_impersonation_money | 50/50 = 100.0% [92.9, 100.0] | 20/33 = 60.6% [43.7, 75.3] | synthetic descriptive |
| V4.4_candidate_b_refined | family | job_task_fee | 45/50 = 90.0% [78.6, 95.7] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V4.4_candidate_b_refined | family | loan_app_threat | 35/50 = 70.0% [56.2, 80.9] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_candidate_b_refined | family | prize_lottery | 38/50 = 76.0% [62.6, 85.7] | 19/33 = 57.6% [40.8, 72.8] | synthetic descriptive |
| V4.4_candidate_b_refined | family | promotion_no_secret | 0/0; unavailable | 13/100 = 13.0% [7.8, 21.0] | indicative only |
| V4.4_candidate_b_refined | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_candidate_b_refined | has_url | false | 220/240 = 91.7% [87.5, 94.5] | 89/188 = 47.3% [40.3, 54.5] | synthetic descriptive |
| V4.4_candidate_b_refined | has_url | true | 284/360 = 78.9% [74.4, 82.8] | 162/312 = 51.9% [46.4, 57.4] | synthetic descriptive |
| V4.4_candidate_b_refined | channel_style | SMS | 257/300 = 85.7% [81.2, 89.2] | 114/250 = 45.6% [39.5, 51.8] | synthetic descriptive |
| V4.4_candidate_b_refined | channel_style | WhatsApp | 247/300 = 82.3% [77.6, 86.2] | 137/250 = 54.8% [48.6, 60.9] | synthetic descriptive |
| V4.4_candidate_b_refined | length_bin | 16_30 | 290/329 = 88.1% [84.2, 91.2] | 123/154 = 79.9% [72.8, 85.4] | synthetic descriptive |
| V4.4_candidate_b_refined | length_bin | 6_15 | 214/271 = 79.0% [73.7, 83.4] | 128/346 = 37.0% [32.1, 42.2] | synthetic descriptive |
| V4.4_candidate_b_refined | noise_level | clean | 76/120 = 63.3% [54.4, 71.4] | 56/105 = 53.3% [43.8, 62.6] | synthetic descriptive |
| V4.4_candidate_b_refined | noise_level | missing_vowels | 91/120 = 75.8% [67.4, 82.6] | 43/105 = 41.0% [32.0, 50.5] | synthetic descriptive |
| V4.4_candidate_b_refined | noise_level | mixed_case | 120/120 = 100.0% [96.9, 100.0] | 80/93 = 86.0% [77.5, 91.6] | synthetic descriptive |
| V4.4_candidate_b_refined | noise_level | texting_abbrev | 117/120 = 97.5% [92.9, 99.1] | 64/105 = 61.0% [51.4, 69.7] | synthetic descriptive |
| V4.4_candidate_b_refined | noise_level | typos | 100/120 = 83.3% [75.7, 88.9] | 8/92 = 8.7% [4.5, 16.2] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | colloquial_adviser | 61/75 = 81.3% [71.1, 88.5] | 34/65 = 52.3% [40.4, 64.0] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | formal_desk | 64/75 = 85.3% [75.6, 91.6] | 30/63 = 47.6% [35.8, 59.7] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | friend | 69/79 = 87.3% [78.2, 93.0] | 33/64 = 51.6% [39.6, 63.4] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | household | 68/78 = 87.2% [78.0, 92.9] | 29/59 = 49.2% [36.8, 61.6] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | hurried_texter | 63/71 = 88.7% [79.3, 94.2] | 28/61 = 45.9% [34.0, 58.3] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | merchant | 54/73 = 74.0% [62.9, 82.7] | 29/61 = 47.5% [35.5, 59.8] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | student | 64/77 = 83.1% [73.2, 89.9] | 37/67 = 55.2% [43.4, 66.5] | synthetic descriptive |
| V4.4_candidate_b_refined | generator_batch | terse_service | 61/72 = 84.7% [74.7, 91.2] | 31/60 = 51.7% [39.3, 63.8] | synthetic descriptive |
| V4.4_candidate_b_refined | hinglish_density | heavy | 179/222 = 80.6% [74.9, 85.3] | 97/188 = 51.6% [44.5, 58.6] | synthetic descriptive |
| V4.4_candidate_b_refined | hinglish_density | medium | 325/378 = 86.0% [82.1, 89.1] | 154/312 = 49.4% [43.9, 54.9] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | APK_install_lure | 40/50 = 80.0% [67.0, 88.8] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | OTP_coercion | 45/50 = 90.0% [78.6, 95.7] | 23/33 = 69.7% [52.7, 82.6] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | SIM_telecom_KYC | 36/50 = 72.0% [58.3, 82.5] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | UPI_collect_refund | 43/50 = 86.0% [73.8, 93.0] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | bank_KYC_block | 44/50 = 88.0% [76.2, 94.4] | 24/33 = 72.7% [55.8, 84.9] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | challan_tax_government | 39/50 = 78.0% [64.8, 87.2] | 11/33 = 33.3% [19.8, 50.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | courier_customs_fee | 48/50 = 96.0% [86.5, 98.9] | 19/33 = 57.6% [40.8, 72.8] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | electricity_gas_callback | 35/50 = 70.0% [56.2, 80.9] | 8/33 = 24.2% [12.8, 41.0] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | friend_impersonation_money | 42/50 = 84.0% [71.5, 91.7] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | job_task_fee | 41/50 = 82.0% [69.2, 90.2] | 16/33 = 48.5% [32.5, 64.8] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | loan_app_threat | 26/50 = 52.0% [38.5, 65.2] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | prize_lottery | 38/50 = 76.0% [62.6, 85.7] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | family | promotion_no_secret | 0/0; unavailable | 13/100 = 13.0% [7.8, 21.0] | indicative only |
| V4.4_candidate_c_balanced | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_candidate_c_balanced | has_url | false | 220/240 = 91.7% [87.5, 94.5] | 97/188 = 51.6% [44.5, 58.6] | synthetic descriptive |
| V4.4_candidate_c_balanced | has_url | true | 257/360 = 71.4% [66.5, 75.8] | 119/312 = 38.1% [32.9, 43.6] | synthetic descriptive |
| V4.4_candidate_c_balanced | channel_style | SMS | 242/300 = 80.7% [75.8, 84.7] | 93/250 = 37.2% [31.4, 43.3] | synthetic descriptive |
| V4.4_candidate_c_balanced | channel_style | WhatsApp | 235/300 = 78.3% [73.3, 82.6] | 123/250 = 49.2% [43.1, 55.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | length_bin | 16_30 | 276/329 = 83.9% [79.5, 87.5] | 105/154 = 68.2% [60.5, 75.0] | synthetic descriptive |
| V4.4_candidate_c_balanced | length_bin | 6_15 | 201/271 = 74.2% [68.6, 79.0] | 111/346 = 32.1% [27.4, 37.2] | synthetic descriptive |
| V4.4_candidate_c_balanced | noise_level | clean | 64/120 = 53.3% [44.4, 62.0] | 41/105 = 39.0% [30.3, 48.6] | synthetic descriptive |
| V4.4_candidate_c_balanced | noise_level | missing_vowels | 79/120 = 65.8% [57.0, 73.7] | 35/105 = 33.3% [25.0, 42.8] | synthetic descriptive |
| V4.4_candidate_c_balanced | noise_level | mixed_case | 120/120 = 100.0% [96.9, 100.0] | 83/93 = 89.2% [81.3, 94.1] | synthetic descriptive |
| V4.4_candidate_c_balanced | noise_level | texting_abbrev | 114/120 = 95.0% [89.5, 97.7] | 44/105 = 41.9% [32.9, 51.5] | synthetic descriptive |
| V4.4_candidate_c_balanced | noise_level | typos | 100/120 = 83.3% [75.7, 88.9] | 13/92 = 14.1% [8.4, 22.7] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | colloquial_adviser | 58/75 = 77.3% [66.7, 85.3] | 32/65 = 49.2% [37.5, 61.1] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | formal_desk | 62/75 = 82.7% [72.6, 89.6] | 24/63 = 38.1% [27.1, 50.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | friend | 65/79 = 82.3% [72.4, 89.1] | 27/64 = 42.2% [30.9, 54.4] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | household | 65/78 = 83.3% [73.5, 90.0] | 25/59 = 42.4% [30.6, 55.1] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | hurried_texter | 59/71 = 83.1% [72.7, 90.1] | 26/61 = 42.6% [31.0, 55.1] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | merchant | 52/73 = 71.2% [60.0, 80.3] | 22/61 = 36.1% [25.2, 48.6] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | student | 60/77 = 77.9% [67.5, 85.7] | 33/67 = 49.3% [37.7, 60.9] | synthetic descriptive |
| V4.4_candidate_c_balanced | generator_batch | terse_service | 56/72 = 77.8% [66.9, 85.8] | 27/60 = 45.0% [33.1, 57.5] | synthetic descriptive |
| V4.4_candidate_c_balanced | hinglish_density | heavy | 168/222 = 75.7% [69.6, 80.9] | 82/188 = 43.6% [36.7, 50.8] | synthetic descriptive |
| V4.4_candidate_c_balanced | hinglish_density | medium | 309/378 = 81.7% [77.5, 85.3] | 134/312 = 42.9% [37.6, 48.5] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | APK_install_lure | 38/50 = 76.0% [62.6, 85.7] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | OTP_coercion | 38/50 = 76.0% [62.6, 85.7] | 20/33 = 60.6% [43.7, 75.3] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | SIM_telecom_KYC | 35/50 = 70.0% [56.2, 80.9] | 25/33 = 75.8% [59.0, 87.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | UPI_collect_refund | 36/50 = 72.0% [58.3, 82.5] | 10/33 = 30.3% [17.4, 47.3] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | bank_KYC_block | 33/50 = 66.0% [52.2, 77.6] | 18/33 = 54.5% [38.0, 70.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | challan_tax_government | 31/50 = 62.0% [48.2, 74.1] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | courier_customs_fee | 45/50 = 90.0% [78.6, 95.7] | 13/33 = 39.4% [24.7, 56.3] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | electricity_gas_callback | 27/50 = 54.0% [40.4, 67.0] | 7/33 = 21.2% [10.7, 37.8] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | friend_impersonation_money | 43/50 = 86.0% [73.8, 93.0] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | job_task_fee | 41/50 = 82.0% [69.2, 90.2] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | loan_app_threat | 25/50 = 50.0% [36.6, 63.4] | 11/33 = 33.3% [19.8, 50.4] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | prize_lottery | 39/50 = 78.0% [64.8, 87.2] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | family | promotion_no_secret | 0/0; unavailable | 7/100 = 7.0% [3.4, 13.7] | indicative only |
| V4.4_rc2_experiment_1 | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_rc2_experiment_1 | has_url | false | 198/240 = 82.5% [77.2, 86.8] | 81/188 = 43.1% [36.2, 50.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | has_url | true | 233/360 = 64.7% [59.7, 69.5] | 98/312 = 31.4% [26.5, 36.8] | synthetic descriptive |
| V4.4_rc2_experiment_1 | channel_style | SMS | 225/300 = 75.0% [69.8, 79.6] | 77/250 = 30.8% [25.4, 36.8] | synthetic descriptive |
| V4.4_rc2_experiment_1 | channel_style | WhatsApp | 206/300 = 68.7% [63.2, 73.7] | 102/250 = 40.8% [34.9, 47.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | length_bin | 16_30 | 251/329 = 76.3% [71.4, 80.6] | 95/154 = 61.7% [53.8, 69.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | length_bin | 6_15 | 180/271 = 66.4% [60.6, 71.8] | 84/346 = 24.3% [20.1, 29.1] | synthetic descriptive |
| V4.4_rc2_experiment_1 | noise_level | clean | 55/120 = 45.8% [37.2, 54.7] | 28/105 = 26.7% [19.1, 35.8] | synthetic descriptive |
| V4.4_rc2_experiment_1 | noise_level | missing_vowels | 68/120 = 56.7% [47.7, 65.2] | 33/105 = 31.4% [23.3, 40.8] | synthetic descriptive |
| V4.4_rc2_experiment_1 | noise_level | mixed_case | 120/120 = 100.0% [96.9, 100.0] | 70/93 = 75.3% [65.6, 82.9] | synthetic descriptive |
| V4.4_rc2_experiment_1 | noise_level | texting_abbrev | 110/120 = 91.7% [85.3, 95.4] | 38/105 = 36.2% [27.6, 45.7] | synthetic descriptive |
| V4.4_rc2_experiment_1 | noise_level | typos | 78/120 = 65.0% [56.1, 72.9] | 10/92 = 10.9% [6.0, 18.9] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | colloquial_adviser | 58/75 = 77.3% [66.7, 85.3] | 30/65 = 46.2% [34.6, 58.1] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | formal_desk | 52/75 = 69.3% [58.2, 78.6] | 20/63 = 31.7% [21.6, 44.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | friend | 56/79 = 70.9% [60.1, 79.7] | 21/64 = 32.8% [22.6, 45.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | household | 55/78 = 70.5% [59.6, 79.5] | 21/59 = 35.6% [24.6, 48.3] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | hurried_texter | 51/71 = 71.8% [60.5, 81.0] | 19/61 = 31.1% [20.9, 43.6] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | merchant | 49/73 = 67.1% [55.7, 76.8] | 21/61 = 34.4% [23.7, 47.0] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | student | 56/77 = 72.7% [61.9, 81.4] | 29/67 = 43.3% [32.1, 55.2] | synthetic descriptive |
| V4.4_rc2_experiment_1 | generator_batch | terse_service | 54/72 = 75.0% [63.9, 83.6] | 18/60 = 30.0% [19.9, 42.5] | synthetic descriptive |
| V4.4_rc2_experiment_1 | hinglish_density | heavy | 159/222 = 71.6% [65.4, 77.1] | 68/188 = 36.2% [29.6, 43.3] | synthetic descriptive |
| V4.4_rc2_experiment_1 | hinglish_density | medium | 272/378 = 72.0% [67.2, 76.2] | 111/312 = 35.6% [30.5, 41.0] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | APK_install_lure | 35/50 = 70.0% [56.2, 80.9] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | OTP_coercion | 36/50 = 72.0% [58.3, 82.5] | 21/33 = 63.6% [46.6, 77.8] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | SIM_telecom_KYC | 34/50 = 68.0% [54.2, 79.2] | 24/33 = 72.7% [55.8, 84.9] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | UPI_collect_refund | 36/50 = 72.0% [58.3, 82.5] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | bank_KYC_block | 37/50 = 74.0% [60.4, 84.1] | 19/33 = 57.6% [40.8, 72.8] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | challan_tax_government | 34/50 = 68.0% [54.2, 79.2] | 10/33 = 30.3% [17.4, 47.3] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | courier_customs_fee | 39/50 = 78.0% [64.8, 87.2] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | electricity_gas_callback | 25/50 = 50.0% [36.6, 63.4] | 6/33 = 18.2% [8.6, 34.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | friend_impersonation_money | 34/50 = 68.0% [54.2, 79.2] | 16/33 = 48.5% [32.5, 64.8] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | job_task_fee | 41/50 = 82.0% [69.2, 90.2] | 14/33 = 42.4% [27.2, 59.2] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | loan_app_threat | 28/50 = 56.0% [42.3, 68.8] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | prize_lottery | 36/50 = 72.0% [58.3, 82.5] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | family | promotion_no_secret | 0/0; unavailable | 10/100 = 10.0% [5.5, 17.4] | indicative only |
| V4.4_rc2_experiment_2 | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_rc2_experiment_2 | has_url | false | 197/240 = 82.1% [76.7, 86.4] | 87/188 = 46.3% [39.3, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | has_url | true | 218/360 = 60.6% [55.4, 65.5] | 104/312 = 33.3% [28.3, 38.7] | synthetic descriptive |
| V4.4_rc2_experiment_2 | channel_style | SMS | 209/300 = 69.7% [64.2, 74.6] | 83/250 = 33.2% [27.7, 39.3] | synthetic descriptive |
| V4.4_rc2_experiment_2 | channel_style | WhatsApp | 206/300 = 68.7% [63.2, 73.7] | 108/250 = 43.2% [37.2, 49.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | length_bin | 16_30 | 247/329 = 75.1% [70.1, 79.4] | 99/154 = 64.3% [56.5, 71.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | length_bin | 6_15 | 168/271 = 62.0% [56.1, 67.6] | 92/346 = 26.6% [22.2, 31.5] | synthetic descriptive |
| V4.4_rc2_experiment_2 | noise_level | clean | 53/120 = 44.2% [35.6, 53.1] | 31/105 = 29.5% [21.6, 38.8] | synthetic descriptive |
| V4.4_rc2_experiment_2 | noise_level | missing_vowels | 64/120 = 53.3% [44.4, 62.0] | 33/105 = 31.4% [23.3, 40.8] | synthetic descriptive |
| V4.4_rc2_experiment_2 | noise_level | mixed_case | 114/120 = 95.0% [89.5, 97.7] | 75/93 = 80.6% [71.5, 87.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | noise_level | texting_abbrev | 101/120 = 84.2% [76.6, 89.6] | 41/105 = 39.0% [30.3, 48.6] | synthetic descriptive |
| V4.4_rc2_experiment_2 | noise_level | typos | 83/120 = 69.2% [60.4, 76.7] | 11/92 = 12.0% [6.8, 20.2] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | colloquial_adviser | 54/75 = 72.0% [61.0, 80.9] | 30/65 = 46.2% [34.6, 58.1] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | formal_desk | 50/75 = 66.7% [55.4, 76.3] | 22/63 = 34.9% [24.3, 47.2] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | friend | 57/79 = 72.2% [61.4, 80.8] | 23/64 = 35.9% [25.3, 48.2] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | household | 51/78 = 65.4% [54.3, 75.0] | 24/59 = 40.7% [29.1, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | hurried_texter | 50/71 = 70.4% [59.0, 79.8] | 19/61 = 31.1% [20.9, 43.6] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | merchant | 48/73 = 65.8% [54.3, 75.6] | 20/61 = 32.8% [22.3, 45.3] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | student | 50/77 = 64.9% [53.8, 74.7] | 32/67 = 47.8% [36.3, 59.5] | synthetic descriptive |
| V4.4_rc2_experiment_2 | generator_batch | terse_service | 55/72 = 76.4% [65.4, 84.7] | 21/60 = 35.0% [24.2, 47.6] | synthetic descriptive |
| V4.4_rc2_experiment_2 | hinglish_density | heavy | 153/222 = 68.9% [62.6, 74.6] | 73/188 = 38.8% [32.2, 46.0] | synthetic descriptive |
| V4.4_rc2_experiment_2 | hinglish_density | medium | 262/378 = 69.3% [64.5, 73.7] | 118/312 = 37.8% [32.6, 43.3] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | APK_install_lure | 36/50 = 72.0% [58.3, 82.5] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | OTP_coercion | 35/50 = 70.0% [56.2, 80.9] | 16/33 = 48.5% [32.5, 64.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | SIM_telecom_KYC | 36/50 = 72.0% [58.3, 82.5] | 24/33 = 72.7% [55.8, 84.9] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | UPI_collect_refund | 30/50 = 60.0% [46.2, 72.4] | 12/33 = 36.4% [22.2, 53.4] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | bank_KYC_block | 33/50 = 66.0% [52.2, 77.6] | 17/33 = 51.5% [35.2, 67.5] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | challan_tax_government | 29/50 = 58.0% [44.2, 70.6] | 8/33 = 24.2% [12.8, 41.0] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | courier_customs_fee | 40/50 = 80.0% [67.0, 88.8] | 9/33 = 27.3% [15.1, 44.2] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | electricity_gas_callback | 25/50 = 50.0% [36.6, 63.4] | 6/33 = 18.2% [8.6, 34.4] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | friend_impersonation_money | 32/50 = 64.0% [50.1, 75.9] | 15/33 = 45.5% [29.8, 62.0] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | job_task_fee | 35/50 = 70.0% [56.2, 80.9] | 10/33 = 30.3% [17.4, 47.3] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | loan_app_threat | 23/50 = 46.0% [33.0, 59.6] | 9/33 = 27.3% [15.1, 44.2] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | prize_lottery | 30/50 = 60.0% [46.2, 72.4] | 13/33 = 39.4% [24.7, 56.3] | synthetic descriptive |
| V4.4_rc2_experiment_3 | family | promotion_no_secret | 0/0; unavailable | 7/100 = 7.0% [3.4, 13.7] | indicative only |
| V4.4_rc2_experiment_3 | family | safe_OTP_transaction | 0/0; unavailable | 1/4 = 25.0% [4.6, 69.9] | indicative only |
| V4.4_rc2_experiment_3 | has_url | false | 183/240 = 76.2% [70.5, 81.2] | 78/188 = 41.5% [34.7, 48.6] | synthetic descriptive |
| V4.4_rc2_experiment_3 | has_url | true | 201/360 = 55.8% [50.7, 60.9] | 81/312 = 26.0% [21.4, 31.1] | synthetic descriptive |
| V4.4_rc2_experiment_3 | channel_style | SMS | 193/300 = 64.3% [58.8, 69.5] | 67/250 = 26.8% [21.7, 32.6] | synthetic descriptive |
| V4.4_rc2_experiment_3 | channel_style | WhatsApp | 191/300 = 63.7% [58.1, 68.9] | 92/250 = 36.8% [31.1, 42.9] | synthetic descriptive |
| V4.4_rc2_experiment_3 | length_bin | 16_30 | 231/329 = 70.2% [65.1, 74.9] | 89/154 = 57.8% [49.9, 65.3] | synthetic descriptive |
| V4.4_rc2_experiment_3 | length_bin | 6_15 | 153/271 = 56.5% [50.5, 62.2] | 70/346 = 20.2% [16.3, 24.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | noise_level | clean | 46/120 = 38.3% [30.1, 47.3] | 26/105 = 24.8% [17.5, 33.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | noise_level | missing_vowels | 68/120 = 56.7% [47.7, 65.2] | 26/105 = 24.8% [17.5, 33.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | noise_level | mixed_case | 108/120 = 90.0% [83.3, 94.2] | 66/93 = 71.0% [61.1, 79.2] | synthetic descriptive |
| V4.4_rc2_experiment_3 | noise_level | texting_abbrev | 87/120 = 72.5% [63.9, 79.7] | 30/105 = 28.6% [20.8, 37.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | noise_level | typos | 75/120 = 62.5% [53.6, 70.6] | 11/92 = 12.0% [6.8, 20.2] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | colloquial_adviser | 51/75 = 68.0% [56.8, 77.5] | 29/65 = 44.6% [33.2, 56.7] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | formal_desk | 48/75 = 64.0% [52.7, 73.9] | 17/63 = 27.0% [17.6, 39.0] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | friend | 53/79 = 67.1% [56.1, 76.4] | 17/64 = 26.6% [17.3, 38.5] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | household | 50/78 = 64.1% [53.0, 73.9] | 15/59 = 25.4% [16.1, 37.8] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | hurried_texter | 47/71 = 66.2% [54.6, 76.1] | 17/61 = 27.9% [18.2, 40.2] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | merchant | 44/73 = 60.3% [48.8, 70.7] | 18/61 = 29.5% [19.6, 41.9] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | student | 43/77 = 55.8% [44.7, 66.4] | 30/67 = 44.8% [33.5, 56.6] | synthetic descriptive |
| V4.4_rc2_experiment_3 | generator_batch | terse_service | 48/72 = 66.7% [55.2, 76.5] | 16/60 = 26.7% [17.1, 39.0] | synthetic descriptive |
| V4.4_rc2_experiment_3 | hinglish_density | heavy | 135/222 = 60.8% [54.3, 67.0] | 64/188 = 34.0% [27.6, 41.1] | synthetic descriptive |
| V4.4_rc2_experiment_3 | hinglish_density | medium | 249/378 = 65.9% [61.0, 70.5] | 95/312 = 30.4% [25.6, 35.8] | synthetic descriptive |
