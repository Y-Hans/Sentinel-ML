# TEST/OOD Error Stratification

**REPRODUCED** from all TEST/OOD rows and frozen model predictions at τ=.61. Groups with zero BENIGN or MALICIOUS examples show FPR or recall as N/A, not zero. Project taxonomy defines primary_type as intent categories; category and intent strata are the same underlying annotation. source_scam_type is included as a separate descriptive proxy. URL/phone groups distinguish raw model-regex matches from placeholders.

## TEST

| Group | N | B/S/M | benign FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

### source_id

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| SRC_CURATED_HARD_NEGATIVES_V1 | 20 | 20/0/0 | 0/0.00% | 0/0 (N/A) | 0 | 0 | 0 |

| SRC_IMC25_FISHING_SMISHING | 1649 | 0/131/1518 | 0/N/A | 1476/1518 (97.23%) | 68 | 18 | 24 |

| SRC_MENDELEY_SMISHING_2022 | 568 | 479/51/38 | 1/0.21% | 34/38 (89.47%) | 20 | 4 | 0 |

| SRC_UCI_SMS_SPAM_2011 | 27 | 21/6/0 | 1/4.76% | 0/0 (N/A) | 2 | 0 | 0 |

### language

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| UNKNOWN | 3 | 0/0/3 | 0/N/A | 2/3 (66.67%) | 0 | 0 | 1 |

| en | 2258 | 519/188/1551 | 2/0.39% | 1506/1551 (97.10%) | 90 | 22 | 23 |

| hinglish | 3 | 1/0/2 | 0/0.00% | 2/2 (100.00%) | 0 | 0 | 0 |

### category

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| BANKING_TRANSACTIONAL | 640 | 0/0/640 | 0/N/A | 638/640 (99.69%) | 0 | 1 | 1 |

| DELIVERY | 143 | 10/0/133 | 0/0.00% | 128/133 (96.24%) | 0 | 2 | 3 |

| GOVERNMENT_INFO | 142 | 0/0/142 | 0/N/A | 142/142 (100.00%) | 0 | 0 | 0 |

| PERSONAL_P2P | 500 | 500/0/0 | 2/0.40% | 0/0 (N/A) | 0 | 0 | 0 |

| PROMOTIONAL | 188 | 0/188/0 | 0/N/A | 0/0 (N/A) | 90 | 0 | 0 |

| SERVICE_UPDATE | 171 | 10/0/161 | 0/0.00% | 155/161 (96.27%) | 0 | 4 | 2 |

| UNKNOWN | 480 | 0/0/480 | 0/N/A | 447/480 (93.12%) | 0 | 15 | 18 |

### intent

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| BANKING_TRANSACTIONAL | 640 | 0/0/640 | 0/N/A | 638/640 (99.69%) | 0 | 1 | 1 |

| DELIVERY | 143 | 10/0/133 | 0/0.00% | 128/133 (96.24%) | 0 | 2 | 3 |

| GOVERNMENT_INFO | 142 | 0/0/142 | 0/N/A | 142/142 (100.00%) | 0 | 0 | 0 |

| PERSONAL_P2P | 500 | 500/0/0 | 2/0.40% | 0/0 (N/A) | 0 | 0 | 0 |

| PROMOTIONAL | 188 | 0/188/0 | 0/N/A | 0/0 (N/A) | 90 | 0 | 0 |

| SERVICE_UPDATE | 171 | 10/0/161 | 0/0.00% | 155/161 (96.27%) | 0 | 4 | 2 |

| UNKNOWN | 480 | 0/0/480 | 0/N/A | 447/480 (93.12%) | 0 | 15 | 18 |

### source_scam_type

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| UNKNOWN | 622 | 520/57/45 | 2/0.38% | 40/45 (88.89%) | 22 | 4 | 1 |

| banking | 640 | 0/0/640 | 0/N/A | 638/640 (99.69%) | 0 | 1 | 1 |

| delivery | 133 | 0/0/133 | 0/N/A | 128/133 (96.24%) | 0 | 2 | 3 |

| government | 142 | 0/0/142 | 0/N/A | 142/142 (100.00%) | 0 | 0 | 0 |

| hey mum/dad | 9 | 0/0/9 | 0/N/A | 8/9 (88.89%) | 0 | 0 | 1 |

| others | 395 | 0/0/395 | 0/N/A | 374/395 (94.68%) | 0 | 11 | 10 |

| spam | 131 | 0/131/0 | 0/N/A | 0/0 (N/A) | 68 | 0 | 0 |

| telecom | 161 | 0/0/161 | 0/N/A | 155/161 (96.27%) | 0 | 4 | 2 |

| wrong number | 31 | 0/0/31 | 0/N/A | 25/31 (80.65%) | 0 | 0 | 6 |

### threat_vector

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| APK_MALWARE_DROPPER | 22 | 0/2/20 | 0/N/A | 20/20 (100.00%) | 1 | 0 | 0 |

| BANK_KYC_SUSPENSION | 640 | 0/0/640 | 0/N/A | 638/640 (99.69%) | 0 | 1 | 1 |

| COMMERCIAL_SPAM | 188 | 0/188/0 | 0/N/A | 0/0 (N/A) | 90 | 0 | 0 |

| CREDENTIAL_REQUEST | 783 | 0/0/783 | 0/N/A | 744/783 (95.02%) | 0 | 19 | 20 |

| DELIVERY_SCAM | 133 | 0/0/133 | 0/N/A | 128/133 (96.24%) | 0 | 2 | 3 |

| NONE | 520 | 520/0/0 | 2/0.38% | 0/0 (N/A) | 0 | 0 | 0 |

### url_presence

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| NO_URL | 1522 | 520/115/887 | 2/0.38% | 850/887 (95.83%) | 53 | 13 | 24 |

| PLACEHOLDER_ONLY | 742 | 0/73/669 | 0/N/A | 660/669 (98.65%) | 37 | 9 | 0 |

### phone_presence

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| NO_PHONE | 1996 | 520/156/1320 | 2/0.38% | 1278/1320 (96.82%) | 70 | 18 | 24 |

| PLACEHOLDER_ONLY | 268 | 0/32/236 | 0/N/A | 232/236 (98.31%) | 20 | 4 | 0 |

## OOD

| Group | N | B/S/M | benign FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

### source_id

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| SRC_CURATED_HARD_NEGATIVES_V1 | 23 | 11/0/12 | 1/9.09% | 11/12 (91.67%) | 0 | 1 | 0 |

| SRC_IMC25_FISHING_SMISHING | 818 | 0/58/760 | 0/N/A | 729/760 (95.92%) | 28 | 14 | 17 |

| SRC_MENDELEY_SMISHING_2022 | 274 | 229/23/22 | 0/0.00% | 21/22 (95.45%) | 3 | 1 | 0 |

| SRC_UCI_SMS_SPAM_2011 | 17 | 15/2/0 | 0/0.00% | 0/0 (N/A) | 0 | 0 | 0 |

### language

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| en | 1129 | 253/83/793 | 1/0.40% | 760/793 (95.84%) | 31 | 16 | 17 |

| hinglish | 3 | 2/0/1 | 0/0.00% | 1/1 (100.00%) | 0 | 0 | 0 |

### category

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| BANKING_TRANSACTIONAL | 327 | 0/0/327 | 0/N/A | 325/327 (99.39%) | 0 | 0 | 2 |

| DELIVERY | 83 | 10/0/73 | 0/0.00% | 72/73 (98.63%) | 0 | 0 | 1 |

| GOVERNMENT_INFO | 74 | 0/0/74 | 0/N/A | 71/74 (95.95%) | 0 | 1 | 2 |

| OTP_AUTH | 10 | 0/0/10 | 0/N/A | 10/10 (100.00%) | 0 | 0 | 0 |

| PERSONAL_P2P | 244 | 244/0/0 | 0/0.00% | 0/0 (N/A) | 0 | 0 | 0 |

| PROMOTIONAL | 84 | 0/83/1 | 0/N/A | 0/1 (0.00%) | 31 | 1 | 0 |

| SERVICE_UPDATE | 72 | 1/0/71 | 1/100.00% | 68/71 (95.77%) | 0 | 2 | 1 |

| UNKNOWN | 238 | 0/0/238 | 0/N/A | 215/238 (90.34%) | 0 | 12 | 11 |

### intent

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| BANKING_TRANSACTIONAL | 327 | 0/0/327 | 0/N/A | 325/327 (99.39%) | 0 | 0 | 2 |

| DELIVERY | 83 | 10/0/73 | 0/0.00% | 72/73 (98.63%) | 0 | 0 | 1 |

| GOVERNMENT_INFO | 74 | 0/0/74 | 0/N/A | 71/74 (95.95%) | 0 | 1 | 2 |

| OTP_AUTH | 10 | 0/0/10 | 0/N/A | 10/10 (100.00%) | 0 | 0 | 0 |

| PERSONAL_P2P | 244 | 244/0/0 | 0/0.00% | 0/0 (N/A) | 0 | 0 | 0 |

| PROMOTIONAL | 84 | 0/83/1 | 0/N/A | 0/1 (0.00%) | 31 | 1 | 0 |

| SERVICE_UPDATE | 72 | 1/0/71 | 1/100.00% | 68/71 (95.77%) | 0 | 2 | 1 |

| UNKNOWN | 238 | 0/0/238 | 0/N/A | 215/238 (90.34%) | 0 | 12 | 11 |

### source_scam_type

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| UNKNOWN | 315 | 255/25/35 | 1/0.39% | 33/35 (94.29%) | 3 | 2 | 0 |

| banking | 327 | 0/0/327 | 0/N/A | 325/327 (99.39%) | 0 | 0 | 2 |

| delivery | 73 | 0/0/73 | 0/N/A | 72/73 (98.63%) | 0 | 0 | 1 |

| government | 74 | 0/0/74 | 0/N/A | 71/74 (95.95%) | 0 | 1 | 2 |

| hey mum/dad | 3 | 0/0/3 | 0/N/A | 3/3 (100.00%) | 0 | 0 | 0 |

| others | 204 | 0/0/204 | 0/N/A | 185/204 (90.69%) | 0 | 11 | 8 |

| spam | 58 | 0/58/0 | 0/N/A | 0/0 (N/A) | 28 | 0 | 0 |

| telecom | 70 | 0/0/70 | 0/N/A | 67/70 (95.71%) | 0 | 2 | 1 |

| wrong number | 8 | 0/0/8 | 0/N/A | 5/8 (62.50%) | 0 | 0 | 3 |

### threat_vector

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| APK_MALWARE_DROPPER | 10 | 0/1/9 | 0/N/A | 9/9 (100.00%) | 0 | 0 | 0 |

| BANK_KYC_SUSPENSION | 337 | 0/0/337 | 0/N/A | 335/337 (99.41%) | 0 | 0 | 2 |

| COMMERCIAL_SPAM | 83 | 0/83/0 | 0/N/A | 0/0 (N/A) | 31 | 0 | 0 |

| CREDENTIAL_REQUEST | 382 | 0/0/382 | 0/N/A | 353/382 (92.41%) | 0 | 15 | 14 |

| DELIVERY_SCAM | 73 | 0/0/73 | 0/N/A | 72/73 (98.63%) | 0 | 0 | 1 |

| ELECTRICITY_DISCONNECTION_SCAM | 1 | 0/0/1 | 0/N/A | 1/1 (100.00%) | 0 | 0 | 0 |

| NONE | 255 | 255/0/0 | 1/0.39% | 0/0 (N/A) | 0 | 0 | 0 |

| OTP_DISCLOSURE_REQUEST | 10 | 0/0/10 | 0/N/A | 10/10 (100.00%) | 0 | 0 | 0 |

| PART_TIME_JOB_SCAM | 1 | 0/0/1 | 0/N/A | 0/1 (0.00%) | 0 | 1 | 0 |

### url_presence

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| NO_URL | 778 | 255/44/479 | 1/0.39% | 451/479 (94.15%) | 15 | 11 | 17 |

| PLACEHOLDER_ONLY | 354 | 0/39/315 | 0/N/A | 310/315 (98.41%) | 16 | 5 | 0 |

### phone_presence

| Value | N | B/S/M | B FP/FPR | M recall | S→M | M→S | M→B |
|---|---:|---:|---:|---:|---:|---:|---:|

| NO_PHONE | 1011 | 255/72/684 | 1/0.39% | 654/684 (95.61%) | 28 | 13 | 17 |

| PLACEHOLDER_ONLY | 121 | 0/11/110 | 0/N/A | 107/110 (97.27%) | 3 | 3 | 0 |

## Distribution findings

- **REPRODUCED:** all 90 TEST and 31 OOD SPAM→MALICIOUS errors are category PROMOTIONAL and threat vector COMMERCIAL_SPAM. They are spread across sources: TEST IMC25 68/131 spam rows (51.9%), Mendeley 20/51 (39.2%), UCI 2/6 (33.3%); OOD IMC25 28/58 (48.3%), Mendeley 3/23 (13.0%), UCI 0/2. Small non-IMC denominators limit comparison.
- **REPRODUCED:** TEST malicious misses: 42/1,518 IMC25 malicious (2.77%), 4/38 Mendeley (10.53%); OOD: 31/760 IMC25 (4.08%), 1/22 Mendeley (4.55%), 1/12 curated (8.33%). OOD/secondary-source strata are small.
- **REPRODUCED:** TEST malicious misses concentrate in UNKNOWN category (33/480; 18 M→B and 15 M→S), then SERVICE_UPDATE (6/171), DELIVERY (5/143), BANKING_TRANSACTIONAL (2/640). OOD: UNKNOWN 23/238, BANKING_TRANSACTIONAL 2/327, GOVERNMENT_INFO 3/74, plus small residual groups.
- **REPRODUCED:** three Hinglish rows occur in each TEST/OOD split and none carries a reported target-class error. This is not evidence of language robustness; group size is inadequate.
- **INFERENCE:** SPAM→MALICIOUS errors are more category/semantic-class-specific than source-exclusive. Malicious misses are distributed among source and category strata, with UNKNOWN metadata accounting for much of the miss count.
- **VERIFIED:** raw URL and phone feature presence is zero throughout TEST/OOD. Placeholder-conditioned counts and rates are still shown in the full tables; lexical representation remains exposed to the placeholder token.

Complete exact-count tables with class-conditional probability means: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).
