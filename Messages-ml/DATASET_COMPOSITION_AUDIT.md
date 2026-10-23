# Dataset Composition Audit — Full-Corpus V4.3

Status tags: **REPRODUCED** means counted from the complete named JSONL file or inferred directly from frozen V4.3 outputs; **VERIFIED** means metadata/code checked. No counts below were estimated from error rows. Threshold fixed at 0.61.

Source JSON includes file/artifact SHA-256, raw counts, percentages, label-conditioned distributions, and all row-level dimensions. Percentages for threat_vectors use flattened multi-label assignments and can sum above 100%. The project taxonomy documents primary_type as an intent category independent of security status. The category and intent tables both map to that one stored field; they are not independent labels. Source scam_type is shown separately.

## TRAIN — N=19672

### Labels

| Value | Count | Percent |
|---|---|---|
| BENIGN | 5891 | 29.95% |
| MALICIOUS | 12612 | 64.11% |
| SUSPICIOUS_SPAM | 1169 | 5.94% |

### source_id

| Value | Count | Percent |
|---|---|---|
| SRC_CURATED_HARD_NEGATIVES_V1 | 230 | 1.17% |
| SRC_IMC25_FISHING_SMISHING | 11343 | 57.66% |
| SRC_MENDELEY_SMISHING_2022 | 4095 | 20.82% |
| SRC_UCI_SMS_SPAM_2011 | 187 | 0.95% |
| SRC_V4_3_BANKING_BENIGN | 140 | 0.71% |
| SRC_V4_3_DELIVERY | 294 | 1.49% |
| SRC_V4_3_DELIVERY_BENIGN | 168 | 0.85% |
| SRC_V4_3_ELECTRICITY | 210 | 1.07% |
| SRC_V4_3_GOVERNMENT_BENIGN | 80 | 0.41% |
| SRC_V4_3_HINGLISH_CONVERSATION | 240 | 1.22% |
| SRC_V4_3_HINGLISH_THREAT | 140 | 0.71% |
| SRC_V4_3_INSTITUTIONAL | 546 | 2.78% |
| SRC_V4_3_OTP_INTENT | 117 | 0.59% |
| SRC_V4_3_SHORT_CHAT_INTENT | 1368 | 6.95% |
| SRC_V4_3_TELCO | 100 | 0.51% |
| SRC_V4_3_URL_BENIGN | 10 | 0.05% |
| SRC_V4_3_URL_INTENT | 210 | 1.07% |
| SRC_V4_3_URL_MALICIOUS | 50 | 0.25% |
| SRC_V4_3_UTILITY_BENIGN | 144 | 0.73% |

### source_type

| Value | Count | Percent |
|---|---|---|
| CONTROLLED_CONTRASTIVE | 3817 | 19.40% |
| INTERNAL_CURATED | 230 | 1.17% |
| PUBLIC_RESEARCH | 15625 | 79.43% |

### language

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 14 | 0.07% |
| en | 17861 | 90.79% |
| hinglish | 1797 | 9.13% |

### script

| Value | Count | Percent |
|---|---|---|
| metadata:LATIN | 15772 | 80.17% |
| metadata:MIXED | 69 | 0.35% |
| metadata:OTHER | 12 | 0.06% |
| metadata:UNKNOWN | 3819 | 19.41% |

### category

| Value | Count | Percent |
|---|---|---|
| ACADEMIC_ANNOUNCEMENT | 273 | 1.39% |
| BANKING_TRANSACTIONAL | 4815 | 24.48% |
| BILLING_INFORMATION | 120 | 0.61% |
| BILL_AND_SERVICE | 60 | 0.31% |
| CAMPUS_IMPERSONATION_PHISHING | 273 | 1.39% |
| CASUAL_CHAT | 720 | 3.66% |
| CLEAN_RESOURCE_LINK | 20 | 0.10% |
| CREDENTIAL_THEFT_DEMAND | 52 | 0.26% |
| DELIVERY | 939 | 4.77% |
| FAKE_PACKAGE_SMISHING | 147 | 0.75% |
| GOVERNMENT_INFO | 998 | 5.07% |
| INFORMATIONAL_P2P | 240 | 1.22% |
| LEGIT_BANKING_NOTICE | 140 | 0.71% |
| LEGIT_DELIVERY_ALERT | 168 | 0.85% |
| LEGIT_GOVT_ADVISORY | 80 | 0.41% |
| LEGIT_POWER_NOTICE | 144 | 0.73% |
| NAKED_MALICIOUS_LINK | 250 | 1.27% |
| OTP_AUTH | 111 | 0.56% |
| OTP_RECEIPT_OR_QUERY | 65 | 0.33% |
| PACKAGE_STATUS | 147 | 0.75% |
| PERSONAL_P2P | 3532 | 17.95% |
| POWER_CUT_SCAM | 90 | 0.46% |
| PROMOTIONAL | 1190 | 6.05% |
| SERVICE_UPDATE | 1008 | 5.12% |
| SIM_BLOCK_SCAM | 40 | 0.20% |
| SMISHING_COERCION | 140 | 0.71% |
| THEFT_DEMAND | 648 | 3.29% |
| UNKNOWN | 3262 | 16.58% |

### intent

| Value | Count | Percent |
|---|---|---|
| ACADEMIC_ANNOUNCEMENT | 273 | 1.39% |
| BANKING_TRANSACTIONAL | 4815 | 24.48% |
| BILLING_INFORMATION | 120 | 0.61% |
| BILL_AND_SERVICE | 60 | 0.31% |
| CAMPUS_IMPERSONATION_PHISHING | 273 | 1.39% |
| CASUAL_CHAT | 720 | 3.66% |
| CLEAN_RESOURCE_LINK | 20 | 0.10% |
| CREDENTIAL_THEFT_DEMAND | 52 | 0.26% |
| DELIVERY | 939 | 4.77% |
| FAKE_PACKAGE_SMISHING | 147 | 0.75% |
| GOVERNMENT_INFO | 998 | 5.07% |
| INFORMATIONAL_P2P | 240 | 1.22% |
| LEGIT_BANKING_NOTICE | 140 | 0.71% |
| LEGIT_DELIVERY_ALERT | 168 | 0.85% |
| LEGIT_GOVT_ADVISORY | 80 | 0.41% |
| LEGIT_POWER_NOTICE | 144 | 0.73% |
| NAKED_MALICIOUS_LINK | 250 | 1.27% |
| OTP_AUTH | 111 | 0.56% |
| OTP_RECEIPT_OR_QUERY | 65 | 0.33% |
| PACKAGE_STATUS | 147 | 0.75% |
| PERSONAL_P2P | 3532 | 17.95% |
| POWER_CUT_SCAM | 90 | 0.46% |
| PROMOTIONAL | 1190 | 6.05% |
| SERVICE_UPDATE | 1008 | 5.12% |
| SIM_BLOCK_SCAM | 40 | 0.20% |
| SMISHING_COERCION | 140 | 0.71% |
| THEFT_DEMAND | 648 | 3.29% |
| UNKNOWN | 3262 | 16.58% |

### source_scam_type

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 8386 | 42.63% |
| banking | 4812 | 24.46% |
| delivery | 869 | 4.42% |
| government | 988 | 5.02% |
| hey mum/dad | 41 | 0.21% |
| others | 2619 | 13.31% |
| spam | 812 | 4.13% |
| telecom | 993 | 5.05% |
| wrong number | 152 | 0.77% |

### threat_vector

| Value | Count | Percent |
|---|---|---|
| APK_MALWARE_DROPPER | 197 | 0.99% |
| BANK_KYC_SUSPENSION | 4815 | 24.18% |
| COMMERCIAL_SPAM | 1169 | 5.87% |
| CREDENTIAL_REQUEST | 5245 | 26.34% |
| DELIVERY_SCAM | 869 | 4.36% |
| ELECTRICITY_DISCONNECTION_SCAM | 13 | 0.07% |
| LOTTERY_PRIZE_FRAUD | 10 | 0.05% |
| NONE | 3714 | 18.65% |
| OTP_DISCLOSURE_REQUEST | 21 | 0.11% |
| PART_TIME_JOB_SCAM | 1 | 0.01% |
| PAYMENT_SCAM | 20 | 0.10% |
| UNANNOTATED | 3817 | 19.17% |
| UPI_COLLECT_FRAUD | 20 | 0.10% |

### URL and phone presence

Counts are reported both for the frozen model's raw regex and the normalized placeholder visible to lexical vectorizers.

URL raw-regex: NO 19002 (96.59%), YES 670 (3.41%). URL token: NO 14738 (74.92%), YES 4934 (25.08%).

Phone raw-regex: NO 19536 (99.31%), YES 136 (0.69%). Phone token: NO 17768 (90.32%), YES 1904 (9.68%).

### Message length (characters)

| Group | N | p0 | p25 | p50 | p75 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|---|
| BENIGN | 5891 | 2.0 | 35.0 | 68.0 | 124.0 | 157.0 | 187.0 | 239.1 | 623.0 |
| SUSPICIOUS_SPAM | 1169 | 5.0 | 103.0 | 136.0 | 163.0 | 233.2 | 305.0 | 562.9 | 984.0 |
| MALICIOUS | 12612 | 5.0 | 102.0 | 132.0 | 164.0 | 246.0 | 320.0 | 553.6 | 1445.0 |

## VAL — N=3397

### Labels

| Value | Count | Percent |
|---|---|---|
| BENIGN | 807 | 23.76% |
| MALICIOUS | 2316 | 68.18% |
| SUSPICIOUS_SPAM | 274 | 8.07% |

### source_id

| Value | Count | Percent |
|---|---|---|
| SRC_CURATED_HARD_NEGATIVES_V1 | 64 | 1.88% |
| SRC_IMC25_FISHING_SMISHING | 2396 | 70.53% |
| SRC_MENDELEY_SMISHING_2022 | 894 | 26.32% |
| SRC_UCI_SMS_SPAM_2011 | 43 | 1.27% |

### source_type

| Value | Count | Percent |
|---|---|---|
| INTERNAL_CURATED | 64 | 1.88% |
| PUBLIC_RESEARCH | 3333 | 98.12% |

### language

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 2 | 0.06% |
| en | 3377 | 99.41% |
| hinglish | 18 | 0.53% |

### script

| Value | Count | Percent |
|---|---|---|
| metadata:LATIN | 3378 | 99.44% |
| metadata:MIXED | 17 | 0.50% |
| metadata:OTHER | 2 | 0.06% |

### category

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 971 | 28.58% |
| DELIVERY | 197 | 5.80% |
| GOVERNMENT_INFO | 212 | 6.24% |
| OTP_AUTH | 20 | 0.59% |
| PERSONAL_P2P | 766 | 22.55% |
| PROMOTIONAL | 275 | 8.10% |
| SERVICE_UPDATE | 232 | 6.83% |
| UNKNOWN | 724 | 21.31% |

### intent

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 971 | 28.58% |
| DELIVERY | 197 | 5.80% |
| GOVERNMENT_INFO | 212 | 6.24% |
| OTP_AUTH | 20 | 0.59% |
| PERSONAL_P2P | 766 | 22.55% |
| PROMOTIONAL | 275 | 8.10% |
| SERVICE_UPDATE | 232 | 6.83% |
| UNKNOWN | 724 | 21.31% |

### source_scam_type

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 1011 | 29.76% |
| banking | 970 | 28.55% |
| delivery | 187 | 5.50% |
| government | 206 | 6.06% |
| hey mum/dad | 6 | 0.18% |
| others | 584 | 17.19% |
| spam | 193 | 5.68% |
| telecom | 206 | 6.06% |
| wrong number | 34 | 1.00% |

### threat_vector

| Value | Count | Percent |
|---|---|---|
| APK_MALWARE_DROPPER | 29 | 0.84% |
| BANK_KYC_SUSPENSION | 971 | 28.25% |
| COMMERCIAL_SPAM | 274 | 7.97% |
| CREDENTIAL_REQUEST | 1137 | 33.08% |
| DELIVERY_SCAM | 187 | 5.44% |
| ELECTRICITY_DISCONNECTION_SCAM | 10 | 0.29% |
| NONE | 807 | 23.48% |
| OTP_DISCLOSURE_REQUEST | 10 | 0.29% |
| PART_TIME_JOB_SCAM | 1 | 0.03% |
| PAYMENT_SCAM | 10 | 0.29% |
| TRAFFIC_CHALLAN_PHISHING | 1 | 0.03% |

### URL and phone presence

Counts are reported both for the frozen model's raw regex and the normalized placeholder visible to lexical vectorizers.

URL raw-regex: NO 3397 (100.00%). URL token: NO 2378 (70.00%), YES 1019 (30.00%).

Phone raw-regex: NO 3397 (100.00%). Phone token: NO 2966 (87.31%), YES 431 (12.69%).

### Message length (characters)

| Group | N | p0 | p25 | p50 | p75 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|---|
| BENIGN | 807 | 5.0 | 36.0 | 59.0 | 110.0 | 154.0 | 162.0 | 296.6 | 910.0 |
| SUSPICIOUS_SPAM | 274 | 30.0 | 105.0 | 137.5 | 163.8 | 242.0 | 323.7 | 563.6 | 919.0 |
| MALICIOUS | 2316 | 5.0 | 108.0 | 134.0 | 168.0 | 266.0 | 352.0 | 574.0 | 1054.0 |

## TEST — N=2264

### Labels

| Value | Count | Percent |
|---|---|---|
| BENIGN | 520 | 22.97% |
| MALICIOUS | 1556 | 68.73% |
| SUSPICIOUS_SPAM | 188 | 8.30% |

### source_id

| Value | Count | Percent |
|---|---|---|
| SRC_CURATED_HARD_NEGATIVES_V1 | 20 | 0.88% |
| SRC_IMC25_FISHING_SMISHING | 1649 | 72.84% |
| SRC_MENDELEY_SMISHING_2022 | 568 | 25.09% |
| SRC_UCI_SMS_SPAM_2011 | 27 | 1.19% |

### source_type

| Value | Count | Percent |
|---|---|---|
| INTERNAL_CURATED | 20 | 0.88% |
| PUBLIC_RESEARCH | 2244 | 99.12% |

### language

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 3 | 0.13% |
| en | 2258 | 99.73% |
| hinglish | 3 | 0.13% |

### script

| Value | Count | Percent |
|---|---|---|
| metadata:LATIN | 2246 | 99.20% |
| metadata:MIXED | 15 | 0.66% |
| metadata:OTHER | 3 | 0.13% |

### category

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 640 | 28.27% |
| DELIVERY | 143 | 6.32% |
| GOVERNMENT_INFO | 142 | 6.27% |
| PERSONAL_P2P | 500 | 22.08% |
| PROMOTIONAL | 188 | 8.30% |
| SERVICE_UPDATE | 171 | 7.55% |
| UNKNOWN | 480 | 21.20% |

### intent

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 640 | 28.27% |
| DELIVERY | 143 | 6.32% |
| GOVERNMENT_INFO | 142 | 6.27% |
| PERSONAL_P2P | 500 | 22.08% |
| PROMOTIONAL | 188 | 8.30% |
| SERVICE_UPDATE | 171 | 7.55% |
| UNKNOWN | 480 | 21.20% |

### source_scam_type

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 622 | 27.47% |
| banking | 640 | 28.27% |
| delivery | 133 | 5.87% |
| government | 142 | 6.27% |
| hey mum/dad | 9 | 0.40% |
| others | 395 | 17.45% |
| spam | 131 | 5.79% |
| telecom | 161 | 7.11% |
| wrong number | 31 | 1.37% |

### threat_vector

| Value | Count | Percent |
|---|---|---|
| APK_MALWARE_DROPPER | 22 | 0.96% |
| BANK_KYC_SUSPENSION | 640 | 28.00% |
| COMMERCIAL_SPAM | 188 | 8.22% |
| CREDENTIAL_REQUEST | 783 | 34.25% |
| DELIVERY_SCAM | 133 | 5.82% |
| NONE | 520 | 22.75% |

### URL and phone presence

Counts are reported both for the frozen model's raw regex and the normalized placeholder visible to lexical vectorizers.

URL raw-regex: NO 2264 (100.00%). URL token: NO 1522 (67.23%), YES 742 (32.77%).

Phone raw-regex: NO 2264 (100.00%). Phone token: NO 1996 (88.16%), YES 268 (11.84%).

### Message length (characters)

| Group | N | p0 | p25 | p50 | p75 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|---|
| BENIGN | 520 | 7.0 | 37.0 | 56.5 | 110.0 | 142.1 | 158.0 | 229.6 | 331.0 |
| SUSPICIOUS_SPAM | 188 | 16.0 | 106.2 | 135.0 | 157.2 | 251.2 | 368.8 | 582.2 | 655.0 |
| MALICIOUS | 1556 | 5.0 | 109.0 | 133.0 | 169.0 | 276.0 | 329.8 | 575.3 | 1119.0 |

## OOD — N=1132

### Labels

| Value | Count | Percent |
|---|---|---|
| BENIGN | 255 | 22.53% |
| MALICIOUS | 794 | 70.14% |
| SUSPICIOUS_SPAM | 83 | 7.33% |

### source_id

| Value | Count | Percent |
|---|---|---|
| SRC_CURATED_HARD_NEGATIVES_V1 | 23 | 2.03% |
| SRC_IMC25_FISHING_SMISHING | 818 | 72.26% |
| SRC_MENDELEY_SMISHING_2022 | 274 | 24.20% |
| SRC_UCI_SMS_SPAM_2011 | 17 | 1.50% |

### source_type

| Value | Count | Percent |
|---|---|---|
| INTERNAL_CURATED | 23 | 2.03% |
| PUBLIC_RESEARCH | 1109 | 97.97% |

### language

| Value | Count | Percent |
|---|---|---|
| en | 1129 | 99.73% |
| hinglish | 3 | 0.27% |

### script

| Value | Count | Percent |
|---|---|---|
| metadata:LATIN | 1128 | 99.65% |
| metadata:MIXED | 4 | 0.35% |

### category

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 327 | 28.89% |
| DELIVERY | 83 | 7.33% |
| GOVERNMENT_INFO | 74 | 6.54% |
| OTP_AUTH | 10 | 0.88% |
| PERSONAL_P2P | 244 | 21.55% |
| PROMOTIONAL | 84 | 7.42% |
| SERVICE_UPDATE | 72 | 6.36% |
| UNKNOWN | 238 | 21.02% |

### intent

| Value | Count | Percent |
|---|---|---|
| BANKING_TRANSACTIONAL | 327 | 28.89% |
| DELIVERY | 83 | 7.33% |
| GOVERNMENT_INFO | 74 | 6.54% |
| OTP_AUTH | 10 | 0.88% |
| PERSONAL_P2P | 244 | 21.55% |
| PROMOTIONAL | 84 | 7.42% |
| SERVICE_UPDATE | 72 | 6.36% |
| UNKNOWN | 238 | 21.02% |

### source_scam_type

| Value | Count | Percent |
|---|---|---|
| UNKNOWN | 315 | 27.83% |
| banking | 327 | 28.89% |
| delivery | 73 | 6.45% |
| government | 74 | 6.54% |
| hey mum/dad | 3 | 0.27% |
| others | 204 | 18.02% |
| spam | 58 | 5.12% |
| telecom | 70 | 6.18% |
| wrong number | 8 | 0.71% |

### threat_vector

| Value | Count | Percent |
|---|---|---|
| APK_MALWARE_DROPPER | 10 | 0.87% |
| BANK_KYC_SUSPENSION | 337 | 29.25% |
| COMMERCIAL_SPAM | 83 | 7.20% |
| CREDENTIAL_REQUEST | 382 | 33.16% |
| DELIVERY_SCAM | 73 | 6.34% |
| ELECTRICITY_DISCONNECTION_SCAM | 1 | 0.09% |
| NONE | 255 | 22.14% |
| OTP_DISCLOSURE_REQUEST | 10 | 0.87% |
| PART_TIME_JOB_SCAM | 1 | 0.09% |

### URL and phone presence

Counts are reported both for the frozen model's raw regex and the normalized placeholder visible to lexical vectorizers.

URL raw-regex: NO 1132 (100.00%). URL token: NO 778 (68.73%), YES 354 (31.27%).

Phone raw-regex: NO 1132 (100.00%). Phone token: NO 1011 (89.31%), YES 121 (10.69%).

### Message length (characters)

| Group | N | p0 | p25 | p50 | p75 | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|---|---|
| BENIGN | 255 | 7.0 | 34.0 | 58.0 | 101.0 | 132.6 | 147.6 | 212.2 | 486.0 |
| SUSPICIOUS_SPAM | 83 | 24.0 | 99.5 | 146.0 | 169.0 | 242.2 | 353.7 | 505.6 | 750.0 |
| MALICIOUS | 794 | 12.0 | 108.0 | 133.0 | 165.0 | 281.0 | 356.0 | 591.9 | 1219.0 |

## Annotation schema and taxonomy agreement

**VERIFIED:** canonical schema allows 8 primary_type values; taxonomy lists 10; V4.3 train uses 28 distinct values. Twenty distinct V4.3 training values (3,817 rows, all generated additions) are outside both enumerations: 2,177 BENIGN and 1,640 MALICIOUS. The test/validation/OOD records remain within schema values. This is an annotation-schema mismatch; the categories themselves may still be semantically useful.

**VERIFIED:** source_type values CONTROLLED_CONTRASTIVE (3,817 train rows) and INTERNAL_CURATED (230 train + 107 evaluation rows) are outside the schema enum. The 3,817 controlled additions have no threat_vectors field (UNANNOTATED); schema default NONE is distinct from a positive NONE annotation. Nineteen rows use language UNKNOWN uppercase, while schema enum uses lowercase unknown. Details and per-split counts are in annotation_taxonomy_audit in the JSON.

## Directly verified source concentration

**REPRODUCED:** TEST has 1,649/2,264 = 72.84% IMC25; OOD has 818/1,132 = 72.26% IMC25. Mendeley contributes 25.09% and 24.20%, respectively. This materially supports source concentration. The evidence is direct count data; whether the split procedure intended source independence is a separate unknown.

The raw regex columns also show zero raw URL/phone matches in VAL, TEST, and OOD. TEST nevertheless contains 742 `<URL>` placeholders (32.77%) and 268 phone placeholders (11.84%); OOD has 354 (31.27%) and 121 (10.69%). The structural raw-pattern features are therefore zero on all held-out records, while lexical features can still see placeholders.

## Row and artifact integrity

**REPRODUCED:** inference used class order [0, 1, 2], 4019 features, and 111 stored boosting iterations. VAL/TEST/OOD metric counts are in the JSON under `split_metrics`; they match the prior V4.3 reproduction.

Full aggregate tables, class-conditioned source/language/category/intent-proxy/threat-vector distributions, quantiles, hashes, and probabilities: [DATASET_COMPOSITION_AUDIT.json](DATASET_COMPOSITION_AUDIT.json).
