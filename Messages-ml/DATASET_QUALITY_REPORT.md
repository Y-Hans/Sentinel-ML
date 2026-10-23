# Sentinel Message ML — Phase 2.2 Dataset Quality & Audit Report

## 1. Executive Summary

Phase 2.2B has established the first verified, provenance-preserving, privacy-scrubbed, and leak-free Message ML dataset partition. 

The canonical corpus combines vetted open-access academic benchmarks, modern empirical smishing campaign feeds (ACM IMC 2025), and TRAI/RBI-compliant Indian banking and OTP calibration fixtures into a structured 3-tier security classification dataset.

```
RAW SOURCES (34,387 Records)
      ↓
EXACT DEDUPLICATION (11,739 Duplicates Collapsed)
      ↓
PRIVACY / SENSITIVE DATA MASKING (Zero PII Leaks)
      ↓
TEMPLATE CLUSTERING (21,680 Unique Clusters)
      ↓
GROUP-AWARE PARTITIONING (Zero Template Leakage)
      ↓
PROCESSED CORPUS (22,648 Records: 100% Schema Valid)
├── TRAIN: 15,855 records (70.0%)
├── VALIDATION: 3,397 records (15.0%)
├── TEST: 2,264 records (10.0%)
└── OOD: 1,132 records (5.0%)
```

---

## 2. Sources Acquired

| Source ID | Dataset Name | Version / DOI | License | Acquired Record Count | Raw Storage Location |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **`SRC_MENDELEY_SMISHING_2022`** | SMS Phishing Dataset for Machine Learning | 1 / [10.17632/f45bkkt8pr.1](https://doi.org/10.17632/f45bkkt8pr.1) | CC BY 4.0 | 5,971 | `Messages-ml/data/raw/SRC_MENDELEY_SMISHING_2022/Dataset_5971.zip` |
| **`SRC_CURATED_HARD_NEGATIVES_V1`** | Sentinel Curated DLT & Hard Negatives | 1.0.0 | Internal | 500 | `Messages-ml/data/raw/SRC_CURATED_HARD_NEGATIVES_V1/curated_hard_negatives.jsonl` |
| **`SRC_IMC25_FISHING_SMISHING`** | Smishing-Dataset-IMC25 (*Fishing for Smishing*) | IMC 2025 | CC BY 4.0 | 22,342 (en/hi filtered) | `Messages-ml/data/raw/SRC_IMC25_FISHING_SMISHING/final_dataset_output.csv` |
| **`SRC_UCI_SMS_SPAM_2011`** | UCI SMS Spam Collection | 2011 / [10.24432/C5CC84](https://doi.org/10.24432/C5CC84) | CC BY 4.0 | 5,574 | `Messages-ml/data/raw/SRC_UCI_SMS_SPAM_2011/sms+spam+collection.zip` |

---

## 3. Sources Skipped / Retained as Manifest-Only

| Source ID | Dataset Name | Reason for Manifest-Only Status | Permitted Usage |
| :--- | :--- | :--- | :--- |
| **`SRC_IIITD_SMS_SPAM`** | IIIT-D SMS Spam Dataset (SMSAssassin) | Academic research license prohibits direct public repository redistribution. Retained as manifest entry in [`acquisition_manifest.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/raw/acquisition_manifest.json) for local offline evaluation. | Local Research Only |
| **`SRC_NUS_SMS_CORPUS_2013`** | NUS SMS Corpus | Overwhelming 55,000+ pure ham volume would cause severe class skew; retained in registry for future balanced downsampling. | Research with Citation |

---

## 4. License Verification Findings

All acquired raw files were verified at download time:
- **`SRC_MENDELEY_SMISHING_2022`**: Verified `CC BY 4.0` in Mendeley Data metadata. SHA-256: `9bbf3188fdad81495d8e82825648b9b63b53fc86841a3d26c02629990b233cc3`.
- **`SRC_IMC25_FISHING_SMISHING`**: Verified `CC BY 4.0` in official repository `LICENSE.txt`. SHA-256: `576550785ea83cb0d0e6530656a599602cffef03aaecbe523d42e616238b939c`.
- **`SRC_UCI_SMS_SPAM_2011`**: Verified `CC BY 4.0` in UCI Machine Learning repository. SHA-256: `a937a0915ba87fe3fbe1d0cf887cfca970425a498075dc6fc0df1eef554a9ba1`.
- **`SRC_CURATED_HARD_NEGATIVES_V1`**: Internal project license. SHA-256: `18ba721665a31a5cb23fb2f4da898a96fc19d45e505ba1e5d7ae22119ebda24f`.

---

## 5. Raw vs Valid Record Counts

- **Total Raw Records Ingested Across Sources**: 34,387 records.
- **Exact Duplicate Records Collapsed**: 11,739 records (34.1% exact repetition across web campaigns and baseline spam).
- **Total Unique Canonical Records**: **22,648 records**.
- **Malformed / Corrupt Records**: **0** (100% parse rate).
- **Invalid Records**: **0** (100% schema compliance verified via `dataset_validator.py`).
- **Duplicate Message IDs**: **0**.

---

## 6. Privacy & PII Scrubbing Findings

Every record underwent deterministic privacy masking before partition assignment:

| Sensitive Data Category | Masking Token | Instances Masked | Semantic Preservation Strategy |
| :--- | :---: | :---: | :--- |
| **Phone Numbers** | `<PHONE>` | 711 | Preserves call-to-action threat signal without storing victim/attacker numbers. |
| **Bank Account / Cards** | `<ACCOUNT>` | 1,731 | Preserves financial notification structure while removing personal digits. |
| **Numeric Verification OTPs** | `<NUM_CODE>` | 2,098 | Retains presence of authentication codes without logging live credentials. |
| **UPI VPAs** | `<UPI_VPA>` | 57 | Preserves payment handles while removing personal identity strings. |
| **Raw Phishing / Shortener URLs** | `<URL>` | 7,128 | Preserves URL presence, protocol, and shortener indicators without committing active malicious domains. |

> [!NOTE]
> **Zero Raw PII Exposure**: No live phone numbers, active session OTPs, bank account numbers, or personal user handles are committed in processed partitions.

---

## 7. Label Mapping & Intent Distributions

### Security Label Distribution (3 Tiers)

| Security Label | Record Count | Percentage (%) | Role in Subsystem |
| :--- | :---: | :---: | :--- |
| **`MALICIOUS`** | **15,638** | **69.05%** | High-risk cyber threats (Reverse OTP theft, fake KYC, electricity extortion, APK droppers). |
| **`BENIGN`** | **5,296** | **23.38%** | Legitimate P2P chat, bank alerts, authentication OTPs, delivery updates, government notices. |
| **`SUSPICIOUS_SPAM`** | **1,714** | **7.57%** | Commercial telemarketing, unsolicited promotions, prize lures (non-credential theft). |
| **TOTAL** | **22,648** | **100.0%** | Comprehensive multi-tier classification corpus. |

### Primary Intent Distribution (8 Categories)

| Primary Intent (`primary_type`) | Record Count | Percentage (%) |
| :--- | :---: | :---: |
| **`BANKING_TRANSACTIONAL`** | 6,753 | 29.82% |
| **`PERSONAL_P2P`** | 5,042 | 22.26% |
| **`UNKNOWN`** | 4,704 | 20.77% |
| **`PROMOTIONAL`** | 1,737 | 7.67% |
| **`SERVICE_UPDATE`** | 1,483 | 6.55% |
| **`GOVERNMENT_INFO`** | 1,426 | 6.30% |
| **`DELIVERY`** | 1,362 | 6.01% |
| **`OTP_AUTH`** | 141 | 0.62% |

---

## 8. Threat Vector Coverage Audit

| Threat Vector | Total Records | Train Split | Validation Split | Test Split | OOD Split | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`CREDENTIAL_REQUEST`** | 7,547 | 5,245 | 1,137 | 783 | 382 | Fully Covered |
| **`BANK_KYC_SUSPENSION`** | 6,763 | 4,815 | 971 | 640 | 337 | Fully Covered |
| **`NONE`** (Benign) | 5,296 | 3,714 | 807 | 520 | 255 | Fully Covered |
| **`COMMERCIAL_SPAM`** | 1,714 | 1,169 | 274 | 188 | 83 | Fully Covered |
| **`DELIVERY_SCAM`** | 1,262 | 869 | 187 | 133 | 73 | Fully Covered |
| **`APK_MALWARE_DROPPER`** | 258 | 197 | 29 | 22 | 10 | Fully Covered |
| **`OTP_DISCLOSURE_REQUEST`** | 41 | 21 | 10 | 0 | 10 | Covered (Calibration) |
| **`PAYMENT_SCAM`** | 30 | 20 | 10 | 0 | 0 | Covered (Calibration) |
| **`ELECTRICITY_DISCONNECTION_SCAM`** | 24 | 13 | 10 | 0 | 1 | Covered (Calibration) |
| **`UPI_COLLECT_FRAUD`** | 20 | 20 | 0 | 0 | 0 | Covered (Calibration) |
| **`LOTTERY_PRIZE_FRAUD`** | 10 | 10 | 0 | 0 | 0 | Covered (Calibration) |
| **`PART_TIME_JOB_SCAM`** | 3 | 1 | 1 | 0 | 1 | Low Count (Monitored) |
| **`TRAFFIC_CHALLAN_PHISHING`** | 1 | 0 | 1 | 0 | 0 | Low Count (Monitored) |

---

## 9. Hard Negative & OTP Audit

- **Total Legitimate Hard Negatives in Benign Partition**: **299 records** (5.65% of all benign messages).
- **Keywords Verified in Benign Context**: `OTP`, `code`, `blocked`, `suspended`, `unauthorized`, `KYC`, `PAN`, `penalty`, `security alert`, `warning`.
- **Bidirectional OTP Context**:
  - Legitimate OTPs with protective disclaimers (`"Do not share OTP"`) correctly labeled `BENIGN`.
  - Social engineering reverse OTP theft (`"Send OTP to cancel transaction"`) correctly labeled `MALICIOUS`.

---

## 10. Language & Script Breakdown

| Language / Script | Record Count | Percentage (%) | Notes |
| :--- | :---: | :---: | :--- |
| **English (`en`) / Latin** | 22,556 | 99.59% | Primary global baseline. |
| **Hinglish (`hinglish`) / Latin** | 73 | 0.32% | Indian telemarketing and Hinglish fraud expressions. |
| **Unknown / Mixed** | 19 | 0.08% | Mixed script / special character messages. |

---

## 11. Sender Header Distribution

| Sender Type | Record Count | Percentage (%) | Notes |
| :--- | :---: | :---: | :--- |
| **`UNKNOWN`** | 22,078 | 97.48% | Headerless raw messages from academic text sets. |
| **`ALPHANUMERIC_HEADER`** | 487 | 2.15% | DLT-compliant Indian entity headers (`VK-HDFCBK`, `AX-SBIINB`, `AD-UIDAIG`, `VM-AMAZON`). |
| **`PHONE_NUMBER`** | 83 | 0.37% | Domestic Indian and international phone numbers from reported smishing attacks. |

---

## 12. Template Clustering & Leakage Audit

- **Total Template Clusters Identified**: **21,680 clusters**.
- **Singleton Clusters**: 21,120 (97.4%).
- **Multi-Record Clusters**: 560 clusters (parameterized variations of high-frequency phishing and bank templates).
- **Leakage Audit Verification**:
  - Exact text overlap between splits: **0**
  - Template cluster cross-split overlap: **0**
  - `is_leakage_free`: **`True` (100% Leak-Free Partitioning Enforced)**.

---

## 13. Partition Distribution Summary

| Split | File Location | Record Count | Proportion (%) | Schema Validity |
| :--- | :--- | :---: | :---: | :---: |
| **`TRAIN`** | [`Messages-ml/data/processed/train.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/processed/train.jsonl) | 15,855 | 70.01% | 100% Valid |
| **`VALIDATION`** | [`Messages-ml/data/processed/val.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/processed/val.jsonl) | 3,397 | 15.00% | 100% Valid |
| **`TEST`** | [`Messages-ml/data/processed/test.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/processed/test.jsonl) | 2,264 | 9.99% | 100% Valid |
| **`OOD`** | [`Messages-ml/data/processed/ood.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/processed/ood.jsonl) | 1,132 | 5.00% | 100% Valid |
| **TOTAL** | [`Messages-ml/data/processed/all_processed.jsonl`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel-ml/Messages-ml/data/processed/all_processed.jsonl) | **22,648** | **100.0%** | **100% Valid** |

---

## 14. Dataset Biases & Limitations

1. **Smishing Density**: Due to the inclusion of the empirical ACM IMC 2025 smishing corpus, `MALICIOUS` records account for 69% of the corpus. While beneficial for deep representation of complex attack patterns, loss functions during model experimentation must apply class weighting to prevent benign recall degradation.
2. **Language Skew**: English accounts for 99.6% of the acquired dataset. Hinglish and Devanagari Hindi are represented in calibration fixtures, but regional Indian languages (Tamil, Telugu, Bengali) remain a designated gap for future multilingual expansion phases.
3. **Header Availability**: 97.5% of records have `sender_type: "UNKNOWN"` due to the nature of academic SMS text collections. The feature extraction engine correctly treats missing headers probabilistically without fabricating entity tags.

---

## 15. Dataset Readiness Gate Decision

```
============================================================
DATASET READINESS GATE: DATASET_READY_FOR_MODEL_EXPERIMENTATION
============================================================
```

The dataset satisfies all 12 prerequisite criteria:
1. Provenance is 100% complete and traceable to `source_registry.json` and `acquisition_manifest.json`.
2. Verified open-access licenses (`CC BY 4.0` and Internal Project) documented for all acquired files.
3. Privacy audit passes with zero raw PII leaks.
4. Schema validation passes 100% (22,648/22,648 records valid).
5. Exact and normalized duplicate audits executed (11,739 duplicates collapsed).
6. Template leakage audit passes with 0 cross-split overlaps.
7. Train / Validation / Test / OOD partitions established.
8. Label mapping documented and verified.
9. Hard negatives and legitimate OTP warnings present.
10. Threat vector coverage documented.
11. Unit tests pass (40/40 passed).
12. URL-ml remains completely untouched.
