# Sentinel — URL-ML Project Documentation

This directory houses the project-level architectural and technical documentation for the **URL Threat Classification Machine Learning Pipeline (Sentinel URL-ML)**.

---

## 1. Project Directory Structure

```text
sentinel-ml/URL-ml/
├── data/                 # Training, validation, and holdout datasets (CSV/Parquet)
├── docs/                 # Project documentation and architectural guides
├── experiments/          # Pre-registered isolated evaluation campaigns (Phase 1C, 1D)
├── model/                # Challenger checkpoints and candidate models
├── models/               # Frozen production champion models (v8_champion.joblib)
├── reports/              # Audit reports, gate validations, and forensic dossiers
├── scripts/              # Feature extractors, classifiers, exporters, benchmarks
├── tests/                # Automated regression and parity test suites
├── venv/                 # Python 3.11 isolated virtual environment
├── V8_AUDIT.md           # Comprehensive V8 release and benchmark audit
└── V8_PROMOTION_GATE_REPORT.md  # Official promotion gate evaluation report
```

---

## 2. Model & Pipeline Architecture

### 2.1 The Frozen Champion V8
- **Base Estimator:** `HistGradientBoostingClassifier` trained on source-diverse, hard-negative augmented corpora.
- **Dimensionality:** Exactly 67 features (`V7_FEATURE_NAMES`).
- **Cryptographic Hash:** `073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58`.
- **Operating Threshold:** `0.2800` (calibrated for high adversarial sensitivity).

### 2.2 Canonicalization Contract
Implemented in [`scripts/v7_features.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v7_features.py) and [`scripts/v8_normalization.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/scripts/v8_normalization.py):
- Strips leading/trailing whitespace and trailing delimiters (`.,;:!?)]}"'<>`).
- Normalizes schemeless (`www.domain.com`) and protocol-relative (`//domain.com`) inputs to `https://` (`IsHTTPS = 1.0f`).
- Preserves explicit `http://` as HTTP (`IsHTTPS = 0.0f`), maintaining active insecure-protocol threat penalization.

---

## 3. Key Project References

- **V8 Promotion Gate Report:** [`../V8_PROMOTION_GATE_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/V8_PROMOTION_GATE_REPORT.md)
- **V8 Release Audit:** [`../V8_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/V8_AUDIT.md)
- **Phase 1A Parity Final Audit:** [`../reports/PHASE_1A_PYTHON_KOTLIN_PARITY_FINAL_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/PHASE_1A_PYTHON_KOTLIN_PARITY_FINAL_AUDIT.md)
- **Parity Test Suite:** [`../tests/test_url_canonicalization_parity.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/tests/test_url_canonicalization_parity.py)
