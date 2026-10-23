# Sentinel-ML — Shared Protocols and Contracts

This directory contains common schemas, data contracts, and interface definitions shared across the Sentinel Machine Learning pipelines (`URL-ml`, `Messages-ml`) and the integration bridge (`android-runtime`).

---

## 1. Scope & Purpose

- **Standardized Interfaces**: Establishes common Python enumerations and data structures (`contracts.py`) defining threat classes, evidence severity, and adjudication verdicts.
- **Cross-Pipeline Compatibility**: Ensures that message text parsing, URL extraction, and risk fusion evaluation operate against identical data contracts.
- **Parity Alignment**: Mirrors the Kotlin domain models in `sentinel-ai` (`EvidenceSeverity`, `DecisionVerdict`, `RiskFusionModels`) to maintain float-precision and logic parity across platforms.

---

## 2. Core Entities

| Entity | Description | Reference |
| :--- | :--- | :--- |
| `EvidenceSeverity` | Hierarchical threat severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). | [`contracts.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/shared/contracts.py) |
| `DecisionVerdict` | High-level enforcement action (`ALLOW`, `WARN`, `BLOCK`). | [`contracts.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/shared/contracts.py) |
| `MessageThreatClass` | 3-class taxonomy: `BENIGN`, `SPAM`, `MALICIOUS`. | [`contracts.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/shared/contracts.py) |
| `UrlThreatClass` | Binary URL classification: `BENIGN`, `MALICIOUS`. | [`contracts.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/shared/contracts.py) |
| `RiskFusionDecision` | Unified multi-signal decision enforcing the `PAYLOAD OVERRIDES CONTEXT` invariant. | [`contracts.py`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/shared/contracts.py) |
