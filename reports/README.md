# Sentinel-ML — Reports and Audit Dossiers

This directory provides a consolidated index of evaluation reports, forensic audits, sprint outcomes, and promotion gate reviews across the Sentinel-ML projects.

---

## 1. Top-Level Sentinel-ML Reports

| Report | Path | Description |
| :--- | :--- | :--- |
| **Android Deployment Readiness** | [`FINAL_ANDROID_DEPLOYMENT_READINESS.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/FINAL_ANDROID_DEPLOYMENT_READINESS.md) | Verification ledger for pure-Kotlin mobile model deployment. |
| **Messages V4 Final Report** | [`MESSAGES_V4_FINAL_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/MESSAGES_V4_FINAL_REPORT.md) | V4 model evaluation, classification performance, and release notes. |
| **Messages V4 Forensic Baseline** | [`MESSAGES_V4_FORENSIC_BASELINE.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/MESSAGES_V4_FORENSIC_BASELINE.md) | Baseline audit metrics and feature representation analysis. |
| **Messages V4 Release Decision** | [`MESSAGES_V4_RELEASE_DECISION.json`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/MESSAGES_V4_RELEASE_DECISION.json) | Structured release criteria sign-off ledger. |
| **V3 Architecture Audit** | [`V3_ARCHITECTURE_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/V3_ARCHITECTURE_AUDIT.md) | Historical audit of V3 model architectures and transition to V4. |
| **Workspace Organization Report** | [`WORKSPACE_ORGANIZATION_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/WORKSPACE_ORGANIZATION_REPORT.md) | Prior workspace audit and governance ledger. |

---

## 2. Sprint Evaluation Dossiers

### 2.1 URL-ML Sprint (`url_sprint_01/`)
Located at [`url_sprint_01/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/url_sprint_01/):
- [`BASELINE_RESULTS.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/url_sprint_01/BASELINE_RESULTS.md): Initial baseline evaluation for URL models.
- [`FEATURE_LEDGER.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/url_sprint_01/FEATURE_LEDGER.md): Deterministic feature audit for URL-ML V8.
- [`PRE_REGISTRATION.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/url_sprint_01/PRE_REGISTRATION.md): Pre-registered evaluation gates and evaluation protocol.
- [`PROBE_DESIGN.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/url_sprint_01/PROBE_DESIGN.md): Probe design for edge-case URL evaluation.

### 2.2 Messages-ML Sprint (`dev_sprint_01/`)
Located at [`dev_sprint_01/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/dev_sprint_01/):
- `hinglish_probe/`: Evaluation of multi-lingual Hinglish text threat detection.
- `sprint_v2_20261023/`: Messages sprint verification and evidence runs.

### 2.3 Simulation Diagnosis (`simulation_diagnosis/`)
Located at [`simulation_diagnosis/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/simulation_diagnosis/):
- `20261022_preflight_01/`: Threat simulation preflight checks.
- `20261022_run_02/`: Threat simulation runs and diagnostic traces.

### 2.4 Independent Review (`assistant_review_20261023/`)
Located at [`assistant_review_20261023/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/assistant_review_20261023/):
- [`INDEPENDENT_REVIEW.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/reports/assistant_review_20261023/INDEPENDENT_REVIEW.md): Independent analyst evaluation of Messages-ML and URL-ML.
- `AGENT_A_NEXT.md` & `AGENT_C_NEXT.md`: Next-step triage notes for agent pipelines.
- `ANNOTATED_REVIEW_SAMPLE.csv`: Annotated test sample reviews.

---

## 3. Subsystem Reports

### 3.1 URL-ML Subsystem
Located under [`URL-ml/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/):
- [`V8_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/V8_AUDIT.md): Comprehensive V8 HistGBM audit, 67-feature analysis, and adversarial tests.
- [`V8_PROMOTION_GATE_REPORT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/V8_PROMOTION_GATE_REPORT.md): Stage gate promotion audit for V8 champion status.
- `PHASE_1A_PYTHON_KOTLIN_PARITY_FINAL_AUDIT.md`: Cross-language floating-point parity verification.
- `PHASE_1B_BRAND_SAFETY_REPORT.md`: Brand domain protection and safe-gating evaluation.
- `PHASE_1C_GROUP_CONTEXT_REPORT.md`: Invariant verification under conversational and group chat context.

### 3.2 Messages-ML Subsystem
Located under [`Messages-ml/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/reports/) and top-level Messages-ml:
- [`CLASS_CONFUSION_ANALYSIS.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/CLASS_CONFUSION_ANALYSIS.md): Multi-class confusion analysis across BENIGN, SPAM, and MALICIOUS.
- [`COUNTERFACTUAL_METHOD_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/COUNTERFACTUAL_METHOD_AUDIT.md): Methodological evaluation of counterfactual robustness probes.
- [`DATASET_COMPOSITION_AUDIT.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/DATASET_COMPOSITION_AUDIT.md): Composition, class distribution, and source provenance breakdown.
- [`ERROR_STRATIFICATION.md`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/ERROR_STRATIFICATION.md): Stratified error analysis across message lengths and formats.
