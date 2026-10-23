# Sentinel — Research Notes & Technical References

This directory contains workspace-level research documentation, technical references, threat classification methodologies, and master planning records.

---

## 1. Master Plan & Governance

Sentinel development and evaluation adhere to the evidence-first governance model specified in the Sentinel Master Plan.

### Key Governance Principles
1. **Pre-Registered Evaluation Gates:** Candidate models must be evaluated against frozen benchmarks across pre-registered gates before consideration for promotion.
2. **Raw vs. Adjudicated Independence:** Model raw probabilities from tree models are strictly separated from post-classification security invariant adjudication.
3. **Evidence-First Verification:** No performance claim is accepted without cryptographic provenance, executable verification scripts, and isolated test logs.
4. **Boundary Isolation:** Production mobile applications (`sentinel-ai/`) and offline research pipelines maintain strict separation of concerns.

---

## 2. Threat Classification Taxonomies

### 2.1 URL Threats
- **Brand Impersonation & Typosquatting:** Leet substitutions (`g00gle`, `paypa1`), homoglyphs, and punycode attacks targeting high-value platforms.
- **Payload & Malicious Downloads:** URLs directly serving executable extensions (`.exe`, `.apk`, `.scr`, `.bat`, `.vbs`, `.zip`, `.iso`).
- **Open Redirects:** Exploitation of legitimate redirect parameters (`target=`, `dest=`, `url=`, `redirect_uri=`) pointing to malicious destinations.
- **Credential Harvesting:** Phishing forms, authentication lookalikes, and OTP grabbers targeting sensitive financial or identity services.
- **Bare-Apex Anomalies:** Empty-path, empty-query apex domains exhibiting anomalous lexical morphology.

### 2.2 Message & Communication Threats
- **Smishing (SMS Phishing):** Urgent call-to-action messages impersonating banking, tax, or courier authorities.
- **WhatsApp Notification Threats:** Malicious links delivered via social and messaging notification channels.
- **Sender Profile Spoofing:** Incongruent sender headers, non-standard shortcodes, and alphanumeric sender masquerading.

---

## 3. Related Project Reports

For empirical evaluation data and experiment records, consult the specialized project report repositories:
- **URL-ML Phase Audit Reports:** [`../sentinel-ml/URL-ml/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/URL-ml/reports/)
- **Messages-ML Forensic Reports:** [`../sentinel-ml/Messages-ml/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/Messages-ml/reports/)
- **Android Runtime Parity Reports:** [`../sentinel-ml/android-runtime/reports/`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ml/android-runtime/reports/)
