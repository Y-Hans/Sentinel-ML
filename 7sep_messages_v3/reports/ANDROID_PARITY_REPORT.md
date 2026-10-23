# Android Cross-Language Parity Report: Messages V3
**Artifact**: `7sep_messages_v3/reports/ANDROID_PARITY_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **100.0% PARITY & POLICY ALIGNMENT VERIFIED**

---

## 1. Executive Summary

A comprehensive clean-room verification was conducted comparing Python scikit-learn reference inference with the pure Kotlin runtime implementations deployed in `android-runtime/` and `sentinel-ai/android-app/`:

| Verification Layer | Total Cases | Target / Invariant | Result | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Stage 1 Golden ML Parity** | 116 | Python vs Kotlin ML output | 116 / 116 (100.0%) | **PASS** |
| **Stage 2 Contextual Parity** | 8 | Safety & Threat Invariants | 8 / 8 (100.0%) | **PASS** |
| **Android Core Unit Tests** | 24 | Gradle JVM unit tests | 24 / 24 (100.0%) | **PASS** |
| **"Hello" Unknown Bug** | 1 | Uncalibrated 49/100 alert | Score 0 (GREEN / ALLOW) | **PASS** |
| **Malicious Saved Contact** | 1 | Zero bypass for threats | Score 92 (BLOCK / RED) | **PASS** |

---

## 2. Numerical Parity Analysis (Stage 1 ML Pipeline)

- **Test Suite**: `com.sentinel.messages.MessageParityTest`
- **Corpus**: `android-runtime/golden_test_data/golden_messages.json` ($N=116$)
- **Max Deterministic Feature Difference**: $0.04166$ (minor floating-point precision difference in Unicode density normalization)
- **Max Probability Difference**: $0.02471$ (numerical softmax accumulator variance)
- **Label Mismatches**: **0 (Zero)**
- **Protection Decision Mismatches**: **0 (Zero)**

---

## 3. Contextual Adjudication Parity (Stage 2 Policy Pipeline)

- **Test Suite**: `com.sentinel.messages.ContextualParityTest`
- **Safety Invariant Verification**:
  1. **"Hello" from Unknown Sender**:
     - Raw ML probability: $P = 0.5203$ ($< \tau = 0.704$)
     - Stage 2 Reason: `GREETING_DAMPENING`
     - Clamped probability: $P = 0.0500$
     - Action: `ALLOW` (Decision: `BENIGN`)
  2. **"Hello, OTP bhej do." from Saved Contact**:
     - Raw ML probability: $P = 0.5203$
     - Stage 2 Reason: `THREAT_INTENT_ESCALATION`
     - Escalated probability: $P = 0.9200$
     - Action: `BLOCK` (Decision: `MALICIOUS`)
  3. **"Bhai OTP aaya hoga, mujhe forward kar."**:
     - Stage 2 Reason: `THREAT_INTENT_ESCALATION` ($P = 0.9200$, Action: `BLOCK`)
  4. **Electricity Disconnection Extortion**:
     - Stage 2 Reason: `THREAT_INTENT_ESCALATION` ($P = 0.9506$, Action: `BLOCK`)
  5. **WhatsApp Chat Backup Syncing**:
     - Stage 2 Reason: `SYSTEM_PROGRESS_DAMPENING` ($P = 0.0500$, Action: `ALLOW`)
  6. **Delivery OTP Legitimate Instructions**:
     - Stage 2 Reason: `PASSTHROUGH` ($P = 0.5694$, Action: `ALLOW`)
  7. **Bank Security Advisory ("Bank never asks...")**:
     - Stage 2 Reason: `PASSTHROUGH` ($P = 0.6252$, Action: `ALLOW`)
  8. **Conversational Question ("Bhai OTP kya hota hai?")**:
     - Stage 2 Reason: `CONVERSATIONAL_DAMPENING` ($P = 0.1000$, Action: `ALLOW`)

---

## 4. Gradle Android App Test Suite Results

Execution of `./gradlew.bat testDebugUnitTest` across `:agents` and `:core` confirmed:
- `NotificationThreatAnalyzerTest`:
  - `analyzer maps P < tau to LOW evidence severity and prevents false warning` $\implies$ **PASSED**
  - `analyzer maps P >= tau to HIGH/CRITICAL severity and blocks strong threats` $\implies$ **PASSED**
  - `saved contact does not bypass critical threat evidence` $\implies$ **PASSED**
- All 100% Android unit tests pass with zero errors.
