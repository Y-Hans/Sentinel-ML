# Sentinel — Phase 1B: Calibrated Safe-Brand Escalation Policy Report
**Document ID:** `PHASE_1B_SAFE_BRAND_ESCALATION_REPORT`  
**Execution Context:** `SENTINEL_MASTER_PLAN.md` Version `3.1.0-EVIDENCE-FIRST-CALIBRATED` (Phase 1B)  
**Date:** 2026-10-21  
**Status:** COMPLETE & VERIFIED — ZERO REGRESSIONS  

---

## 1. Executive Summary & Objective

Phase 1B implements and verifies the **Calibrated Safe-Brand Escalation Policy** across [`NotificationThreatAnalyzer.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzer.kt) and [`SafeDomainAdjudicator.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt).

### The Dual Security Requirement
The threat analyzer operates at the boundary between URL-ML model predictions and overall notification threat evaluation. It must enforce two non-negotiable security contracts:

1. **Case A (Clean Safe Brand):**
   When a URL points to a verified benign brand domain without active threat indicators (e.g., `https://github.com/password_reset`, `https://www.netflix.com/password/reset`, `https://accounts.google.com/signin/v2/challenge/password`), `urlResult.isSafeBrandGated == true` and `urlResult.isMalicious == false`.
   - **Requirement:** The threat analyzer must emit evidence with severity `LOW` (or suppress `CRITICAL` escalation).
   - **Outcome:** The user's legitimate notification remains unobstructed (`ProtectionDecision.ALLOW`).

2. **Case B (Active Threat Payload on Safe Brand):**
   When an attacker attempts to exploit brand reputation or cloud hosting to deliver malware, open redirects, or credential harvesting forms (e.g., `https://github.com/exploit/drop/releases/download/v1.0/drop.apk`, `https://google.com/url?q=https://evil.xyz`, `https://www.amazon.com/search?q=%252e%252e/etc/passwd`):
   - **Requirement:** Brand reputation must **never** grant immunity. Active threat indicators must strictly override brand gating, setting `urlResult.isSafeBrandGated = false`, `isMalicious = true`, and probability $\ge 0.95$.
   - **Outcome:** The threat analyzer must emit evidence with severity `CRITICAL`, triggering `ProtectionDecision.BLOCK`.

---

## 2. Architecture & Implementation

### A. Adjudication Layer (`SafeDomainAdjudicator.kt`)
In [`SafeDomainAdjudicator.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/ml/url/SafeDomainAdjudicator.kt#L136-L215):
- Verified brand status is determined via deterministic public domain suffix analysis and feature `idxSafeBrand == 1.0f`.
- Active threat detectors inspect for:
  - Suspicious executable extensions (`PAYLOAD_EXTENSIONS`: `.apk`, `.exe`, `.scr`, `.bat`, `.dll`, `.msi`, `.ps1`, `.iso`).
  - Open redirects (`idxRedirect > 0.0f` or target parameter in query).
  - Malware hostile terms (`HOSTILE_TERMS`: `token_grabber`, `keylogger`, `reverse_shell`, `trojan`, `backdoor`, `dropper`).
  - Credential harvesting on untrusted domains or public user forms (`google.com/forms`, `docs.google.com`).
  - Path traversal and double encoding (`idxDoubleEnc > 0.0f`, `%252e%252e`, `/etc/passwd`).
- Safe brand gating is guarded:
  ```kotlin
  val isSafeBrand = isVerifiedBrand && (rawProba < decisionThreshold)
  val isGated = isSafeBrand && (!hasThreat)

  if (isGated) {
      pFinal = 0.001f
  }
  ```
  If `hasThreat == true`, gating is negated, `pFinal` escalates to $\ge 0.95$, and `isMalicious = true`.

### B. Notification Threat Analyzer (`NotificationThreatAnalyzer.kt`)
In [`NotificationThreatAnalyzer.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzer.kt#L228-L235):
Evidence severity derivation is strictly calibrated:
```kotlin
val severity = when {
    p >= 0.80f || mlScore >= 90.0f -> EvidenceSeverity.CRITICAL
    urlResult.isMalicious -> EvidenceSeverity.HIGH
    else -> EvidenceSeverity.LOW
}
```
- For clean safe brands, `p = 0.001f`, `urlResult.isMalicious = false` $\implies$ `severity = EvidenceSeverity.LOW`.
- For threats on brands, `p >= 0.95f`, `mlScore >= 90.0f` $\implies$ `severity = EvidenceSeverity.CRITICAL`.

---

## 3. Empirical Verification Evidence

Verification was conducted via automated test execution in [`NotificationThreatAnalyzerTest.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/NotificationThreatAnalyzerTest.kt#L507-L553):
Run command: `gradlew.bat :agents:testDebugUnitTest --tests com.sentinel.ai.agents.whatsapp.NotificationThreatAnalyzerTest`  
Outcome: **PASSED (19s execution, 0 failures)**

### Evaluated Test Cohorts

| Category | URL Tested | Feature / Indicator Triggered | Severity Assigned | Final Decision | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Clean Brand** | `https://github.com/password_reset` | Safe Brand Gated | `LOW` | `ALLOW` | PASS |
| **Clean Brand** | `https://www.netflix.com/password/reset` | Safe Brand Gated | `LOW` | `ALLOW` | PASS |
| **Clean Brand** | `https://accounts.google.com/signin/...` | Safe Brand Gated | `LOW` | `ALLOW` | PASS |
| **Clean Brand** | `https://store.steampowered.com/account/...`| Safe Brand Gated | `LOW` | `ALLOW` | PASS |
| **Clean Brand** | `https://www.amazon.com/ap/forgotpassword` | Safe Brand Gated | `LOW` | `ALLOW` | PASS |
| **Threat Payload** | `https://github.com/.../drop.apk` | `PAYLOAD_EXTENSIONS (.apk)` | `CRITICAL` | `BLOCK` | PASS |
| **Threat Payload** | `https://github.com/.../payload.exe` | `PAYLOAD_EXTENSIONS (.exe)` | `CRITICAL` | `BLOCK` | PASS |
| **Threat Payload** | `https://google.com/url?q=https://evil.xyz`| Open Redirect | `CRITICAL` | `BLOCK` | PASS |
| **Threat Payload** | `https://www.amazon.com/search?q=%252e%252e`| Query Exploit / Traversal | `CRITICAL` | `BLOCK` | PASS |
| **Mixed Message** | `https://google.com` + `http://phish.biz` | Malicious URL Dominance | `CRITICAL` | `BLOCK` | PASS |

---

## 4. Phase 1B Acceptance Declaration

Phase 1B has satisfied all pre-registered requirements:
- Clean safe-brand URLs consistently evaluate with `LOW` severity and `ALLOW` decision.
- Malicious payloads, open redirects, and exploitation paths hosted on reputable domains strictly escalate to `CRITICAL` severity and enforce `BLOCK`.
- Mixed safe and malicious URLs in a single notification correctly allow the malicious payload to dominate.
- Zero mutations to frozen model weights or production asset files.
