# Sentinel — Phase 1C: WhatsApp Group Context and 5 Security Invariants Report
**Document ID:** `PHASE_1C_GROUP_CONTEXT_REPORT`  
**Execution Context:** `SENTINEL_MASTER_PLAN.md` Version `3.1.0-EVIDENCE-FIRST-CALIBRATED` (Phase 1C)  
**Date:** 2026-10-21  
**Status:** COMPLETE & VERIFIED — ZERO REGRESSIONS  

---

## 1. Executive Summary & Objective

In Phase 1C, Sentinel establishes the end-to-end integration of **WhatsApp Group Context** and formally verifies the **5 Mandatory Security Invariants** governing group messaging, trust boundaries, and malicious payload overrides.

### Threat Model in Group Contexts
Instant messaging groups (WhatsApp, Telegram) represent high-risk attack surfaces:
1. Attackers frequently join public, semi-private, or community groups to broadcast malicious links, phishing forms, and APK droppers.
2. Attackers exploit familiar conversational framing ("hey bro check this out", "urgent watch this video") to deceive group participants into clicking malicious links.
3. In a group chat, messages from unknown senders are frequently received alongside messages from known contacts.
4. If an application incorrectly treats group membership as a trusted contact whitelist, or allows conversational trust dampening to suppress links, users become vulnerable to account takeover and mobile malware delivery.

---

## 2. The 5 Mandatory Security Invariants

Sentinel enforces five inviolable architectural invariants:

| Invariant | Principle | Description & Policy |
| :--- | :--- | :--- |
| **Invariant 1** | **Group Context Preservation** | Group metadata is faithfully parsed from Android notifications into `WhatsAppRawNotificationData.isGroupChat` and passed directly into `FusionContext.isGroup`. |
| **Invariant 2** | **`GROUP != WHITELIST`** | Group context must **never** create a whitelist. Known-contact contextual trust dampening is strictly restricted to 1-on-1 private conversations and is never applied in group chats. |
| **Invariant 3** | **Unknown Contact Invariant** | An unknown contact in a group chat is never treated as trusted. Missing phone numbers or group titles never grant immunity. |
| **Invariant 4** | **Payload Escalation Overrides Context** | If an attached URL or file payload exhibits $\text{severity} \ge \text{HIGH}$, risk fusion must alert (`WARN` or `BLOCK`) and can **never** evaluate to `ALLOW`, regardless of group status. |
| **Invariant 5** | **Conversational Framing Invariance** | Friendly conversational framing ("check this out bro", "funny video") never suppresses active threats. A malicious link or APK dropper in a group chat must always be blocked. |

---

## 3. Surgical Implementation Details

Three surgical modifications were applied to connect group context across the domain boundary:

### A. Context Schema Definition (`RiskFusionModels.kt`)
In [`RiskFusionModels.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionModels.kt#L22-L30):
Added `isGroup: Boolean = false` to `FusionContext`:
```kotlin
data class FusionContext(
    val source: String = "",
    val target: String? = null,
    val senderProfile: SenderProfile? = null,
    val contactResolution: ContactResolution? = null,
    val isKnownContact: Boolean = contactResolution?.isKnownContact ?: senderProfile?.isKnownContact ?: false,
    val timestamp: Long = 0L,
    val isGroup: Boolean = false
)
```

### B. Group Context Propagation (`NotificationAgentCoordinator.kt`)
In [`NotificationAgentCoordinator.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/agents/src/main/java/com/sentinel/ai/agents/whatsapp/NotificationAgentCoordinator.kt#L100-L107):
Wired `raw.isGroupChat` to `FusionContext`:
```kotlin
val fusionContext = FusionContext(
    source = raw.normalized.packageName,
    target = raw.messageText,
    senderProfile = senderProfile,
    isKnownContact = isKnownContact,
    timestamp = snapshot.timestampMs,
    isGroup = raw.isGroupChat
)
```

### C. Trust Boundary Enforcement (`RiskFusionEngine.kt`)
In [`RiskFusionEngine.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/main/java/com/sentinel/ai/core/fusion/RiskFusionEngine.kt#L233-L248):
Enforced that known-contact trust dampening is strictly bypassed in group chats:
```kotlin
// 2. Known Contact Contextual Dampening
// SECURITY INVARIANT: Group context NEVER dampens threats (GROUP != WHITELIST).
if (context.isKnownContact && !context.isGroup) {
    val maxPayloadSeverity = evidence.filter { it.isPayloadVector() }.maxOfOrNull { it.severity } ?: EvidenceSeverity.INFO

    // CRITICAL INVARIANT: Trust context NEVER suppresses HIGH/CRITICAL payload threats (e.g. compromised contact sending malware)
    if (maxPayloadSeverity < EvidenceSeverity.HIGH) {
        val dampeningFactor = when {
            intentScore <= 45.0f -> 30.0f
            intentScore <= 65.0f -> 20.0f
            else -> 10.0f
        }
        dampened = max(0.0f, dampened - dampeningFactor)
    }
}
```

---

## 4. Empirical Verification Evidence

Verification was conducted via automated test suites in [`RiskFusionEngineTest.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/core/src/test/java/com/sentinel/ai/core/fusion/RiskFusionEngineTest.kt#L425-L550) and [`WhatsAppAgentCoordinatorTest.kt`](file:///c:/Users/user/Programing%20files/Yajat/Projects/sentinel/sentinel-ai/android-app/agents/src/test/java/com/sentinel/ai/agents/whatsapp/WhatsAppAgentCoordinatorTest.kt):

### A. 5 Security Invariant Unit Tests (`RiskFusionEngineTest.kt`)
Run command: `gradlew.bat :core:testDebugUnitTest --tests com.sentinel.ai.core.fusion.RiskFusionEngineTest`  
Outcome: **17 / 17 PASSED (0 failures, 44s execution)**

| Test Name | Scenario Tested | Expected Behavior | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| `invariant 1 - group context preserved` | Direct vs Group `FusionContext` | `isGroup` boolean state matches source | Matched | PASS |
| `invariant 2 - group != whitelist` | Conversational urgency + payment in Group vs Direct | Direct: `ALLOW` (dampened); Group: `WARN` (undampened) | Direct: `ALLOW`<br>Group: `WARN` | PASS |
| `invariant 3 - unknown contact in group` | Urgency from unknown sender in Group | No dampening applied, risk score = 40.0 (`YELLOW`) | `WARN` ($40.0$) | PASS |
| `invariant 4 - malicious payload alerts` | `URL_ML` `HIGH` evidence across all group/contact combos | Decision $\ne$ `ALLOW` in all 4 contexts (`WARN` or `BLOCK`) | `WARN`/`BLOCK`<br>(never `ALLOW`) | PASS |
| `invariant 5 - friendly framing invariant`| "Hey bro check this out" + `video.apk` dropper in Group | Friendly text ignored; critical payload override triggers | `BLOCK` ($95.0$) | PASS |

### B. Coordinator Integration Suite (`WhatsAppAgentCoordinatorTest.kt`)
Run command: `gradlew.bat :agents:testDebugUnitTest --tests com.sentinel.ai.agents.whatsapp.WhatsAppAgentCoordinatorTest`  
Outcome: **PASSED (43s execution, 0 failures)**

---

## 5. Phase 1C Acceptance Declaration

Phase 1C has satisfied all pre-registered requirements:
- Group context is faithfully extracted, mapped, and preserved across domain boundaries.
- Group membership is completely decoupled from contact whitelisting (`GROUP != WHITELIST`).
- Unknown group participants are never granted trusted status.
- High and critical severity payloads strictly alert or block in all scenarios.
- Conversational framing never dampens payload threats.
- Zero mutations to frozen model weights or production asset files.
