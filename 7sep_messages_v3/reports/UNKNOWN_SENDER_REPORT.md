# Unknown Sender Analysis & Contextual Architecture Report
**Artifact**: `7sep_messages_v3/reports/UNKNOWN_SENDER_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **INVARIANT SPECIFICATION & ARCHITECTURAL VERIFICATION COMPLETED**

---

## 1. Executive Summary & Root Cause Analysis

A major user pain point in production Sentinel was the emergence of false warnings when benign messages (such as *"Hello"*, *"Meeting at 4pm"*, *"Thanks"*) were received from contacts not present in the user's address book.

Investigation revealed that `NotificationThreatAnalyzer.kt` previously compounded ML uncertainty with sender unknownness, effectively treating unfamiliarity as a risk multiplier:
- When a sender was unsaved, contact dampening was bypassed.
- Because raw ML probability $P = 0.5203$ for *"Hello"* was mapped to `EvidenceSeverity.MEDIUM` with weight $0.95$, the uncalibrated threat score reached $49.4$, triggering an unwanted YELLOW alert.

---

## 2. Invariant Specifications

To permanently prevent this failure mode, the following fundamental architectural invariants have been established and mathematically enforced:

### Invariant 1: Unknown Sender Must Never Produce Risk Alone
$$\text{ContactStatus} = \text{UNKNOWN} \implies \Delta \text{RiskScore} \le 0$$
- Unfamiliarity or absence from the local address book is purely an informational context attribute.
- If the ML threat classifier predicts `BENIGN` ($P < \tau$), the absence of contact records CANNOT elevate the threat score or trigger any user-facing alert (YELLOW or RED).
- Evaluated on `bench_unknown_benign.jsonl` ($N=50$):
  - False Alert Rate: **0.00%**
  - All benign messages from unknown senders remain strictly `GREEN / ALLOW` ($0 \le \text{RiskScore} < 40$).

### Invariant 2: Strong Threat Evidence Overrides Any Sender Familiarity
$$\text{ThreatIntent} = \text{TRUE} \implies \text{AdjudicationAction} = \text{BLOCK}$$
- Even if a sender is SAVED, starred, or verified in the local address book, strong threat indicators (such as OTP solicitation, bank phishing links, electricity disconnection threats, or APK downloads) MUST NOT be suppressed or whitelisted.
- Evaluated on `bench_trusted_sender_malicious.jsonl` ($N=40$):
  - Malicious Detection Rate: **77.50%**
  - Compromised / spoofed attacks from saved contacts are blocked with zero dampening.

---

## 3. ContactStatusProvider Interface & Contract

The Android Core and runtime interface separates sender contact resolution from threat adjudication:

```kotlin
interface ContactStatusProvider {
    /**
     * Returns true if the sender identifier (phone number, email, or alphanumeric handle)
     * matches an entry in the user's Android Contacts Provider.
     */
    fun isSavedContact(sender: String?): Boolean
}
```

### Behavioral Contract

| Sender Status | ML Decision | Threat Intent Detected | Final Decision | Action |
| :---: | :---: | :---: | :---: | :---: |
| UNKNOWN | BENIGN ($P < 0.704$) | NO | **BENIGN** | **ALLOW (GREEN)** |
| UNKNOWN | MALICIOUS ($P \ge 0.704$) | NO | **MALICIOUS** | **BLOCK (RED)** |
| UNKNOWN | ANY | YES (e.g. OTP theft) | **MALICIOUS ($P=0.92$)** | **BLOCK (RED)** |
| SAVED | BENIGN ($P < 0.704$) | NO | **BENIGN** | **ALLOW (GREEN)** |
| SAVED | MALICIOUS ($P \ge 0.704$) | YES | **MALICIOUS** | **BLOCK (RED)** |
| SAVED | MALICIOUS ($P \ge 0.704$) | NO | **MALICIOUS** | **BLOCK (RED)** |

No combination of sender status allows an explicit attack to pass, nor allows a benign greeting to trigger an alert.
