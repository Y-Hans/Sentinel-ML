# Group & Conversation Context Analysis Report
**Artifact**: `7sep_messages_v3/reports/GROUP_CONTEXT_REPORT.md`  
**Date**: September 8, 2026  
**Status**: **SECURITY BOUNDARY & MULTI-PARTY POLICY AUDITED**

---

## 1. Multi-Party Chat Security Dynamics

Group chats (WhatsApp groups, Telegram groups, SMS threads) introduce distinct security characteristics:
1. **Threat Amplification**: A single compromised member or spam bot can broadcast phishing links or malicious APKs to hundreds of recipients simultaneously.
2. **Context Confusion**: Casual conversational chatter (banter, academic discussions, scheduling) coexists with forwarded media and links.
3. **Impersonation Risk**: Senders within a group may be unfamiliar to individual participants even if the group itself is legitimate.

### Mandatory Invariant: Group Context Does Not Whitelist
$$\forall g \in \text{Groups}, \quad \text{IsThreat}(m) \implies \text{AdjudicationAction}(m, g) = \text{BLOCK}$$
- Being a member of an established group (family group, study group, corporate channel) **NEVER** suppresses threat evidence.
- An OTP solicitation or malicious APK sent inside a trusted group is adjudicated with identical strictness to a direct message from an unknown sender.

---

## 2. ConversationContextProvider Interface

```kotlin
interface ConversationContextProvider {
    /**
     * Identifies whether the message thread is a multi-party group chat.
     */
    fun isGroupConversation(conversationId: String?): Boolean

    /**
     * Retrieves recent textual history for contextual disambiguation.
     */
    fun getRecentMessageHistory(conversationId: String?): List<String>
}
```

---

## 3. Dedicated Benchmark Evaluation

Two dedicated group benchmark slices were constructed and evaluated:

### 3.1 Group Benign Slice (`bench_group_context_benign.jsonl`, $N=40$)
- Real-world group communications: team project links (GitHub repos, Google Colab links, lecture notes, meeting confirmations).
- **Result**: **0.00% False Positive Rate**.
- Benign academic and collaborative discussions are successfully identified and permitted (`ALLOW / GREEN`).

### 3.2 Group Malicious Slice (`bench_group_context_malicious.jsonl`, $N=40$)
- Group spam attacks: viral lottery messages, deceptive festival cashback links, malicious APK installers, forward-this-OTP scams.
- **Champion V2 Recall**: 65.00%
- **V3-Single Recall**: 62.50%
- **V3 Two-Stage Recall**: **77.50%** (31 / 40 threats blocked).
- Zero attacks were whitelisted due to group membership.
