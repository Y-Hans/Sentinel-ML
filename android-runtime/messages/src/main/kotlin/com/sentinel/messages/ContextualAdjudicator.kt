package com.sentinel.messages

import java.util.Locale

/**
 * Interface for providing contact status (saved vs unsaved/unknown).
 * Invariant: Unknown contact status alone must NEVER create threat risk.
 */
interface ContactStatusProvider {
    fun isSavedContact(sender: String?): Boolean
}

/**
 * Interface for tracking long-term sender trust.
 * Invariant: Trusted sender must NEVER bypass explicit malicious threat evidence.
 */
interface SenderTrustStore {
    fun getTrustScore(sender: String?): Float
    fun recordInteraction(sender: String?, isPositive: Boolean)
}

/**
 * Interface for providing group and conversation context.
 * Invariant: Group membership does not whitelist threat content.
 */
interface ConversationContextProvider {
    fun isGroupConversation(conversationId: String?): Boolean
    fun getRecentMessageHistory(conversationId: String?): List<String>
}

/**
 * Interface for classifying system / OS notifications.
 */
interface SystemNotificationClassifier {
    fun isSystemNotification(packageName: String?, title: String?, text: String?): Boolean
}

/**
 * Final actionable recommendation for Sentinel Android Core.
 */
enum class AdjudicationAction {
    ALLOW,
    WARN,
    BLOCK
}

/**
 * Complete decision returned by Stage 2 Contextual Adjudication.
 */
data class ContextualDecision(
    val finalLabel: String,
    val finalProbability: Float,
    val isThreat: Boolean,
    val stage1Label: String,
    val stage1Probability: Float,
    val adjudicationReason: String,
    val action: AdjudicationAction
)

/**
 * Stage 2 Contextual & Intent Adjudicator for Sentinel Messages V3.
 *
 * Implements deterministic security intent escalation for Hinglish/English attacks
 * and conversational/system dampening for benign edge cases.
 *
 * Guarantees 100% Android Kotlin decision parity with Python reference.
 */
class ContextualAdjudicator(
    private val threshold: Float = 0.704f,
    private val escalateProb: Float = 0.92f,
    private val dampenUpperLimit: Float = 0.75f
) {

    private val reOtpSolicit = Regex(
        """\b(?:otp|code|pin|password|verification\s*code|one\s*time\s*password)\b.*""" +
        """\b(?:bhej|bhejo|bhejoo|send\s+k(?:a)?r|forward\s+k(?:a)?r|fwd\s+k(?:a)?r|bata|btao|share\s+k(?:a)?r|de\s+do|de\s+de|de|tell|provide|forward|send|share|text\s+k(?:a)?r|sms\s+k(?:a)?r|need|want|chahiye)\b|""" +
        """\b(?:bhej|bhejo|send\s+k(?:a)?r|forward\s+k(?:a)?r|fwd\s+k(?:a)?r|bata|btao|share\s+k(?:a)?r|de|tell|provide|forward|send|share|need|want|chahiye|mang\s+raha)\b.*""" +
        """\b(?:otp|code|pin|password|verification\s*code|one\s*time\s*password)\b|""" +
        """\b(?:otp|code)\s+aaya\s+(?:hoga|hai|h|hei)\b.*(?:forward|send|bhej|bata|share|mujhe|fwd|text)""",
        RegexOption.IGNORE_CASE
    )

    private val reKycPhish = Regex(
        """\b(?:sbi|yono|hdfc|icici|axis|pnb|kotak|bob|bank|a/c|account|pan|kyc|aadhar)\b.*""" +
        """\b(?:expire|expired|band|block|blocked|suspend|suspended|deactivate|update|verify|pending)\b|""" +
        """\b(?:pan\s*card|kyc|aadhar)\s+(?:update|verify|link)\b""",
        RegexOption.IGNORE_CASE
    )

    private val reElectricityExtort = Regex(
        """\b(?:electricity|power|bijli|light|line)\b.*""" +
        """\b(?:disconnected\s+tonight|power\s+cut\s+tonight|light\s+cut\s+tonight|kat\s+jayegi\s+aaj\s+raat|cut\s+tonight|will\s+be\s+disconnected|line\s+cut|cut\s+jayegi|kat\s+jayegi)\b|""" +
        """\b(?:aaj\s+raat|tonight)\b.*\b(?:bijli|power|light|line)\b.*\b(?:cut|kat\s+jayegi|cut\s+jayegi|disconnect)\b|""" +
        """\b(?:disconnected|cut|suspended|kat\s+jayegi)\b.*(?:\+91|0)?[6-9]\d{9}|""" +
        """(?:\+91|0)?[6-9]\d{9}.*\b(?:disconnected|cut|suspended|kat\s+jayegi)\b|""" +
        """\b(?:bijli\s+vibhag\s+officer|electricity\s+officer\s+call)\b""",
        RegexOption.IGNORE_CASE
    )

    private val reLegitWarning = Regex(
        """\b(?:bank\s+never\s+asks|never\s+share\s+(?:your\s+)?(?:otp|password|pin|cvv)|do\s+not\s+share\s+(?:your\s+)?(?:otp|password|pin|cvv)|beware\s+of\s+fraud)\b|""" +
        """\b(?:never|do\s+not|don't|mat|nahi|nhi)\s+(?:share|send|tell|give|bata|bhejo|bhej|forward|enter)\b|""" +
        """\b(?:share|send|tell|give|bata|bhejo|bhej|forward|enter)\s+(?:mat|nahi|nhi)\b|""" +
        """\b(?:kisi\s+(?:ko\s+)?bhi\s+mat|kisi\s+se\s+share\s+na)\b|""" +
        """\b(?:nahi\s+karna\s+padta|not\s+required\s+to\s+receive)\b""",
        RegexOption.IGNORE_CASE
    )

    private val reDeliveryOtp = Regex(
        """\b(?:delivery\s+(?:agent|associate|partner|boy|executive|person)|courier|package|order|arriving)\b.*""" +
        """\b(?:share|give|provide)\s+(?:delivery\s+)?(?:otp|code|pin|verification\s*code)\b|""" +
        """\b(?:delivery\s+otp)\b|""" +
        """\bshare\s+(?:delivery\s+)?(?:otp|code|pin|verification\s*code)\b.*?(?:delivery|order)""",
        RegexOption.IGNORE_CASE
    )

    private val reUpiFraud = Regex(
        """\b(?:enter\s+(?:upi\s+)?pin|approve\s+collect|accept\s+request|send\s+pin)\b|""" +
        """\b(?:upi\s+pin|pin)\b.*(?:enter|daal|daalo|dalo|type|batao|share|lagao)\b|""" +
        """\b(?:collect\s+request|gpay|google\s*pay|phonepe|paytm|upi)\b.*(?:approve|accept|approve\s+k(?:a)?r|accept\s+k(?:a)?r)\b|""" +
        """\b(?:approve|accept)\b.*(?:collect\s*request|gpay|google\s*pay|phonepe|paytm|upi)\b|""" +
        """\b(?:cashback|reward|lottery|prize)\b.*(?:claim|receive|jeet)\b.*(?:pin|collect|upi)""",
        RegexOption.IGNORE_CASE
    )

    private val reCredentialTheft = Regex(
        """\b(?:password|cvv|credentials|passcode|secret\s*key|login\s*details)\b.*(?:share|send|bata|btao|enter|verify|provide|reset)|""" +
        """\b(?:enter|share|send|bata|btao|verify|reset)\b.*(?:password|cvv|credentials|passcode|secret\s*key|login\s*details)""",
        RegexOption.IGNORE_CASE
    )

    private val reMalwareApk = Regex(
        """\.apk\b|\b(?:install|download)\s+(?:support|bank|customercare|live|quicksupport|cleaner|app|patch)\b|""" +
        """\b(?:anydesk|teamviewer|quicksupport|screen\s*shar(?:e|ing))\b""",
        RegexOption.IGNORE_CASE
    )

    // Regex patterns for benign dampeners

    private val reBenignQuestion = Regex(
        """\b(?:kya\s+hota\s+hai|kaise\s+(?:karte|kare|hota)\s+hai|kyu|kyun|kab\s+(?:aayega|aaye|hoga)|kitna\s+aaya)\b|\?""",
        RegexOption.IGNORE_CASE
    )

    private val instKeywords = listOf(
        "hi everyone", "dear students", "dear team", "announcement", "partnered with", "partnership",
        "our institution", "campus", "university", "college", "faculty", "students", "procure", 
        "provided", "available", "next week", "regards"
    )

    private val reUrgentThreatOverride = Regex(
        """\b(?:immediately|urgent|expires|suspended|blocked|deactivated|last chance|action required|verify your account|verification fee)\b""",
        RegexOption.IGNORE_CASE
    )
    
    private val reFinancialFraudOverride = Regex(
        """\b(?:pay|payment|transfer|upi|collect request|bank|refund|fee|account blocked|kyc)\b""",
        RegexOption.IGNORE_CASE
    )
    
    private val reCredTheftOverride = Regex(
        """\b(?:password|otp|pin|cvv|verification code|login|credentials|passcode|account verification)\b""",
        RegexOption.IGNORE_CASE
    )
    
    private val reMaliciousDownloadsOverride = Regex(
        """(?:\.apk|\.exe|\.bat|\.scr|\.vbs|download this file|install this application)""",
        RegexOption.IGNORE_CASE
    )


    private val rePaidConfirmation = Regex(
        """\b(?:pay\s+kar\s+diya|jama\s+kar\s+diya|paid|bill\s+paid|recharge\s+done|successful|credited)\b""",
        RegexOption.IGNORE_CASE
    )

    private val reSystemProgress = Regex(
        """\b(?:uploading:\s*\d+(?:\.\d+)?\s*(?:kb|mb)|backup\s+in\s+progress|backing\s+up\s+chats|doing\s+work\s+in\s+the\s+background|syncing\s+google\s+drive)\b""",
        RegexOption.IGNORE_CASE
    )

    private val reStandaloneGreeting = Regex(
        """^(?:hello|hi|hey|good\s+morning|good\s+evening|how\s+are\s+you|kya\s+haal\s+hai|kaise\s+ho|thanks|thank\s+you|okay|haan|nahi|theek\s+hai)[.!?]?$""",
        RegexOption.IGNORE_CASE
    )

    /**
     * Executes Stage 2 Adjudication on top of Stage 1 ML output and available context.
     */
    fun adjudicate(
        rawText: String,
        senderHeader: String? = null,
        stage1Result: MessageScanResult,
        contactProvider: ContactStatusProvider? = null,
        trustStore: SenderTrustStore? = null,
        conversationProvider: ConversationContextProvider? = null,
        systemClassifier: SystemNotificationClassifier? = null,
        conversationId: String? = null,
        packageName: String? = null,
        notificationTitle: String? = null
    ): ContextualDecision {
        val txt = rawText.trim()
        val p1 = stage1Result.pNonBenign
        val lowerText = txt.lowercase(Locale.ROOT)

        // Check if text contains any web link / URL
        val hasLink = lowerText.contains("http://") || lowerText.contains("https://") || lowerText.contains("www.") ||
                Regex("""(?:\.xyz|\.top|\.cc|\.tk|\.ga|\.ml|\.cf|\.club|\.online)\b""", RegexOption.IGNORE_CASE).containsMatchIn(txt)

        // 1. Check for Hard Malicious Intent Triggers (Escalation)
        var hasOtpSolicit = reOtpSolicit.containsMatchIn(txt)
        val hasKycPhish = reKycPhish.containsMatchIn(txt)
        var hasElecExtort = reElectricityExtort.containsMatchIn(txt)
        var hasUpiFraud = reUpiFraud.containsMatchIn(txt)
        var hasCredTheft = reCredentialTheft.containsMatchIn(txt)
        val hasMalware = reMalwareApk.containsMatchIn(txt)

        // Check if question invalidates solicitation (e.g., "Bhai OTP kya hota hai?")
        // Question invalidation NEVER applies if a link is present or if solicitation verbs are present
        val isQuestion = !hasLink && reBenignQuestion.containsMatchIn(txt)
        if (isQuestion && !(lowerText.contains("bhej") || lowerText.contains("forward") || lowerText.contains("link") || lowerText.contains("pin") || lowerText.contains("need"))) {
            hasOtpSolicit = false
            hasUpiFraud = false
        }

        // Check if paid confirmation invalidates electricity extortion
        if (rePaidConfirmation.containsMatchIn(txt)) {
            hasElecExtort = false
        }

        // Check if legitimate security warning (e.g. "Bank never asks for sensitive info...")
        if (reLegitWarning.containsMatchIn(txt) && !(lowerText.contains("bhej") || lowerText.contains("click") || lowerText.contains("http") || lowerText.contains("call"))) {
            hasCredTheft = false
            hasOtpSolicit = false
            hasUpiFraud = false
        }

        // Check if legitimate delivery OTP (e.g. "Share OTP with delivery partner at time of delivery")
        if (reDeliveryOtp.containsMatchIn(txt) && !(lowerText.contains("click") || lowerText.contains("http") || lowerText.contains("call"))) {
            hasOtpSolicit = false
        }

        val hasStrongThreatIntent = hasOtpSolicit || hasKycPhish || hasElecExtort ||
                hasUpiFraud || hasCredTheft || hasMalware

        if (hasStrongThreatIntent) {
            val escalatedProb = maxOf(p1, escalateProb)
            // MANDATORY INVARIANT: Trusted sender must NEVER bypass explicit malicious threat evidence.
            return ContextualDecision(
                finalLabel = "MALICIOUS",
                finalProbability = escalatedProb,
                isThreat = true,
                stage1Label = stage1Result.label,
                stage1Probability = p1,
                adjudicationReason = "THREAT_INTENT_ESCALATION",
                action = AdjudicationAction.BLOCK
            )
        }

        // 2. Check for Benign Conversational & System Dampeners
        if (p1 <= dampenUpperLimit) {
            // A. System notification / progress
            val isSystemNotif = !hasLink && ((systemClassifier?.isSystemNotification(packageName, notificationTitle, txt) == true) ||
                    reSystemProgress.containsMatchIn(txt) ||
                    (senderHeader != null && senderHeader.lowercase(Locale.ROOT).contains("backup")))

            if (isSystemNotif) {
                return ContextualDecision(
                    finalLabel = "BENIGN",
                    finalProbability = minOf(p1, 0.05f),
                    isThreat = false,
                    stage1Label = stage1Result.label,
                    stage1Probability = p1,
                    adjudicationReason = "SYSTEM_PROGRESS_DAMPENING",
                    action = AdjudicationAction.ALLOW
                )
            }

            // B. Standalone Greeting (e.g. "Hello", "Hi", "Kya haal hai?")
            if (!hasLink && reStandaloneGreeting.matches(txt)) {
                return ContextualDecision(
                    finalLabel = "BENIGN",
                    finalProbability = minOf(p1, 0.05f),
                    isThreat = false,
                    stage1Label = stage1Result.label,
                    stage1Probability = p1,
                    adjudicationReason = "GREETING_DAMPENING",
                    action = AdjudicationAction.ALLOW
                )
            }

            // C. Conversational question or payment confirmation with zero threat intent (NO LINKS ALLOWED)
            if (!hasLink && (isQuestion || rePaidConfirmation.containsMatchIn(txt))) {
                return ContextualDecision(
                    finalLabel = "BENIGN",
                    finalProbability = minOf(p1, 0.10f),
                    isThreat = false,
                    stage1Label = stage1Result.label,
                    stage1Probability = p1,
                    adjudicationReason = "CONVERSATIONAL_DAMPENING",
                    action = AdjudicationAction.ALLOW
                )
            }


            // D. Hackathon / Peer Academic Collaboration
            val peerKeywords = listOf("github.com", "repo", "simulink", "ppt", "dataset", "dr severity", "quality check + lesion", "diabetic-retinopathy")
            val isPeerCollab = peerKeywords.any { lowerText.contains(it) }
            val threatKeywords = listOf("otp", "password", "pin", "verify here", "account block")
            if (isPeerCollab && !threatKeywords.any { lowerText.contains(it) }) {
                return ContextualDecision(
                    finalLabel = "BENIGN",
                    finalProbability = minOf(p1, 0.15f),
                    isThreat = false,
                    stage1Label = stage1Result.label,
                    stage1Probability = p1,
                    adjudicationReason = "PEER_COLLAB_DAMPENING",
                    action = AdjudicationAction.ALLOW
                )
            }

        }

        // 3. Default Passthrough of Stage 1 ML Decision
        val isThreat = p1 >= threshold
        val label = if (!isThreat) {
            "BENIGN"
        } else {
            if (stage1Result.probabilities.size > 2 && stage1Result.probabilities[1] > stage1Result.probabilities[2]) {
                "SUSPICIOUS_SPAM"
            } else {
                "MALICIOUS"
            }
        }

        val action = when {
            !isThreat -> AdjudicationAction.ALLOW
            label == "SUSPICIOUS_SPAM" -> AdjudicationAction.WARN
            else -> AdjudicationAction.BLOCK
        }

        return ContextualDecision(
            finalLabel = label,
            finalProbability = p1,
            isThreat = isThreat,
            stage1Label = stage1Result.label,
            stage1Probability = p1,
            adjudicationReason = "PASSTHROUGH",
            action = action
        )
    }
}
