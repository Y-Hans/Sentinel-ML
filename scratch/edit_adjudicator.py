import re

filepath = r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml\android-runtime\messages\src\main\kotlin\com\sentinel\messages\ContextualAdjudicator.kt"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

new_regexes = """
    private val reBenignQuestion = Regex(
        \"\"\"\\b(?:kya\\s+hota\\s+hai|kaise\\s+(?:karte|kare|hota)\\s+hai|kyu|kyun|kab\\s+(?:aayega|aaye|hoga)|kitna\\s+aaya)\\b|\\?\"\"\",
        RegexOption.IGNORE_CASE
    )

    private val instKeywords = listOf(
        "hi everyone", "dear students", "dear team", "announcement", "partnered with", "partnership",
        "our institution", "campus", "university", "college", "faculty", "students", "procure", 
        "provided", "available", "next week", "regards"
    )

    private val reUrgentThreatOverride = Regex(
        \"\"\"\\b(?:immediately|urgent|expires|suspended|blocked|deactivated|last chance|action required|verify your account|verification fee)\\b\"\"\",
        RegexOption.IGNORE_CASE
    )
    
    private val reFinancialFraudOverride = Regex(
        \"\"\"\\b(?:pay|payment|transfer|upi|collect request|bank|refund|fee|account blocked|kyc)\\b\"\"\",
        RegexOption.IGNORE_CASE
    )
    
    private val reCredTheftOverride = Regex(
        \"\"\"\\b(?:password|otp|pin|cvv|verification code|login|credentials|passcode|account verification)\\b\"\"\",
        RegexOption.IGNORE_CASE
    )
    
    private val reMaliciousDownloadsOverride = Regex(
        \"\"\"(?:\\.apk|\\.exe|\\.bat|\\.scr|\\.vbs|download this file|install this application)\"\"\",
        RegexOption.IGNORE_CASE
    )
"""

code = code.replace("""    private val reBenignQuestion = Regex(
        \"\"\"\\b(?:kya\\s+hota\\s+hai|kaise\\s+(?:karte|kare|hota)\\s+hai|kyu|kyun|kab\\s+(?:aayega|aaye|hoga)|kitna\\s+aaya)\\b|\\?\"\"\",
        RegexOption.IGNORE_CASE
    )""", new_regexes)


dampener_logic = """
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

            // E. Institutional / Academic Announcement
            val instMatchCount = instKeywords.count { lowerText.contains(it) }
            if (instMatchCount >= 2) {
                val hasOverride = hasLink || 
                        hasStrongThreatIntent || 
                        reUrgentThreatOverride.containsMatchIn(txt) ||
                        reFinancialFraudOverride.containsMatchIn(txt) ||
                        reCredTheftOverride.containsMatchIn(txt) ||
                        reMaliciousDownloadsOverride.containsMatchIn(txt)
                        
                if (!hasOverride) {
                    return ContextualDecision(
                        finalLabel = "BENIGN",
                        finalProbability = minOf(p1, 0.15f),
                        isThreat = false,
                        stage1Label = stage1Result.label,
                        stage1Probability = p1,
                        adjudicationReason = "INSTITUTIONAL_DAMPENING",
                        action = AdjudicationAction.ALLOW
                    )
                }
            }
"""

code = code.replace("""            // D. Hackathon / Peer Academic Collaboration
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
            }""", dampener_logic)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

