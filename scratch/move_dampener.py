import re

filepath = r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml\android-runtime\messages\src\main\kotlin\com\sentinel\messages\ContextualAdjudicator.kt"
with open(filepath, "r", encoding="utf-8") as f:
    code = f.read()

# Remove the E. Institutional dampener from inside the p1 <= 0.75 block
# and place it right after the hasStrongThreatIntent check.

# 1. Clean up old E block from the current position.
# We will just replace it with empty string.
dampener_logic_old = """
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
code = code.replace(dampener_logic_old, "")

# 2. Insert the Institutional block right after:
#        if (hasStrongThreatIntent) {
#            ...
#            return ContextualDecision(...)
#        }

target_insertion = """        if (hasStrongThreatIntent) {
            val escalatedProb = maxOf(p1, escalateProb)
            return ContextualDecision(
                finalLabel = "MALICIOUS",
                finalProbability = escalatedProb,
                isThreat = true,
                stage1Label = stage1Result.label,
                stage1Probability = p1,
                adjudicationReason = "THREAT_INTENT_ESCALATION",
                action = AdjudicationAction.BLOCK
            )
        }"""

new_dampener = """
        // E. Institutional / Academic Announcement (Can apply to high-probability FPs)
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

code = code.replace(target_insertion, target_insertion + "\n" + new_dampener)

with open(filepath, "w", encoding="utf-8") as f:
    f.write(code)

