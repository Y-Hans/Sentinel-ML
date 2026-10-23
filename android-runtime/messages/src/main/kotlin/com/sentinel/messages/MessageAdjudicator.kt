package com.sentinel.messages

data class MessageScanResult(
    val label: String,
    val classIndex: Int,
    val probabilities: FloatArray,
    val isNonBenign: Boolean,
    val pNonBenign: Float
)

/**
 * Adjudication logic for Messages-ML Champion V2.
 * Applies threshold tau = 0.704 on P(SUSPICIOUS_SPAM) + P(MALICIOUS).
 */
class MessageAdjudicator(
    val threshold: Float = 0.704f
) {
    fun adjudicate(probabilities: FloatArray): MessageScanResult {
        val pBenign = probabilities[0]
        val pSusp = probabilities[1]
        val pMal = probabilities[2]
        val pNonBenign = pSusp + pMal

        val label: String
        val classIndex: Int
        val isNonBenign: Boolean

        if (pNonBenign >= threshold) {
            isNonBenign = true
            if (pSusp > pMal) {
                label = "SUSPICIOUS_SPAM"
                classIndex = 1
            } else {
                label = "MALICIOUS"
                classIndex = 2
            }
        } else {
            isNonBenign = false
            label = "BENIGN"
            classIndex = 0
        }

        return MessageScanResult(
            label = label,
            classIndex = classIndex,
            probabilities = probabilities,
            isNonBenign = isNonBenign,
            pNonBenign = pNonBenign
        )
    }
}
