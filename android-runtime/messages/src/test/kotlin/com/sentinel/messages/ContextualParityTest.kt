package com.sentinel.messages

import java.io.File

object ContextualParityTest {

    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML STAGE 2 CONTEXTUAL ADJUDICATION PARITY TEST")
        println("=" .repeat(80))

        val assetsDir = File("android-runtime/messages/assets")
        val wFile = File(assetsDir, "champion_v2_word_vocab_idf.json")
        val cFile = File(assetsDir, "champion_v2_char_vocab_idf.json")
        val sFile = File(assetsDir, "champion_v2_scaler.json")
        val tFile = File(assetsDir, "champion_v2_trees.json")

        val scanner = MessageScanner.create(
            wordJson = wFile.readText(Charsets.UTF_8),
            charJson = cFile.readText(Charsets.UTF_8),
            scalerJson = sFile.readText(Charsets.UTF_8),
            treesJson = tFile.readText(Charsets.UTF_8),
            threshold = 0.704f
        )

        // Mock providers
        val savedContactProvider = object : ContactStatusProvider {
            override fun isSavedContact(sender: String?): Boolean = (sender == "+919876543210" || sender == "Mom" || sender == "Boss")
        }

        val testCases = listOf(
            // 1. Mandatory Hello Bug Fix: Unknown sender sending greeting
            TestCase(
                name = "Hello from Unknown Sender",
                text = "Hello",
                sender = "+919999999999",
                expectedLabel = "BENIGN",
                expectedAction = AdjudicationAction.ALLOW,
                expectedReason = "GREETING_DAMPENING",
                isSaved = false
            ),
            // 2. Mandatory Hinglish OTP attack: Saved contact compromised
            TestCase(
                name = "OTP Solicitation from Saved Contact",
                text = "Hello, OTP bhej do.",
                sender = "+919876543210",
                expectedLabel = "MALICIOUS",
                expectedAction = AdjudicationAction.BLOCK,
                expectedReason = "THREAT_INTENT_ESCALATION",
                isSaved = true
            ),
            // 3. Hinglish OTP forward attack
            TestCase(
                name = "Hinglish OTP Forward Solicitation",
                text = "Bhai OTP aaya hoga, mujhe forward kar.",
                sender = "+919888888888",
                expectedLabel = "MALICIOUS",
                expectedAction = AdjudicationAction.BLOCK,
                expectedReason = "THREAT_INTENT_ESCALATION",
                isSaved = false
            ),
            // 4. Electricity scam with tonight cut threat
            TestCase(
                name = "Electricity Disconnection Extortion",
                text = "Dear customer, your electricity power will be disconnected tonight at 9:30 PM from electricity office. Contact officer at 9876543210.",
                sender = "BESCOM",
                expectedLabel = "MALICIOUS",
                expectedAction = AdjudicationAction.BLOCK,
                expectedReason = "THREAT_INTENT_ESCALATION",
                isSaved = false
            ),
            // 5. System progress notification
            TestCase(
                name = "WhatsApp Backup In Progress",
                text = "Backup in progress uploading: 12.4 MB chats",
                sender = "WhatsApp",
                expectedLabel = "BENIGN",
                expectedAction = AdjudicationAction.ALLOW,
                expectedReason = "SYSTEM_PROGRESS_DAMPENING",
                isSaved = false
            ),
            // 6. Delivery OTP legitimate instructions
            TestCase(
                name = "Delivery OTP Legitimate Instructions",
                text = "Your Flipkart package is arriving today. Share delivery OTP at the time of delivery.",
                sender = "FLIPKT",
                expectedLabel = "BENIGN",
                expectedAction = AdjudicationAction.ALLOW,
                expectedReason = "PASSTHROUGH",
                isSaved = false
            ),
            // 7. Legitimate security advisory from bank
            TestCase(
                name = "Bank Security Advisory",
                text = "Bank never asks for sensitive information like Passwords or PIN.",
                sender = "HDFCBK",
                expectedLabel = "BENIGN",
                expectedAction = AdjudicationAction.ALLOW,
                expectedReason = "PASSTHROUGH",
                isSaved = false
            ),
            // 8. Conversational question about OTP
            TestCase(
                name = "Conversational Question Invalidator",
                text = "Bhai OTP kya hota hai?",
                sender = "+919876543210",
                expectedLabel = "BENIGN",
                expectedAction = AdjudicationAction.ALLOW,
                expectedReason = "CONVERSATIONAL_DAMPENING",
                isSaved = true
            )
        )

        var passed = 0
        for ((idx, tc) in testCases.withIndex()) {
            val decision = scanner.scanWithContext(
                rawText = tc.text,
                senderHeader = tc.sender,
                contactProvider = savedContactProvider
            )

            val labelMatch = decision.finalLabel == tc.expectedLabel
            val actionMatch = decision.action == tc.expectedAction
            val reasonMatch = decision.adjudicationReason == tc.expectedReason

            if (labelMatch && actionMatch && reasonMatch) {
                passed++
                println("  [PASS] #${idx+1} ${tc.name}: Label=${decision.finalLabel}, Action=${decision.action}, Reason=${decision.adjudicationReason}, P_final=${"%.4f".format(decision.finalProbability)}")
            } else {
                println("  [FAIL] #${idx+1} ${tc.name}:")
                println("         Expected: Label=${tc.expectedLabel}, Action=${tc.expectedAction}, Reason=${tc.expectedReason}")
                println("         Actual:   Label=${decision.finalLabel}, Action=${decision.action}, Reason=${decision.adjudicationReason}, P_final=${decision.finalProbability}")
            }
        }

        println("=" .repeat(80))
        println("CONTEXTUAL ADJUDICATION TEST SUMMARY: $passed / ${testCases.size} PASSED")
        println("=" .repeat(80))

        if (passed != testCases.size) {
            throw AssertionError("ContextualParityTest FAILED ($passed/${testCases.size})")
        } else {
            println("SUCCESS: ALL CONTEXTUAL ADJUDICATION & SAFETY INVARIANTS VERIFIED 100%!")
        }
    }

    data class TestCase(
        val name: String,
        val text: String,
        val sender: String?,
        val expectedLabel: String,
        val expectedAction: AdjudicationAction,
        val expectedReason: String,
        val isSaved: Boolean
    )
}
