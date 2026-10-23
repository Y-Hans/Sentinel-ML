package com.sentinel

import com.sentinel.messages.MessageScanner
import com.sentinel.url.UrlScanner
import java.io.File
import java.util.Arrays

object BenchmarkRunner {
    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML ANDROID RUNTIME PERFORMANCE BENCHMARK")
        println("=" .repeat(80))

        val runtime = Runtime.getRuntime()
        runtime.gc()
        Thread.sleep(200)
        val initialMemory = runtime.totalMemory() - runtime.freeMemory()

        // 1. URL-ML V7 Benchmark
        println("\n--- [1/2] URL-ML V7 Performance Benchmark ---")
        val urlModelFile = File("android-runtime/url/assets/v7_champion_portable.json")
        val urlScanner = UrlScanner.fromJson(urlModelFile.readText(Charsets.UTF_8))

        
        val urlTestCases = listOf(
            "https://www.google.com/search?q=security+updates",
            "http://192.168.1.1/login.php?admin=true",
            "https://secure-login.bankofamerica.com.account-verify.xyz/auth/login.html",
            "https://bit.ly/3x8GiftClaimNow",
            "https://github.com/torvalds/linux/blob/master/README.md"
        )

        // Warm-up 100 iterations
        for (i in 0 until 100) {
            for (u in urlTestCases) urlScanner.scan(u)
        }

        val urlN = 1000
        val urlLatencies = DoubleArray(urlN)
        for (i in 0 until urlN) {
            val targetUrl = urlTestCases[i % urlTestCases.size]
            val t0 = System.nanoTime()
            val res = urlScanner.scan(targetUrl)
            val t1 = System.nanoTime()
            urlLatencies[i] = (t1 - t0) / 1000000.0
        }
        Arrays.sort(urlLatencies)
        val urlMean = urlLatencies.average()
        val urlMedian = urlLatencies[urlN / 2]
        val urlP95 = urlLatencies[(urlN * 0.95).toInt()]
        val urlP99 = urlLatencies[(urlN * 0.99).toInt()]

        val urlBytes = urlModelFile.length()
        println("  Asset Size:       " + (urlBytes / 1024) + " KB (" + urlBytes + " bytes)")
        println("  Iterations:       " + urlN)
        println("  Mean Latency:     %.4f ms (%.2f scans/sec)".format(urlMean, 1000.0 / urlMean))
        println("  Median (P50):     %.4f ms".format(urlMedian))
        println("  P95 Latency:      %.4f ms".format(urlP95))
        println("  P99 Latency:      %.4f ms".format(urlP99))

        // 2. Messages-ML V2 Benchmark
        println("\n--- [2/2] Messages-ML V2 Performance Benchmark ---")
        val msgAssetsDir = File("android-runtime/messages/assets")
        val wJson = File(msgAssetsDir, "champion_v2_word_vocab_idf.json").readText(Charsets.UTF_8)
        val cJson = File(msgAssetsDir, "champion_v2_char_vocab_idf.json").readText(Charsets.UTF_8)
        val sJson = File(msgAssetsDir, "champion_v2_scaler.json").readText(Charsets.UTF_8)
        val tJson = File(msgAssetsDir, "champion_v2_trees.json").readText(Charsets.UTF_8)

        val msgScanner = MessageScanner.create(wJson, cJson, sJson, tJson, 0.704f)

        val msgTestCases = listOf(
            Pair("Your HDFC Bank account XX1234 has been debited by Rs. 2,500.00 on 24-AUG-26. Avl bal: Rs. 45,210.50. Txn: UPI/482910.", "VK-HDFCBK"),
            Pair("482910 is your OTP for Axis Bank NetBanking login. OTP is confidential. Bank never asks to share OTP or password with anyone.", "AX-AXISBK"),
            Pair("Congratulations! Your mobile number won Rs 25,00,000 in KBC Lucky Draw. Call customer manager Mr. Sharma immediately at 9876501234.", "+919820012345"),
            Pair("Dear SBI User, your YONO account has been blocked today due to incomplete KYC document verification. Click immediately to update PAN card: https://bit.ly/sbi-pan-update", "+919123456789"),
            Pair("Dear customer, your electricity power will be disconnected tonight at 9:30 PM from electricity office because your previous month bill was not update. Please immediately contact our electricity officer at 9876543210. Mahavitaran MSEDCL.", "+918877665544")
        )

        // Warm-up 100 iterations
        for (i in 0 until 100) {
            for (m in msgTestCases) msgScanner.scan(m.first, m.second)
        }

        val msgN = 1000
        val msgLatencies = DoubleArray(msgN)
        for (i in 0 until msgN) {
            val (txt, hdr) = msgTestCases[i % msgTestCases.size]
            val t0 = System.nanoTime()
            val res = msgScanner.scan(txt, hdr)
            val t1 = System.nanoTime()
            msgLatencies[i] = (t1 - t0) / 1000000.0
        }
        Arrays.sort(msgLatencies)
        val msgMean = msgLatencies.average()
        val msgMedian = msgLatencies[msgN / 2]
        val msgP95 = msgLatencies[(msgN * 0.95).toInt()]
        val msgP99 = msgLatencies[(msgN * 0.99).toInt()]

        val totalMsgAssetBytes = File(msgAssetsDir, "champion_v2_word_vocab_idf.json").length() +
                                File(msgAssetsDir, "champion_v2_char_vocab_idf.json").length() +
                                File(msgAssetsDir, "champion_v2_scaler.json").length() +
                                File(msgAssetsDir, "champion_v2_trees.json").length()

        println("  Total Asset Size: " + (totalMsgAssetBytes / 1024) + " KB (" + totalMsgAssetBytes + " bytes)")
        println("  Iterations:       " + msgN)
        println("  Mean Latency:     %.4f ms (%.2f scans/sec)".format(msgMean, 1000.0 / msgMean))
        println("  Median (P50):     %.4f ms".format(msgMedian))
        println("  P95 Latency:      %.4f ms".format(msgP95))
        println("  P99 Latency:      %.4f ms".format(msgP99))

        runtime.gc()
        Thread.sleep(200)
        val finalMemory = runtime.totalMemory() - runtime.freeMemory()
        val deltaMemory = (finalMemory - initialMemory).coerceAtLeast(0L)
        println("\n--- Memory Footprint ---")
        println("  Resident Heap Used: ~%.2f MB (%d bytes)".format(deltaMemory / (1024.0 * 1024.0), deltaMemory))
        println("=" .repeat(80))
    }
}