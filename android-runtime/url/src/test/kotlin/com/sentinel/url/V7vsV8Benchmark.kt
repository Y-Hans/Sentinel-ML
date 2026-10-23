package com.sentinel.url

import java.io.File
import java.util.Arrays

object V7vsV8Benchmark {
    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML URL SUBSYSTEM BENCHMARK: V7 vs V8 RUNTIME PROFILING")
        println("=" .repeat(80))

        val v7File = File("android-runtime/url/assets/v7_champion_portable.json")
        val v8File = File("android-runtime/url/assets/v8_champion_portable.json")

        val testUrls = listOf(
            "https://www.google.com/search?q=security+updates",
            "http://192.168.1.1/login.php?admin=true",
            "https://secure-login.bankofamerica.com.account-verify.xyz/auth/login.html",
            "https://bit.ly/3x8GiftClaimNow",
            "https://github.com/torvalds/linux/blob/master/README.md",
            "https://chessigma.com/",
            "https://crazygames.io/game/bullet-force-multiplayer",
            "https://codenames.game/room/tiger-35",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://github.com/kubernetes/kubernetes/commit/54b7ad52899dc6ae801334ee0ee693b4a20b0fa7"
        )

        val rt = Runtime.getRuntime()

        // 1. Profile V7
        rt.gc()
        Thread.sleep(150)
        val memV7Before = rt.totalMemory() - rt.freeMemory()
        val v7Scanner = UrlScanner.fromJson(v7File.readText(Charsets.UTF_8))
        val memV7After = rt.totalMemory() - rt.freeMemory()
        val v7MemDelta = (memV7After - memV7Before) / 1024.0

        // Warmup V7
        for (i in 0 until 500) {
            v7Scanner.scan(testUrls[i % testUrls.size])
        }

        val N = 3000
        val v7Latencies = DoubleArray(N)
        for (i in 0 until N) {
            val u = testUrls[i % testUrls.size]
            val t0 = System.nanoTime()
            v7Scanner.scan(u)
            val t1 = System.nanoTime()
            v7Latencies[i] = (t1 - t0) / 1000000.0
        }
        Arrays.sort(v7Latencies)
        val v7Mean = v7Latencies.average()
        val v7Median = v7Latencies[N / 2]
        val v7P95 = v7Latencies[(N * 0.95).toInt()]
        val v7P99 = v7Latencies[(N * 0.99).toInt()]

        // 2. Profile V8
        rt.gc()
        Thread.sleep(150)
        val memV8Before = rt.totalMemory() - rt.freeMemory()
        val v8Scanner = UrlScanner.fromJson(v8File.readText(Charsets.UTF_8))
        val memV8After = rt.totalMemory() - rt.freeMemory()
        val v8MemDelta = (memV8After - memV8Before) / 1024.0

        // Warmup V8
        for (i in 0 until 500) {
            v8Scanner.scan(testUrls[i % testUrls.size])
        }

        val v8Latencies = DoubleArray(N)
        for (i in 0 until N) {
            val u = testUrls[i % testUrls.size]
            val t0 = System.nanoTime()
            v8Scanner.scan(u)
            val t1 = System.nanoTime()
            v8Latencies[i] = (t1 - t0) / 1000000.0
        }
        Arrays.sort(v8Latencies)
        val v8Mean = v8Latencies.average()
        val v8Median = v8Latencies[N / 2]
        val v8P95 = v8Latencies[(N * 0.95).toInt()]
        val v8P99 = v8Latencies[(N * 0.99).toInt()]

        println("\n--- [V7 FOCUSED METRICS] ---")
        println("  Asset Size:       ${v7File.length() / 1024} KB (${v7File.length()} bytes)")
        println("  Loaded Heap Delta:~%.1f KB".format(v7MemDelta))
        println("  Evaluations:      $N")
        println("  Mean Latency:     %.4f ms (%.1f scans/sec)".format(v7Mean, 1000.0 / v7Mean))
        println("  Median (P50):     %.4f ms".format(v7Median))
        println("  P95 Latency:      %.4f ms".format(v7P95))
        println("  P99 Latency:      %.4f ms".format(v7P99))

        println("\n--- [V8 FOCUSED METRICS] ---")
        println("  Asset Size:       ${v8File.length() / 1024} KB (${v8File.length()} bytes)")
        println("  Loaded Heap Delta:~%.1f KB".format(v8MemDelta))
        println("  Evaluations:      $N")
        println("  Mean Latency:     %.4f ms (%.1f scans/sec)".format(v8Mean, 1000.0 / v8Mean))
        println("  Median (P50):     %.4f ms".format(v8Median))
        println("  P95 Latency:      %.4f ms".format(v8P95))
        println("  P99 Latency:      %.4f ms".format(v8P99))

        println("\n--- [DELTA COMPARISON (V8 vs V7)] ---")
        println("  Asset Size Delta: ${v8File.length() - v7File.length()} bytes")
        println("  Mean Latency Diff: %+.4f ms".format(v8Mean - v7Mean))
        println("  P50 Latency Diff:  %+.4f ms".format(v8Median - v7Median))
        println("  P95 Latency Diff:  %+.4f ms".format(v8P95 - v7P95))
        println("  P99 Latency Diff:  %+.4f ms".format(v8P99 - v7P99))
        println("=" .repeat(80))
    }
}
