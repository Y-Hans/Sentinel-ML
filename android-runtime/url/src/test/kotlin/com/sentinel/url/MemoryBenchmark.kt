package com.sentinel.url

import java.io.File
import java.lang.management.ManagementFactory
import java.util.Arrays

/**
 * Rigorous Android / JVM Memory & Resource Profiler for URL-ML V8.
 *
 * Measures:
 * 1. Cold-start heap delta upon loading V8 JSON bundle
 * 2. Warm heap delta after JIT compilation and warmup
 * 3. Peak heap allocation under sustained throughput (10,000 scans)
 * 4. Steady-state retained memory after garbage collection
 * 5. Garbage collection frequency and pause time
 * 6. High-precision P50, P90, P95, P99, and Max latency
 */
object MemoryBenchmark {

    private fun getUsedMemory(): Long {
        val rt = Runtime.getRuntime()
        return rt.totalMemory() - rt.freeMemory()
    }

    private fun forceGc() {
        System.gc()
        System.runFinalization()
        try { Thread.sleep(200) } catch (e: InterruptedException) {}
        System.gc()
        try { Thread.sleep(200) } catch (e: InterruptedException) {}
    }

    private fun getGcStats(): Pair<Long, Long> {
        var count = 0L
        var timeMs = 0L
        for (gcBean in ManagementFactory.getGarbageCollectorMXBeans()) {
            val c = gcBean.collectionCount
            if (c > 0) count += c
            val t = gcBean.collectionTime
            if (t > 0) timeMs += t
        }
        return Pair(count, timeMs)
    }

    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML URL-ML V8 RUNTIME MEMORY & ALLOCATION PROFILER")
        println("=" .repeat(80))

        val v8AssetFile = File("android-runtime/url/assets/v8_champion_portable.json")
        val v7AssetFile = File("android-runtime/url/assets/v7_champion_portable.json")

        if (!v8AssetFile.exists()) {
            throw IllegalStateException("V8 asset not found: ${v8AssetFile.absolutePath}")
        }

        println("V8 Asset Path:  ${v8AssetFile.path}")
        println("V8 Asset Size:  ${v8AssetFile.length() / 1024} KB (${v8AssetFile.length()} bytes)")
        println("V7 Asset Size:  ${v7AssetFile.length() / 1024} KB (${v7AssetFile.length()} bytes)")

        val testCorpus = listOf(
            "https://www.google.com/search?q=security+advisories+android+cve",
            "http://192.168.1.1/admin/network.php?login=true",
            "https://secure-login.bankofamerica.com.account-verify.xyz/auth/login.html",
            "https://bit.ly/3x8GiftClaimNow",
            "https://github.com/torvalds/linux/blob/master/README.md",
            "https://chessigma.com/",
            "https://crazygames.io/game/bullet-force-multiplayer",
            "https://codenames.game/room/tiger-35",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            "https://www.youtube.com/@mkbhd",
            "https://github.com/kubernetes/kubernetes/commit/54b7ad52899dc6ae801334ee0ee693b4a20b0fa7",
            "https://local-artisan-bakery.co.nz/menu",
            "https://chase.com/personal/banking/login",
            "https://attacker.com/r?link=https%3A%2F%2Fbank.com%2Fverify",
            "http://paypal.account-security-update.com/login",
            "https://github.com/releases/download/v1.0/stealer.exe"
        )

        // 1. Initial Baseline Memory
        forceGc()
        val baselineMemory = getUsedMemory()
        val (gcCount0, gcTime0) = getGcStats()

        // 2. Cold-start Loading
        val tLoad0 = System.nanoTime()
        val scanner = UrlScanner.fromJson(v8AssetFile.readText(Charsets.UTF_8))
        val tLoad1 = System.nanoTime()
        val loadTimeMs = (tLoad1 - tLoad0) / 1_000_000.0

        val coldStartMemory = getUsedMemory()
        val coldStartDelta = coldStartMemory - baselineMemory

        // 3. Warm-up
        for (i in 0 until 1000) {
            scanner.scan(testCorpus[i % testCorpus.size])
        }
        val warmMemory = getUsedMemory()
        val warmDelta = warmMemory - baselineMemory

        // 4. Sustained Throughput & Peak Allocation Tracking (10,000 continuous scans)
        val N = 10000
        val latencies = DoubleArray(N)
        var peakMemoryObserved = warmMemory

        val tRun0 = System.nanoTime()
        for (i in 0 until N) {
            val u = testCorpus[i % testCorpus.size]
            val t0 = System.nanoTime()
            scanner.scan(u)
            val t1 = System.nanoTime()
            latencies[i] = (t1 - t0) / 1_000_000.0

            if (i % 1000 == 0) {
                val current = getUsedMemory()
                if (current > peakMemoryObserved) {
                    peakMemoryObserved = current
                }
            }
        }
        val tRun1 = System.nanoTime()
        val totalRunTimeMs = (tRun1 - tRun0) / 1_000_000.0

        val (gcCount1, gcTime1) = getGcStats()
        val gcsDuringRun = gcCount1 - gcCount0
        val gcTimeDuringRun = gcTime1 - gcTime0

        // 5. Steady-state Retained Memory Post-Run
        forceGc()
        val retainedMemory = getUsedMemory()
        val retainedDelta = retainedMemory - baselineMemory

        // Latency sorting & percentiles
        Arrays.sort(latencies)
        val meanLat = latencies.average()
        val p50 = latencies[N / 2]
        val p90 = latencies[(N * 0.90).toInt()]
        val p95 = latencies[(N * 0.95).toInt()]
        val p99 = latencies[(N * 0.99).toInt()]
        val maxLat = latencies[N - 1]

        println("\n--- [1] MEMORY FOOTPRINT METRICS ---")
        println("  Baseline Initial Heap:      %.2f MB (%d bytes)".format(baselineMemory / (1024.0 * 1024.0), baselineMemory))
        println("  Model Load Time (JSON):     %.2f ms".format(loadTimeMs))
        println("  Cold-Start Heap Delta:      %.2f MB (%+d bytes)".format(coldStartDelta / (1024.0 * 1024.0), coldStartDelta))
        println("  Warm Heap Delta (Post-JIT): %.2f MB (%+d bytes)".format(warmDelta / (1024.0 * 1024.0), warmDelta))
        println("  Peak Allocation (10k run):  %.2f MB (%d bytes)".format(peakMemoryObserved / (1024.0 * 1024.0), peakMemoryObserved))
        println("  Retained Steady-State Heap: %.2f MB (%+d bytes)".format(retainedDelta / (1024.0 * 1024.0), retainedDelta))

        println("\n--- [2] GARBAGE COLLECTION ACTIVITY ---")
        println("  Total GC Collections:       %d events".format(gcsDuringRun))
        println("  Total GC Pause Time:        %d ms".format(gcTimeDuringRun))

        println("\n--- [3] INFERENCE LATENCY DISTRIBUTION (N = 10,000) ---")
        println("  Total Batch Duration:       %.1f ms (%.1f scans/sec)".format(totalRunTimeMs, N * 1000.0 / totalRunTimeMs))
        println("  Mean Latency:               %.4f ms".format(meanLat))
        println("  Median (P50) Latency:       %.4f ms".format(p50))
        println("  90th Percentile (P90):      %.4f ms".format(p90))
        println("  95th Percentile (P95):      %.4f ms".format(p95))
        println("  99th Percentile (P99):      %.4f ms".format(p99))
        println("  Max Latency:                %.4f ms".format(maxLat))

        println("=" .repeat(80))
        println("V8 MEMORY BENCHMARK COMPLETED SUCCESSFULLY.")
    }
}
