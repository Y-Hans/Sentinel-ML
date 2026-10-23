from pathlib import Path

BASE = Path(__file__).resolve().parents[2]
URL_TEST_DIR = BASE / 'android-runtime' / 'url' / 'src' / 'test' / 'kotlin' / 'com' / 'sentinel' / 'url'
MSG_TEST_DIR = BASE / 'android-runtime' / 'messages' / 'src' / 'test' / 'kotlin' / 'com' / 'sentinel' / 'messages'

URL_TEST_DIR.mkdir(parents=True, exist_ok=True)
MSG_TEST_DIR.mkdir(parents=True, exist_ok=True)

# 1. UrlParityTest.kt
url_test_kt = '''package com.sentinel.url

import java.io.File
import kotlin.math.abs
import kotlin.math.max

object UrlParityTest {

    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML URL-ML V7 CROSS-LANGUAGE GOLDEN PARITY TEST")
        println("=" .repeat(80))

        val modelFile = File("android-runtime/url/assets/v7_champion_portable.json")
        if (!modelFile.exists()) {
            throw IllegalStateException("Model bundle not found: ${modelFile.absolutePath}")
        }
        val goldenFile = File("android-runtime/golden_test_data/golden_urls.json")
        if (!goldenFile.exists()) {
            throw IllegalStateException("Golden dataset not found: ${goldenFile.absolutePath}")
        }

        println("Loading model from: ${modelFile.path} (${modelFile.length() / 1024} KB)")
        val scanner = UrlScanner.fromJson(modelFile.readText(Charsets.UTF_8))

        println("Loading golden records from: ${goldenFile.path}")
        val jsonStr = goldenFile.readText(Charsets.UTF_8)
        val records = parseGoldenUrlRecords(jsonStr)
        println("Loaded ${records.size} golden URL test records.\\n")

        var labelMatches = 0
        var maxFeatDiff = 0.0
        var maxRawPDiff = 0.0
        var maxFinalPDiff = 0.0
        val mismatches = mutableListOf<String>()

        for (rec in records) {
            val ktFeatures = scanner.extractFeatures(rec.url)
            val result = scanner.scan(rec.url)

            // 1. Check feature diffs
            for (i in 0 until 67) {
                val pyVal = rec.features[i]
                val ktVal = ktFeatures[i]
                val diff = abs(pyVal.toDouble() - ktVal.toDouble())
                if (diff > maxFeatDiff) maxFeatDiff = diff
                if (diff > 1e-4) {
                    println("  [FEAT MISMATCH] ${rec.id} feat $i: Py=$pyVal, Kt=$ktVal, diff=$diff")
                }
            }

            // 2. Check probability diffs
            val rawDiff = abs(rec.rawProbability.toDouble() - result.rawProbability.toDouble())
            if (rawDiff > maxRawPDiff) maxRawPDiff = rawDiff

            val finalDiff = abs(rec.finalProbability.toDouble() - result.probability.toDouble())
            if (finalDiff > maxFinalPDiff) maxFinalPDiff = finalDiff

            // 3. Check label match
            if (rec.label == result.label && rec.isMalicious == result.isMalicious) {
                labelMatches++
            } else {
                mismatches.add(rec.id)
                println("  [LABEL MISMATCH] ${rec.id} -> Py: ${rec.label} (${rec.finalProbability}), Kt: ${result.label} (${result.probability}) | URL: ${rec.url}")
            }
        }

        println("=" .repeat(80))
        println("URL-ML V7 PARITY TEST SUMMARY:")
        println("  Total Evaluated:      ${records.size}")
        println("  Label Parity:         $labelMatches / ${records.size} (${labelMatches * 100.0 / records.size}%)")
        println("  Max Feature Diff:     $maxFeatDiff")
        println("  Max Raw P Diff:       $maxRawPDiff")
        println("  Max Final P Diff:     $maxFinalPDiff")
        println("  Mismatches Count:     ${mismatches.size}")
        println("=" .repeat(80))

        if (labelMatches != records.size) {
            throw AssertionError("URL-ML Parity Test FAILED with ${mismatches.size} label mismatches!")
        } else {
            println("SUCCESS: URL-ML V7 PASSED 100% BIT-FOR-BIT LABEL PARITY!")
        }
    }

    data class GoldenUrlRecord(
        val id: String,
        val url: String,
        val category: String,
        val features: FloatArray,
        val rawProbability: Float,
        val finalProbability: Float,
        val isMalicious: Boolean,
        val label: String
    )

    private fun parseGoldenUrlRecords(json: String): List<GoldenUrlRecord> {
        val records = mutableListOf<GoldenUrlRecord>()
        var pos = 0
        while (pos < json.length) {
            val idMarker = "\\"id\\""
            val idIdx = json.indexOf(idMarker, pos)
            if (idIdx == -1) break

            fun getField(key: String, from: Int): String {
                val marker = "\\"$key\\""
                val idx = json.indexOf(marker, from)
                if (idx == -1) return ""
                val colonIdx = json.indexOf(':', idx)
                if (colonIdx == -1) return ""
                var start = colonIdx + 1
                while (start < json.length && json[start].isWhitespace()) start++
                if (start < json.length && json[start] == '"') {
                    val s = start + 1
                    var e = s
                    while (e < json.length && json[e] != '"') {
                        if (json[e] == '\\\\') e += 2 else e++
                    }
                    return json.substring(s, e)
                } else {
                    var e = start
                    while (e < json.length && json[e] != ',' && json[e] != '}' && json[e] != '\\n') e++
                    return json.substring(start, e).trim()
                }
            }

            val id = getField("id", idIdx)
            val url = getField("url", idIdx)
            val cat = getField("category", idIdx)
            val rawP = getField("raw_probability", idIdx).toFloat()
            val finalP = getField("final_probability", idIdx).toFloat()
            val label = getField("label", idIdx)
            val isMal = label == "MALICIOUS"

            // Parse features array
            val fMarker = "\\"features\\""
            val fIdx = json.indexOf(fMarker, idIdx)
            val fStart = json.indexOf('[', fIdx) + 1
            val fEnd = json.indexOf(']', fStart)
            val fTokens = json.substring(fStart, fEnd).split(',')
            val features = FloatArray(fTokens.size)
            for (i in 0 until fTokens.size) {
                features[i] = fTokens[i].trim().toFloat()
            }

            records.add(GoldenUrlRecord(id, url, cat, features, rawP, finalP, isMal, label))
            pos = fEnd
        }
        return records
    }
}
'''
URL_TEST_DIR.joinpath('UrlParityTest.kt').write_text(url_test_kt.strip(), encoding='utf-8')
print('Wrote UrlParityTest.kt')

# 2. MessageParityTest.kt
msg_test_kt = '''package com.sentinel.messages

import java.io.File
import kotlin.math.abs
import kotlin.math.max

object MessageParityTest {

    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML MESSAGES-ML V2 CROSS-LANGUAGE GOLDEN PARITY TEST")
        println("=" .repeat(80))

        val assetsDir = File("android-runtime/messages/assets")
        val wFile = File(assetsDir, "champion_v2_word_vocab_idf.json")
        val cFile = File(assetsDir, "champion_v2_char_vocab_idf.json")
        val sFile = File(assetsDir, "champion_v2_scaler.json")
        val tFile = File(assetsDir, "champion_v2_trees.json")

        val goldenFile = File("android-runtime/golden_test_data/golden_messages.json")
        if (!goldenFile.exists()) {
            throw IllegalStateException("Golden dataset not found: ${goldenFile.absolutePath}")
        }

        println("Loading Messages-ML assets from: ${assetsDir.path}")
        val scanner = MessageScanner.create(
            wordJson = wFile.readText(Charsets.UTF_8),
            charJson = cFile.readText(Charsets.UTF_8),
            scalerJson = sFile.readText(Charsets.UTF_8),
            treesJson = tFile.readText(Charsets.UTF_8),
            threshold = 0.704f
        )

        println("Loading golden records from: ${goldenFile.path}")
        val records = parseGoldenMessageRecords(goldenFile.readText(Charsets.UTF_8))
        println("Loaded ${records.size} golden Messages test records.\\n")

        var labelMatches = 0
        var maxDetDiff = 0.0
        var maxPDiff = 0.0
        val mismatches = mutableListOf<String>()

        for (rec in records) {
            val ktDet = MessageFeatureExtractor.extractDeterministicFeatures(rec.text, rec.sender)
            val result = scanner.scan(rec.text, rec.sender)

            // 1. Check deterministic features diff
            for (i in 0 until 70) {
                val pyVal = rec.detFeatures[i]
                val ktVal = ktDet[i]
                val diff = abs(pyVal.toDouble() - ktVal.toDouble())
                if (diff > maxDetDiff) maxDetDiff = diff
                if (diff > 1e-4) {
                    println("  [DET FEAT MISMATCH] ${rec.id} feat $i: Py=$pyVal, Kt=$ktVal, diff=$diff")
                }
            }

            // 2. Check probabilities diff
            for (k in 0 until 3) {
                val pyP = rec.probabilities[k]
                val ktP = result.probabilities[k]
                val diff = abs(pyP.toDouble() - ktP.toDouble())
                if (diff > maxPDiff) maxPDiff = diff
            }

            // 3. Check label match
            if (rec.label == result.label && rec.predictedClass == result.classIndex) {
                labelMatches++
            } else {
                mismatches.add(rec.id)
                println("  [LABEL MISMATCH] ${rec.id} -> Py: ${rec.label} (${rec.probabilities[1] + rec.probabilities[2]}), Kt: ${result.label} (${result.pNonBenign}) | Text: ${rec.text.take(60)}")
            }
        }

        println("=" .repeat(80))
        println("MESSAGES-ML V2 PARITY TEST SUMMARY:")
        println("  Total Evaluated:          ${records.size}")
        println("  Label Parity:             $labelMatches / ${records.size} (${labelMatches * 100.0 / records.size}%)")
        println("  Max Deterministic Diff:   $maxDetDiff")
        println("  Max Probability Diff:     $maxPDiff")
        println("  Mismatches Count:         ${mismatches.size}")
        println("=" .repeat(80))

        if (labelMatches != records.size) {
            throw AssertionError("Messages-ML Parity Test FAILED with ${mismatches.size} label mismatches!")
        } else {
            println("SUCCESS: MESSAGES-ML V2 PASSED 100% BIT-FOR-BIT LABEL PARITY!")
        }
    }

    data class GoldenMessageRecord(
        val id: String,
        val text: String,
        val sender: String?,
        val category: String,
        val detFeatures: FloatArray,
        val probabilities: FloatArray,
        val predictedClass: Int,
        val label: String
    )

    private fun parseGoldenMessageRecords(json: String): List<GoldenMessageRecord> {
        val records = mutableListOf<GoldenMessageRecord>()
        var pos = 0
        while (pos < json.length) {
            val idMarker = "\\"id\\""
            val idIdx = json.indexOf(idMarker, pos)
            if (idIdx == -1) break

            fun unescapeJson(s: String): String {
                val sb = java.lang.StringBuilder(s.length)
                var i = 0
                while (i < s.length) {
                    val c = s[i]
                    if (c == '\\\\' && i + 1 < s.length) {
                        val next = s[i + 1]
                        when (next) {
                            'n' -> { sb.append('\\n'); i += 2 }
                            'r' -> { sb.append('\\r'); i += 2 }
                            't' -> { sb.append('\\t'); i += 2 }
                            'b' -> { sb.append('\\b'); i += 2 }
                            'f' -> { sb.append('\\u000c'); i += 2 }
                            '"' -> { sb.append('"'); i += 2 }
                            '\\\\' -> { sb.append('\\\\'); i += 2 }
                            '/' -> { sb.append('/'); i += 2 }
                            'u' -> {
                                if (i + 5 < s.length) {
                                    val hex = s.substring(i + 2, i + 6)
                                    val code = hex.toIntOrNull(16)
                                    if (code != null) {
                                        sb.append(code.toChar())
                                        i += 6
                                    } else {
                                        sb.append(c)
                                        i++
                                    }
                                } else {
                                    sb.append(c)
                                    i++
                                }
                            }
                            else -> { sb.append(c); i++ }
                        }
                    } else {
                        sb.append(c)
                        i++
                    }
                }
                return sb.toString()
            }

            fun getStrField(key: String, from: Int): String {
                val marker = "\\"$key\\""
                val idx = json.indexOf(marker, from)
                if (idx == -1) return ""
                val colonIdx = json.indexOf(':', idx)
                if (colonIdx == -1) return ""
                var st = colonIdx + 1
                while (st < json.length && json[st].isWhitespace()) st++
                if (json.startsWith("null", st)) return ""
                if (st < json.length && json[st] == '"') {
                    val s = st + 1
                    var e = s
                    while (e < json.length && json[e] != '"') {
                        if (json[e] == '\\\\') e += 2 else e++
                    }
                    val v = json.substring(s, e)
                    return unescapeJson(v)
                }
                return ""
            }

            fun getNumField(key: String, from: Int): String {
                val marker = "\\"$key\\""
                val idx = json.indexOf(marker, from)
                if (idx == -1) return ""
                val colonIdx = json.indexOf(':', idx)
                if (colonIdx == -1) return ""
                var st = colonIdx + 1
                while (st < json.length && json[st].isWhitespace()) st++
                var e = st
                while (e < json.length && json[e] != ',' && json[e] != '}' && json[e] != '\\n') e++
                return json.substring(st, e).trim()
            }

            val id = getStrField("id", idIdx)
            val text = getStrField("text", idIdx)
            val senderRaw = getStrField("sender", idIdx)
            val sender = if (senderRaw.isEmpty()) null else senderRaw
            val cat = getStrField("category", idIdx)
            val label = getStrField("label", idIdx)
            val predClass = getNumField("predicted_class", idIdx).toIntOrNull() ?: 0

            // Deterministic features
            val detMarker = "\\"deterministic_features\\""
            val detIdx = json.indexOf(detMarker, idIdx)
            val detStart = json.indexOf('[', detIdx) + 1
            val detEnd = json.indexOf(']', detStart)
            val detTokens = json.substring(detStart, detEnd).split(',')
            val detFeatures = FloatArray(detTokens.size)
            for (i in 0 until detTokens.size) {
                detFeatures[i] = detTokens[i].trim().toFloat()
            }

            // Probabilities
            val pMarker = "\\"probabilities\\""
            val pIdx = json.indexOf(pMarker, idIdx)
            val pStart = json.indexOf('[', pIdx) + 1
            val pEnd = json.indexOf(']', pStart)
            val pTokens = json.substring(pStart, pEnd).split(',')
            val probs = FloatArray(3)
            for (i in 0 until 3) {
                probs[i] = pTokens[i].trim().toFloat()
            }

            records.add(GoldenMessageRecord(id, text, sender, cat, detFeatures, probs, predClass, label))
            pos = pEnd
        }
        return records
    }
}
'''
MSG_TEST_DIR.joinpath('MessageParityTest.kt').write_text(msg_test_kt.strip(), encoding='utf-8')
print('Wrote MessageParityTest.kt')

# 3. CompareS01.kt
compare_s01_kt = '''package com.sentinel.messages

import java.io.File

object CompareS01 {
    @JvmStatic
    fun main(args: Array<String>) {
        val assetsDir = File("android-runtime/messages/assets")
        val wFile = File(assetsDir, "champion_v2_word_vocab_idf.json")
        val cFile = File(assetsDir, "champion_v2_char_vocab_idf.json")
        val sFile = File(assetsDir, "champion_v2_scaler.json")
        val tFile = File(assetsDir, "champion_v2_trees.json")

        val (wVocab, wIdf, stopWords) = MessageAssetLoader.loadWordTfidf(wFile.readText(Charsets.UTF_8))
        val (cVocab, cIdf) = MessageAssetLoader.loadCharTfidf(cFile.readText(Charsets.UTF_8))
        val (mean, scale) = MessageAssetLoader.loadScaler(sFile.readText(Charsets.UTF_8))
        val (basePred, binThresh, trees3D, nClasses, nIters) = MessageAssetLoader.loadTrees(tFile.readText(Charsets.UTF_8))

        val tfidf = DualTfidfVectorizer(wVocab, wIdf, stopWords, cVocab, cIdf)
        val scaler = FeatureScaler(2070, mean, scale)
        val evaluator = MultiClassTreeEvaluator(nClasses, nIters, basePred, binThresh, trees3D)
        val adjudicator = MessageAdjudicator(0.704f)
        val scanner = MessageScanner(tfidf, scaler, evaluator, adjudicator)

        val txt = "Congratulations! Your mobile number won Rs 25,00,000 in KBC Lucky Draw. Call customer manager Mr. Sharma immediately at 9876501234."
        val hdr = "+919820012345"

        val rawVec = scanner.assembleFeatureVector(txt, hdr)
        val rawMargins = evaluator.predictRawMargins(rawVec)
        val probs = evaluator.predictProba(rawVec)
        val res = adjudicator.adjudicate(probs)

        println("Raw margins: [" + rawMargins[0] + ", " + rawMargins[1] + ", " + rawMargins[2] + "]")
        println("Probs: [" + probs[0] + ", " + probs[1] + ", " + probs[2] + "]")
        println("Adjudicated: " + res.label + " (class " + res.classIndex + ")")
    }
}
'''
MSG_TEST_DIR.joinpath('CompareS01.kt').write_text(compare_s01_kt.strip(), encoding='utf-8')
print('Wrote CompareS01.kt')

# 4. debug_trace.py
trace_py = '''import pickle, json, numpy as np

clf = pickle.load(open('Messages-ml/champion_v2_model.pkl', 'rb'))
kt = json.load(open('debug_s01_kt.json'))
scaled_vec = np.array(kt['scaled'], dtype=np.float64)

binned = clf._bin_mapper.transform(scaled_vec.reshape(1, -1))[0]

scores = np.array(clf._baseline_prediction[0], dtype=np.float64)
for iter_idx in range(len(clf._predictors)):
    for k in range(3):
        tree = clf._predictors[iter_idx][k]
        node_idx = 0
        while True:
            node = tree.nodes[node_idx]
            if node['is_leaf']:
                scores[k] += node['value']
                break
            feat_idx = int(node['feature_idx'])
            bin_thresh = int(node['bin_threshold'])
            b_val = binned[feat_idx]
            if b_val <= bin_thresh:
                node_idx = int(node['left'])
            else:
                node_idx = int(node['right'])

print("=== Iteration 1 Class 0 in Python ===")
tree = clf._predictors[1][0]
node_idx = 0
while True:
    node = tree.nodes[node_idx]
    if node['is_leaf']:
        print(f"Leaf value = {node['value']}, node_idx={node_idx}")
        break
    feat_idx = int(node['feature_idx'])
    bin_thresh = int(node['bin_threshold'])
    b_val = binned[feat_idx]
    thresh_float = clf._bin_mapper.bin_thresholds_[feat_idx][bin_thresh] if bin_thresh < len(clf._bin_mapper.bin_thresholds_[feat_idx]) else 999.0
    print(f"Node {node_idx}: feat {feat_idx} (scaled_val={scaled_vec[feat_idx]}, bin {b_val} vs thresh {bin_thresh}, thresh_float={thresh_float})")
    if b_val <= bin_thresh:
        node_idx = int(node['left'])
    else:
        node_idx = int(node['right'])
'''
# 5. BenchmarkRunner.kt
bench_kt = """package com.sentinel

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
        println("\\n--- [1/2] URL-ML V7 Performance Benchmark ---")
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
        println("\\n--- [2/2] Messages-ML V2 Performance Benchmark ---")
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
        println("\\n--- Memory Footprint ---")
        println("  Resident Heap Used: ~%.2f MB (%d bytes)".format(deltaMemory / (1024.0 * 1024.0), deltaMemory))
        println("=" .repeat(80))
    }
}
"""
BASE.joinpath('android-runtime/tools/BenchmarkRunner.kt').write_text(bench_kt.strip(), encoding='utf-8')
print('Wrote BenchmarkRunner.kt')








