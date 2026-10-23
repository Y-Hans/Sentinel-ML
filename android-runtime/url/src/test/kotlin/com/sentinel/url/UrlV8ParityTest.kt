package com.sentinel.url

import java.io.File
import kotlin.math.abs

object UrlV8ParityTest {

    @JvmStatic
    fun main(args: Array<String>) {
        println("=" .repeat(80))
        println("SENTINEL-ML URL-ML V8 CROSS-LANGUAGE GOLDEN PARITY TEST")
        println("=" .repeat(80))

        val modelFile = File("android-runtime/url/assets/v8_champion_portable.json")
        if (!modelFile.exists()) {
            throw IllegalStateException("Model bundle not found: ${modelFile.absolutePath}")
        }
        val goldenFile = File("android-runtime/golden_test_data/golden_urls_v8.json")
        if (!goldenFile.exists()) {
            throw IllegalStateException("Golden dataset not found: ${goldenFile.absolutePath}")
        }

        println("Loading V8 model from: ${modelFile.path} (${modelFile.length() / 1024} KB)")
        val scanner = UrlScanner.fromJson(modelFile.readText(Charsets.UTF_8))

        println("Loading golden records from: ${goldenFile.path}")
        val jsonStr = goldenFile.readText(Charsets.UTF_8)
        val records = parseGoldenUrlRecords(jsonStr)
        println("Loaded ${records.size} golden V8 URL test records.\n")

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
                println("  [LABEL MISMATCH] ${rec.id} (${rec.category}) -> Py: ${rec.label} (${rec.finalProbability}), Kt: ${result.label} (${result.probability}) | URL: ${rec.url}")
            }
        }

        println("=" .repeat(80))
        println("URL-ML V8 PARITY TEST SUMMARY:")
        println("  Total Evaluated:      ${records.size}")
        println("  Label Parity:         $labelMatches / ${records.size} (${labelMatches * 100.0 / records.size}%)")
        println("  Max Feature Diff:     $maxFeatDiff")
        println("  Max Raw P Diff:       $maxRawPDiff")
        println("  Max Final P Diff:     $maxFinalPDiff")
        println("  Mismatches Count:     ${mismatches.size}")
        println("=" .repeat(80))

        if (labelMatches != records.size) {
            throw AssertionError("URL-ML V8 Parity Test FAILED with ${mismatches.size} label mismatches!")
        } else {
            println("SUCCESS: URL-ML V8 PASSED 100% BIT-FOR-BIT LABEL PARITY!")
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
            val idMarker = "\"id\""
            val idIdx = json.indexOf(idMarker, pos)
            if (idIdx == -1) break

            fun getField(key: String, from: Int): String {
                val marker = "\"$key\""
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
                        if (json[e] == '\\') e += 2 else e++
                    }
                    return json.substring(s, e)
                } else {
                    var e = start
                    while (e < json.length && json[e] != ',' && json[e] != '}' && json[e] != '\n') e++
                    return json.substring(start, e).trim()
                }
            }

            val id = getField("id", idIdx)
            val url = getField("url", idIdx)
            val cat = getField("category", idIdx)
            val rawP = getField("rawProbability", idIdx).toFloat()
            val finalP = getField("finalProbability", idIdx).toFloat()
            val label = getField("label", idIdx)
            val isMal = label == "MALICIOUS"

            // Parse features array
            val fMarker = "\"features\""
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
