package com.sentinel.messages

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
        println("Loaded ${records.size} golden Messages test records.\n")

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
            val idMarker = "\"id\""
            val idIdx = json.indexOf(idMarker, pos)
            if (idIdx == -1) break

            fun unescapeJson(s: String): String {
                val sb = java.lang.StringBuilder(s.length)
                var i = 0
                while (i < s.length) {
                    val c = s[i]
                    if (c == '\\' && i + 1 < s.length) {
                        val next = s[i + 1]
                        when (next) {
                            'n' -> { sb.append('\n'); i += 2 }
                            'r' -> { sb.append('\r'); i += 2 }
                            't' -> { sb.append('\t'); i += 2 }
                            'b' -> { sb.append('\b'); i += 2 }
                            'f' -> { sb.append('\u000c'); i += 2 }
                            '"' -> { sb.append('"'); i += 2 }
                            '\\' -> { sb.append('\\'); i += 2 }
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
                val marker = "\"$key\""
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
                        if (json[e] == '\\') e += 2 else e++
                    }
                    val v = json.substring(s, e)
                    return unescapeJson(v)
                }
                return ""
            }

            fun getNumField(key: String, from: Int): String {
                val marker = "\"$key\""
                val idx = json.indexOf(marker, from)
                if (idx == -1) return ""
                val colonIdx = json.indexOf(':', idx)
                if (colonIdx == -1) return ""
                var st = colonIdx + 1
                while (st < json.length && json[st].isWhitespace()) st++
                var e = st
                while (e < json.length && json[e] != ',' && json[e] != '}' && json[e] != '\n') e++
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
            val detMarker = "\"deterministic_features\""
            val detIdx = json.indexOf(detMarker, idIdx)
            val detStart = json.indexOf('[', detIdx) + 1
            val detEnd = json.indexOf(']', detStart)
            val detTokens = json.substring(detStart, detEnd).split(',')
            val detFeatures = FloatArray(detTokens.size)
            for (i in 0 until detTokens.size) {
                detFeatures[i] = detTokens[i].trim().toFloat()
            }

            // Probabilities
            val pMarker = "\"probabilities\""
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