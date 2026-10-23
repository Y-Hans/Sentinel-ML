package com.sentinel.url

import java.io.InputStream
import java.nio.charset.StandardCharsets

data class UrlScanResult(
    val label: String,
    val probability: Float,
    val isMalicious: Boolean,
    val rawProbability: Float,
    val isSafeBrandGated: Boolean
)

/**
 * Production Android / JVM URL Scanner (Supporting Sentinel-ML V7 and V8).
 * Fully self-contained with zero external ML dependencies.
 */
class UrlScanner(
    private val evaluator: HistGbmTreeEvaluator,
    private val adjudicatorV7: SafeDomainAdjudicator? = null,
    private val adjudicatorV8: V8RelationalAdjudicator? = null
) {
    // Secondary constructor for backward compatibility with V7
    constructor(evaluator: HistGbmTreeEvaluator, adjudicator: SafeDomainAdjudicator) :
        this(evaluator, adjudicatorV7 = adjudicator, adjudicatorV8 = null)

    // Secondary constructor for V8
    constructor(evaluator: HistGbmTreeEvaluator, adjudicator: V8RelationalAdjudicator) :
        this(evaluator, adjudicatorV7 = null, adjudicatorV8 = adjudicator)

    fun scan(url: String): UrlScanResult {
        val features = UrlFeatureExtractor.extractFeatures(url)
        val rawProba = evaluator.predictProba(features)
        return if (adjudicatorV8 != null) {
            adjudicatorV8.adjudicate(url, features, rawProba)
        } else {
            adjudicatorV7!!.adjudicate(features, rawProba)
        }
    }

    fun extractFeatures(url: String): FloatArray {
        return UrlFeatureExtractor.extractFeatures(url)
    }

    companion object {
        fun fromJson(jsonStr: String): UrlScanner {
            val parser = SimpleJsonParser(jsonStr)
            val nTrees = parser.getInt("n_trees")
            val baseScore = parser.getDouble("base_score")
            val decisionThreshold = parser.getDouble("decision_threshold").toFloat()
            val confBound = parser.getDouble("conf_bound").toFloat()

            val binThreshArray = parser.getFloatArray2D("bin_thresholds")
            val rawTrees = parser.getTrees3D("trees")

            val evaluator = HistGbmTreeEvaluator(
                nTrees = nTrees,
                baseScore = baseScore,
                binThresholds = binThreshArray,
                trees = rawTrees
            )

            // Detect version
            val isV8 = jsonStr.contains("\"version\":\"8.")

            return if (isV8) {
                val adjudicator = V8RelationalAdjudicator(
                    decisionThreshold = decisionThreshold,
                    confBound = confBound
                )
                UrlScanner(evaluator, adjudicator)
            } else {
                val adjudicator = SafeDomainAdjudicator(
                    decisionThreshold = decisionThreshold,
                    confBound = confBound
                )
                UrlScanner(evaluator, adjudicator)
            }
        }

        fun fromInputStream(stream: InputStream): UrlScanner {
            val text = stream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
            return fromJson(text)
        }
    }
}
