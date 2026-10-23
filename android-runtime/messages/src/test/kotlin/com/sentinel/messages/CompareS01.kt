package com.sentinel.messages

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