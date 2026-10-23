package com.sentinel.messages

/**
 * Production Android / JVM Messages Scanner (Sentinel-ML Champion V2).
 * Complete self-contained pipeline from raw text -> 2070 features -> 309 trees -> adjudication.
 */
class MessageScanner(
    private val tfidf: DualTfidfVectorizer,
    private val scaler: FeatureScaler,
    private val evaluator: MultiClassTreeEvaluator,
    private val adjudicator: MessageAdjudicator
) {
    fun assembleFeatureVector(rawText: String, senderHeader: String? = null): DoubleArray {
        // 1. 70 deterministic features
        val det = MessageFeatureExtractor.extractDeterministicFeatures(rawText, senderHeader)
        
        // 2. 1500 word tfidf
        val word = tfidf.transformWord(rawText)
        
        // 3. 500 char tfidf
        val char = tfidf.transformChar(rawText)
        
        // 4. Concatenate: [xd(70), xw(1500), xc(500)] = 2070
        val rawVector = DoubleArray(2070)
        System.arraycopy(det, 0, rawVector, 0, 70)
        System.arraycopy(word, 0, rawVector, 70, 1500)
        System.arraycopy(char, 0, rawVector, 1570, 500)
        
        // 5. Standard scale
        return scaler.transform(rawVector)
    }

    val contextualAdjudicator: ContextualAdjudicator = ContextualAdjudicator(adjudicator.threshold)

    fun scan(rawText: String, senderHeader: String? = null): MessageScanResult {
        val scaledVector = assembleFeatureVector(rawText, senderHeader)
        val probabilities = evaluator.predictProba(scaledVector)
        return adjudicator.adjudicate(probabilities)
    }

    fun scanWithContext(
        rawText: String,
        senderHeader: String? = null,
        contactProvider: ContactStatusProvider? = null,
        trustStore: SenderTrustStore? = null,
        conversationProvider: ConversationContextProvider? = null,
        systemClassifier: SystemNotificationClassifier? = null,
        conversationId: String? = null,
        packageName: String? = null,
        notificationTitle: String? = null
    ): ContextualDecision {
        val stage1 = scan(rawText, senderHeader)
        return contextualAdjudicator.adjudicate(
            rawText = rawText,
            senderHeader = senderHeader,
            stage1Result = stage1,
            contactProvider = contactProvider,
            trustStore = trustStore,
            conversationProvider = conversationProvider,
            systemClassifier = systemClassifier,
            conversationId = conversationId,
            packageName = packageName,
            notificationTitle = notificationTitle
        )
    }

    companion object {
        fun create(
            wordJson: String,
            charJson: String,
            scalerJson: String,
            treesJson: String,
            threshold: Float = 0.704f
        ): MessageScanner {
            val (wVocab, wIdf, stopWords) = MessageAssetLoader.loadWordTfidf(wordJson)
            val (cVocab, cIdf) = MessageAssetLoader.loadCharTfidf(charJson)
            val (mean, scale) = MessageAssetLoader.loadScaler(scalerJson)
            val (basePred, binThresh, trees3D, nClasses, nIters) = MessageAssetLoader.loadTrees(treesJson)

            val tfidf = DualTfidfVectorizer(wVocab, wIdf, stopWords, cVocab, cIdf)
            val scaler = FeatureScaler(2070, mean, scale)
            val evaluator = MultiClassTreeEvaluator(nClasses, nIters, basePred, binThresh, trees3D)
            val adjudicator = MessageAdjudicator(threshold)

            return MessageScanner(tfidf, scaler, evaluator, adjudicator)
        }
    }
}
