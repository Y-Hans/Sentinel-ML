package com.sentinel.url

/**
 * V8 Relational Adjudicator for Sentinel-ML Champion V8.
 *
 * Implements non-negotiable security invariants:
 * 1. Brand Impersonation on lookalike/subdomain is ALWAYS MALICIOUS (>= 0.95).
 * 2. Malicious downloads / executable extensions on ANY platform are ALWAYS MALICIOUS (>= 0.98).
 * 3. Open redirects on platforms are ALWAYS MALICIOUS (>= 0.95).
 * 4. Financial domain sensitive actions (login, otp, kyc, verify) are NEVER suppressed.
 * 5. Principled relaxation for verified benign morphology (GitHub commits, deep blobs, CrazyGames, Chessigma, Codenames, YouTube).
 */
class V8RelationalAdjudicator(
    val decisionThreshold: Float = 0.2800f,
    val confBound: Float = 0.80f
) {
    // Feature indices in the 67-feature vector
    val idxBrandImp = 0
    val idxDomainLength = 1
    val idxAt = 2
    val idxNestedUrl = 3
    val idxNonAscii = 4
    val idxPort = 5
    val idxPuny = 11
    val idxIsIp = 14
    val idxSubdomain = 18
    val idxSlashes = 20
    val idxPathDepth = 21
    val idxDoubleEnc = 23
    val idxPathHexHash = 26
    val idxPathLength = 27
    val idxSuspExt = 28
    val idxPathWords = 29
    val idxRedirect = 38
    val idxQueryWords = 39
    val idxSafeBrand = 60
    val idxSafeClean = 61
    val idxSuspTld = 63

    private val FINANCIAL_KEYWORDS = arrayOf(
        "bank", "pay", "chase", "wellsfargo", "citibank", "capitalone", "barclays",
        "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard", "americanexpress",
        "discover", "mastercard", "visa", "binance", "coinbase", "kraken", "metamask",
        "gemini", "crypto", "blockchain", "stripe", "square", "paypal"
    )

    private val DEV_PLATFORMS = arrayOf(
        "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
        "githubusercontent.com", "npmjs.com", "pypi.org"
    )

    private val MEDIA_PLATFORMS = arrayOf(
        "youtube.com", "youtu.be", "vimeo.com", "twitch.tv", "spotify.com"
    )

    private val GAMING_PLATFORMS = arrayOf(
        "chessigma.com", "crazygames.io", "codenames.game", "itch.io", "miniclip.com", "poki.com"
    )

    fun extractParent(host: String): String {
        if (host.isEmpty()) return ""
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size <= 1) return host
        val sSize = if (labels.size >= 2 && UrlFeatureExtractor.TWO_LABEL_SUFFIXES.contains(labels[labels.size - 2] + "." + labels[labels.size - 1])) 2 else 1
        if (labels.size > sSize) {
            val cand = labels.subList(labels.size - (sSize + 1), labels.size).joinToString(".")
            return cand
        }
        return labels.joinToString(".")
    }

    fun adjudicate(url: String, features: FloatArray, rawProba: Float): UrlScanResult {
        val parsed = UrlFeatureExtractor.parseUrl(url)
        val host = parsed.host
        val parent = extractParent(host)
        val pathLower = parsed.path.lowercase()
        val queryLower = parsed.query.lowercase()

        val isDev = DEV_PLATFORMS.any { parent.contains(it) || it == parent }
        val isMedia = MEDIA_PLATFORMS.any { parent.contains(it) || it == parent }
        val isGaming = GAMING_PLATFORMS.any { parent.contains(it) || it == parent }
        val isFin = FINANCIAL_KEYWORDS.any { parent.contains(it) }

        // 1. Executables and malicious binary payloads on any platform
        val suspiciousExts = arrayOf(".exe", ".apk", ".scr", ".bat", ".vbs", ".dll", ".msi", ".ps1", ".cmd", ".iso", ".dmg")
        val hasSuspExt = features[idxSuspExt] > 0.0f || suspiciousExts.any { ext ->
            pathLower.endsWith(ext) || pathLower.contains("$ext/") || pathLower.contains("$ext?") || queryLower.contains(ext)
        }

        // 2. Open redirect detection
        val redirectParams = arrayOf("target=", "dest=", "return_to=", "next=", "url=", "link=", "redirect_uri=")
        val redirectSchemes = arrayOf("http%3a", "https%3a", "http://", "https://")
        val isOpenRedirect = (
            features[idxRedirect] > 0.0f ||
            (pathLower.contains("redirect") && redirectSchemes.any { queryLower.contains(it) }) ||
            (redirectParams.any { queryLower.contains(it) } && redirectSchemes.any { queryLower.contains(it) })
        )

        // 3. Credential harvesting and stealers
        val credKeywords = arrayOf(
            "password", "otp", "credential", "token_grabber", "stealer",
            "token_stealer", "credential_dump", "password_dump", "keylogger"
        )
        val isCredHarvest = credKeywords.any { queryLower.contains(it) || pathLower.contains(it) }

        // 4. Typosquatting / leetspeak substitutions on brand names (e.g. g00gle, paypa1, g1thub)
        val regDomain = parent.split('.').firstOrNull() ?: ""
        val regTrans = regDomain.map { c ->
            when (c) {
                '0' -> 'o'
                '1' -> 'l'
                '3' -> 'e'
                '4' -> 'a'
                '5' -> 's'
                '7' -> 't'
                '@' -> 'a'
                '$' -> 's'
                else -> c
            }
        }.joinToString("")
        val isBrandTyposquat = UrlFeatureExtractor.COMMON_BRANDS.contains(regTrans) && regDomain != regTrans && regDomain.any { it.isDigit() }

        // 5. Query-based command injection or traversal exploits
        val hasQueryExploit = features[idxDoubleEnc] > 0.0f ||
            arrayOf("etc/passwd", "%252e%252e", "cmd=", "whoami", "%26cmd", "%2526cmd").any { queryLower.contains(it) }

        // 6. Baseline threat indicators
        var hasThreat = (
            features[idxBrandImp] > 0.0f ||
            isBrandTyposquat ||
            features[idxSuspTld] > 0.0f ||
            features[idxIsIp] > 0.0f ||
            hasSuspExt ||
            isOpenRedirect ||
            isCredHarvest ||
            hasQueryExploit ||
            features[idxPuny] > 0.0f ||
            features[idxPort] > 0.0f ||
            features[idxSlashes] > 0.0f ||
            features[idxNonAscii] > 0.0f ||
            features[idxNestedUrl] > 0.0f ||
            features[idxSubdomain] >= 2.0f
        )

        // Handle '@' symbol: YouTube @handle is channel syntax, not credential embedding
        if (features[idxAt] > 0.0f) {
            if (!( (parent == "youtube.com" || parent == "youtu.be") && parsed.path.startsWith("/@") )) {
                hasThreat = true
            }
        }

        // Suspicious keywords handling
        if (!isDev) {
            if (features[idxPathWords] > 0.0f || features[idxQueryWords] > 0.0f) {
                hasThreat = true
            }
        }

        // Special Financial Invariant: Financial parent + sensitive action is NEVER suppressed
        if (isFin) {
            if (features[idxPathWords] > 0.0f || features[idxQueryWords] > 0.0f ||
                listOf("login", "verify", "otp", "auth", "account", "update", "kyc", "card").any { pathLower.contains(it) }) {
                hasThreat = true
            }
        }

        var pFinal = rawProba
        var isGated = false

        // Mandatory Security Overrides (Floors)
        if (features[idxBrandImp] > 0.0f || isBrandTyposquat) {
            pFinal = kotlin.math.max(pFinal, 0.95f)
        } else if (hasSuspExt) {
            pFinal = kotlin.math.max(pFinal, 0.98f)
        } else if (isOpenRedirect) {
            pFinal = kotlin.math.max(pFinal, 0.95f)
        } else if (isCredHarvest) {
            pFinal = kotlin.math.max(pFinal, 0.95f)
        } else if (hasQueryExploit) {
            pFinal = kotlin.math.max(pFinal, 0.95f)
        } else if (!hasThreat) {
            // Principled Legitimate Site Relaxation
            val isSafeBrand = (features[idxSafeBrand] == 1.0f) && (rawProba < confBound)
            val isDevMorphology = isDev && (features[idxSafeBrand] == 1.0f || parent == "github.com" || parent == "gitlab.com" || parent == "stackoverflow.com") &&
                (listOf("commit", "blob", "tree", "issues", "pull", "releases", "raw", "questions", "tags", "archive").any { pathLower.contains(it) } || parsed.path.split('/').filter { it.isNotEmpty() }.size >= 2)
            val isSearchQuery = (parent == "google.com" || parent == "bing.com" || parent == "duckduckgo.com") && (pathLower.contains("search") || queryLower.contains("q=")) && !hasQueryExploit
            val isCleanGaming = (isGaming || parent == "chessigma.com" || parent == "crazygames.io" || parent == "codenames.game") && (features[idxSafeClean] == 1.0f)
            val isCleanMedia = isMedia && (features[idxSafeClean] == 1.0f)
            val isCleanDocs = (parent == "arxiv.org" || parent == "python.org" || parent == "wikipedia.org" || parent == "mozilla.org") && (features[idxSafeClean] == 1.0f)

            if (isSafeBrand || isDevMorphology || isSearchQuery || isCleanGaming || isCleanMedia || isCleanDocs) {
                pFinal = 0.001f
                isGated = true
            }
        }

        val isMalicious = pFinal >= decisionThreshold
        val label = if (isMalicious) "MALICIOUS" else "BENIGN"

        return UrlScanResult(
            label = label,
            probability = pFinal,
            isMalicious = isMalicious,
            rawProbability = rawProba,
            isSafeBrandGated = isGated
        )
    }
}
