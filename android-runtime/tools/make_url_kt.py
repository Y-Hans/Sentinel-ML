# Write URL Kotlin sources
from pathlib import Path

SRC = Path('android-runtime/url/src/main/kotlin/com/sentinel/url')
SRC.mkdir(parents=True, exist_ok=True)

# 1. SimpleJsonParser.kt
(SRC / 'SimpleJsonParser.kt').write_text('''package com.sentinel.url

/**
 * Lightweight, zero-dependency streaming JSON parser tailored for model bundles.
 * Avoids adding heavy external JSON libraries (Gson/Jackson/Moshi) to Android assets.
 */
class SimpleJsonParser(val json: String) {

    fun getInt(key: String): Int {
        val marker = "\\"$key\\":"
        val idx = json.indexOf(marker)
        if (idx == -1) throw IllegalArgumentException("Key not found: $key")
        val start = idx + marker.length
        var end = start
        while (end < json.length && (json[end].isDigit() || json[end] == '-')) end++
        return json.substring(start, end).trim().toInt()
    }

    fun getDouble(key: String): Double {
        val marker = "\\"$key\\":"
        val idx = json.indexOf(marker)
        if (idx == -1) throw IllegalArgumentException("Key not found: $key")
        val start = idx + marker.length
        var end = start
        while (end < json.length && (json[end].isDigit() || json[end] == '-' || json[end] == '.' || json[end] == 'e' || json[end] == 'E' || json[end] == '+')) end++
        return json.substring(start, end).trim().toDouble()
    }

    fun getFloatArray2D(key: String): Array<FloatArray> {
        val marker = "\\"$key\\":["
        val idx = json.indexOf(marker)
        if (idx == -1) throw IllegalArgumentException("Key not found: $key")
        var pos = idx + marker.length

        val result = mutableListOf<FloatArray>()
        while (pos < json.length && json[pos] != ']') {
            if (json[pos] == '[') {
                pos++
                val innerStart = pos
                while (pos < json.length && json[pos] != ']') pos++
                val innerStr = json.substring(innerStart, pos).trim()
                if (innerStr.isEmpty()) {
                    result.add(FloatArray(0))
                } else {
                    val tokens = innerStr.split(',')
                    val arr = FloatArray(tokens.size)
                    for (t in 0 until tokens.size) {
                        arr[t] = tokens[t].trim().toFloat()
                    }
                    result.add(arr)
                }
                pos++ // skip ']'
            } else {
                pos++
            }
        }
        return result.toTypedArray()
    }

    fun getTrees3D(key: String): Array<Array<HistGbmTreeEvaluator.Node>> {
        val marker = "\\"$key\\":["
        val idx = json.indexOf(marker)
        if (idx == -1) throw IllegalArgumentException("Key not found: $key")
        var pos = idx + marker.length

        val allTrees = mutableListOf<Array<HistGbmTreeEvaluator.Node>>()

        while (pos < json.length && json[pos] != ']') {
            if (json[pos] == '[') {
                // Start of a tree
                pos++
                val treeNodes = mutableListOf<HistGbmTreeEvaluator.Node>()
                while (pos < json.length && json[pos] != ']') {
                    if (json[pos] == '[') {
                        // Start of a node: [feature_idx, bin_threshold, left, right, value, is_leaf, missing_go_to_left]
                        pos++
                        val nodeStart = pos
                        while (pos < json.length && json[pos] != ']') pos++
                        val nodeStr = json.substring(nodeStart, pos)
                        val parts = nodeStr.split(',')
                        val f = parts[0].trim().toInt()
                        val th = parts[1].trim().toInt()
                        val l = parts[2].trim().toInt()
                        val r = parts[3].trim().toInt()
                        val v = parts[4].trim().toDouble()
                        val leaf = parts[5].trim().toInt() == 1
                        val ml = parts[6].trim().toInt() == 1

                        treeNodes.add(
                            HistGbmTreeEvaluator.Node(
                                featureIdx = f,
                                binThreshold = th,
                                left = l,
                                right = r,
                                value = v,
                                isLeaf = leaf,
                                missingGoToLeft = ml
                            )
                        )
                        pos++ // skip ']'
                    } else {
                        pos++
                    }
                }
                allTrees.add(treeNodes.toTypedArray())
                pos++ // skip ']' of tree
            } else {
                pos++
            }
        }
        return allTrees.toTypedArray()
    }
}
''', encoding='utf-8')
print('Wrote SimpleJsonParser.kt')

# 2. HistGbmTreeEvaluator.kt
(SRC / 'HistGbmTreeEvaluator.kt').write_text('''package com.sentinel.url

import java.util.Arrays
import kotlin.math.exp

/**
 * Portable Native Tree Traversal Engine for HistGradientBoosting models.
 * Evaluates binary classification trees with left-sided quantile binning.
 */
class HistGbmTreeEvaluator(
    val nTrees: Int,
    val baseScore: Double,
    val binThresholds: Array<FloatArray>,
    val trees: Array<Array<Node>>
) {
    data class Node(
        val featureIdx: Int,
        val binThreshold: Int,
        val left: Int,
        val right: Int,
        val value: Double,
        val isLeaf: Boolean,
        val missingGoToLeft: Boolean
    )

    /**
     * Map continuous features to discrete uint8 bins via searchsorted (side='left').
     */
    fun binFeatures(features: FloatArray, outBins: IntArray) {
        val n = features.size
        for (j in 0 until n) {
            val thresholds = binThresholds[j]
            val v = features[j]
            if (thresholds.isEmpty()) {
                outBins[j] = 0
                continue
            }
            var idx = Arrays.binarySearch(thresholds, v)
            if (idx >= 0) {
                while (idx > 0 && thresholds[idx - 1] == v) {
                    idx--
                }
                outBins[j] = idx
            } else {
                outBins[j] = -idx - 1
            }
        }
    }

    /**
     * Predict raw margin score across all trees.
     */
    fun predictRawMargin(features: FloatArray): Double {
        val binned = IntArray(features.size)
        binFeatures(features, binned)

        var margin = baseScore
        for (treeIdx in 0 until nTrees) {
            val treeNodes = trees[treeIdx]
            var nodeIdx = 0
            while (true) {
                val node = treeNodes[nodeIdx]
                if (node.isLeaf) {
                    margin += node.value
                    break
                }
                val binVal = binned[node.featureIdx]
                if (binVal <= node.binThreshold) {
                    nodeIdx = node.left
                } else {
                    nodeIdx = node.right
                }
            }
        }
        return margin
    }

    /**
     * Predict calibrated probability via logistic sigmoid.
     */
    fun predictProba(features: FloatArray): Float {
        val margin = predictRawMargin(features)
        val p = 1.0 / (1.0 + exp(-margin))
        return p.toFloat()
    }
}
''', encoding='utf-8')
print('Wrote HistGbmTreeEvaluator.kt')

# 3. SafeDomainAdjudicator.kt
(SRC / 'SafeDomainAdjudicator.kt').write_text('''package com.sentinel.url

/**
 * Safe-Domain Gated Adjudication for URL-ML V7.
 */
class SafeDomainAdjudicator(
    val decisionThreshold: Float = 0.22588723f,
    val confBound: Float = 0.80f
) {
    // Feature indices in the 67-feature vector
    val idxSafeBrand = 60
    val idxBrandImp = 0
    val idxSuspTld = 63
    val idxIsIp = 14
    val idxSuspExt = 28
    val idxRedirect = 38
    val idxPathWords = 29
    val idxQueryWords = 39
    val idxDoubleEnc = 23
    val idxAt = 2
    val idxSubdomain = 18
    val idxPuny = 11
    val idxPort = 5
    val idxSlashes = 20
    val idxNonAscii = 4
    val idxNestedUrl = 3

    fun adjudicate(features: FloatArray, rawProba: Float): UrlScanResult {
        val hasThreat = (
            features[idxBrandImp] > 0.0f ||
            features[idxSuspTld] > 0.0f ||
            features[idxIsIp] > 0.0f ||
            features[idxSuspExt] > 0.0f ||
            features[idxRedirect] > 0.0f ||
            features[idxPathWords] > 0.0f ||
            features[idxQueryWords] > 0.0f ||
            features[idxDoubleEnc] > 0.0f ||
            features[idxAt] > 0.0f ||
            features[idxPuny] > 0.0f ||
            features[idxPort] > 0.0f ||
            features[idxSlashes] > 0.0f ||
            features[idxNonAscii] > 0.0f ||
            features[idxNestedUrl] > 0.0f ||
            features[idxSubdomain] >= 2.0f
        )

        val isSafeBrand = (features[idxSafeBrand] == 1.0f) && (!hasThreat)
        var pFinal = rawProba
        val isGated = isSafeBrand && (rawProba < confBound)
        if (isGated) {
            pFinal = 0.001f
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
''', encoding='utf-8')
print('Wrote SafeDomainAdjudicator.kt')

# 4. UrlScanner.kt
(SRC / 'UrlScanner.kt').write_text('''package com.sentinel.url

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
 * Production Android / JVM URL Scanner (Sentinel-ML V7 Champion).
 * Fully self-contained with zero external ML dependencies.
 */
class UrlScanner(
    private val evaluator: HistGbmTreeEvaluator,
    private val adjudicator: SafeDomainAdjudicator
) {
    fun scan(url: String): UrlScanResult {
        val features = UrlFeatureExtractor.extractFeatures(url)
        val rawProba = evaluator.predictProba(features)
        return adjudicator.adjudicate(features, rawProba)
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
            val adjudicator = SafeDomainAdjudicator(
                decisionThreshold = decisionThreshold,
                confBound = confBound
            )
            return UrlScanner(evaluator, adjudicator)
        }

        fun fromInputStream(stream: InputStream): UrlScanner {
            val text = stream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
            return fromJson(text)
        }
    }
}
''', encoding='utf-8')
print('Wrote UrlScanner.kt')

# 5. UrlFeatureExtractor.kt
(SRC / 'UrlFeatureExtractor.kt').write_text(r'''package com.sentinel.url

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.regex.Pattern
import kotlin.math.abs
import kotlin.math.log2
import kotlin.math.max
import kotlin.math.min

object UrlFeatureExtractor {

    val SUSPICIOUS_WORDS = arrayOf(
        "login", "signin", "verify", "verification", "secure", "account",
        "password", "credential", "wallet", "update", "unlock", "billing",
        "checkout", "confirm", "session", "token", "recover", "authenticate",
        "banking", "oauth", "security", "support-desk", "helpdesk"
    )

    val SUSPICIOUS_TLDS = setOf(
        "biz", "buzz", "cf", "click", "country", "download", "ga", "gq",
        "info", "loan", "ml", "online", "rest", "review", "ru", "stream",
        "support", "tk", "top", "work", "xyz", "fit", "surf", "racing",
        "cam", "kim", "mom", "icu", "sbs", "cfd", "monster", "bar",
        "vip", "pw", "cc", "ws"
    )

    val COMMON_BRANDS = setOf(
        "google", "apple", "microsoft", "amazon", "meta", "facebook", "instagram", "whatsapp",
        "twitter", "x", "linkedin", "tiktok", "snapchat", "telegram", "discord", "reddit",
        "spotify", "netflix", "youtube", "twitch", "vimeo", "hulu", "disney", "pinterest", "tumblr",
        "github", "gitlab", "bitbucket", "stackoverflow", "docker", "kubernetes", "npm", "pypi", "npmjs",
        "adobe", "dropbox", "box", "slack", "zoom", "salesforce", "oracle", "ibm", "cisco", "atlassian", "trello",
        "nvidia", "intel", "amd", "qualcomm", "samsung", "sony", "cloudflare", "fastly", "akamai",
        "aws", "azure", "digitalocean", "linode", "heroku", "vercel", "netlify", "notion", "figma",
        "mozilla", "blogger", "epicgames", "wordpress", "arstechnica", "canva", "medium", "substack",
        "paypal", "stripe", "square", "shopify", "chase", "wellsfargo", "bankofamerica", "citibank",
        "capitalone", "barclays", "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard",
        "americanexpress", "discover", "mastercard", "visa", "binance", "coinbase", "kraken",
        "metamask", "gemini", "crypto", "blockchain",
        "ebay", "etsy", "walmart", "target", "costco", "bestbuy", "homedepot", "ikea", "nike",
        "adidas", "starbucks", "mcdonalds", "subway", "uber", "lyft", "airbnb", "booking",
        "expedia", "tripadvisor", "marriott", "hilton", "delta", "united", "americanairlines",
        "fedex", "ups", "usps", "dhl", "doordash", "grubhub", "instacart", "steam", "steamcommunity",
        "bbc", "cnn", "nytimes", "wsj", "washingtonpost", "forbes", "bloomberg", "reuters",
        "theguardian", "huffpost", "techcrunch", "theverge", "wired", "npr", "pbs",
        "att", "verizon", "tmobile", "vodafone", "orange",
        "wikipedia", "wikimedia", "archive", "coursera", "edx", "udemy", "khanacademy",
        "quora", "mit", "stanford", "harvard", "berkeley", "oxford", "cambridge",
        "cdc", "who", "nih", "nasa", "un", "europa", "gov", "irs", "usa", "uk"
    )

    val TWO_LABEL_SUFFIXES = setOf(
        "ac.in", "ac.jp", "ac.uk", "co.in", "co.jp", "co.nz", "co.uk",
        "com.au", "com.br", "com.cn", "com.mx", "com.sg", "gov.in", "gov.uk",
        "net.au", "net.in", "org.au", "org.in", "org.uk", "edu.au", "edu.cn",
        "gob.es", "gob.mx", "gc.ca", "gouv.fr", "fed.us", "edu.in", "res.in"
    )

    val SUSPICIOUS_EXTENSIONS = arrayOf(
        ".exe", ".scr", ".zip", ".apk", ".vbs", ".bat", ".cmd",
        ".pif", ".hta", ".iso", ".php", ".jsp", ".cgi", ".sh", ".bin"
    )

    private val RE_HEX_8 = Pattern.compile("[0-9a-fA-F]{8,}")
    private val RE_HEX_16 = Pattern.compile("[0-9a-fA-F]{16,}")
    private val RE_PERCENT_ENC = Pattern.compile("%[0-9a-fA-F]{2}")
    private val RE_REDIRECT = Pattern.compile("(?:url|next|redirect|target|dest|return|r|link|uri)=(?:https?%3A%2F%2F|https?://)", Pattern.CASE_INSENSITIVE)
    private val RE_ALPHANUM_ONLY = Pattern.compile("[^a-z0-9]")
    private val RE_SPLIT_NON_ALPHANUM = Pattern.compile("[^a-z0-9]+")

    private fun translateLeet(s: String): String {
        val sb = java.lang.StringBuilder(s.length)
        for (i in 0 until s.length) {
            val c = s[i]
            when (c) {
                '0' -> sb.append('o')
                '1' -> sb.append('l')
                '3' -> sb.append('e')
                '4' -> sb.append('a')
                '5' -> sb.append('s')
                '7' -> sb.append('t')
                '@' -> sb.append('a')
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    data class ParsedUrl(
        val raw: String,
        val scheme: String,
        val host: String,
        val port: Int?,
        val path: String,
        val query: String
    )

    fun parseUrl(url: String): ParsedUrl {
        val raw = url.trim()
        var scheme = "http"
        var host = ""
        var port: Int? = null
        var path = ""
        var query = ""

        try {
            var work = raw
            if (work.startsWith("//")) {
                work = "http:$work"
            } else if (!work.contains("://")) {
                work = "http://$work"
            }

            val schemeEnd = work.indexOf("://")
            if (schemeEnd != -1) {
                val foundScheme = work.substring(0, schemeEnd).lowercase()
                if (raw.contains("://")) {
                    scheme = foundScheme
                }
                work = work.substring(schemeEnd + 3)
            }

            val slashIdx = work.indexOf('/')
            val qIdx = work.indexOf('?')
            val hashIdx = work.indexOf('#')

            var endAuthority = work.length
            if (slashIdx != -1) endAuthority = min(endAuthority, slashIdx)
            if (qIdx != -1) endAuthority = min(endAuthority, qIdx)
            if (hashIdx != -1) endAuthority = min(endAuthority, hashIdx)

            val authority = work.substring(0, endAuthority)
            val remainder = work.substring(endAuthority)

            val atIdx = authority.lastIndexOf('@')
            val hostPort = if (atIdx != -1) authority.substring(atIdx + 1) else authority

            if (hostPort.startsWith("[") && hostPort.contains("]")) {
                val closeBracket = hostPort.indexOf(']')
                host = hostPort.substring(1, closeBracket).lowercase()
                val portPart = hostPort.substring(closeBracket + 1)
                if (portPart.startsWith(":")) {
                    port = portPart.substring(1).toIntOrNull()
                }
            } else if (hostPort.contains(":")) {
                val colon = hostPort.lastIndexOf(':')
                host = hostPort.substring(0, colon).lowercase().trimEnd('.')
                port = hostPort.substring(colon + 1).toIntOrNull()
            } else {
                host = hostPort.lowercase().trimEnd('.')
            }

            val qInRem = remainder.indexOf('?')
            val hashInRem = remainder.indexOf('#')

            if (qInRem != -1) {
                path = remainder.substring(0, qInRem)
                val qEnd = if (hashInRem != -1 && hashInRem > qInRem) hashInRem else remainder.length
                query = remainder.substring(qInRem + 1, qEnd)
            } else if (hashInRem != -1) {
                path = remainder.substring(0, hashInRem)
            } else {
                path = remainder
            }
        } catch (e: Exception) {
            host = ""
            path = ""
            query = ""
        }

        return ParsedUrl(raw, scheme, host, port, path, query)
    }

    private fun isIp(host: String): Boolean {
        if (host.isEmpty()) return false
        return isIpv4(host) || isIpv6(host)
    }

    private fun isIpv4(host: String): Boolean {
        if (host.isEmpty()) return false
        val parts = host.split('.')
        if (parts.size != 4) return false
        for (p in parts) {
            val num = p.toIntOrNull() ?: return false
            if (num !in 0..255) return false
            if (p.length > 1 && p.startsWith('0')) return false
        }
        return true
    }

    private fun isIpv6(host: String): Boolean {
        if (host.isEmpty()) return false
        return host.contains(':')
    }

    private fun suffixSize(labels: List<String>): Int {
        if (labels.size >= 2) {
            val two = labels[labels.size - 2] + "." + labels[labels.size - 1]
            if (two in TWO_LABEL_SUFFIXES) return 2
        }
        return 1
    }

    private fun registrableLabel(host: String): String {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.isEmpty() || isIp(host)) return host
        val sSize = suffixSize(labels)
        if (labels.size > sSize) {
            val cand = labels[labels.size - (sSize + 1)]
            if (cand == "www" && labels.size == sSize + 1) {
                return labels[labels.size - sSize]
            }
            return cand
        }
        return labels[0]
    }

    private fun subdomainDepth(host: String): Int {
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (isIp(host) || labels.size <= 1) return 0
        return max(0, labels.size - suffixSize(labels) - 1)
    }

    private fun entropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val counts = mutableMapOf<Char, Int>()
        for (i in 0 until s.length) {
            val c = s[i]
            counts[c] = (counts[c] ?: 0) + 1
        }
        val n = s.length.toDouble()
        var ent = 0.0
        for (count in counts.values) {
            val p = count.toDouble() / n
            ent -= p * log2(p)
        }
        return ent
    }

    private fun oneEditApart(left: String, right: String): Boolean {
        if (left == right) return true
        if (abs(left.length - right.length) > 1) return false
        if (left.length == right.length) {
            var diff = 0
            for (i in 0 until left.length) {
                if (left[i] != right[i]) {
                    diff++
                    if (diff > 1) return false
                }
            }
            return diff == 1
        }
        val (short, long) = if (left.length < right.length) Pair(left, right) else Pair(right, left)
        var i = 0
        var j = 0
        var diffs = 0
        while (i < short.length && j < long.length) {
            if (short[i] == long[j]) {
                i++
                j++
            } else {
                diffs++
                j++
                if (diffs > 1) return false
            }
        }
        return true
    }

    private fun brandImpersonationScore(host: String): Float {
        if (host.isEmpty() || isIp(host)) return 0.0f
        val regLabel = registrableLabel(host)
        val regClean = translateLeet(RE_ALPHANUM_ONLY.matcher(regLabel).replaceAll(""))
        if (regClean in COMMON_BRANDS) return 0.0f

        val candidates = mutableListOf<String>()
        val labels = host.split('.')
        for (label in labels) {
            val compact = translateLeet(RE_ALPHANUM_ONLY.matcher(label).replaceAll(""))
            if (compact.length >= 4) {
                candidates.add(compact)
            }
            val tokens = RE_SPLIT_NON_ALPHANUM.split(label)
            for (token in tokens) {
                val tokenClean = translateLeet(token)
                if (tokenClean.length >= 4) {
                    candidates.add(tokenClean)
                }
            }
        }

        for (cand in candidates) {
            if (cand in COMMON_BRANDS && cand != regClean) {
                return 1.0f
            }
        }

        var best = 0.0f
        for (cand in candidates) {
            for (brand in COMMON_BRANDS) {
                if (brand.length < 5 || cand.length < 5) continue
                if (brand in cand || cand in brand) {
                    val score = (min(cand.length, brand.length).toFloat()) / (max(cand.length, brand.length).toFloat())
                    if (score >= 0.80f) {
                        best = max(best, score)
                    }
                }
                if (abs(cand.length - brand.length) <= 1 && oneEditApart(cand, brand)) {
                    best = max(best, 0.85f)
                }
            }
        }
        return if (best >= 0.80f) best else 0.0f
    }

    fun extractFeatures(url: String): FloatArray {
        val parsed = parseUrl(url)
        val raw = parsed.raw
        val host = parsed.host
        val path = parsed.path
        val query = parsed.query

        val labels = host.split('.').filter { it.isNotEmpty() }
        val seg = path.split('/').filter { it.isNotEmpty() }
        val cleanPathStr = seg.joinToString("/")
        
        var decodedPath = path
        try {
            decodedPath = URLDecoder.decode(path, StandardCharsets.UTF_8.name())
        } catch (e: Exception) {}

        val rawLen = max(1, raw.length)
        val hostLen = max(1, host.length)

        val isIpVal = if (isIp(host)) 1.0f else 0.0f
        val isIpv4Val = if (isIpv4(host)) 1.0f else 0.0f

        val tld = if (host.contains('.') && isIpVal == 0.0f) host.substring(host.lastIndexOf('.') + 1) else ""
        val suspTld = if (tld in SUSPICIOUS_TLDS) 1.0f else 0.0f

        val brandImp = brandImpersonationScore(host)
        val regLabelRaw = registrableLabel(host)
        val regLabel = translateLeet(RE_ALPHANUM_ONLY.matcher(regLabelRaw).replaceAll(""))
        val knownBrand = if (regLabel in COMMON_BRANDS || regLabelRaw in COMMON_BRANDS) 1.0f else 0.0f

        val subDepth = subdomainDepth(host).toFloat()
        val hostHyphens = host.count { it == '-' }.toFloat()
        val hostUnderscores = host.count { it == '_' }.toFloat()
        val hostDigits = host.count { it.isDigit() }.toFloat()
        val hostDigitRatio = hostDigits / hostLen.toFloat()
        val hostEntropy = entropy(host).toFloat()
        val hostPunycode = if (host.contains("xn--")) 1.0f else 0.0f
        val hostHexPattern = if (RE_HEX_8.matcher(host).find()) 1.0f else 0.0f

        val hostVowelsList = regLabel.filter { it.isLetter() }
        val vowelCount = hostVowelsList.count { it in "aeiou" }
        val hostVowelRatio = vowelCount.toFloat() / max(1, hostVowelsList.length).toFloat()
        val hostNumericLabels = labels.count { l -> l.all { it.isDigit() } }.toFloat()

        val isHttps = if (parsed.scheme == "https") 1.0f else 0.0f
        val hasPort = if (parsed.port != null && parsed.port !in listOf(80, 443)) 1.0f else 0.0f

        val pathLen = cleanPathStr.length.toFloat()
        val pathDepth = seg.size.toFloat()
        val pathConsecutiveSlashes = countOccurrences(path, "//").toFloat()
        val pathTraversal = (countOccurrences(path, "..") + countOccurrences(path, "/.")).toFloat()
        val pathEntropy = if (cleanPathStr.isNotEmpty()) entropy(decodedPath).toFloat() else 0.0f
        val pathSuspExt = if (SUSPICIOUS_EXTENSIONS.any { path.lowercase().endsWith(it) }) 1.0f else 0.0f
        val pathEncodedCount = countPatternMatches(RE_PERCENT_ENC, path).toFloat()
        val pathDoubleEncoded = if (path.lowercase().contains("%25")) 1.0f else 0.0f
        val pathAtSymbol = if (path.contains('@')) 1.0f else 0.0f
        val pathDigits = cleanPathStr.count { it.isDigit() }.toFloat()
        val pathDigitRatio = pathDigits / max(1, cleanPathStr.length).toFloat()
        val pathHexHash = if (RE_HEX_16.matcher(cleanPathStr).find()) 1.0f else 0.0f

        val pathLower = cleanPathStr.lowercase()
        val pathCompact = translateLeet(RE_ALPHANUM_ONLY.matcher(pathLower).replaceAll(""))
        var pathSuspWords = 0.0f
        for (w in SUSPICIOUS_WORDS) {
            if (pathLower.contains(w) || pathCompact.contains(w)) pathSuspWords += 1.0f
        }

        val queryLen = query.length.toFloat()
        val params = if (query.isNotEmpty()) query.split('&') else emptyList()
        val queryParamCount = params.size.toFloat()
        val queryEncodedCount = countPatternMatches(RE_PERCENT_ENC, query).toFloat()
        val queryAtSymbol = if (query.contains('@')) 1.0f else 0.0f
        val queryEntropy = entropy(query).toFloat()

        val queryLower = query.lowercase()
        val queryCompact = translateLeet(RE_ALPHANUM_ONLY.matcher(queryLower).replaceAll(""))
        val queryRedirect = if (RE_REDIRECT.matcher(queryLower).find()) 1.0f else 0.0f
        var querySuspWords = 0.0f
        for (w in SUSPICIOUS_WORDS) {
            if (queryLower.contains(w) || queryCompact.contains(w)) querySuspWords += 1.0f
        }
        val queryHexHash = if (RE_HEX_16.matcher(query).find()) 1.0f else 0.0f
        var queryMaxValLen = 0
        for (p in params) {
            val parts = p.split('=', limit = 2)
            if (parts.size == 2) {
                if (parts[1].length > queryMaxValLen) queryMaxValLen = parts[1].length
            }
        }
        val queryLongVal = if (queryMaxValLen >= 64) 1.0f else 0.0f

        val hasAtSymbol = if (raw.contains('@')) 1.0f else 0.0f
        val urlCharEntropy = entropy(raw).toFloat()
        val contentPortion = host + (if (cleanPathStr.isNotEmpty()) "/$cleanPathStr" else "") + (if (query.isNotEmpty()) "?$query" else "")
        val specialCharCount = contentPortion.count { !it.isLetterOrDigit() }.toFloat()
        val specialCharRatio = specialCharCount / max(1, contentPortion.length).toFloat()
        val hasNonAscii = if (raw.any { it.code > 127 }) 1.0f else 0.0f
        val urlUpperRatio = raw.count { it.isUpperCase() }.toFloat() / rawLen.toFloat()

        val rawLower = raw.lowercase()
        val rawLowerAfter8 = if (rawLower.length > 8) rawLower.substring(8) else ""
        val hasNestedUrl = if (rawLowerAfter8.contains("http://") || rawLowerAfter8.contains("https://") || rawLower.contains("http%3a") || rawLower.contains("https%3a")) 1.0f else 0.0f

        val isSuspHost = (suspTld > 0.0f) || (brandImp > 0.0f) || (isIpVal > 0.0f) || (subDepth >= 2.0f) || (hostPunycode > 0.0f)

        val riskSuspWordSuspTld = (pathSuspWords + querySuspWords) * suspTld
        val riskSuspWordBrandImp = (pathSuspWords + querySuspWords) * brandImp
        val riskSuspWordIp = (pathSuspWords + querySuspWords) * isIpVal
        val riskSuspWordSubdomain = (pathSuspWords + querySuspWords) * (if (subDepth >= 2.0f) 1.0f else 0.0f)
        val riskBrandImpSuspTld = brandImp * suspTld
        val riskBrandImpSubdomain = brandImp * (if (subDepth >= 1.0f) 1.0f else 0.0f)
        val riskIpWithPath = isIpVal * (if (pathLen > 0.0f) 1.0f else 0.0f)
        val riskHttpBrandImp = (1.0f - isHttps) * brandImp
        val riskHttpSuspTld = (1.0f - isHttps) * suspTld
        val riskHttpSuspWords = (1.0f - isHttps) * (pathSuspWords + querySuspWords)
        val riskRedirectSuspHost = queryRedirect * (if (isSuspHost) 1.0f else 0.0f)
        val riskSuspExtSuspHost = pathSuspExt * (if (isSuspHost) 1.0f else 0.0f)

        val riskPathDigitSuspHost = pathDigitRatio * (if (isSuspHost) 1.0f else 0.0f)
        val riskPathDepthSuspHost = pathDepth * (if (isSuspHost) 1.0f else 0.0f)
        val riskPathEntropySuspHost = pathEntropy * (if (isSuspHost) 1.0f else 0.0f)

        val riskHyphenBrandImp = hostHyphens * brandImp
        val riskHyphenSuspTld = hostHyphens * suspTld
        val riskHyphenSubdomain = hostHyphens * (if (subDepth >= 2.0f) 1.0f else 0.0f)
        val riskDigitsBrandImp = hostDigitRatio * brandImp
        val riskDigitsSuspTld = hostDigitRatio * suspTld

        val safeCleanDomain = if (suspTld == 0.0f && brandImp == 0.0f && isIpVal == 0.0f && subDepth <= 1.0f && hostPunycode == 0.0f && hasPort == 0.0f && urlUpperRatio < 0.15f && hasNonAscii == 0.0f) 1.0f else 0.0f
        val safeBrandDomain = if (knownBrand == 1.0f && suspTld == 0.0f && brandImp == 0.0f && isIpVal == 0.0f && subDepth <= 1.0f && pathSuspExt == 0.0f && queryRedirect == 0.0f && hostPunycode == 0.0f && hasPort == 0.0f && urlUpperRatio < 0.15f && hasNonAscii == 0.0f && hasNestedUrl == 0.0f) 1.0f else 0.0f

        return floatArrayOf(
            brandImp,                    //  0: BrandImpersonationScore
            hostLen.toFloat(),           //  1: DomainLength
            hasAtSymbol,                 //  2: HasAtSymbol
            hasNestedUrl,                //  3: HasNestedURL
            hasNonAscii,                 //  4: HasNonAscii
            hasPort,                     //  5: HasPort
            hostDigitRatio,              //  6: HostDigitRatio
            hostEntropy,                 //  7: HostEntropy
            hostHexPattern,              //  8: HostHexPattern
            hostHyphens,                 //  9: HostHyphenCount
            hostNumericLabels,           // 10: HostNumericLabels
            hostPunycode,                // 11: HostPunycode
            hostUnderscores,             // 12: HostUnderscoreCount
            hostVowelRatio,              // 13: HostVowelRatio
            isIpVal,                     // 14: IsDomainIP
            isHttps,                     // 15: IsHTTPS
            isIpv4Val,                   // 16: IsIPv4
            knownBrand,                  // 17: KnownBrandDomain
            subDepth,                    // 18: NoOfSubDomain
            pathAtSymbol,                // 19: PathAtSymbol
            pathConsecutiveSlashes,      // 20: PathConsecutiveSlashes
            pathDepth,                   // 21: PathDepth
            pathDigitRatio,              // 22: PathDigitRatio
            pathDoubleEncoded,           // 23: PathDoubleEncoded
            pathEncodedCount,            // 24: PathEncodedCount
            pathEntropy,                 // 25: PathEntropy
            pathHexHash,                 // 26: PathHexHash
            pathLen,                     // 27: PathLength
            pathSuspExt,                 // 28: PathSuspiciousExtension
            pathSuspWords,               // 29: PathSuspiciousWords
            pathTraversal,               // 30: PathTraversalCount
            queryAtSymbol,               // 31: QueryAtSymbol
            queryEncodedCount,           // 32: QueryEncodedCount
            queryEntropy,                // 33: QueryEntropy
            queryHexHash,                // 34: QueryHexHash
            queryLen,                    // 35: QueryLength
            queryLongVal,                // 36: QueryLongValue
            queryParamCount,             // 37: QueryParamCount
            queryRedirect,               // 38: QueryRedirect
            querySuspWords,              // 39: QuerySuspiciousWords
            riskBrandImpSubdomain,       // 40: Risk_BrandImpersonation_on_Subdomain
            riskBrandImpSuspTld,         // 41: Risk_BrandImpersonation_on_SuspiciousTLD
            riskDigitsBrandImp,          // 42: Risk_Digits_with_BrandImp
            riskDigitsSuspTld,           // 43: Risk_Digits_with_SuspiciousTLD
            riskHttpBrandImp,            // 44: Risk_HTTP_with_BrandImpersonation
            riskHttpSuspTld,             // 45: Risk_HTTP_with_SuspiciousTLD
            riskHttpSuspWords,           // 46: Risk_HTTP_with_SuspiciousWords
            riskHyphenBrandImp,          // 47: Risk_Hyphen_with_BrandImp
            riskHyphenSubdomain,         // 48: Risk_Hyphen_with_Subdomain
            riskHyphenSuspTld,           // 49: Risk_Hyphen_with_SuspiciousTLD
            riskIpWithPath,              // 50: Risk_IP_with_Path
            riskPathDepthSuspHost,       // 51: Risk_PathDepth_on_SuspiciousHost
            riskPathDigitSuspHost,       // 52: Risk_PathDigit_on_SuspiciousHost
            riskPathEntropySuspHost,     // 53: Risk_PathEntropy_on_SuspiciousHost
            riskRedirectSuspHost,        // 54: Risk_Redirect_on_SuspiciousHost
            riskSuspExtSuspHost,         // 55: Risk_SuspiciousExt_on_SuspiciousHost
            riskSuspWordBrandImp,        // 56: Risk_SuspiciousWord_on_BrandImpersonation
            riskSuspWordIp,              // 57: Risk_SuspiciousWord_on_IP
            riskSuspWordSubdomain,       // 58: Risk_SuspiciousWord_on_Subdomain
            riskSuspWordSuspTld,         // 59: Risk_SuspiciousWord_on_SuspiciousTLD
            safeBrandDomain,             // 60: Safe_Brand_Domain
            safeCleanDomain,             // 61: Safe_Clean_Domain
            specialCharRatio,            // 62: SpecialCharRatio
            suspTld,                     // 63: SuspiciousTLD
            urlCharEntropy,              // 64: URLCharEntropy
            raw.length.toFloat(),        // 65: URLLength
            urlUpperRatio                // 66: URLUppercaseRatio
        )
    }

    private fun countOccurrences(s: String, sub: String): Int {
        var count = 0
        var idx = 0
        while (true) {
            val found = s.indexOf(sub, idx)
            if (found == -1) break
            count++
            idx = found + sub.length
        }
        return count
    }

    private fun countPatternMatches(p: Pattern, s: String): Int {
        val m = p.matcher(s)
        var count = 0
        while (m.find()) count++
        return count
    }
}
''', encoding='utf-8')
print('Wrote UrlFeatureExtractor.kt')
print('All URL Kotlin source files generated successfully.')

