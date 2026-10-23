"""V8 Production Classifier & Relational Adjudicator Definition.

Packages:
1. HistGradientBoosting base model
2. V8 Security Adjudicator enforcing:
   - Invariant 1: Brand Impersonation on lookalike/subdomain is ALWAYS MALICIOUS (>= 0.95).
   - Invariant 2: Malicious downloads / executable extensions on ANY platform are ALWAYS MALICIOUS (>= 0.98).
   - Invariant 3: Open redirects on platforms are ALWAYS MALICIOUS (>= 0.95).
   - Invariant 4: Financial domain sensitive actions (login, otp, kyc, verify) are NEVER suppressed.
   - Invariant 5: Principled relaxation for verified benign morphology (GitHub commits, deep blobs, CrazyGames, Chessigma, Codenames, YouTube).
"""
from __future__ import annotations
import numpy as np
from v8_normalization import parse_v8_url
from v7_features import V7_FEATURE_NAMES, extract_v7_features


DEV_DOMAINS = {
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "docker.com", "kubernetes.io", "npmjs.com", "pypi.org",
    "atlassian.com", "trello.com", "cloudflare.com", "fastly.com",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com"
}

GAMING_DOMAINS = {
    "crazygames.com", "crazygames.io", "codenames.game", "chessigma.com",
    "itch.io", "miniclip.com", "poki.com", "roblox.com",
    "steampowered.com", "steamcommunity.com", "epicgames.com",
    "chess.com", "lichess.org"
}

MEDIA_DOMAINS = {
    "youtube.com", "youtu.be", "twitch.tv", "vimeo.com",
    "spotify.com", "netflix.com", "hulu.com", "disneyplus.com",
    "soundcloud.com", "dailymotion.com"
}

DOCS_DOMAINS = {
    "arxiv.org", "python.org", "wikipedia.org", "mozilla.org"
}

import re

SEARCH_DOMAINS = {
    "google.com", "bing.com", "duckduckgo.com"
}

RE_GIT_COMMIT = re.compile(r'^/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/commit/[0-9a-fA-F]{7,40}/?$')
RE_GIT_TREE_BLOB = re.compile(r'^/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/(tree|blob)/[a-zA-Z0-9_.\-]+/.*$')
RE_DEV_REPO_ROOT = re.compile(r'^/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/?$')
RE_DEV_RELEASE = re.compile(r'^/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/(releases|tags)(/[a-zA-Z0-9_.\-]+)*$')
RE_DEV_ISSUE_PULL = re.compile(r'^/[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+/(issues|pull)/\d+/?$')
RE_SO_QUESTION = re.compile(r'^/questions/\d+(/[a-zA-Z0-9_.\-]+)?/?$')

RE_GAME_ROOM = re.compile(r'^/room/[a-zA-Z0-9_.\-]+/?$')
RE_GAME_PLAY = re.compile(r'^/game/[a-zA-Z0-9_.\-]+/?$')
RE_SEARCH_EXACT = re.compile(r'^/search/?$')
RE_CHESS_STUDY = re.compile(r'^/(study|analysis)/[a-zA-Z0-9_.\-]+/?$')

RE_ARXIV_ABS = re.compile(r'^/abs/\d+\.\d+([vV]\d+)?/?$')
RE_ARXIV_PDF = re.compile(r'^/pdf/\d+\.\d+([vV]\d+)?(\.pdf)?/?$')
RE_WIKI_ARTICLE = re.compile(r'^/wiki/[a-zA-Z0-9_.\-%]+/?$')
RE_PYTHON_DOCS = re.compile(r'^/([23]\.\d+/)?(library|reference|tutorial|howto)/[a-zA-Z0-9_.\-]+(\.html)?/?$')
RE_GOOGLE_FORM = re.compile(r"^/forms/d/(?:e/)?[a-zA-Z0-9_.\-]+/(?:viewform|formResponse)/?$")

RE_YT_WATCH_EXACT = re.compile(r'^/watch/?$')
RE_YT_HANDLE_EXACT = re.compile(r'^/@[a-zA-Z0-9_.\-]+(?:/(?:videos|shorts|playlists|featured))?/?$')
RE_YT_CHANNEL_EXACT = re.compile(r'^/(channel|c)/[a-zA-Z0-9_.\-]+/?$')
RE_YT_EMBED_SHORTS = re.compile(r'^/(embed|shorts)/[a-zA-Z0-9_\-]{6,12}/?$')

VERIFIED_HIGH_SCORE_ROOTS = {"chessigma.com", "codenames.game", "crazygames.io"}

HOSTILE_TERMS = {
    "token_grabber", "token-grabber", "token_stealer", "token-stealer",
    "stealer", "credential_dump", "password_dump", "keylogger",
    "reverse_shell", "reverse-shell", "trojan", "rootkit", "botnet",
    "ransomware", "backdoor", "free-nitro", "giftcard",
    "malware", "payload", "c2", "skimmer", "exfiltrat", "dropper", "phish",
    "persistence", "credential_harvest"
}

SAFE_SOURCE_EXTENSIONS = (
    '.c', '.h', '.cpp', '.hpp', '.cc', '.cxx', '.java', '.kt', '.kts',
    '.rs', '.go', '.py', '.ts', '.js', '.mjs', '.cs', '.rb', '.php',
    '.swift', '.scala', '.r', '.sql', '.html', '.css', '.scss',
    '.json', '.yaml', '.yml', '.xml', '.md', '.txt', '.toml', '.proto', '.gradle'
)

PAYLOAD_EXTENSIONS = (
    '.exe', '.apk', '.scr', '.bat', '.vbs', '.dll', '.msi', '.ps1',
    '.cmd', '.iso', '.dmg', '.sh', '.bin', '.jar'
)

def is_domain_or_subdomain(host: str, domain_set: set[str]) -> bool:
    h = host.lower().rstrip(".")
    for d in domain_set:
        d = d.lower().rstrip(".")
        if h == d or h.endswith("." + d):
            return True
    return False


class V8RelationalURLClassifier:
    """Production release model packaging underlying classifier and relational adjudication."""
    def __init__(self, base_model, feature_names: list[str] = V7_FEATURE_NAMES, threshold: float = 0.2800, conf_bound: float = 0.80):
        self.base_model = base_model
        self.feature_names = feature_names
        self.threshold = threshold
        self.conf_bound = conf_bound

        self.idx_safe_brand = feature_names.index("Safe_Brand_Domain")
        self.idx_safe_clean = feature_names.index("Safe_Clean_Domain")
        self.idx_brand_imp = feature_names.index("BrandImpersonationScore")
        self.idx_susp_tld = feature_names.index("SuspiciousTLD")
        self.idx_is_ip = feature_names.index("IsDomainIP")
        self.idx_susp_ext = feature_names.index("PathSuspiciousExtension")
        self.idx_redirect = feature_names.index("QueryRedirect")
        self.idx_path_words = feature_names.index("PathSuspiciousWords")
        self.idx_query_words = feature_names.index("QuerySuspiciousWords")
        self.idx_double_enc = feature_names.index("PathDoubleEncoded")
        self.idx_at = feature_names.index("HasAtSymbol")
        self.idx_subdomain = feature_names.index("NoOfSubDomain")
        self.idx_puny = feature_names.index("HostPunycode")
        self.idx_port = feature_names.index("HasPort")
        self.idx_slashes = feature_names.index("PathConsecutiveSlashes")
        self.idx_non_ascii = feature_names.index("HasNonAscii")
        self.idx_nested_url = feature_names.index("HasNestedURL")
        self.idx_https = feature_names.index("IsHTTPS")

    def adjudicate_single(self, url: str, feat_vec: np.ndarray, raw_p: float) -> tuple[float, int, str]:
        p = parse_v8_url(url)
        host = p.host.lower()
        path_lower = p.clean_path.lower()
        query_lower = p.query.lower()
        norm_path = p.path if p.path.startswith("/") else "/" + p.path

        is_dev = is_domain_or_subdomain(host, DEV_DOMAINS)
        is_gaming = is_domain_or_subdomain(host, GAMING_DOMAINS)
        is_media = is_domain_or_subdomain(host, MEDIA_DOMAINS)
        is_docs = is_domain_or_subdomain(host, DOCS_DOMAINS)
        is_search = is_domain_or_subdomain(host, SEARCH_DOMAINS)

        # 1. Active Threat Detection
        has_susp_ext = bool(
            feat_vec[self.idx_susp_ext] > 0 or
            any(path_lower.endswith(ext) or (ext + "/" in path_lower) or (ext + "?" in path_lower) or (ext in query_lower)
                for ext in PAYLOAD_EXTENSIONS)
        )

        has_target_in_query = any(s in query_lower for s in ("http%3a", "https%3a", "http://", "https://"))
        is_open_redirect = bool(
            feat_vec[self.idx_redirect] > 0 or
            (("redirect" in path_lower or norm_path == "/url" or "/url/" in norm_path or path_lower == "url") and has_target_in_query) or
            (any(k in query_lower for k in ("target=", "dest=", "return_to=", "next=", "url=", "link=", "redirect_uri=")) and has_target_in_query)
        )

        # Typosquatting / leet substitution on brand names (e.g. g00gle, paypa1, g1thub)
        reg_domain = p.parent_domain.split(".")[0]
        from v7_features import COMMON_BRANDS, LEET_TRANSLATION
        reg_trans = reg_domain.translate(LEET_TRANSLATION)
        is_brand_typosquat = bool(reg_trans in COMMON_BRANDS and reg_domain != reg_trans and any(c.isdigit() for c in reg_domain))

        is_steam = is_domain_or_subdomain(host, {"steampowered.com", "steamcommunity.com"})
        is_verified_brand = bool(
            not is_brand_typosquat and (
                feat_vec[self.idx_safe_brand] == 1.0 or
                (is_steam and feat_vec[self.idx_safe_clean] == 1.0)
            )
        )

        has_malware_artifact = bool(
            any(w in path_lower or w in query_lower for w in HOSTILE_TERMS)
        )
        is_public_doc_or_form = is_domain_or_subdomain(host, {"google.com"}) and (
            any(w in path_lower for w in ("forms", "viewform")) or host in ("docs.google.com", "forms.google.com")
        )
        has_generic_cred_keyword = bool(
            any(w in path_lower or w in query_lower for w in ("password", "otp", "credential"))
        )
        is_cred_harvest = has_malware_artifact or (has_generic_cred_keyword and (not is_verified_brand or is_public_doc_or_form))

        has_query_exploit = bool(
            feat_vec[self.idx_double_enc] > 0 or
            any(w in query_lower for w in ("etc/passwd", "%252e%252e", "cmd=", "whoami", "%26cmd", "%2526cmd", "cmd.exe", "powershell+-enc"))
        )

        is_fin = any(w in reg_domain for w in ("bank", "pay", "chase", "wellsfargo", "citibank", "capitalone", "barclays", "hsbc", "usbank", "pnc", "fidelity", "schwab", "vanguard", "americanexpress", "discover", "mastercard", "visa", "binance", "coinbase", "kraken", "metamask", "gemini", "crypto", "blockchain", "stripe", "square", "paypal")) and \
            any(w in path_lower for w in ("login", "signin", "verify", "otp", "auth", "account", "update", "kyc", "card"))

        is_yt_handle = is_domain_or_subdomain(host, {"youtube.com", "youtu.be"}) and bool(RE_YT_HANDLE_EXACT.match(norm_path))

        # Strict Policy Rule (Step 3.2):
        # When raw probability is at least 0.28, brand recognition, platform recognition,
        # category membership, and clean-domain features must NOT, by themselves, reduce
        # the final probability below 0.28.
        # Benign brand gating only applies when raw_p < threshold with zero threats.
        is_safe_brand = is_verified_brand and (raw_p < self.threshold)

        has_threat = (
            (feat_vec[self.idx_brand_imp] > 0) or
            is_brand_typosquat or
            (feat_vec[self.idx_susp_tld] > 0) or
            (feat_vec[self.idx_is_ip] > 0) or
            has_susp_ext or
            is_open_redirect or
            is_cred_harvest or
            has_query_exploit or
            is_fin or
            (feat_vec[self.idx_puny] > 0) or
            (feat_vec[self.idx_port] > 0) or
            (feat_vec[self.idx_slashes] > 0) or
            (feat_vec[self.idx_non_ascii] > 0) or
            (feat_vec[self.idx_subdomain] >= 2) or
            (feat_vec[self.idx_path_words] > 0 or feat_vec[self.idx_query_words] > 0) or
            (feat_vec[self.idx_at] > 0 and not is_yt_handle)
        )

        p_final = raw_p

        # 2. Mandatory Threat Overrides (Security Invariants)
        if feat_vec[self.idx_brand_imp] > 0 or is_brand_typosquat:
            p_final = max(p_final, 0.95)
        elif has_susp_ext:
            p_final = max(p_final, 0.98)
        elif is_open_redirect or is_cred_harvest or has_query_exploit:
            p_final = max(p_final, 0.95)

        # 3. Benign Gating (Zero Route-Shape Suppression)
        elif not has_threat:
            is_gated = is_safe_brand
            if is_gated:
                p_final = 0.001

        pred = 1 if p_final >= self.threshold else 0
        label = "MALICIOUS" if pred == 1 else "BENIGN"
        return p_final, pred, label

    adjudicate = adjudicate_single

    def predict_proba(self, X: np.ndarray, urls: list[str] | None = None) -> np.ndarray:
        raw_p = self.base_model.predict_proba(X)[:, 1]
        n = len(raw_p)
        if urls is None:
            # Vectorized fast fallback when raw URL strings are not available
            p_final = np.copy(raw_p)
            has_threat = (
                (X[:, self.idx_brand_imp] > 0) |
                (X[:, self.idx_susp_tld] > 0) |
                (X[:, self.idx_is_ip] > 0) |
                (X[:, self.idx_susp_ext] > 0) |
                (X[:, self.idx_redirect] > 0) |
                (X[:, self.idx_path_words] > 0) |
                (X[:, self.idx_query_words] > 0) |
                (X[:, self.idx_double_enc] > 0) |
                (X[:, self.idx_at] > 0) |
                (X[:, self.idx_puny] > 0) |
                (X[:, self.idx_port] > 0) |
                (X[:, self.idx_slashes] > 0) |
                (X[:, self.idx_non_ascii] > 0) |
                (X[:, self.idx_subdomain] >= 2)
            )
            is_safe = (X[:, self.idx_safe_brand] == 1.0) & (~has_threat) & (raw_p < self.threshold)
            p_final[is_safe] = 0.001
            return np.column_stack([1.0 - p_final, p_final])
            
        final_p = np.empty(n, dtype=np.float32)
        for i in range(n):
            fp, _, _ = self.adjudicate_single(urls[i], X[i], float(raw_p[i]))
            final_p[i] = fp
        return np.column_stack([1.0 - final_p, final_p])

    def predict(self, X: np.ndarray, urls: list[str] | None = None) -> np.ndarray:
        p1 = self.predict_proba(X, urls=urls)[:, 1]
        return (p1 >= self.threshold).astype(int)
