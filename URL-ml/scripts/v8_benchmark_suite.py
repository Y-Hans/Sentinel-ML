"""V8 Multi-Slice Dedicated Benchmark Suite.

Constructs explicit evaluation categories and matched-pair benchmarks:
1. BENCHMARK_LEGITIMATE_SITES:
   - chessigma.com, crazygames.io, codenames.game, youtube.com, youtu.be, github.com (short, long, commit, PR, issue, blob, raw, search), stackoverflow.com, docs.python.org, wikipedia.org, etc.
2. BENCHMARK_LONG_URL_PAIRS:
   - Matched pairs: short benign vs long benign, short malicious vs long malicious, short GitHub vs long GitHub.
3. BENCHMARK_TRUSTED_PARENT_ATTACKS:
   - Legitimate platform + malware (.exe, .bat, .apk, .vbs)
   - Legitimate platform + open redirect
   - Legitimate platform + credential harvesting
   - Legitimate platform + encoded payload
4. BENCHMARK_PARENT_IMPERSONATION:
   - Lookalike, subdomain trick, and punycode attacks (github.com.evil.example, evil-github.example, youtube-auth.example, etc.)
5. BENCHMARK_FINANCIAL_PAYMENT:
   - Legitimate banking vs banking phishing / OTP traps / KYC traps
6. BENCHMARK_UNKNOWN_DOMAINS:
   - Unseen benign domains and unseen malicious domains.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkItem:
    url: str
    expected_label: int  # 0 = Benign, 1 = Malicious
    category: str
    description: str


def get_all_benchmark_slices() -> dict[str, list[BenchmarkItem]]:
    slices: dict[str, list[BenchmarkItem]] = {}

    # =========================================================================
    # SLICE 1: LEGITIMATE PROBLEMATIC SITES (Reported False Positives)
    # =========================================================================
    legit_items = [
        # Gaming / Minigames / Chess
        BenchmarkItem("https://chessigma.com", 0, "legit_problem", "Chessigma homepage"),
        BenchmarkItem("https://chessigma.com/analysis", 0, "legit_problem", "Chessigma analysis board"),
        BenchmarkItem("https://chessigma.com/study/french-defense-advanced", 0, "legit_problem", "Chessigma study guide"),
        BenchmarkItem("https://crazygames.io", 0, "legit_problem", "CrazyGames homepage"),
        BenchmarkItem("https://www.crazygames.io/game/space-waves", 0, "legit_problem", "CrazyGames game space-waves"),
        BenchmarkItem("https://www.crazygames.io/game/bullet-force-multiplayer", 0, "legit_problem", "CrazyGames game bullet force"),
        BenchmarkItem("https://codenames.game", 0, "legit_problem", "Codenames online homepage"),
        BenchmarkItem("https://codenames.game/room/apple-banana-cherry", 0, "legit_problem", "Codenames game room"),
        BenchmarkItem("https://codenames.game/room/secret-agent-room-4829", 0, "legit_problem", "Codenames game room with numbers"),

        # YouTube / youtu.be
        BenchmarkItem("https://www.youtube.com/watch?v=dQw4w9WgXcQ", 0, "legit_problem", "YouTube standard video watch"),
        BenchmarkItem("https://youtu.be/dQw4w9WgXcQ", 0, "legit_problem", "YouTu.be short link"),
        BenchmarkItem("https://www.youtube.com/results?search_query=machine+learning+tutorial+for+beginners", 0, "legit_problem", "YouTube query search"),
        BenchmarkItem("https://www.youtube.com/shorts/3x8GiftClaimNow", 0, "legit_problem", "YouTube shorts video"),
        BenchmarkItem("https://www.youtube.com/@Veritasium/videos", 0, "legit_problem", "YouTube channel video list"),

        # GitHub (Short, Medium, Long, Deep Paths, Commits, PRs, Raw)
        BenchmarkItem("https://github.com", 0, "legit_github", "GitHub homepage"),
        BenchmarkItem("https://github.com/torvalds/linux", 0, "legit_github", "GitHub torvalds/linux repo"),
        BenchmarkItem("https://github.com/thealoneprogrammer/diabetic-retinopathy", 0, "legit_github", "GitHub real-device chat repo 1"),
        BenchmarkItem("https://github.com/rsk97/Diabetic-Retinopathy-Detection", 0, "legit_github", "GitHub real-device chat repo 2"),
        BenchmarkItem("https://github.com/24pandeo-rbu/Explainable-AI-for-Diabetic-Retinopathy-Screening-in-Rural-India", 0, "legit_github", "GitHub long repo name (flagged in V7)"),
        BenchmarkItem("https://github.com/kandulapoojitharani-ai/Ai-for-Diabetic-Retinopathy-Screening-in-Rural-India", 0, "legit_github", "GitHub long repo name 2"),
        BenchmarkItem("https://github.com/torvalds/linux/commit/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", 0, "legit_github", "GitHub commit with 40-char SHA (flagged in V7)"),
        BenchmarkItem("https://github.com/torvalds/linux/pull/123", 0, "legit_github", "GitHub pull request"),
        BenchmarkItem("https://github.com/torvalds/linux/issues/456", 0, "legit_github", "GitHub issue tracker"),
        BenchmarkItem("https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/intel/e1000/e1000_main.c", 0, "legit_github", "GitHub deep nested code blob (flagged in V7)"),
        BenchmarkItem("https://raw.githubusercontent.com/torvalds/linux/master/README", 0, "legit_github", "GitHub raw user content README"),
        BenchmarkItem("https://github.com/search?q=repo%3Atorvalds%2Flinux+e1000+fix+buffer+overflow&type=code", 0, "legit_github", "GitHub complex code search query"),
        BenchmarkItem("https://github.com/tensorflow/tensorflow/releases/tag/v2.16.1", 0, "legit_github", "GitHub official release tag"),

        # Developer / Docs / Media
        BenchmarkItem("https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array", 0, "legit_dev", "StackOverflow long question with slug (flagged in V7)"),
        BenchmarkItem("https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit", 0, "legit_dev", "Python documentation with anchor"),
        BenchmarkItem("https://en.wikipedia.org/wiki/Machine_learning", 0, "legit_media", "Wikipedia article"),
        BenchmarkItem("https://arxiv.org/abs/1706.03762", 0, "legit_dev", "ArXiv research paper"),
        BenchmarkItem("https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview", 0, "legit_dev", "MDN web docs deep path"),
    ]
    slices["legitimate_sites"] = legit_items

    # =========================================================================
    # SLICE 2: LONG URL MATCHED PAIRS (Demonstrating Long != Malicious)
    # =========================================================================
    long_url_pairs = [
        # Pair 1: Benign Short vs Benign Long
        BenchmarkItem("https://github.com/torvalds/linux", 0, "long_url_pair", "Short benign GitHub"),
        BenchmarkItem("https://github.com/torvalds/linux/tree/master/arch/x86/include/asm/special_insns.h", 0, "long_url_pair", "Long benign GitHub deep path"),

        # Pair 2: Benign Short Query vs Benign Long Query
        BenchmarkItem("https://www.google.com/search?q=weather", 0, "long_url_pair", "Short benign query"),
        BenchmarkItem("https://www.google.com/search?q=how+to+configure+hist+gradient+boosting+classifier+in+scikit+learn+python+tutorial&client=firefox-b-d&sca_esv=59821&source=hp", 0, "long_url_pair", "Very long benign query"),

        # Pair 3: Malicious Short vs Malicious Long
        BenchmarkItem("http://182.92.12.4/login.php", 1, "long_url_pair", "Short malicious IP phishing"),
        BenchmarkItem("http://182.92.12.4/auth/session/update_card_info.php?user_token=9a8b7c6d5e4f3a2b1c0d&redirect=https://evil.ru/steal.php&action=verify_otp_immediate_account_unblock", 1, "long_url_pair", "Long malicious query/path attack"),

        # Pair 4: Benign Long Game URL vs Malicious Long Game Impersonation
        BenchmarkItem("https://www.crazygames.io/game/super-liquid-soccer-multiplayer-tournament-edition", 0, "long_url_pair", "Long benign gaming URL"),
        BenchmarkItem("http://crazygames.io.free-robux-giveaway.xyz/claim/giftcard?token=482910482910482910&user=target&ref=telegram_group_scam", 1, "long_url_pair", "Long malicious gaming phishing attack"),
    ]
    slices["long_url_pairs"] = long_url_pairs

    # =========================================================================
    # SLICE 3: TRUSTED-PARENT ATTACKS (Mandatory Security Gate: Zero Bypass)
    # =========================================================================
    trusted_parent_attacks = [
        # GitHub hosting malicious executable / script
        BenchmarkItem("https://github.com/malicious-actor/payload/releases/download/v1.0/trojan_installer.exe", 1, "trusted_parent_attack", "GitHub hosting .exe trojan"),
        BenchmarkItem("https://github.com/phisher-user/tools/raw/main/reverse_shell.sh", 1, "trusted_parent_attack", "GitHub hosting .sh exploit script"),
        BenchmarkItem("https://github.com/exploit-drop/kit/raw/main/stealer_payload.bat", 1, "trusted_parent_attack", "GitHub hosting .bat payload"),
        BenchmarkItem("https://raw.githubusercontent.com/scammer/rat/main/discord_token_grabber.py", 1, "trusted_parent_attack", "Raw GitHub hosting token stealer"),

        # YouTube / Media hosting open redirect / phishing redirection
        BenchmarkItem("https://www.youtube.com/redirect?q=https%3A%2F%2Fevil-credential-harvester.top%2Flogin.php", 1, "trusted_parent_attack", "YouTube open redirect parameter to phishing site"),
        BenchmarkItem("https://youtu.be/redirect?target=http://crypto-airdrop-giveaway.xyz/claim", 1, "trusted_parent_attack", "YouTu.be open redirect to crypto scam"),

        # Major platforms hosting malicious credential harvesting
        BenchmarkItem("https://sites.google.com/view/sbi-yono-kyc-verification-update/login", 1, "trusted_parent_attack", "Google Sites hosting banking phishing"),
        BenchmarkItem("https://storage.googleapis.com/malware-bucket-982/ransomware_decryptor.scr", 1, "trusted_parent_attack", "Google Cloud Storage hosting .scr malware"),
        BenchmarkItem("https://docs.google.com/forms/d/e/1FAIpQLSc98/viewform?usp=pp_url&entry.123=enter_your_bank_password_and_otp", 1, "trusted_parent_attack", "Google Forms credential harvesting attack"),
    ]
    slices["trusted_parent_attacks"] = trusted_parent_attacks

    # =========================================================================
    # SLICE 4: PARENT IMPERSONATION & TYPOSQUATTING (Zero Transfer of Prior)
    # =========================================================================
    parent_impersonation = [
        # Subdomain / Lookalike tricks
        BenchmarkItem("https://github.com.evil.example/login", 1, "parent_impersonation", "Subdomain trick simulating github.com"),
        BenchmarkItem("https://github.com.account-recovery.xyz/reset-password", 1, "parent_impersonation", "Subdomain trick on suspicious TLD"),
        BenchmarkItem("https://youtube.com.evil.example/watch?v=dQw4w9WgXcQ", 1, "parent_impersonation", "Subdomain trick simulating youtube.com"),
        BenchmarkItem("https://evil-github.com/login", 1, "parent_impersonation", "Hyphenated prefix brand impersonation"),
        BenchmarkItem("https://youtube-auth.example/verify", 1, "parent_impersonation", "Hyphenated suffix brand impersonation"),
        BenchmarkItem("https://google-security-alert.net/login.php", 1, "parent_impersonation", "Brand impersonation security trap"),
        BenchmarkItem("https://chase-bank-online-verification.com/auth", 1, "parent_impersonation", "Bank brand impersonation"),
        BenchmarkItem("https://paypal-confirm-identity.xyz/security", 1, "parent_impersonation", "PayPal brand impersonation on .xyz"),
        BenchmarkItem("https://xn--gthub-1qa.com/login", 1, "parent_impersonation", "Punycode lookalike homoglyph for github"),
    ]
    slices["parent_impersonation"] = parent_impersonation

    # =========================================================================
    # SLICE 5: FINANCIAL / PAYMENT PROTECTION (Strict Security Floor)
    # =========================================================================
    financial_protection = [
        # Legitimate banking portals (Must be BENIGN)
        BenchmarkItem("https://www.chase.com", 0, "financial_banking", "Chase homepage"),
        BenchmarkItem("https://secure.chase.com/web/auth/#/logon/logon/chaseOnline", 0, "financial_banking", "Chase legitimate portal"),
        BenchmarkItem("https://www.bankofamerica.com", 0, "financial_banking", "Bank of America homepage"),
        BenchmarkItem("https://www.paypal.com/signin", 0, "financial_banking", "PayPal legitimate signin"),
        BenchmarkItem("https://stripe.com/docs/api", 0, "financial_banking", "Stripe developer documentation"),

        # Financial phishing / OTP traps / KYC traps (MUST BE DETECTED 100%)
        BenchmarkItem("https://secure-login.bankofamerica.com.account-verify.xyz/auth/login.html", 1, "financial_banking", "Bank of America fake KYC verify on .xyz"),
        BenchmarkItem("https://chase.com.fake-login.xyz/verify-otp", 1, "financial_banking", "Chase fake OTP verification"),
        BenchmarkItem("https://paypal.com-account-restricted.support/verify_card.php", 1, "financial_banking", "PayPal account restricted scam"),
        BenchmarkItem("https://userver.net52.cc/login.php?ref=sbi_secure", 1, "financial_banking", "SBI phishing attack (sentinel.db)"),
        BenchmarkItem("https://userver.net52.cc/verify_kyc_pan.html", 1, "financial_banking", "PAN/KYC phishing attack (sentinel.db)"),
        BenchmarkItem("https://userver.net52.cc/update_account_info", 1, "financial_banking", "Account update phishing attack (sentinel.db)"),
    ]
    slices["financial_protection"] = financial_protection

    # =========================================================================
    # SLICE 6: UNKNOWN DOMAINS (Neutral Prior: Benign remains Benign, Threats caught)
    # =========================================================================
    unknown_domains = [
        # Unseen legitimate personal/regional websites (Must NOT be flagged merely for being unknown)
        BenchmarkItem("https://karan-sharma-portfolio.dev/projects", 0, "unknown_domains", "Unseen developer portfolio on .dev"),
        BenchmarkItem("https://local-artisan-bakery.co.nz/menu", 0, "unknown_domains", "Unseen regional business website"),
        BenchmarkItem("https://my-family-genealogy.org/records", 0, "unknown_domains", "Unseen community genealogy site"),
        BenchmarkItem("https://greenfield-gardening-tips.net/spring-flowers", 0, "unknown_domains", "Unseen hobbyist blog"),

        # Unseen malicious attacks on unknown domains (Must be detected normally)
        BenchmarkItem("http://83.149.98.112/malware_update.exe", 1, "unknown_domains", "Unknown IP direct malware download"),
        BenchmarkItem("http://unknown-domain-482.xyz/login.php?user=admin&token=8471&redirect=http://stealer.ru", 1, "unknown_domains", "Unknown domain with credentials and open redirect"),
        BenchmarkItem("http://security-check-account-unblock.top/verify_otp.html", 1, "unknown_domains", "Unknown domain with suspicious TLD and OTP attack"),
    ]
    slices["unknown_domains"] = unknown_domains

    return slices
