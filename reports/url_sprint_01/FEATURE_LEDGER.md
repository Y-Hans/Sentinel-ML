# Feature ledger — OBSERVED from code
The model contract is 67 names sorted alphabetically (CSV index is the actual model order, not dictionary insertion order). FEATURE_LEDGER.csv contains each exact expression, transitive intermediate definitions, source line, group, and measured collapse/distinguish flags. A flag is an equality on the concrete pair in static_parity.json, not a universal equivalence proof. Canonicalization merges schemeless and protocol-relative forms with https; it does not remove www. Host identity is otherwise compressed into lexical counts/entropy/brand heuristics: unrelated domains can collide. Path/query identity is largely lost beyond keywords, lengths, entropy and patterns. There is no ranking, live reputation, DNS, certificate, page content or destination resolution feature.

Parse definitions: raw is canonicalized trimmed input; p is urllib.parse.urlsplit; host is lowercase hostname with trailing dots removed; seg is nonempty slash-separated raw path segments; decoded_path is one urllib.unquote. clean_path_str rejoins seg with /. raw_len/host_len are floored at one. Entropy is base-2 empirical character Shannon entropy. _registrable_label and _subdomain_depth use the fixed v7 suffix table, not a complete public suffix list. Brand matching applies alphanumeric compaction, leet normalization, candidate tokens, substring similarity >=0.8, and one-edit similarity 0.85; known registrable brands return zero impersonation. Safe brand recognition matches a label, not verified domain ownership or TLD. code_constants.json lists all literal domain/brand/suffix/extension/word registries with their source module. Helpers and exact source hashes are recorded in static_parity.json. Read the intermediate formulas with these definitions.

Adjudicator execution order (OBSERVED): parse URL; derive platform flags (dev/gaming/media/docs/search); detect extension using feature OR path/query suffix checks; redirect feature OR path/query target checks; detect leet registrable-brand typo; derive verified-brand/Steam context; hostile-artifact and public Google docs/forms context; generic password/otp/credential harvest conditional on verification; query exploit/double encoding; financial sensitive path; YouTube @handle exception; aggregate feature/threat blockers. Then (1) impersonation/leet -> max(raw,0.95); else (2) suspicious extension -> max(raw,0.98); else (3) redirect/credential/exploit -> max(raw,0.95); else (4) verified brand with raw strictly below 0.28 and no blockers -> 0.001; otherwise passthrough. Final >=0.28 alerts. Suspicious TLD/IP/punycode/financial flags block discount but do not themselves force an override. conf_bound and many platform regexes are present but unused in current decision logic. No high-score route-shape suppression executes. The no-URL Python fallback only applies below-threshold safe-brand gating and never adds the URL-string threat overrides, so its alert decisions match raw at the frozen threshold.

Python/Kotlin visible divergences (static findings, no Kotlin execution):
- Kotlin URLDecoder converts + in paths to spaces; Python unquote preserves +. Malformed escapes are caught differently. Entropy can diverge.
- Kotlin uses UTF-16 Char counts/lengths; Python counts Unicode code points. Supplementary Unicode changes length, entropy and ratios; Unicode predicates need runtime parity tests.
- Kotlin isIpv6 tests only for a colon; Python ipaddress validates the address. Malformed colon hosts can diverge. Kotlin HasPort considers port 0 nonstandard; Python bool(port_val) excludes zero.
- Kotlin SafeDomainAdjudicator translateLeet handles 0/1/3/4/5, omitting Python 7/@; Kotlin feature extractor has its own mapping.
- Kotlin featureThreat wraps the whole OR in !(HasAt && isYoutubeHandle); Python exempts only its HasAt term. Other blockers can be masked for a YouTube handle in Kotlin (mandatory explicit overrides remain separate).
- Python V8 normalization adds com.tr/github.io/gitlab.io/pages.dev/web.app to v7 suffix handling. Kotlin feature extractor parentDomain returns the registrable label using the v7 table. Python adjudicator splits the V8 full parent at the first dot. Tenant and suffix boundary contexts can differ.
- Kotlin no-URL overload calls URL adjudication with an empty string; Python no-URL overload uses a vectorized fallback without mandatory feature overrides. They are different APIs.
- Both redirect feature regexes contain uppercase %3A/%2F while matching a lowercased query: encoded branch does not match; V8 URL adjudicator may recover it via other checks. Features remain frozen.

No parity fixes are made. A feature proposal would require updating Kotlin extraction and indices, portable metadata, malformed/Unicode/encoding parity fixtures, Android runtime cost and benchmarks; it is outside this sprint. Permutation results will be supplied separately from a domain-grouped clean-test sample using raw V8 average precision; correlated feature masking limits interpretation and importance does not establish causality.

| Index | Feature | Group | Exact expression |
|---|---|---|---|
| 0 | BrandImpersonationScore | host | `float(brand_impersonation)` |
| 1 | DomainLength | host | `float(len(host))` |
| 2 | HasAtSymbol | url_scheme | `float(has_at_symbol)` |
| 3 | HasNestedURL | url_scheme | `float(has_nested_url)` |
| 4 | HasNonAscii | url_scheme | `float(has_non_ascii)` |
| 5 | HasPort | url_scheme | `float(has_port)` |
| 6 | HostDigitRatio | host | `float(host_digit_ratio)` |
| 7 | HostEntropy | host | `float(host_entropy)` |
| 8 | HostHexPattern | host | `float(host_hex_pattern)` |
| 9 | HostHyphenCount | host | `float(host_hyphens)` |
| 10 | HostNumericLabels | host | `float(host_numeric_labels)` |
| 11 | HostPunycode | host | `float(host_punycode)` |
| 12 | HostUnderscoreCount | host | `float(host_underscores)` |
| 13 | HostVowelRatio | host | `float(host_vowel_ratio)` |
| 14 | IsDomainIP | host | `float(is_ip)` |
| 15 | IsHTTPS | url_scheme | `float(is_https)` |
| 16 | IsIPv4 | host | `float(is_ipv4)` |
| 17 | KnownBrandDomain | host | `float(known_brand)` |
| 18 | NoOfSubDomain | host | `float(subdomain_depth)` |
| 19 | PathAtSymbol | path | `float(path_at_symbol)` |
| 20 | PathConsecutiveSlashes | path | `float(path_consecutive_slashes)` |
| 21 | PathDepth | path | `float(path_depth)` |
| 22 | PathDigitRatio | path | `float(path_digit_ratio)` |
| 23 | PathDoubleEncoded | path | `float(path_double_encoded)` |
| 24 | PathEncodedCount | path | `float(path_encoded_count)` |
| 25 | PathEntropy | path | `float(path_entropy)` |
| 26 | PathHexHash | path | `float(path_hex_hash)` |
| 27 | PathLength | path | `float(path_len)` |
| 28 | PathSuspiciousExtension | path | `float(path_susp_ext)` |
| 29 | PathSuspiciousWords | path | `float(path_susp_words)` |
| 30 | PathTraversalCount | path | `float(path_traversal)` |
| 31 | QueryAtSymbol | query | `float(query_at_symbol)` |
| 32 | QueryEncodedCount | query | `float(query_encoded_count)` |
| 33 | QueryEntropy | query | `float(query_entropy)` |
| 34 | QueryHexHash | query | `float(query_hex_hash)` |
| 35 | QueryLength | query | `float(query_len)` |
| 36 | QueryLongValue | query | `float(query_long_val)` |
| 37 | QueryParamCount | query | `float(query_param_count)` |
| 38 | QueryRedirect | query | `float(query_redirect)` |
| 39 | QuerySuspiciousWords | query | `float(query_susp_words)` |
| 40 | Risk_BrandImpersonation_on_Subdomain | interaction | `float(risk_brand_imp_subdomain)` |
| 41 | Risk_BrandImpersonation_on_SuspiciousTLD | interaction | `float(risk_brand_imp_susp_tld)` |
| 42 | Risk_Digits_with_BrandImp | interaction | `float(risk_digits_brand_imp)` |
| 43 | Risk_Digits_with_SuspiciousTLD | interaction | `float(risk_digits_susp_tld)` |
| 44 | Risk_HTTP_with_BrandImpersonation | interaction | `float(risk_http_brand_imp)` |
| 45 | Risk_HTTP_with_SuspiciousTLD | interaction | `float(risk_http_susp_tld)` |
| 46 | Risk_HTTP_with_SuspiciousWords | interaction | `float(risk_http_susp_words)` |
| 47 | Risk_Hyphen_with_BrandImp | interaction | `float(risk_hyphen_brand_imp)` |
| 48 | Risk_Hyphen_with_Subdomain | interaction | `float(risk_hyphen_subdomain)` |
| 49 | Risk_Hyphen_with_SuspiciousTLD | interaction | `float(risk_hyphen_susp_tld)` |
| 50 | Risk_IP_with_Path | interaction | `float(risk_ip_with_path)` |
| 51 | Risk_PathDepth_on_SuspiciousHost | interaction | `float(risk_path_depth_susp_host)` |
| 52 | Risk_PathDigit_on_SuspiciousHost | interaction | `float(risk_path_digit_susp_host)` |
| 53 | Risk_PathEntropy_on_SuspiciousHost | interaction | `float(risk_path_entropy_susp_host)` |
| 54 | Risk_Redirect_on_SuspiciousHost | interaction | `float(risk_redirect_susp_host)` |
| 55 | Risk_SuspiciousExt_on_SuspiciousHost | interaction | `float(risk_susp_ext_susp_host)` |
| 56 | Risk_SuspiciousWord_on_BrandImpersonation | interaction | `float(risk_susp_word_brand_imp)` |
| 57 | Risk_SuspiciousWord_on_IP | interaction | `float(risk_susp_word_ip)` |
| 58 | Risk_SuspiciousWord_on_Subdomain | interaction | `float(risk_susp_word_subdomain)` |
| 59 | Risk_SuspiciousWord_on_SuspiciousTLD | interaction | `float(risk_susp_word_susp_tld)` |
| 60 | Safe_Brand_Domain | safe_context | `float(safe_brand_domain)` |
| 61 | Safe_Clean_Domain | safe_context | `float(safe_clean_domain)` |
| 62 | SpecialCharRatio | url_scheme | `float(special_char_ratio)` |
| 63 | SuspiciousTLD | host | `float(susp_tld)` |
| 64 | URLCharEntropy | url_scheme | `float(url_char_entropy)` |
| 65 | URLLength | url_scheme | `float(len(raw))` |
| 66 | URLUppercaseRatio | url_scheme | `float(url_upper_ratio)` |
