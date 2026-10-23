# Feature ledger — code and CPU measurements

OBSERVED: FEATURE_LEDGER.csv enumerates all 6,089 active inputs (V2 70 + 1,500 word + 500 character; V4.3 19 + 1,500 word + 2,500 character). Each entry includes order, expression/token/IDF, group, source line, missingness behavior, regex dependence and Kotlin cost. feature_definitions.json preserves return expressions and locals; feature_regexes.json gives exact patterns. No architecture or feature was changed. Current sources/hashes are in feature_evidence.json. All source files inspected were below 1 MB; corpora were streamed.

## Executable contract, not comments

OBSERVED: V4.3 returns 19 features, despite comments saying 15 and 18. Its training-script prose says 19,070 rows; the current train_v4_3.jsonl streams 19,672. These are conflicting documentation vs current-file observations, not a claim about the original fit's exact data. The frozen pickle was loaded and reproduced; original lineage still needs its historical manifest. V2 default groups exclude NGRAM_HASH; enabling those 16 bins changes the input contract. V2 always adds 11 interaction keys; nine reference absent dictionary names and therefore equal zero by construction. Only urgency_x_legit_intent and kyc_x_sender have existing constituent keys. Kotlin explicitly mirrors the nine zeros. Do not silently repair them in a data-only run.

OBSERVED: both URL patterns are `https?://\S+|www\.\S+`, case-insensitive; phone pattern is `(?:\+91|0)?[6-9]\d{9}`. Spaces inside 90000 00NNN would fail the phone regex. V2 lexical regexes use normalized lowercase; routing patterns use raw text. NFKD/homoglyph replacement and zero-width removal occur in V2 numeric extraction, while saved TF-IDF vectorizers receive raw text. V4.3 trims text and counts format/URLs/phones; it has no explicit demand/negation detector. Its structural counts do not identify English versus Romanized Hinglish intent. Saved analyzer settings and exact tokens are in the CSV.

OBSERVED static Kotlin review: extractV43Features mostly mirrors Python, but empty text has average word length 1.0 in Kotlin versus 0.0 in Python. No Kotlin execution/parity claim is made. MessageScanner selects V4.3 only when scaler.nFeatures==4019; other sizes enter a hardcoded 2070-wide V2 branch. Increasing vocabularies or adding numeric dimensions therefore needs Kotlin dispatch/dimension changes, even with the same HGB architecture. Data-only replacement at 4019 dimensions and unchanged tokenization can use new vocab/IDF/scaler/tree assets without extractor changes; export remains unauthorized.

## Sender metadata and policy

OBSERVED: parse_sender_header captures optional DLT category -P/-G/-S but the six V2 sender features do not consume that category. Missing sender produces UNKNOWN and zero sender indicators; kyc_x_sender is also zero. For a recognized six-character entity, switching P/G/S leaves numeric features unchanged (sender_code_tests.json). The Python DLT entity pattern requires exactly six alphanumeric characters; the Android policy classifier accepts 3–8 and maps P to PROMOTIONAL, G to GOVERNMENT, S to SERVICE. Header shape and bank-name matching are contextual proxies, never sender authentication. V4.3's 19-feature path ignores sender_header entirely. Do not fabricate headers for training.

OBSERVED: MessageAdjudicator selects BENIGN below P(S)+P(M) threshold, otherwise the larger spam/malicious class. Its isThreat aliases isNonBenign. NotificationThreatAnalyzer assigns high evidence to isNonBenign, including SPAM; therefore this app path conflicts with the requested MALICIOUS-only alert policy. RiskFusionEngine has SERVICE/GOVERNMENT OTP-only dampening and a known-contact exception guarded by !isGroup and high-payload protection. Static inspection identifies the policy dependencies but does not certify the complete shipped fusion outcome. Runtime-policy fixes and Android tests need separate authorization; training alone cannot fix those branches.

PROPOSED: keep sender category as a policy enum {MISSING, UNKNOWN, SERVICE, GOVERNMENT, PROMOTIONAL, PERSONAL}, separate from the model. Header-category changes must not suppress a malicious request or high-risk payload. Test header null/blank/P/G/S and group/contact combinations on the identical text. Store true metadata only.

## Observed sender missingness

OBSERVED: table aggregates each streamed training file; duplicates across files are not independent data. Exact breakdown by file × original label × source, missing/absent key, and suffix counts is in sender_missing_by_file_label_source.csv. No claim that every listed corpus trained every model. Source strings are metadata, not validated provenance.

| File | N | Null/blank | Share | -P | -G |
| --- | --- | --- | --- | --- | --- |
| sentinel-ml/6sep/messages/candidates/train_candidate_v1.jsonl | 17511 | 11694 | 66.78% | 0 | 0 |
| sentinel-ml/6sep/messages/candidates/train_candidate_v3b.jsonl | 17384 | 11694 | 67.27% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train.jsonl | 15855 | 10188 | 64.26% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_contrastive.jsonl | 16215 | 10548 | 65.05% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded.jsonl | 16175 | 10508 | 64.96% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v2.jsonl | 16935 | 11268 | 66.54% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v3.jsonl | 16725 | 11058 | 66.12% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v4.jsonl | 17017 | 11350 | 66.70% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v4_3x.jsonl | 17181 | 11514 | 67.02% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v5.jsonl | 17361 | 11694 | 67.36% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v6.jsonl | 17629 | 11962 | 67.85% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v7.jsonl | 17541 | 11874 | 67.69% | 0 | 0 |
| sentinel-ml/Messages-ml/data/processed/train_expanded_v8.jsonl | 18311 | 12644 | 69.05% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4/data/train_v4.jsonl | 17473 | 11806 | 67.57% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4/experiment_2/data/train_v4_2.jsonl | 18601 | 12934 | 69.53% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_3/data/train_v4_3.jsonl | 19672 | 12789 | 65.01% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4.jsonl | 20164 | 13281 | 65.86% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_b.jsonl | 20257 | 13374 | 66.02% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_c.jsonl | 20404 | 13521 | 66.27% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_rc2_exp1.jsonl | 20495 | 13374 | 65.25% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_rc2_exp2.jsonl | 20543 | 13422 | 65.34% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_4/data/train_v4_4_rc2_exp3.jsonl | 20581 | 13460 | 65.40% | 0 | 0 |
| sentinel-ml/Messages-ml/messages_v4_5/experiments/next_architecture/data/auxiliary_train.jsonl | 12753 | 8695 | 68.18% | 0 | 0 |

## Held-out permutation importance

OBSERVED: historical TEST stratified sample N=588 (200 BENIGN,188 SPAM,200 MALICIOUS), seed 202610232, three permutation seeds 202610233–235. Sender=None for both models. 315 predict-only permutations; all 89 structural columns individually, TF-IDF blocks jointly, and V2 named groups. Entire column blocks use one row permutation so within-block dependencies remain. No model/calibrator/vectorizer fit. Individual TF-IDF-token permutation was not run; block scores measure combined contribution. Sample indices, frozen source hash, baselines and every repeat are saved.

PROVISIONAL interpretation: correlated blocks and shuffled impossible combinations limit causal attribution; results are sensitivity, not proof of feature necessity or independent new-test performance. Sender importance is necessarily zero in this text-only condition and cannot show that real sender metadata is useless. Means below are percentage points; negative recall drop is possible.

| Model | Feature/group | Balanced-accuracy drop | Recall drop | False-alert increase |
| --- | --- | --- | --- | --- |
| V2 | CHAR_TFIDF | 33.47 | 22.83 | 29.90 |
| V2 | ALL_STRUCTURAL | 14.33 | 0.83 | 10.91 |
| V2 | STRUCTURAL | 11.37 | 1.00 | 5.67 |
| V2 | WORD_TFIDF | 6.80 | 5.50 | 5.41 |
| V2 | FEAR_THREAT | 1.24 | -0.17 | 1.72 |
| V2 | total_fear_signals_count | 1.13 | -0.17 | 1.55 |
| V4.3 | CHAR_TFIDF | 42.92 | 37.50 | 31.53 |
| V4.3 | ALL_STRUCTURAL | 4.69 | -0.33 | 5.15 |
| V4.3 | WORD_TFIDF | 2.48 | -0.33 | 3.35 |
| V4.3 | uppercase_ratio | 1.71 | -1.17 | 2.32 |
| V4.3 | digit_ratio | 0.24 | 0.00 | 0.34 |
| V4.3 | uppercase_count | 0.00 | -0.17 | -0.17 |

## Hinglish activation and proxies

OBSERVED: 275 exact scenario pairs (150 malicious/100 benign/25 spam) compare numeric activation without fitting. Full matrix is paired_feature_activation.csv. These are generator-conditioned observations. English urgency/threat/OTP lexical patterns sometimes lose activation in Hinglish; zero script-mix on Romanized Hindi is expected and does not mean the text is English. V4.3's repaired URL/phone counts work in both languages; its absence of an explicit intent representation remains a design limitation, not proof that all structural features collapse. Numeric/casing/length/URL form are plausible channel/source proxies; high permutation effects on case ratios warrant source-held-out testing. TF-IDF can learn the author's wording or sender brand strings in body text, so vocabulary coverage must be checked on independent sources.

| V2 feature | Pairs | H nonzero | E nonzero | E active/H zero |
| --- | --- | --- | --- | --- |
| total_fear_signals_count | 275 | 34 | 44 | 11 |
| deadline_word_count | 275 | 1 | 8 | 8 |
| high_pressure_score | 275 | 2 | 9 | 8 |
| penalty_signal | 275 | 15 | 22 | 7 |
| legal_action_signal | 275 | 7 | 11 | 4 |
| otp_intent_risk_score | 275 | 0 | 4 | 4 |
| account_blocked_signal | 275 | 2 | 3 | 3 |
| has_legit_notice | 275 | 9 | 11 | 2 |
| legit_context_score | 275 | 31 | 33 | 2 |
| legit_notice_keyword_count | 275 | 9 | 11 | 2 |
| otp_disclosure_request | 275 | 0 | 2 | 2 |
| otp_negation_warning | 275 | 0 | 2 | 2 |
