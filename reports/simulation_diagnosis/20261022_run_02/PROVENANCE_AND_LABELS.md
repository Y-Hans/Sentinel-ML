# Provenance, recovery and labels


Date: October 22, 2026 (Asia/Calcutta). Scope: analysis, frozen-model inference and development design only.

Evidence labels: **OBSERVED** = computed or inspected in this run; **REPORTED** = historical/user claim not established here; **ASSUMED** = scenario/design choice; **PROVISIONAL** = inference conditional on unreviewed labels, authored cases or salvage. Observing a stored label is not observing its correctness. Null/NA means not estimable, never zero errors. No candidate training, model/calibrator fitting, model export, promotion, frozen-threshold change, Kotlin/Gradle/Android execution or Git mutation was performed.

## Three-pull provenance

**REPORTED user mapping:** `sentinel_db` = Messages v1/URL v7; `sentinel_db(1)` and October 22 archive = Messages v2/URL v8. **REPORTED master mapping:** older 562 history = installed Messages Champion V2/URL V7; unsigned 2.1.0 = Messages V4.3/URL V8. The names “v1/v2” in the user chronology are not assumed identical to canonical model generation names.

| Pull | New candidate rows | Candidate offsets not accepted | Time min UTC | Time max UTC | Model generation |
| --- | --- | --- | --- | --- | --- |
| pull_1 | 72 | 194 | 2026-09-11T04:58:57.740000+00:00 | 2026-09-11T08:16:41.444000+00:00 | UNRESOLVED |
| pull_2 | 75 | 597 | 2026-09-04T16:20:47.303000+00:00 | 2026-09-05T18:16:00.382000+00:00 | UNRESOLVED |
| pull_3 | 568 | 9397 | 2026-10-01T17:26:29.040000+00:00 | 2026-10-21T12:39:55.489000+00:00 | UNRESOLVED |

**OBSERVED:** no explicit model-version strings were found in recovered explanations. Explanation/score patterns per pull are preserved in `provenance_followup.json`; they describe model outputs, not truth. The candidate timestamp ranges place pull_2 before pull_1, so filename order cannot prove chronological capture order. Transfer damage and missing WAL history can affect timestamps. Per-model logged/current agreement is in `logged_comparison_summary.json` and the row-level comparison file; agreement does not identify the historical installed model. All three model_generation values remain UNRESOLVED, per the authorized fallback.

| Canonical artifact (user alias mapping unresolved) | Bytes | SHA-256 |
| --- | --- | --- |
| sentinel-ml/6sep/messages/final/champion_v2_model.pkl | 1786995 | d10108f3e38e53b0c93185a2544327c7a06ed320109e6c219a5184e9bd8ca887 |
| sentinel-ml/Messages-ml/messages_v4/artifacts/messages_v4_model.pkl | 1467770 | 9b747822a941a92d278f11d0e1458c48497c14ce8c35ecf58dc72e7effaff7e0 |
| sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl | 2707591 | 2ca29457acd27bf93d6967d8f9d64778b8ba0e404030175465c802fe1a138a7d |
| sentinel-ml/URL-ml/models/v7_champion.joblib | 1649433 | d414bf668484ea5ba6056b626f0d8e674e0085208ba23d964522b09557affdaa |
| sentinel-ml/URL-ml/models/v8_champion.joblib | 709417 | 073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58 |

**OBSERVED APK listings:**

| APK | APK SHA-256 | Model asset names |
| --- | --- | --- |
| sentinel-ai/installed-sentinel.apk | 0d06c3e3ba24ae33e54eb34c9c8d0147cc99f9ed3c62b604768fe52487b6bf63 | assets/champion_v2_char_vocab_idf.json, assets/champion_v2_scaler.json, assets/champion_v2_trees.json, assets/champion_v2_word_vocab_idf.json, assets/v7_champion_portable.json |
| sentinel-ml/Messages-ml/release/apk/SentinelAI-2.1.0-release-unsigned.apk | a79f290d37ad625eef6600774a26eda2d44569e17365c7df321da32675f65398 | assets/messages_v4_3_char_vocab_idf.json, assets/messages_v4_3_scaler.json, assets/messages_v4_3_trees.json, assets/messages_v4_3_word_vocab_idf.json, assets/v8_champion_portable.json |

**OBSERVED:** installed APK packages Champion V2 and URL V7; unsigned 2.1.0 packages V4.3 and V8 assets. Each embedded asset's byte length and SHA-256 is in `recovery_provenance.json`/`provenance_followup.json`. This is package evidence, not proof which package generated a particular pull. Canonical legacy Messages V4 artifact is listed to make the unresolved “v1/m1 V4” alias explicit, not to select it by guesswork.

## Independent recovery

**OBSERVED:** original files are UTF-16LE encodings of CP437-rendered bytes. Strict reversal round-trips; original bytes were preserved under new filenames. CRLF→LF reversal restores plausible lengths but cannot distinguish original byte 0D from 0A after text transfer. New exact/standalone-header copies were opened `mode=ro&immutable=1`; SQLite schemas/counts/integrity results and exceptions are recorded in `recovery_provenance.json` and `recovery_v2.json`. All attempted SQLite paths still fail validation. Altering WAL header bytes in a NEW standalone view is explicitly recorded and did not certify data integrity.

**OBSERVED:** first conservative page scanner recovered zero because newline transformation destroys table-leaf markers/offsets. The corrected independent carver validates SQLite serialization around UUIDs, requires exactly 11 threat-record columns, SCAN_RESULT, risk enum, UTF-8 content and a plausible timestamp. It found 72+75+568=715 distinct candidate records. These are **PROVISIONAL_SALVAGE**, not 715 certified original table rows. In particular, carving an archive can retain old snapshots/WAL copies. The exact dedup key is `(id, recordType, timestamp, UTF8 content SHA-256)`; 715 candidates remain after exact dedup, zero exact duplicates. Same-ID versions remain distinct and are not silently collapsed.

**OBSERVED:** unaccepted UUID offsets are 194/597/9397 by pull, including index copies and non-record regions. They are exact candidate-offset counts, NOT numbers of lost threat records. An exact unrecoverable original-row total is **UNKNOWN**, because no trusted original table count/integrity check is available. This is a stated evidence limitation, not an unfilled implementation decision. No complete recovery or WAL checksum certificate is claimed. Recovering pristine binaries or a validated WAL solver is future ingestion work; this pass continues with the documented salvage fallback.

| REPORTED comparison source | Stored rows | Exact ID/time/content-key matches to new union | Legacy-only unique keys | New-only unique keys |
| --- | --- | --- | --- | --- |
| sentinel-ml/New_history/bench_real_history_562.jsonl | 562 | 154 | 408 | 561 |
| sentinel-ml/investigation/sentinel_db_parsed.jsonl | 34 | 0 | 7 | 715 |
| sentinel-ml/investigation/sentinel_db1_parsed.jsonl | 26 | 0 | 8 | 715 |

**OBSERVED:** row-by-row comparison files preserve ID, timestamp, content hash and match flags. The 34/26 old parsed files collapse to 7/8 unique keys and contain implausible fields; they are not trusted recovery labels. The old `.recovered.db`/`*_rows.jsonl` files were hashed as protected inputs and remain REPORTED artifacts, not independent verification. Exact source-to-new byte comparisons for each recovered database variant are in recovery metadata; original historical database files have different transformation lineage and are not substituted for raw pulls.

## Label rule and human-review search

**OBSERVED:** `adjudication_search.json` gives searched paths, source hashes, line numbers and excerpts. The master plan states that 31 non-green alerts were human reviewed, 29 natural rows judged false alarms and two synthetic links judged attacks. No `threat_records.json` or hash-linked per-record review ledger was found in the searched repository. `docs/ROOT_CAUSE_ANALYSIS.md` and `PROJECT_CONTEXT_DOSSIER.md` contain model-analysis/provenance claims, not a record-level 31-alert adjudication map. Therefore zero rows are marked ADJUDICATED in this pass; the aggregate master claim remains REPORTED.

**PROVISIONAL rule, explicitly authorized by this request:** only logged GREEN rows with no detected URL, ≥6 digit run, OTP/PIN/payment/account/bank/security keywords, or non-Latin alphabetic content become PROVISIONAL_BENIGN_UNREVIEWED with y=0. All other natural rows remain NEEDS_REVIEW and y=null. This uses GREEN only to select a low-risk provisional review stratum; it does not establish the prediction as ground truth. Emoji are not language/script ground truth. The 294 replay's stored security_label is retained as REPORTED auxiliary metadata but not promoted to human adjudication or natural attack truth. Authored cases are SYNTHETIC_AUTHORED, with author-assumed intent; unresolved authored URLs remain null.

**OBSERVED:** REVIEW_SHEET.csv contains 1,009 data rows (715 independent salvage candidates +294 historical replay rows), with requested columns, original logged predictions, rule-based status and blank reviewer_label/reviewer_note. It includes reserved real exam rows for independent human labeling; exclude model scores and gate decisions from that review. No source row or label was overwritten. The primary simulation has 708 provisional-benign, 117 NEEDS_REVIEW and 180 authored message rows; URL simulation has 84 NEEDS_REVIEW, 16 authored labeled and two authored unresolved URLs. Sensitive/non-Latin rows therefore lack natural accuracy estimates; published natural FPR is selection-biased. Every metric is stratified by label_status and overlap; NEEDS_REVIEW contributes alert counts and logged comparisons only.

**ASSUMED next review procedure:** two independent reviewers blind to present model predictions label each row BENIGN/COMMERCIAL_SPAM/ACTIVE_ATTACK/INSUFFICIENT_CONTEXT and add a rationale/provenance. A third resolves disagreements; native-speaker review is mandatory for each script. Keep a new review-ledger filename rather than editing the frozen set or blank sheet in this pass. Then create a separately versioned evaluation manifest and rerun analyses without changing old results.
