# Simulation design — preflight stopped


Evidence vocabulary: **OBSERVED** = inspected/computed in this pass; **REPORTED** = earlier document or user statement, not reproduced here; **ASSUMED** = proposed design, hypothesis, or conditional calculation, not measured behavior.

**Disposition: STOPPED AT PREFLIGHT. Neither simulation nor sealed final exam was frozen. No model inference, training, calibration, threshold change, export, promotion, Android execution, or Phase 2–7 implementation occurred.** The requested zero-overlap and evidence sufficiency conditions were not met. These are blocker/conditional-design documents, not completed baseline results or an approval-ready training authorization.

## Observed evidence and stop decision

**OBSERVED:** `schema_recovery_findings.json` scans 21 Messages `train*.jsonl` files. A conservative normalized-text screen finds 9/294 legacy replay rows and 6/562 recovered-history rows matching their union. Normalization: Unicode casefold, URL masking, digit masking, whitespace collapse. Row indices and all input hashes are recorded in that JSON. These are screening collisions, not proof of contamination of every model; the union includes later training files. No individual model-to-training lineage clearance or complete domain-group audit has been established. Removing these 15 rows alone would not establish semantic/template independence.

**OBSERVED:** The 294 replay contains 291 BENIGN and 3 MALICIOUS labels, channel counts 283 WhatsApp, 7 Google Messages, 3 link intents, 1 Gmail; all 294 lack `template_cluster_id`. The recovered 562 file contains 552 WhatsApp, 8 Google Messages, 2 link intents; all 562 lack both `security_label` and `template_cluster_id`. Stored `riskLevel` and `riskScore` are previous system predictions, not truth labels. Independent reviewer provenance was not established.

**OBSERVED:** The two raw DB files and October 22 tar have UTF-16LE BOMs. Raw SQLite/tar opening fails; `sentinel_reconstructed.db` and `test_fixed.db` report malformed database images. Strict UTF-16LE→CP437 reversal round-trips in memory for all three inputs, unlike CP850/CP1252. The latest tar exposes a `databases/sentinel_db` member of 872,448 bytes, but SQLite deserialization queries return `unable to open database file`. WAL mode, text transfer damage, omitted/misaligned members, or another format issue remain hypotheses; corruption is not proven irreversible. Recovery was not certified and no extracted data was used for evaluation. See `oem_recovery_findings.json` for exact errors and derived hashes. The old investigation parsed files contain 34/26 rows with implausible channel strings and are not accepted recovered ground truth.

**REPORTED (user, this request):** first pull used Messages m1 V4 + URL V7; next two used Messages V2 + URL V8. **REPORTED (master plan §1–3):** historical 562 stream used installed V2/V7; unsigned 2.1.0 packaged V4.3/V8. These cannot be equated without a pull-to-build map. “m1 V4” identity is unresolved. Archive timestamps or the current checkout cannot prove which APK generated each scan. Capture a manifest linking raw input hash, pull timestamp, APK hash, model assets, app version, device, and dedup/snapshot lineage. APK asset identity checks alone do not prove historical installation.

## Conditional stream design — ASSUMED, not frozen

Messages dimensions: SMS, WhatsApp 1:1, WhatsApp group, other notification apps; English, Romanized Hinglish, Devanagari Hindi, Gujarati, Tamil, Telugu, Bengali, Marathi, Gurmukhi Punjabi; explicit script and code-switch flags. Include OTP/transaction alerts, ordinary chat, campus/exam circulars, commercial spam, callback-only fraud, OTP coercion, KYC/utility/parcel lures, hosted payloads. Keep spam separate from active security attacks and report both any-alert and malicious-alert endpoints. Unknown channel/group/language remains UNKNOWN, never inferred as ground truth from a sender name alone.

URLs dimensions: explicit HTTP/HTTPS, schemeless, protocol-relative, bare apex, www, deep repository paths, search queries, regional government/utility/payment sites, shorteners, IPv4/IPv6, IDN/punycode, and popular-host APK/redirect/credential lures. Store original form, parsed host, public-suffix-list registrable domain, hosting tenant where applicable, path/query family, and independently verified threat label. A login path or IP host alone is not proof of malice. Offline features cannot verify a redirect's destination or domain legitimacy by themselves.

**ASSUMED prevalence scenarios:** 0.1% low-frequency ambient exposure, 1% elevated exposure, 5% incident/campaign stress. These are sensitivity scenarios, not measured Indian-device attack rates. Use class-conditional estimates and reweight to each prevalence; never describe a balanced challenge corpus as deployment traffic. Spam and attack priors require separate estimates. Within benign/attack classes use measured channel/script/template weights only after representative denominator capture, otherwise publish sensitivity ranges rather than an invented “real” mixture.

**ASSUMED traffic scenarios:** 100, 300, 1,000 message notification events/day; 10, 30, 100 URL scan events/day. Central illustrative workloads 300 messages and 30 URLs are independent assumptions. They cannot be summed to unique user alerts without URL/message event linkage and notification deduplication. Repeated events count for alert burden but resample by user/day/template cluster for uncertainty.

## Real versus synthetic provenance — conditional construction

**REPORTED:** the master plan calls 560 of the 562 notifications natural and 2 attack fixtures synthetic; it adjudicates 29 natural non-green alerts benign. This pass observed file counts, not independent label correctness or full natural/synthetic attribution. The 294 replay has stored labels but not a verified independent review trail. Do not use logged risk as a label or infer that absence of user-reported harm means benign.

**ASSUMED construction:** use approved recovered natural streams only after recovery and independent labeling. Derive template/channel weights from deduplicated history; retain raw-event multiplicity separately. Author new scenario families using an explicit scenario grammar (actor, requested action, authenticity, urgency, URL/phone/payload presence), then independent native-speaker translation and back-review. Partition seed families and translation ancestors before generating variants. Preserve generator version, seed, author, reviewer, source license, and scenario ID. Numeric substitutions, paraphrases, and translations share a family. Synthetic rows must be marked synthetic and cannot establish natural language prevalence, FPR, or calibrated real-world PPV.

**ASSUMED overlap protocol:** build a model-specific artifact→training-file manifest for V2, V4.3, every V4.4/V4.5 variant and URL V7/V8, including augmentation and preprocessing fit sources. Validate exact bytes/text, Unicode normalization, placeholders/URLs/phones/dates, template IDs, MinHash/Jaccard candidate pairs, and human semantic-family review. URL comparison uses a versioned offline PSL, full host, registrable domain and tenant. Build connected components linking shared template, source document, translation ancestor, campaign and domain; assign entire components. Any overlap with any historical training source disqualifies an evaluation component. Report excluded counts by reason; unmatched rows are not automatically cleared. Popular domains already in training may make strict domain novelty and realistic popularity coverage incompatible: report that infeasibility and obtain a clarified evaluation design, never silently relax zero overlap.

## Freeze and sealed-exam contract

**OBSERVED:** simulation set count = 0; sealed exam set count = 0; no set hash exists. An empty file or a design hash would falsely imply a usable frozen exam, so none was created.

**ASSUMED future locations:** `sentinel-ml/Messages-ml/experiments/simulation/<new-run>/simulation.jsonl` and `sealed_final_exam.jsonl`, with corresponding URL-track paths. Exact filenames must be unused. Serialize canonical UTF-8; freeze source manifest, labels, group maps, sampling weights, schema, adjudicator version, and set SHA-256 before loading any baseline model. Freeze design changes as new versions, never overwrite. Keep sealed exam access with an independent custodian; the model developer, generator, threshold selector, and gate setter must not inspect rows, scores, or aggregate outcomes until models, calibration, thresholds and gates are final. No exam seed is published to developers. Hash commitment alone is not access control. The 500 hard-benign URLs and 174 golden fixtures remain comparison references only, never synthetic seeds or gate-tuning data.

## Missing evidence required to continue

1. Validated recovery with DB/WAL consistency, record counts, field validity and source-to-recovered lineage for each pull, or a clean binary export.
2. Hash-linked pull-to-APK/model mapping, resolving “m1 V4” and V2/V7 versus V2/V8 claims.
3. Independent record labels and provenance, including spam semantics and disagreement resolution.
4. Complete historical training manifests and cleared template/domain components with sufficient script/channel support.
5. Representative denominators and traffic sampling, or explicit agreement that the resulting study is conditional stress testing.
6. Independently held, unexposed final-exam material and custodial access policy.

**ASSUMED:** until these are supplied/validated, stop before freeze and inference. No provisional set should acquire “frozen” or “sealed” status.
