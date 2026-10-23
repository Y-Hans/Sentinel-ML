# Simulation design and freeze


Date: October 22, 2026 (Asia/Calcutta). Scope: analysis, frozen-model inference and development design only.

Evidence labels: **OBSERVED** = computed or inspected in this run; **REPORTED** = historical/user claim not established here; **ASSUMED** = scenario/design choice; **PROVISIONAL** = inference conditional on unreviewed labels, authored cases or salvage. Observing a stored label is not observing its correctness. Null/NA means not estimable, never zero errors. No candidate training, model/calibrator fitting, model export, promotion, frozen-threshold change, Kotlin/Gradle/Android execution or Git mutation was performed.

## Stream contract

**OBSERVED:** the authoritative freeze is `freeze_manifest_v2.json`; its hashes were committed before reproduction/scoring. Earlier `freeze_manifest.json` remains immutable but its URL overlap tags are superseded. No rows were removed for overlap. New byte recovery is the primary natural source; the 294-row historical replay is a separately identified REPORTED source. The older recovered 562 file was used only for recovery comparison, not silently substituted as newly recovered data.

| Track | Rows | Label status counts | Overlap flagged | SHA-256 |
| --- | --- | --- | --- | --- |
| messages | 1005 | {"NEEDS_REVIEW": 117, "PROVISIONAL_BENIGN_UNREVIEWED": 708, "SYNTHETIC_AUTHORED": 180} | 28 | e1fe47c1d48720c94e74dfb28284dac809592a2d715b6ab500375ce00f6dc5d2 |
| urls | 102 | {"NEEDS_REVIEW": 84, "SYNTHETIC_AUTHORED": 16, "SYNTHETIC_UNRESOLVED": 2} | 66 | 4ee7b9b2ae48e8172a0a91149895a5218a59dfc42a755a734b578579e6503318 |

**OBSERVED:** Messages contains 825 natural/reported replay events and 180 authored events. The authored events are 45 distinct texts (nine language variants of five families) repeated over SMS, WhatsApp 1:1, WhatsApp group and other-app metadata. This repetition tests input routing coverage; it does not create 180 independent linguistic examples. The two authored attack families are callback-only utility fraud and OTP coercion; benign families are chat, OTP secrecy notices and campus/exam circulars. English, Romanized Hinglish, Hindi, Gujarati, Tamil, Telugu, Bengali, Marathi and Punjabi are explicitly authored; automatic language/script tags on natural material remain inferred, with Hindi/Marathi unresolved when only the script is known. Native translations have not been independently reviewed.

**OBSERVED:** URLs include extracted natural links plus authored explicit HTTP/HTTPS, schemeless www, bare apex, protocol-relative, repository deep paths, search queries, regional government/utility/payment domains, shorteners, IPs and popular-host payload/redirect/credential lures. Natural extracted URLs are NEEDS_REVIEW, not labeled benign from their host name. Shortener and illustrative IP destination cases remain unresolved. Payload labels are authored attack intent, not externally verified malware. Popularity is CURATED_FAMILIAR_ASSUMED for selected authored hosts, otherwise UNKNOWN; no current popularity ranking was available or invented.

## Assumptions and weighting

**ASSUMED:** evaluate attack prevalence .1% for low-frequency ambient exposure, 1% for elevated exposure and 5% for campaign stress. These are sensitivity scenarios, not measured deployment rates. Message workload 300 notification events/day, URL workload 30 scans/day; sensitivity workloads are 100/1,000 messages and 10/100 URLs. Daily values scale linearly with volume. Separate tracks cannot be summed into unique alerts without event linkage, deduplication and the exact Android runtime.

**PROVISIONAL:** no stream has a validated natural attack prevalence. Natural rows lack independently reviewed attack labels; authored balanced/attack-enriched cases are diagnostics only. `transported_projection` combines provisionally benign natural Messages FPR with authored attack recall under an explicit class-conditional transport assumption. URL deployment PPV cannot be estimated from its unlabeled natural stream; its displayed PPV scenarios are authored-case stress projections only. No 50/50 sample proportion is presented as deployment prevalence.

**ASSUMED formulas:** false alerts per 1,000 benign = 1000 f; PPV(p)=p r/[p r+(1−p)f]; false alerts/user/day=V(1−p)f; total alerts/day=V[(1−p)f+pr]. r is any-alert recall unless explicitly marked malicious-class recall. Commercial-spam prevalence needs a third term in future deployment estimation. The current natural-label rule screens out sensitive/non-Latin material, so its FPR has selection bias and cannot represent all notifications.

## Overlap and grouping

**OBSERVED:** every simulation row is tagged against 21 Messages training JSONL files using Unicode NFKC/casefold, URL/digit masking, punctuation tokenization, normalized equality and exhaustive token-set Jaccard≥.85 after safe token-length filtering. Corpus paths/hashes and matched source lists are in the freeze and per-row evidence. URL comparison preserves URL content (NFKC/casefold/strip) for exact matching, word-token Jaccard≥.85 and PSL registrable-domain equality. The offline PSL hash and eight URL source CSV hashes are frozen. URL source comparison is a conservative superset including historical holdouts where exact fit lineage is incomplete; a flag means possible exposure, not proof every model trained on that URL. Unflagged does not establish semantic independence or complete historical source closure.

**OBSERVED:** messages use channel/sender grouping, with unknown metadata explicit; authored translations and channel repeats share scenario-family clusters. URLs group by PSL registrable domain. Natural thread IDs are unavailable; inferred group indicators are not ground truth. Metrics are reported all/without-overlap/overlap-only, and by channel, 1:1/group/unknown, language/script, attack family, URL form, domain, popularity, label status and pull. Natural identical templates across different senders can remain correlated: the sender bootstrap does not eliminate this limitation.

## Sealed exam

| Path | Rows | SHA-256 | Reserved sender/channel groups | New authored cases |
| --- | --- | --- | --- | --- |
| SEALED_EXAM_DO_NOT_SCORE.jsonl | 208 | 5d5194a78d5d782ade9cba0addd461f74c475a6b24ea68394ce1685b6ecabe39 | 25 | 24 |

**OBSERVED:** the exam was created before inference. No model, metric, threshold-sensitivity analysis or gate calculation reads its rows. Hash checks read its bytes only. Entire sender/channel groups were reserved using seed 20261022; separately authored exam families were added using unrecorded random identifiers. The review sheet was generated before reservation and includes real rows for human review; it is not a secrecy boundary.

**PROVISIONAL limitation:** this is a sealed-for-this-pass holdout, not a fully independent final certification exam: the author knows the grammar, no separate custodian exists, recovery/labels are provisional, and no exhaustive semantic-family isolation of real exam rows is certified. Do not use it for final release claims. Before future training, assign an independent custodian to validate/regenerate a fresh exam from unexposed source families, with two native reviewers, domain/template/source grouping and an immutable hash commitment. Do not inspect this exam to choose new features/gates. The present plan uses only simulation/reproduction results.

## Statistical contract

**OBSERVED:** `analyze.py` uses seed 20261022 and 2,000 cluster-bootstrap replicates per summary/segment cell, resampling whole sender/scenario/domain clusters and recomputing FPR/recall jointly; 95% percentile intervals are propagated to PPV and daily burden. Undefined replicates/cells yield null. All 988 segment cells are flagged not decision-grade because at least one class or its independent-cluster support is below 30. Synthetic attacks span two message families and five URL domains; narrow/degenerate bootstrap intervals cannot establish population certainty. Zero-FP cells include one-sided independent-row and independent-cluster bounds with assumptions stated. A zero-event bootstrap interval [0,0] or resulting PPV [1,1] is not proof of zero FPR or perfect deployment precision.

**OBSERVED:** reliability curves are ten fixed-bin tables, ECE/Brier are reported unweighted and under each assumed prevalence; these are diagnostic scores, not deployment calibration certificates. Threshold sensitivity is diagnostic only; stored model thresholds and artifacts remain unchanged. The 500 hard-benign URLs were not scored or used to set gates. The 174 golden records were read for comparison-only parity after models loaded, with no tuning to their outcomes.
