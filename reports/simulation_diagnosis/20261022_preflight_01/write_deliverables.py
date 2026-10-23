"""Create new stop-condition reports; all file writes use exclusive creation."""
import hashlib, json, os, platform, subprocess, sys, textwrap
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]; OUT=Path(__file__).resolve().parent
def write(n,s):
    with (OUT/n).open('x',encoding='utf-8',newline='\n') as f: f.write(textwrap.dedent(s).strip()+'\n')
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def dump(n,o): write(n,json.dumps(o,ensure_ascii=False,indent=2))
findings=json.loads((OUT/'schema_recovery_findings.json').read_text(encoding='utf-8'))
before=json.loads((OUT/'hashes_before.json').read_text(encoding='utf-8'))
common='''
Evidence vocabulary: **OBSERVED** = inspected/computed in this pass; **REPORTED** = earlier document or user statement, not reproduced here; **ASSUMED** = proposed design, hypothesis, or conditional calculation, not measured behavior.

**Disposition: STOPPED AT PREFLIGHT. Neither simulation nor sealed final exam was frozen. No model inference, training, calibration, threshold change, export, promotion, Android execution, or Phase 2–7 implementation occurred.** The requested zero-overlap and evidence sufficiency conditions were not met. These are blocker/conditional-design documents, not completed baseline results or an approval-ready training authorization.
'''
write('SIMULATION_DESIGN.md', '# Simulation design — preflight stopped\n\n'+common+'''
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
''')
write('SIMULATION_BASELINE_RESULTS.md','# Simulation baseline results — NOT RUN\n\n'+common+'''
## Execution scope and availability

**OBSERVED:** model executions = 0, inference rows = 0, bootstrap replicates = 0, calibration fits = 0, threshold modifications = 0. The Part A freeze prerequisite failed. Raw and adjudicated outputs are unavailable for every row below; this means NOT MEASURED, never 0 errors or 0 recall.

| Track / baseline | OBSERVED artifact availability | Raw / adjudicated deployment results |
|---|---|---|
| Messages V2 champion | Canonical four pickles in `sentinel-ml/6sep/messages/final/`; duplicate artifact copies inventoried | NOT RUN / NOT RUN |
| Messages V4.3 Candidate-D | Four pickles in `messages_v4_3/models/candidate_d/` | NOT RUN / NOT RUN |
| Messages V4.4 | A, B, C and RC2 experiment 1/2/3 model/vectorizer/scaler artifacts present | Each variant NOT RUN / NOT RUN |
| Messages V4.5 | Ablation A/C classifiers, C HGB, structural scaler and auxiliary next-architecture artifact present; embedding dependency closure not validated | Each variant NOT RUN / NOT RUN |
| URL V7 | Joblib and portable JSON present | NOT RUN / NOT RUN |
| URL V8 raw; V8 + adjudication | Joblib, portable JSON, Python adjudicator source present | NOT RUN / NOT RUN |
| Installed Beta 2.0.1; unsigned 2.1.0 | APK files inventoried and hashed; historical pull linkage unresolved | Python model/adjudicator approximation NOT RUN; exact APK runtime requires authorization |

**OBSERVED:** alerts/1,000 benign, alerts/user/day, PPV, recall, bootstrap CIs, per-language/script/channel/group/form/popularity/family rates, reliability/ECE, threshold-sensitivity curves and worst-error rankings are all NOT ESTIMABLE from this pass. No new worst-case predictions are claimed. N=0 is not decision-grade. A reference report cannot fill these cells as OBSERVED.

## Conditional measurement specification — ASSUMED

Freeze endpoints before running: model thresholded non-benign score, raw malicious classification, adjudicated warning, adjudicated block; preserve three-class Messages probabilities and spam errors. Store raw score, final probability, label, policy branch, original/canonical URL and linkage ID. Adjudicator-mutated values need not be calibrated probabilities; assess calibration of the model separately and label policy outputs decision scores where appropriate. “As shipped” Python approximation must bind to APK asset/source identity and list unsupported metadata; Kotlin fusion/severity/Gradle or device confirmation **requires authorization**.

For attack prevalence p, sensitivity r, benign FPR f:

* false alerts/1,000 benign = 1000 f;
* PPV(p) = p r / [p r + (1-p) f]; undefined if denominator zero;
* false alerts/user/day = V(1-p)f; total alerts/day = V[(1-p)f+pr].

Use the frozen scenario weights from the design. Recall reweighting assumes class-conditional segment distribution is stable; campaign shifts violate it. Spam rates require a third term rather than relabeling spam benign or malicious opportunistically. For unique user alerts, join URL/message events and dedup before counting.

Use 2,000 stratified cluster-bootstrap replicates (seed fixed pre-run), resampling independent users/days and template/domain components, propagating f/r jointly to PPV and daily burden. Publish 95% intervals, component counts and effective sample sizes; use binomial upper bounds for zero-event cells because a bootstrap of zero cannot prove zero risk. Flag every cell with <30 labeled rows in either relevant class as not decision-grade; also reject sparse independent-component counts. Calibration: validation-fixed probability bins, weighted test reliability curves/ECE/Brier/log loss with deployment prior adjustment clearly separated from unadjusted scores. Threshold sensitivity: a predeclared diagnostic grid around existing frozen thresholds, with no chosen replacement and no held-out threshold optimization. Keep validation/test/exam roles separate.

## Reported comparison and disagreement ledger — not reproduced

| Status | Claims retained side by side | Interpretation / unresolved evidence |
|---|---|---|
| REPORTED vs REPORTED | User: first pull m1 V4/V7, next two V2/V8; master plan: historical 562 V2/V7, unsigned V4.3/V8 | Need hash-linked per-pull installation provenance; neither selected as fact |
| OBSERVED vs REPORTED | Replay union-normalized overlap 9/294; history 6/562; master §5 says 6/294 and 0/562 | Different normalization/training universes may explain discrepancy; present pass does not clear individual models |
| OBSERVED vs REPORTED | Candidate-D train file 19,672; its model-source docstring says 19,070 | Manifest and measured count agree on 19,672; docstring discrepancy retained |
| REPORTED vs REPORTED | Master §3 Candidate-D TEST recall 1510/1556, benign FPR 2/520; VAL 2222/2316 and 16/807; OOD 761/794 and 1/255 | Different populations, not interchangeable deployment estimates; no reproduction here |
| REPORTED vs REPORTED | Master §3 OOD 95.84%; V4.5 architecture report clean OOD baseline 95.72% on 747 attacks | Distinct full/clean denominators, not a numerical average |
| REPORTED vs REPORTED | V4.4 earlier system-notification FPR 0/55; final forensic audit 25/55 (45.5%) | Historical audit retracts earlier claim; neither rerun here |
| REPORTED vs REPORTED | V4.4 release says zero collisions; final audit reports 601 normalized rows / 263 keys for B and 598/261 for V4.3 | Exact-string versus normalized/template criteria; no general zero-leakage claim allowed |
| REPORTED vs REPORTED | V4.5 provenance audit says strict leakage rejected despite 307 aggressive-normalized collisions and 5 TEST near-duplicate pairs | Exact-string independence does not satisfy requested grouped-template independence |
| REPORTED vs REPORTED | Master calls source starvation primary; SECOND_FORENSIC_REPORT emphasizes TEST 90/188 and OOD 31/83 spam→malicious errors, underdocumented semantics and source skew | Different failure slices; architectural causality remains unproven |
| REPORTED vs REPORTED | Master V8 schemeless Instagram p=.982; Oct 21 integration report schemeless p=.001 after canonicalization, explicit HTTP .982 | Runtime version/input-form difference; no claim current APK reproduces old failure |
| REPORTED vs REPORTED | URL reconciliation: earlier 4248/4254=99.853%; corrected cohort 4170/4254=98.025%; qualified empty-path 681/682=99.853% | Cohort conflation reported; retain all figures with denominators |
| REPORTED vs REPORTED | URL earlier benign denominator 43,027; reconciliation 42,941 total, 42,937 unique URLs, 42,643 hosts, 40,845 domains | Fixture class accounting and unit distinctions reported |
| REPORTED vs REPORTED | Hard-benign historical draft 304/500=60.8%; reconciliation V8 419/500 raw=83.8%, 420/500 adjudicated=84% | Reference only, not replayed, not deployment FPR or gate-setting data |
| REPORTED vs REPORTED | Master parity gate N=500; integration URL parity 174/174; hard-benign N=500 | Three distinct populations; never substitute one denominator for another |
| REPORTED vs REPORTED | Master Phase 5 cold-start <15 ms; Gate 9 latency <20 ms/RAM<50 MB | Different/underdefined latency endpoints; proposed plan separates cold/warm endpoints |
| REPORTED vs REPORTED | V4.5 report calls V4.3 sole production; user says later V2/V8 | Report date/deployment state differs; release metadata required |

**REPORTED:** V4.4 final audit utility false alarms 26/55 and institutional recall 9/16 versus V4.3 12/16; V4.5 TEST recall 77.70% and FPR 3.08% versus V4.3 97.04%/0.38%. Institutional N=16 per attack cell is not decision-grade. These are earlier report claims, not measurements of the requested simulation.

**OBSERVED limitation:** comparison covers the master plan and the specific source documents in `reference_hashes.json`. It is not an exhaustive reconciliation of every historical report; that requirement remains unfinished because execution stopped. No report conflict was silently resolved by picking the favorable number.

## Commands and environment

**OBSERVED:** working directory for every command was the workspace root printed in `environment.json`; Windows PowerShell, Python executable/version/platform recorded there. Scripts use only Python standard library; `-B` prevents bytecode writes; no project module/model unpickled or imported. Exact substantive commands, counts, exit codes and input/output hashes are in `SIMULATION_RUN_EVIDENCE.md` and the adjacent JSON files. Expected SQLite/codec failures are caught and recorded as diagnostic results; the scripts themselves exited 0. No package installation or network access occurred.
''')
write('FAILURE_DIAGNOSIS.md','# Failure diagnosis — bounded by preflight\n\n'+common+'''
**OBSERVED:** this pass establishes evidence-integrity blockers, not new model failure rates. All model mechanisms below are REPORTED evidence plus ASSUMED causal hypotheses. A cluster is not proof that fresh training helps.

| Finding / classification | Evidence and examples | Mechanism hypothesis and what would disprove it | Requirement |
|---|---|---|---|
| F01 OBSERVED: evaluation provenance; DATA coverage / LABEL quality | 9/294 replay and 6/562 history normalized matches to training union; 562/562 history security labels absent; all 856 lack template IDs | Shared generic templates may inflate apparent independence; independently reviewed family lineage proving false matches would disprove those specific exclusions | R01 explicit model-specific source manifests, labels, family/domain connected components; no scores-as-labels |
| F02 OBSERVED: raw ingestion; DATA coverage | Three UTF-16 raw files; two malformed reconstructed DBs; CP437 round trip but no validated SQLite queries; 34/26 legacy parsed rows have implausible source fields | Transfer encoding/WAL state or parsing error, not a learned-model defect. Validated original binary+WAL recovery with field checks disproves ingestion blocker | R02 byte-preserving export/recovery, record-level lineage and completeness checks |
| F03 REPORTED: Indic blind spots; DATA coverage + FEATURE-representation | Master: Devanagari 68 malicious, 1 spam, 0 benign in train; 0 non-ASCII char ngrams; benign Hindi OTP p(non-benign)=.992; Gujarati callback scam .473 at .61 | Vocabulary truncation/data imbalance may remove intent evidence. Balanced native coverage + active lexical features with persistent failures weakens starvation as sufficient cause; targeted representation ablations needed | R03 script-inclusive tokenizer, per-script vocabulary coverage/negation/action tests, native benign and attack data |
| F04 REPORTED: spam/security boundary; LABEL quality + FEATURE-representation | SECOND_FORENSIC_REPORT: 90/188 TEST, 31/83 OOD spam→malicious; 20 out-of-schema types on 3817 train rows; source/class associations | Source shortcuts and inconsistent intent taxonomy; high score means a threshold-only fix is insufficient. Independent relabeling and source-held-out evaluation with no class coupling would weaken this diagnosis | R04 explicit spam/attack action taxonomy; independent reviewers; source-held-out calibration and evaluation |
| F05 REPORTED: URL form shift; FEATURE-representation + RUNTIME policy | Master `www.instagram.com` .982 vs HTTPS .001; later integration reports canonicalized schemeless .001 and explicit HTTP .982 | Parser semantics change model inputs; model error cannot be separated from canonicalization without paired forms. Matching frozen APK parser features/probabilities across forms would disprove a specific mismatch | R05 original-form indicators, canonicalization contract, Python model/adjudicator trace; Kotlin parity later requires authorization |
| F06 REPORTED: unfamiliar legitimate domains; DATA coverage + FEATURE-representation | Master IRCTC .887, Paytm .957, Tata Power billpay .871 | Training source/host-form gaps and coarse feature collisions may cause FPs. Broad representative benign novelty with no excess FPR, or matched-feature counterexamples separating classes, would weaken the claim | R06 PSL-based registrable domain, host form, lexical host/path views, novelty/abstention; measure collision pairs rather than assume more than 67 features solves it |
| F07 REPORTED: context/reputation suppression and severity; RUNTIME policy | Master group identity disables contact dampening; URL p≥.8 severity; CRITICAL fusion score≥90; later report claims fixes | Same raw score may produce different alerts. Replay identical scores/metadata through exact old and new policies to test attribution. Matching adjudication with residual raw errors disproves policy as cause of those residual errors | R07 raw/policy outcomes separately; GROUP != WHITELIST; payload overrides context; popularity is not immunity |
| F08 REPORTED: calibration / threshold | V4.3 TEST 2/520 benign FP vs VAL 16/807; 24 TEST and 17 OOD malicious→benign under .61 in second forensic | Dataset shift/operating point, but threshold effects do not explain high-confidence spam boundary. Stable class-conditional calibration across sources and languages would weaken calibration diagnosis | R08 validation-only calibration/thresholds, prior sensitivity, uncertainty and per-segment costs |
| F09 REPORTED: frozen embedding regression; ARCHITECTURE hypothesis | V4.5 TEST 77.70% vs 97.04%, benign FPR 3.08% vs .38%; utility probes improve | Frozen generic embeddings may lose character/intent cues; threshold and label confounds remain. Controlled from-scratch byte/sequence comparisons at matched data and budgets could disprove blanket sequence-model inferiority | R09 no inherited embeddings; compare sparse and small learned byte models, character and intent ablations; no architecture conclusion from probes alone |

**ASSUMED:** requirements R01–R09 trace directly to findings above. Raw false positives, spam severity errors and missed attacks require different endpoints. New representation cannot repair source/WAL corruption, wrong labels, or downstream severity overrides. A model-side score cannot establish an Android warning was displayed.

**OBSERVED limitation:** no present-pass per-cluster confusion counts or worst-error list exists. Concrete probabilities/counts in this document come from named reports as REPORTED. Natural label correctness, independent language support, complete training lineage, calibration under device traffic, and per-APK runtime attribution remain unresolved. Do not promote these hypotheses to confirmed causal findings.
''')
write('FROM_SCRATCH_TRAINING_PLAN.md','# From-scratch training plan — conditional design only\n\n'+common+'''
## Release tracks and prerequisites

**ASSUMED:** URL and Messages have independent states: EVIDENCE_BLOCKED → DATA_APPROVED → DESIGN_APPROVED → TRAINING_AUTHORIZED → EVALUATED → RELEASE_REVIEW. Both currently EVIDENCE_BLOCKED. Approval of this document's direction is not training authorization, and neither track's success releases the other. Every candidate uses a new data program, split, representation and fresh random weights; no V2/V4.3/V7/V8 warm start, fine-tuning, pretrained sentence encoder, distilled legacy predictions, patched baseline or threshold replacement. Old models are comparison baselines only. All implementation/training steps below are future work requiring an explicit later scope; none started here.

## Messages track

### Data program (R01–R04)

**ASSUMED:** source candidates are consented, byte-preserving on-device histories with app/1:1/group metadata, licensed SMS research corpora with original labels retained, native-authored scam/benign pairs, and institutional/utility transaction examples with provenance. Establish consent/license and privacy-safe handling before collection. Do not scrape private conversations or treat a sender/header as authenticated automatically. Keep natural versus authored versus translated rows separable.

**ASSUMED experimental acquisition targets:** pilot 1,000 independent benign and 300 attack examples per required language/script, with meaningful SMS/WhatsApp 1:1/group/other-app support. These are acquisition hypotheses, not proof each intersection is decision-grade. Cover English, Romanized Hinglish, Devanagari, Gujarati, Tamil, Telugu, Bengali, Marathi, Punjabi. Allocate incremental samples using uncertainty and learning curves. Compare 10k/25k/50k training budgets and natural-prior, capped class-weighted and enriched-attack sampling. Dataset size and 50/50 balance are experiments, never deployment priors. Pilot per-class distribution: benign categories chat/transactional/OTP/campus/other; attack categories callback-only/OTP coercion/KYC/utility/parcel/URL payload, plus separate commercial spam. Estimate actual proportions from recovered, independently labeled event denominators and source strata; until then no numeric segment prior is accepted. Synthetic diagnostic cells may be balanced but are reported separately from weighted natural traffic.

**ASSUMED labeling:** freeze definitions for BENIGN, COMMERCIAL_SPAM, ACTIVE_SECURITY_ATTACK, AMBIGUOUS/INSUFFICIENT_CONTEXT; record requested action, sensitive asset, authenticity uncertainty, vector, language, script, channel and group evidence. Distinguish “do not share OTP” from “send OTP”; an OTP value alone is not coercion. Two independent reviewers blind to model predictions for every evaluation/exam row and all attack/ambiguous training rows; native-speaker review per script, third reviewer resolves disagreements. Double-review a random 20% of benign training rows and expand to all in a segment if disagreement exceeds PROPOSED 5%. Publish disagreement, label changes, source documents, reviewer IDs and rationales; uncertain cases remain uncertain and are excluded from binary primary metrics with an explicit separate report. Do not self-certify independent review through a second generation pass.

### Representation and architectures (R03, R04, R09)

**ASSUMED M-A:** Unicode-normalized word + script-aware character ngrams with fixed script quotas or hashing, negation/action and numeric/URL structural features, fresh linear multiclass classifier. Advantages: compact, CPU-friendly, preserves obfuscations, interpretable ablations; risks: negation scope and long contextual intent. A fresh bounded tree booster is an optional classifier ablation on the same new feature contract. Kill M-A if native-script active-feature coverage remains PROPOSED <95% of eligible examples, or it cannot satisfy the approved deployment FPR/recall frontier across seeds within memory budget.

**ASSUMED M-B:** small randomly initialized byte/Unicode-subword embedding plus depthwise 1-D CNN/compact gated sequence pooling, explicit URL/phone/action features. No pretrained tokenizer or weights; tokenizer learned from train only with byte fallback. Advantages: script fallback, order/negation and small vocab; risks: from-scratch sample demand, truncation, obfuscation generalization and quantization loss. Kill M-B if its upper uncertainty bound for improvement cannot beat M-A's approved frontier after the capped search, or RAM/latency/model size budgets fail. Sweep 256/512/1024 byte or token limits with tail-window tests; loss of OTP/payload intent at message tail is a kill condition unless resolved inside the fixed resource budget.

**ASSUMED ablations:** script quotas versus none; normalization on/off preserving raw obfuscations; word versus char/byte; structural features; explicit action/negation; source and language balance; spam/attack label hierarchy versus flat classes; tail handling; representative versus synthetic-only enrichment. Same family splits/seeds/budget for paired comparisons; do not generate new fixes from test errors and reevaluate on the same test as independent evidence.

## URL track

### Data program (R01, R02, R05, R06)

**ASSUMED:** use approved URL event captures, licensed phishing/malware feeds with capture time and evidence, independently validated benign government/utility/payment links and ordinary browsing/repository/search URLs. Snapshot each source/hash/time/license; define stale/ambiguous labels and prohibit live fetching of suspected payloads during offline evaluation. Legitimate public-host payload URLs require actual evidence; a `.apk`, IP or login path is a risk feature, not an automatic malicious label. Shorteners without resolved provenance may be UNKNOWN. Popularity tiers use a timestamped offline ranking; missing rank = unknown, not low reputation. Historical hard-benign/golden material is reference-only.

**ASSUMED acquisition targets:** pilot 10,000 independent benign domains and 3,000 attack domains, then staged 25k/100k/250k URL training budgets with domain-level caps. Stratify explicit/schemeless/protocol-relative, apex/www/subdomains/IP/IDN, repository/search, local public services, shorteners, and popular-host payloads. Compare natural exposure weights, capped domain sampling and hard-negative enrichment only within training. Estimate form/popularity/family priors from independent captures, validate with source/time holdouts; no “real” numeric composition is assumed from source feed class ratios. Two independent reviewers for evaluation/exam and attack/ambiguous training records; verify a stratified 20% benign training sample with escalation under the Messages review rule. Provenance must distinguish compromised tenant/page from registrable-domain identity.

### Representation and architectures (R05, R06, R09)

**REPORTED:** V7 uses 67 deterministic numerical features, including some host/brand/path interactions. **ASSUMED:** the limitation is potential many-to-one information loss and coverage, not the number 67 itself. Future feature design includes versioned PSL registrable domain, full host labels, tenant identity, explicit scheme presence versus inferred canonical scheme, protocol-relative form, apex/www/IP/IDN/punycode, percent/double-encoding, bounded host/path/query lexical tokens, payload and nested-target evidence, and original/canonical paired views. No online reputation dependency; rank and rank-age are optional bounded evidence, never safety immunity. Measure same-vector benign/attack collisions and leave-domain/source/form holdouts before claiming feature adequacy. Keep PSL/parser/schema versions in model manifests. No new representation is fitted on validation/test/exam.

**ASSUMED U-A:** bounded fresh gradient-boosted trees over redesigned structural/domain/form/lexical summaries. Pros: inexpensive inference and inspectable paths; cons: lexical compression and known-domain shortcuts. Kill if measured representation collisions prevent approved per-family recall at the false-alert cap, or novel-domain FPR exceeds gates despite capped search.

**ASSUMED U-B:** small fresh byte CNN with separate host/path/query encoders and pooled structural/form features. Pros: character-obfuscation and tenant/payload context; cons: training/quantization/truncation cost and token shortcuts. Kill if no statistically supported gain over U-A at the same alert budget after capped search, or mobile budgets/long-query tail payload tests fail. A sparse char-host/path linear classifier is a cheap feasibility control, not a presumed release winner.

**ASSUMED ablations:** old 67-feature representation as diagnostic reference only versus new feature groups, registrable-domain/form flags, lexical views, popularity omitted/included, payload/query interactions, raw versus canonicalized form, tenant grouping, length caps. Partition domains before generating alternate-form siblings; all variants of one URL/family stay together.

## Shared split, sample-size and training protocol

**ASSUMED split:** reserve independently sourced final-exam components first with a custodian; assign remaining connected components approximately 70% train / 15% validation / 15% test, stratifying only where component constraints permit. Subdivide validation components into hyperparameter, calibration and operating-point partitions or use nested group cross-fitting. Group by template/translation/source/campaign and URL registrable domain; tenant exceptions require explicit approved relaxation of strict domain grouping. Source/time holdouts test distribution shift. Historical baselines' training union excluded from simulation and exam. No old holdout becomes a genuinely unseen exam merely through a filename change. Unexposed future source material may be necessary.

**ASSUMED minimum evidence:** N<30 in either class always not decision-grade; N≥30 alone is not sufficient. For recall near .95 with ±.03 approximate 95% precision, target at least 203 independent attacks per reported primary segment, then inflate for cluster design effect and multiple comparisons. With zero false alerts, one-sided 95% upper FPR bound is 1−.05^(1/n); to show FPR≤.001 requires at least 2,995 independent benign examples, and FPR≤.0001 requires 29,956. Correlation increases needed raw N. Require adequate components and use exact/cluster intervals; a 500-row zero-error benchmark cannot prove zero population FPR. Do not demand every factorial intersection be decision-grade without budgeting its acquisition; flag unsupported cells and block release for required segments. Predeclare primary versus exploratory segments to avoid selective success claims.

**ASSUMED future protocol:** seeds 17, 43, 101 for all shortlisted architectures; at most 12 hyperparameter configurations per architecture on development components, one seed during screening and three seeds for the two finalists. Two architectures/track → at most 24 initial fits plus up to 12 finalist fits/track (36 fits), subject to earlier kill criteria; no adaptive unlimited search. Fixed train-only tokenizer, preprocessing and feature fitting. Hyperparameters selected on grouped development validation; calibration compare identity, temperature/Platt and isotonic only when calibration sample support is adequate. Select calibration via grouped validation proper scoring rules; operating threshold on separate validation partition at the approved false-alert/recall tradeoff. Validation-only prior correction must be documented. Freeze model, calibrator, threshold, schema and gates before the one final test; no threshold choice from simulation challenge tests, 500 URLs, 174 fixtures or sealed exam. No deployment threshold is changed by this pass.

## Proposed evaluation gates — all PROPOSED, needing user approval

**OBSERVED:** Part B has no new baseline measurements. Consequently numeric release gates cannot honestly be derived from Part B, and this document is not approval-ready. The following are PROPOSED gate *rules*, with numeric values pending a valid frozen-baseline study and explicit user approval. No hard-benign/golden performance is used to select them.

| PROPOSED gate | Derivation after Part B | Approval status |
|---|---|---|
| Messages false alerts/user/day | Choose user-tolerated budget A_M; require cluster-95% upper 300(1−p)f≤A_M at each stated p, plus 100/1,000 volume sensitivity | Numeric budget unapproved |
| URL false alerts/user/day | Separate A_U; upper 30(1−p)f≤A_U, with 10/100 sensitivity; joined alert budget assessed separately | Numeric budget unapproved |
| PPV at .1%, 1%, 5% attacks | Require approved lower PPV bound Q(p); f≤pr(1−Q)/[Q(1−p)]; derive feasible Q from measured baseline CI and user alert tolerance | Q(p) unapproved |
| Attack recall by required segment | Lower CI ≥ approved R_min(segment) and paired non-inferiority margin versus baseline; severity of callback/OTP/payload misses guides margin | R_min/margins unapproved |
| Benign FPR by segment | Upper CI ≤ approved cap derived from weighted daily budget; all required scripts/channels/forms represented | Caps unapproved |
| Calibration | Upper uncertainty bound on weighted ECE/Brier and deviation at operating region compared to baseline; binning fixed before evaluation | Tolerances unapproved |
| Sample support | No required safety conclusion on N<30; power/CI-derived benign/attack N and component support above | PROPOSED, needs approval |
| Security policies | Zero violations on independently authored adversarial invariant tests; finite-suite success never proves universal security | PROPOSED, needs approval |

**ASSUMED illustrative arithmetic only:** if a future user-approved message false-alert budget were .1/day at 300 events and p=.001, it would imply f≤.0003337. At r=.95 that f implies PPV≈74.0% at p=.001. Neither .1/day nor .95 recall is adopted here, and these numbers are not from Part B. Use feasibility calculations before approving contradictory PPV/FPR demands.

## Runtime policies outside model training (R07)

**ASSUMED:** GROUP != WHITELIST; popularity is not immunity; payload evidence overrides benign conversation/contact context. Freeze a separate Python adjudicator specification with policy branches and compare identical model scores under known/unknown contact, 1:1/group, popular/unranked host and clean/payload pairs. Include OTP “never share” versus coercion; legitimate software download versus verified malware; encoded redirects and hosted credential theft; unavailable metadata; parser failures; repeated notifications and fail-safe behavior. Use a 2×2 raw/adjudicator attribution matrix to separate changed predictions from changed decisions. Group context may affect confidence but cannot erase payload evidence. Do not label every `.apk`, open redirect parameter or IP universally malicious without ground truth. Exact Kotlin fusion/severity/device display verification **requires authorization** and belongs to a later separately scoped runtime phase.

## Risks, resource envelope, estimates and ordered work

**REPORTED resource context:** master Gate 9 <20 ms inference and <50 MB RAM on Snapdragon 680; Phase 5 calls <15 ms cold start, with different endpoint wording. **ASSUMED PROPOSED design limits:** each track packaged assets ≤10 MiB; combined model/tokenizer/PSL assets ≤20 MiB; incremental combined peak RAM <50 MB; warm p95 inference <20 ms/track and cold first inference <15 ms as conservative separate constraints pending measurement/approval. Include normalization/tokenization/adjudication in latency; measure loading separately; do not claim hardware compliance from Python timings. A compact sequence model that cannot meet both endpoints is killed or requires a newly approved budget. No export/Android benchmark occurs now.

**ASSUMED planning ranges:** preflight recovery/provenance 2–5 engineer days if original binaries exist, otherwise unbounded; independent multilingual collection/labeling 3–8 weeks with parallel human reviewers, size dependent; leakage/split audit 3–5 days; sparse/tree searches 16–64 CPU-hours/track; small fresh sequence searches 24–96 GPU-hours/track on one 16–24 GB GPU plus 16–32 GB host RAM; evaluation/calibration/reporting 3–5 days. These are rough capacity assumptions, not quotes or measured runtimes. Pilot throughput and reviewer agreement must update estimates before compute approval. Training data loss, unsupported scripts, source/label shortcuts, domain-disjoint scarcity, synthetic artifacts, low base-rate uncertainty and sealed-exam exposure can invalidate the schedule. Privacy and collection permission are source-specific constraints, not permission already granted for external data collection.

**ASSUMED ordered work breakdown:**

1. Resolve raw recovery, pull provenance, training manifests and independent truth; stop if unavailable.
2. Agree stream weights, endpoints and supported segments; build grouped simulation plus independently held exam; freeze and hash before any baseline.
3. Run all baseline variants raw/adjudicated in Python, reconcile conflicts and calculate CI-backed feasible gate choices; exact APK runtime deferred.
4. Approve revised training designs, mobile limits, compute caps and all numeric gates; then seek explicit training authorization in a later task.
5. Future authorized data/tokenizer/model work starts from scratch, with bounded validation-only search and independent track states. No Phase 5–7 work is part of this request.

## What would make us NOT train

**ASSUMED no-go conditions:** missing validated recovery or labels; unresolved old training lineage or domain/template leakage; insufficient independent benign/attack support; sealed exam already exposed or no custodian; no acceptable mobile resource budget; source licenses/collection authorization absent; user false-alert/PPV/recall demands statistically incompatible with available N or achievable frontier; label disagreement dominating apparent errors; or controlled raw/adjudicated replay showing the material burden is caused by parser/fusion/context policy while frozen raw models already meet approved deployment needs. Under those conditions, training from scratch is not supported by evidence. Prefer an authorized data/provenance/policy investigation, not training by default. If matched new representation probes show no lost separable information and clean-label/source-controlled learning curves plateau, more architecture or data volume alone is not justified.

**ASSUMED go/no-go checklist:** all prerequisite evidence resolved; simulation/exam commitments and access controls complete; all historical variants reproducible; native/script review complete; zero grouped overlap verified; per-segment power sufficient; raw versus policy attribution complete; every proposed numeric gate and budget approved; separate URL/Messages release ownership; fresh-only training scope explicitly authorized. **OBSERVED:** this pass cannot check these as satisfied. Training decision = NO-GO pending evidence, not rejection of training forever.
''')
write('PLAN_AMENDMENT_TO_MASTER_PLAN.md','# Proposed amendment to master plan — no source edits\n\n'+common+'''
**OBSERVED:** `sentinel-ml/Messages-ml/SENTINEL_MASTER_PLAN.md` was read and hashed, never edited. This standalone amendment is a proposal only; it does not grant implementation authorization or adopt numerical gates.

| Master item | ASSUMED proposed replacement / retained intent |
|---|---|
| Phase 2.1 Tranco Top-100k binary | Supersede immediate implementation with a separately evaluated optional offline popularity feature/policy. Snapshot source/time/PSL, validate novel/local-domain coverage and malicious popular-host bypasses; no safety immunity |
| Phase 2.2 V8 four-state/Python+Kotlin integration | Supersede V8 patch pathway for this project objective with a fresh URL-track representation/model design and separate abstention/policy study. Do not assume four classes solve missing truth or calibration; no Kotlin edits |
| Phase 2.3 42-URL zero-FP / ≥98.5% recall criteria | Retain probes as historical references; replace sufficient release evidence with grouped deployment-weighted FPR/PPV/recall and CI-supported segment gates after Part B |
| Phase 3.1 40–50k language percentages and 50/50 candidates | Retain hypothesis status, supersede fixed composition with consented source pilot, native independent review, source/class-prior experiments and learning curves; balanced training is never deployment prevalence |
| Phase 3.2–3.3 template clustering and cross-split audit | Strengthen to all-old-model training union, translation/campaign/source lineage and domain components; exact-string exclusions and Jaccard alone do not prove semantic independence; reserve sealed exam first |
| Phase 4.1 retrain subword booster | Supersede inherited-data/feature defaults with fresh Unicode representation, fresh linear/tree candidate under new splits and labels |
| Phase 4.2 fine-tune multilingual transformer | Superseded: pretrained fine-tuning violates this request's fresh-weights rule. Replace with small randomly initialized byte/subword sequence candidate, capped search and kill criteria |
| Phase 4.3 legacy paired evaluation | Retain legacy benchmarks as qualified reference; add frozen realistic simulation, source/time/domain/template holdouts, raw/adjudicated traces and an independently sealed exam after model/gate finalization |

**ASSUMED proposed gate amendments, needing user approval:** master gates 1–2 English TEST recall/FPR remain reference comparisons, not deployment sufficiency. Gates 3–4 require each supported script/channel to meet independently approved recall/FPR confidence bounds, replacing aggregate N=500 as sufficient proof. Gate 5 zero observed historical false alarms remains a finite, independently labeled regression aspiration, not population zero-FPR proof. Gates 6–7 need domain/form novelty and deployment PPV/false-alert budgets in addition to legacy recall/utility probes. Gate 8 is deferred: 174 URL fixtures, 500 hard-benign URLs and a future parity corpus are distinct. Gate 9 endpoint/size/RAM limits require reconciliation and approval; Python cannot certify Android performance. Gate 10 invariants retained as separate runtime requirements with finite-test limitations. Numeric changes are pending the missing Part B measurements; no new numeric gate is adopted.

**ASSUMED authorization boundary:** keep URL and Messages independent. Phase 2–4 implementation does not start in this pass. Phase 5 packaging/export, Phase 6 Kotlin/device certification and Phase 7 release remain outside scope and untouched. Existing V2/V4.3/V7/V8 artifacts and thresholds stay protected; the master plan's older permitted output directories do not override this request's restricted new-output locations.

**OBSERVED limitation:** this amendment cannot be approved as a complete baseline-derived replacement because Part A failed before freeze. Required next evidence is listed in SIMULATION_DESIGN.md; approval of direction would still not authorize training.
''')

# Reference commitment, final integrity snapshot, then evidence document.
refs=[
'sentinel-ml/Messages-ml/SENTINEL_MASTER_PLAN.md',
'sentinel-ml/Messages-ml/SECOND_FORENSIC_REPORT.md',
'sentinel-ml/Messages-ml/messages_v4_3/data/dataset_manifest_v4_3.json',
'sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d_v4_3.py',
'sentinel-ml/Messages-ml/messages_v4_5/reports/V4_5_PROVENANCE_AUDIT.md',
'sentinel-ml/Messages-ml/messages_v4_5/reports/V4_5_ARCHITECTURE_EXPERIMENT.md',
'sentinel-ml/Messages-ml/messages_v4_5/reports/artifact_manifest.json',
'sentinel-ml/Messages-ml/messages_v4_4/reports/V4_4_FINAL_FORENSIC_AUDIT_REPORT.md',
'sentinel-ml/URL-ml/reports/URL_V7_REPRESENTATION_REPORT.md',
'sentinel-ml/URL-ml/reports/PHASE_1D_0_1_RECONCILIATION_REPORT.md',
'sentinel-ml/URL-ml/reports/PHASE_1D_URLML_RECONCILIATION_REPORT.md',
'sentinel-ml/URL-ml/reports/PHASE_1D_INTEGRATION_REGRESSION_REPORT.md',
'sentinel-ml/URL-ml/scripts/v8_classifier.py',
'sentinel-ml/investigation/recover_dbs.py']
dump('reference_hashes.json',{p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in refs})
after={p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in before}
dump('hashes_final.json',after)
r=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],capture_output=True,text=True,env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'})
dump('git_final.json',{'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
old=json.loads((OUT/'git_before.json').read_text(encoding='utf-8'))
source_changes=[]
for entry in findings['training_inventory']+findings['sources']:
    if sha(ROOT/entry['path'])!=entry['sha256']: source_changes.append(entry['path'])
comparison={'protected_files':len(before),'changed_files':[p for p in before if before[p]!=after[p]],'git_exit_codes':[old['exit_code'],r.returncode],'git_file_by_file_identical':old['stdout']==r.stdout,'git_lines':len(r.stdout.splitlines()),'additional_training_and_replay_changes':source_changes}
dump('final_integrity_comparison.json',comparison)
hashrows='\n'.join('| `'+p+'` | `'+before[p]['sha256']+'` | `'+after[p]['sha256']+'` |' for p in [
'sentinel-ml/6sep/messages/final/champion_v2_model.pkl','sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl','sentinel-ml/URL-ml/models/v7_champion.joblib','sentinel-ml/URL-ml/models/v8_champion.joblib'])
names=sorted([p.name for p in OUT.iterdir() if p.is_file()]+['SIMULATION_RUN_EVIDENCE.md','created_files_sha256.json'])
write('SIMULATION_RUN_EVIDENCE.md','# Simulation run evidence\n\n'+common+f'''
## Integrity and environment

**OBSERVED:** workspace `{ROOT}`. Environment: `{platform.platform()}`; Python `{sys.executable}`, `{sys.version.splitlines()[0]}`. User-facing date October 22, 2026, Asia/Calcutta. See `environment.json` for exact executable/platform/argv. No external packages, project-code imports, network calls, Kotlin/JVM/Gradle runs or Git mutations. Scripts were invoked with `-B`; Git status subprocesses set `GIT_OPTIONAL_LOCKS=0`.

**OBSERVED:** {len(before)} selected existing artifact/data/manifest files hashed before substantive audit and after it, then again at report completion. Changed files: {comparison['changed_files']}. Additional training/replay source hash changes: {source_changes}. Before/after Git exit codes {comparison['git_exit_codes']}; file-by-file porcelain identical = {comparison['git_file_by_file_identical']}; {comparison['git_lines']} pre-existing porcelain lines. “Identical” means complete status strings, not count equality. Initial reconnaissance also read Git status before the persisted baseline; no mutations occurred between them. Hash collection excludes venv/.git/build/.gradle/node_modules caches and is not a claim of a whole-disk content audit.

| Primary artifact | Before SHA-256 | Final SHA-256 |
|---|---|---|
{hashrows}

**OBSERVED:** all companion scaler/vectorizer/portable/APK files selected by the audit are listed individually in `hashes_before.json`, `hashes_after.json`, and `hashes_final.json`, with sizes. These primary hashes match the master plan's reported primary identities; duplicates remain separately listed. `reference_hashes.json` commits the inspected source documents, not proof their claims are true. Data hashes and matched row indices are in `schema_recovery_findings.json`. Derived CP437 byte hashes are labeled derived in `oem_recovery_findings.json`; originals were never rewritten.

## Substantive commands, results and counts

**OBSERVED:** all commands below ran from `{ROOT}` in PowerShell; exit code 0 for each. Expected data-format exceptions were caught within successful audit scripts and are retained in JSON. Commands are exact (no model call is hidden inside them); inspect the adjacent scripts for full procedure.

```powershell
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_preflight.py before
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_schema_and_recovery.py
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_oem_recovery.py
python -B reports/simulation_diagnosis/20261022_preflight_01/audit_preflight.py after
python -B reports/simulation_diagnosis/20261022_preflight_01/write_deliverables.py
```

**OBSERVED commands inside scripts:** `git -C "{ROOT / 'sentinel-ai'}" status --porcelain` (three persisted snapshots); standard-library SHA-256 streaming, JSONL parsing, read-only immutable SQLite metadata/count queries, and in-memory deserialization/tar reads. SQL statements and exact subprocess argv/cwd/exit codes are retained in scripts and Git JSON. Counts: 21 training JSONL files screened, 294 replay rows (291/3 labels), 562 recovered-history rows (562 security labels absent), old parsed rows 34/26 rejected, 3 raw UTF-16 inputs probed, 2 reconstructed DB query failures, no inferred labels, zero simulation/exam rows frozen, zero models invoked. Model artifacts were hashed, never unpickled.

**OBSERVED audit correction:** the first script expected `text`/`label` and failed to recognize `raw_text`/`security_label`. Its training-label and zero-replay-overlap fields in `preflight_findings.json` are INVALID. The schema-aware second script supersedes those fields, yielding 9/294 and 6/562 normalized overlaps. That error does not affect first-script byte hashes, file counts, database headers or caught DB errors. A negative Latin-1 recovery test did not prove irreversible corruption: subsequent strict CP437 tests round-tripped and found a tar member; database completeness is still unvalidated. All attempts were retained, none overwritten.

## Complete before/after Git porcelain

**OBSERVED before** (unmodified source strings from `git_before.json`):

```text
{old['stdout'].rstrip()}
```

**OBSERVED final** (unmodified source strings from `git_final.json`):

```text
{r.stdout.rstrip()}
```

## New files created

**OBSERVED:** all new files are under `reports/simulation_diagnosis/20261022_preflight_01/`; no existing output filename was reused. This is `reports/` under the supplied sentinel workspace root, not a second nested sentinel directory. No experiment files were needed because freeze/inference stopped. All writes use exclusive creation or new-file patches. Created-file hashes are in `created_files_sha256.json`; that manifest excludes itself to avoid a circular self-hash. This list includes the evidence file and final hash manifest:

'''+ '\n'.join('- `'+x+'`' for x in names)+'''

## Stop disposition and remaining requirements

**OBSERVED:** six requested document names exist as preflight-stop/conditional-design deliverables; the requested complete simulation, all-model deployment measurements, sealed final exam, exhaustive historical reconciliation and baseline-derived approved-ready gates were not achieved. The user-specified insufficient-evidence stop condition was applied before any model execution. This is not an approval request and no training is scheduled. Exact Kotlin/fusion/severity/device work **requires authorization**; raw data validation, provenance, independent labels, complete grouping and an independently held exam are the missing prerequisites.
''')
dump('created_files_sha256.json',{p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.iterdir()) if p.is_file()})
print(json.dumps({'exit_code':0,'deliverables':6,'integrity':comparison,'created_files':len(list(OUT.iterdir())),'status':'STOPPED_PREFLIGHT_NO_MODELS_RUN'},indent=2))
