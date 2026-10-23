# Failure diagnosis


Date: October 22, 2026 (Asia/Calcutta). Scope: analysis, frozen-model inference and development design only.

Evidence labels: **OBSERVED** = computed or inspected in this run; **REPORTED** = historical/user claim not established here; **ASSUMED** = scenario/design choice; **PROVISIONAL** = inference conditional on unreviewed labels, authored cases or salvage. Observing a stored label is not observing its correctness. Null/NA means not estimable, never zero errors. No candidate training, model/calibrator fitting, model export, promotion, frozen-threshold change, Kotlin/Gradle/Android execution or Git mutation was performed.

**OBSERVED:** predictions and count evidence are in frozen inputs, reproduction JSON, schema/vocabulary rechecks and `failure_cluster_evidence.jsonl`. **PROVISIONAL:** natural/synthetic error labels and mechanistic causality. The study does not prove a larger model or fresh training will repair policy, recovery or annotation failures.

| ID / class | Mechanism and observed evidence | Concrete example / limits | What would disprove the diagnosis | Required capability |
| --- | --- | --- | --- | --- |
| F01 DATA / LABEL | 715 strict serialized-record candidates; SQLite validation fails; 154 old-history exact-key matches; no per-row human review ledger | 72/75/568 candidates; exact original missing-row total UNKNOWN; 117 simulation messages and84 natural URLs NEEDS_REVIEW | Pristine binary/WAL recovery with integrity and independently reviewed labels that reverse the implicated classifications | R01 source-byte lineage, recovery certification, independent label provenance |
| F02 FEATURE / DATA | V4.3 vocab1500word/2500char; only3 nonASCIIword/0 nonASCIIchar; Devanagari train68M,1S,0B | Authored Indic mean char activations about4.6–5.4 vs English102; direct OTP/callback text in frozen scenarios | Adequate native benign/attack coverage and active script tokens with unchanged failure after matched controlled ablation would disprove starvation as sufficient cause | R02 script-inclusive fallback, native intent/negation data and measured lexical coverage |
| F03 LABEL / FEATURE | V4.3 TEST90/188 spam→M, medianpM .786366; OOD31/83; TEST24M→B and22M→S | High-confidence promotional/commercial-spam confusion persists above nonbenign threshold; full errors retained | Independent label review removing ambiguity plus source-heldout evaluation with no residual confusion would weaken label/source hypothesis; supervised causal ablations still needed | R03 spam≠active_attack semantics, action/requested-secret/recipient features, source-disjoint tests |
| F04 LABEL / DATA | 3817/19672 train primary_type values outside current schema,20 distinct;4047 source_type out-of-enum | CONTROLLED_CONTRASTIVE3817 and INTERNAL_CURATED230; earlier source count4154 not reproduced | A hash-matched authoritative schema permitting these values and consistent adjudication would disprove current schema inconsistency; it would not prove labels correct | R04 versioned strict schema, migration ledger, review disagreement and provenance |
| F05 FEATURE / RUNTIME-POLICY | Current authored V8 bareinstagram.com .609370 vs form-dependent outcomes; familiar gov/utility paths high | paytm .956639, irctc .887285, Ahmedabadportal .999928; URL known labelN11/5 only | Equivalent feature/score traces across forms, plus independently labeled representative novel-domain data with no excessFPR, would falsify form/coverage mechanism | R05 original host form +PSL domain +lexical path/query coverage; trace parser/feature/model versions |
| F06 RUNTIME-POLICY / THRESHOLD | URL cleanV8 raw207FP/22825TP→URL-aware263FP/22835TP; V7 cleanadjud loses11TP relative raw | Same weights/features, different adjudication path; simulationV8 one added attack alert, no labeled benign change | Exact historically shipped Python-equivalent policy showing identical decisions and raw-only error concentration would disprove policy attribution for that build | R06 separate raw-score and policy error ledgers, payload precedence and bounded reputation context |
| F07 THRESHOLD / FEATURE / DATA | V4.3 adjudication reduces raw conditionalFP44→24 but attack alerts36→32; naturalFP8/708 | Threshold changes move both errors; multilingual authored attack clusters only2 | Validation-only frontier meeting approved recall/false-alert budgets without representation/data change would weaken necessity of new training | R07 calibration and threshold chosen only on independent validation; keep diagnostic sweeps separate |
| F08 ARCHITECTURE (unproven) / DATA | V4.4 variants on same simulation change naturalFP from6–35/708; V4.3=8; authored attack detections improve versus V2 | No controlled architecture-only causal contrast: data, thresholds and vocabulary differ. V4.5 regression is REPORTED, not rerun | Matched fresh-weight architectures under identical clean sources/splits/budgets could show no architecture contribution | R08 at least sparse/tree and small sequence alternatives, matched ablations and kill criteria |
| F09 RUNTIME-POLICY / DATA | Logged app/non-green comparisons differ from current model-only alerts; timestamps conflict with filename ordering | No history-to-APK identity or fused Kotlin run established; 13,536 comparisons are not truth confusion matrices | Hash-linked capturedAPK/source/policy and validated event metadata reproducing logged outcomes would resolve provenance/policy confounding | R09 per-build source/tokenizer/feature/model/policy manifests and independent track release states |

## Cluster counts and representative evidence

**PROVISIONAL:** each row below counts event-level errors conditional on stated labels; translations/channel repeats share families. Full 260-cluster listing, raw/adjudication distinctions and all examples are in `failure_cluster_evidence.jsonl`.

| Model / path | Error | Language | Family | Label status | Count | Example |
| --- | --- | --- | --- | --- | --- | --- |
| Messages_V4.3 adjudicated | FP | English_or_other_Latin_UNRESOLVED | UNKNOWN | PROVISIONAL_BENIGN_UNREVIEWED | 6 | Barabar |
| Messages_V4.3 adjudicated | FP | Hinglish_ASSUMED | UNKNOWN | PROVISIONAL_BENIGN_UNREVIEWED | 2 | Haan subah tak kar dena code upload chalega abhi mai thodi der me karti hun upload readme bana rahi hun |
| Messages_V4.3 adjudicated | FP | English | legit_OTP | SYNTHETIC_AUTHORED | 4 | Your OTP is 482913. Do not share it with anyone. |
| Messages_V4.3 adjudicated | FN | English | callback_scam | SYNTHETIC_AUTHORED | 4 | Your power will be cut tonight. Call 9876543210 and pay the agent now. |
| Messages_V4.3 adjudicated | FN | Hinglish | callback_scam | SYNTHETIC_AUTHORED | 4 | Aaj raat bijli kat jayegi. Abhi 9876543210 par call karke agent ko paise bhejo. |
| Messages_V4.3 adjudicated | FN | Hinglish | OTP_coercion | SYNTHETIC_AUTHORED | 4 | Account chalu rakhne ke liye abhi aaya OTP mujhe bhejo. |
| Messages_V4.3 adjudicated | FP | Hindi | legit_OTP | SYNTHETIC_AUTHORED | 4 | आपका OTP 482913 है। इसे किसी के साथ साझा न करें। |
| Messages_V4.3 adjudicated | FN | Gujarati | callback_scam | SYNTHETIC_AUTHORED | 4 | આજે રાત્રે વીજળી કપાશે. હવે 9876543210 પર ફોન કરીને એજન્ટને પૈસા મોકલો. |
| Messages_V4.3 adjudicated | FN | Gujarati | OTP_coercion | SYNTHETIC_AUTHORED | 4 | ખાતું ચાલુ રાખવા હમણાં આવેલો OTP મને મોકલો. |
| Messages_V4.3 adjudicated | FN | Tamil | OTP_coercion | SYNTHETIC_AUTHORED | 4 | கணக்கை செயல்பாட்டில் வைத்திருக்க வந்த OTP எண்ணை எனக்கு அனுப்புங்கள். |
| Messages_V4.3 adjudicated | FN | Telugu | callback_scam | SYNTHETIC_AUTHORED | 4 | ఈ రాత్రి విద్యుత్ నిలిపివేస్తాం. ఇప్పుడు 9876543210 కి కాల్ చేసి ఏజెంట్ కు డబ్బు పంపండి. |
| Messages_V4.3 adjudicated | FN | Telugu | OTP_coercion | SYNTHETIC_AUTHORED | 4 | ఖాతా కొనసాగడానికి ఇప్పుడే వచ్చిన OTP నాకు పంపండి. |
| Messages_V4.3 adjudicated | FP | Bengali | legit_OTP | SYNTHETIC_AUTHORED | 4 | আপনার OTP 482913। কাউকে জানাবেন না। |
| Messages_V4.3 adjudicated | FN | Marathi | callback_scam | SYNTHETIC_AUTHORED | 4 | आज रात्री वीज कापली जाईल. आता 9876543210 वर फोन करून एजंटला पैसे पाठवा. |
| Messages_V4.3 adjudicated | FN | Marathi | OTP_coercion | SYNTHETIC_AUTHORED | 4 | खाते चालू ठेवण्यासाठी आत्ताच आलेला OTP मला पाठवा. |
| Messages_V4.3 adjudicated | FP | Punjabi | legit_OTP | SYNTHETIC_AUTHORED | 4 | ਤੁਹਾਡਾ OTP 482913 ਹੈ। ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ। |
| URL_V8 adjudicated | FP | NA | ordinary_url | SYNTHETIC_AUTHORED | 6 | instagram.com |

## Model errors versus policy errors

**OBSERVED:** `finding_summary.json` records decision changes: V4.3 threshold changes26 message decisions; V7 gating changes11 URLs; V8 adjudication changes1 simulation URL. Unknown-label policy changes are not declared fixes. The current wrapper is not the old APK; default HTTPS/form handling and later policy edits can explain conflicts with earlier probes, but exact historical attribution remains unproven. GROUP != WHITELIST, payload overrides context and popularity is not immunity are runtime requirements, not learned guarantees. No Kotlin/Gradle run was attempted. Any future exact fusion/severity/device verification requires separate user authorization; Python model/adjudicator traces are the present fallback.

**ASSUMED:** architecture is the least established causal explanation. Data coverage and representation loss are directly evidenced, but fresh training should proceed only after label/recovery/source controls can distinguish their effects from runtime policy. Requirements R01–R09 are traced to concrete future tests in the development plan.
