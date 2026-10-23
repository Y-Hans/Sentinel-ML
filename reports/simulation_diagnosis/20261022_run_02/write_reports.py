from runlib import *
import collections,math,textwrap
protect()
def write(name,s):
    with (OUT/name).open('x',encoding='utf-8',newline='\n') as f:f.write(textwrap.dedent(s).strip()+'\n')
def table(headers,rows):
    return '| '+' | '.join(headers)+' |\n| '+' | '.join('---' for _ in headers)+' |\n'+'\n'.join('| '+' | '.join(str(v).replace('|','/').replace('\n',' ') for v in r)+' |' for r in rows)+'\n'
def num(x,n=3): return 'NA' if x is None else f'{x:.{n}f}'
def pct(x): return 'NA' if x is None else f'{100*x:.3f}%'
def interval(x,percent=False):return 'NA' if not x else '['+', '.join(pct(v) if percent else num(v) for v in x)+']'
def loadlines(n):return readrows(OUT/n)
freeze=jload('freeze_manifest_v2.json'); rec=jload('recovery_v2.json'); prov=jload('provenance_followup.json'); repro=jload('messages_reproduction.json'); urepro=jload('urls_reproduction.json'); hard=jload('url_hard_reproduction.json'); schema=jload('label_schema_recheck.json'); vocab=jload('indic_vocabulary_recheck.json'); fs=jload('finding_summary.json'); gates=jload('proposed_gate_derivation.json')
summary=loadlines('metrics_summary.jsonl'); security=loadlines('security_metrics_summary.jsonl'); segments=loadlines('segment_metrics.jsonl'); failures=loadlines('failure_cluster_evidence.jsonl'); logs=jload('logged_comparison_summary.json'); calibration=loadlines('calibration_reliability.jsonl'); ms=loadlines(freeze['messages']['path']); us=loadlines(freeze['urls']['path'])
common='''
Date: October 22, 2026 (Asia/Calcutta). Scope: analysis, frozen-model inference and development design only.

Evidence labels: **OBSERVED** = computed or inspected in this run; **REPORTED** = historical/user claim not established here; **ASSUMED** = scenario/design choice; **PROVISIONAL** = inference conditional on unreviewed labels, authored cases or salvage. Observing a stored label is not observing its correctness. Null/NA means not estimable, never zero errors. No candidate training, model/calibrator fitting, model export, promotion, frozen-threshold change, Kotlin/Gradle/Android execution or Git mutation was performed.
'''
design='# Simulation design and freeze\n\n'+common+'''
## Stream contract

**OBSERVED:** the authoritative freeze is `freeze_manifest_v2.json`; its hashes were committed before reproduction/scoring. Earlier `freeze_manifest.json` remains immutable but its URL overlap tags are superseded. No rows were removed for overlap. New byte recovery is the primary natural source; the 294-row historical replay is a separately identified REPORTED source. The older recovered 562 file was used only for recovery comparison, not silently substituted as newly recovered data.

'''+table(['Track','Rows','Label status counts','Overlap flagged','SHA-256'],[[k,freeze[k]['rows'],json.dumps(freeze[k]['label_status']),freeze[k]['overlap_rows'],freeze[k]['sha256']] for k in ('messages','urls')])+'''
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

'''+table(['Path','Rows','SHA-256','Reserved sender/channel groups','New authored cases'],[[freeze['sealed_exam']['path'],freeze['sealed_exam']['rows'],freeze['sealed_exam']['sha256'],freeze['sealed_exam']['heldout_real_groups'],freeze['sealed_exam']['authored_cases']]])+'''
**OBSERVED:** the exam was created before inference. No model, metric, threshold-sensitivity analysis or gate calculation reads its rows. Hash checks read its bytes only. Entire sender/channel groups were reserved using seed 20261022; separately authored exam families were added using unrecorded random identifiers. The review sheet was generated before reservation and includes real rows for human review; it is not a secrecy boundary.

**PROVISIONAL limitation:** this is a sealed-for-this-pass holdout, not a fully independent final certification exam: the author knows the grammar, no separate custodian exists, recovery/labels are provisional, and no exhaustive semantic-family isolation of real exam rows is certified. Do not use it for final release claims. Before future training, assign an independent custodian to validate/regenerate a fresh exam from unexposed source families, with two native reviewers, domain/template/source grouping and an immutable hash commitment. Do not inspect this exam to choose new features/gates. The present plan uses only simulation/reproduction results.

## Statistical contract

**OBSERVED:** `analyze.py` uses seed 20261022 and 2,000 cluster-bootstrap replicates per summary/segment cell, resampling whole sender/scenario/domain clusters and recomputing FPR/recall jointly; 95% percentile intervals are propagated to PPV and daily burden. Undefined replicates/cells yield null. All 988 segment cells are flagged not decision-grade because at least one class or its independent-cluster support is below 30. Synthetic attacks span two message families and five URL domains; narrow/degenerate bootstrap intervals cannot establish population certainty. Zero-FP cells include one-sided independent-row and independent-cluster bounds with assumptions stated. A zero-event bootstrap interval [0,0] or resulting PPV [1,1] is not proof of zero FPR or perfect deployment precision.

**OBSERVED:** reliability curves are ten fixed-bin tables, ECE/Brier are reported unweighted and under each assumed prevalence; these are diagnostic scores, not deployment calibration certificates. Threshold sensitivity is diagnostic only; stored model thresholds and artifacts remain unchanged. The 500 hard-benign URLs were not scored or used to set gates. The 174 golden records were read for comparison-only parity after models loaded, with no tuning to their outcomes.
'''
write('SIMULATION_DESIGN.md',design)

labels='# Provenance, recovery and labels\n\n'+common+'''
## Three-pull provenance

**REPORTED user mapping:** `sentinel_db` = Messages v1/URL v7; `sentinel_db(1)` and October 22 archive = Messages v2/URL v8. **REPORTED master mapping:** older 562 history = installed Messages Champion V2/URL V7; unsigned 2.1.0 = Messages V4.3/URL V8. The names “v1/v2” in the user chronology are not assumed identical to canonical model generation names.

'''+table(['Pull','New candidate rows','Candidate offsets not accepted','Time min UTC','Time max UTC','Model generation'],[[p['pull_id'],p['valid_candidate_rows'],p['candidate_offsets_not_accepted'],p['timestamp_min_UTC'],p['timestamp_max_UTC'],p['model_generation']] for p in prov['pulls']])+'''
**OBSERVED:** no explicit model-version strings were found in recovered explanations. Explanation/score patterns per pull are preserved in `provenance_followup.json`; they describe model outputs, not truth. The candidate timestamp ranges place pull_2 before pull_1, so filename order cannot prove chronological capture order. Transfer damage and missing WAL history can affect timestamps. Per-model logged/current agreement is in `logged_comparison_summary.json` and the row-level comparison file; agreement does not identify the historical installed model. All three model_generation values remain UNRESOLVED, per the authorized fallback.

'''+table(['Canonical artifact (user alias mapping unresolved)','Bytes','SHA-256'],[[p,v['bytes'],v['sha256']] for p,v in prov['canonical_artifacts'].items()])+'''
**OBSERVED APK listings:**

'''+table(['APK','APK SHA-256','Model asset names'],[[a['apk'],a['sha256'],', '.join(x['name'] for x in a['assets'])] for a in prov['apk_assets']])+'''
**OBSERVED:** installed APK packages Champion V2 and URL V7; unsigned 2.1.0 packages V4.3 and V8 assets. Each embedded asset's byte length and SHA-256 is in `recovery_provenance.json`/`provenance_followup.json`. This is package evidence, not proof which package generated a particular pull. Canonical legacy Messages V4 artifact is listed to make the unresolved “v1/m1 V4” alias explicit, not to select it by guesswork.

## Independent recovery

**OBSERVED:** original files are UTF-16LE encodings of CP437-rendered bytes. Strict reversal round-trips; original bytes were preserved under new filenames. CRLF→LF reversal restores plausible lengths but cannot distinguish original byte 0D from 0A after text transfer. New exact/standalone-header copies were opened `mode=ro&immutable=1`; SQLite schemas/counts/integrity results and exceptions are recorded in `recovery_provenance.json` and `recovery_v2.json`. All attempted SQLite paths still fail validation. Altering WAL header bytes in a NEW standalone view is explicitly recorded and did not certify data integrity.

**OBSERVED:** first conservative page scanner recovered zero because newline transformation destroys table-leaf markers/offsets. The corrected independent carver validates SQLite serialization around UUIDs, requires exactly 11 threat-record columns, SCAN_RESULT, risk enum, UTF-8 content and a plausible timestamp. It found 72+75+568=715 distinct candidate records. These are **PROVISIONAL_SALVAGE**, not 715 certified original table rows. In particular, carving an archive can retain old snapshots/WAL copies. The exact dedup key is `(id, recordType, timestamp, UTF8 content SHA-256)`; 715 candidates remain after exact dedup, zero exact duplicates. Same-ID versions remain distinct and are not silently collapsed.

**OBSERVED:** unaccepted UUID offsets are 194/597/9397 by pull, including index copies and non-record regions. They are exact candidate-offset counts, NOT numbers of lost threat records. An exact unrecoverable original-row total is **UNKNOWN**, because no trusted original table count/integrity check is available. This is a stated evidence limitation, not an unfilled implementation decision. No complete recovery or WAL checksum certificate is claimed. Recovering pristine binaries or a validated WAL solver is future ingestion work; this pass continues with the documented salvage fallback.

'''+table(['REPORTED comparison source','Stored rows','Exact ID/time/content-key matches to new union','Legacy-only unique keys','New-only unique keys'],[[p['source'],p['legacy_rows'],p['matching_keys'],p['legacy_only_unique'],p['new_only_unique']] for p in rec['legacy_comparisons']])+'''
**OBSERVED:** row-by-row comparison files preserve ID, timestamp, content hash and match flags. The 34/26 old parsed files collapse to 7/8 unique keys and contain implausible fields; they are not trusted recovery labels. The old `.recovered.db`/`*_rows.jsonl` files were hashed as protected inputs and remain REPORTED artifacts, not independent verification. Exact source-to-new byte comparisons for each recovered database variant are in recovery metadata; original historical database files have different transformation lineage and are not substituted for raw pulls.

## Label rule and human-review search

**OBSERVED:** `adjudication_search.json` gives searched paths, source hashes, line numbers and excerpts. The master plan states that 31 non-green alerts were human reviewed, 29 natural rows judged false alarms and two synthetic links judged attacks. No `threat_records.json` or hash-linked per-record review ledger was found in the searched repository. `docs/ROOT_CAUSE_ANALYSIS.md` and `PROJECT_CONTEXT_DOSSIER.md` contain model-analysis/provenance claims, not a record-level 31-alert adjudication map. Therefore zero rows are marked ADJUDICATED in this pass; the aggregate master claim remains REPORTED.

**PROVISIONAL rule, explicitly authorized by this request:** only logged GREEN rows with no detected URL, ≥6 digit run, OTP/PIN/payment/account/bank/security keywords, or non-Latin alphabetic content become PROVISIONAL_BENIGN_UNREVIEWED with y=0. All other natural rows remain NEEDS_REVIEW and y=null. This uses GREEN only to select a low-risk provisional review stratum; it does not establish the prediction as ground truth. Emoji are not language/script ground truth. The 294 replay's stored security_label is retained as REPORTED auxiliary metadata but not promoted to human adjudication or natural attack truth. Authored cases are SYNTHETIC_AUTHORED, with author-assumed intent; unresolved authored URLs remain null.

**OBSERVED:** REVIEW_SHEET.csv contains 1,009 data rows (715 independent salvage candidates +294 historical replay rows), with requested columns, original logged predictions, rule-based status and blank reviewer_label/reviewer_note. It includes reserved real exam rows for independent human labeling; exclude model scores and gate decisions from that review. No source row or label was overwritten. The primary simulation has 708 provisional-benign, 117 NEEDS_REVIEW and 180 authored message rows; URL simulation has 84 NEEDS_REVIEW, 16 authored labeled and two authored unresolved URLs. Sensitive/non-Latin rows therefore lack natural accuracy estimates; published natural FPR is selection-biased. Every metric is stratified by label_status and overlap; NEEDS_REVIEW contributes alert counts and logged comparisons only.

**ASSUMED next review procedure:** two independent reviewers blind to present model predictions label each row BENIGN/COMMERCIAL_SPAM/ACTIVE_ATTACK/INSUFFICIENT_CONTEXT and add a rationale/provenance. A third resolves disagreements; native-speaker review is mandatory for each script. Keep a new review-ledger filename rather than editing the frozen set or blank sheet in this pass. Then create a separately versioned evaluation manifest and rerun analyses without changing old results.
'''
write('PROVENANCE_AND_LABELS.md',labels)

results='# Simulation baseline results\n\n'+common+'''
## Reproduction gate

**OBSERVED:** Messages uses Python 3.14.4 / numpy 2.5.2 / sklearn 1.9.0; URL uses its venv Python 3.11.15 / numpy 2.4.6 / sklearn 1.9.0. Cache tags include Messages cpython-314 and cpython-311; the selected 3.14 interpreter is supported by Candidate-D cache provenance and exact reproduction, not proof of the historical training environment. All eight Messages pickle bundles and both URL joblibs loaded; their recorded unpickle warning lists are empty. No portable fallback was needed. A portable evaluator exists for a load failure; it was not used to substitute favorable results.

'''+table(['Messages model','Frozen τ','TEST FP/benign','TEST malignant-class correct/attack','TEST spam→malicious','OOD spam→malicious'],[[m['model'],m['threshold'],f"{m['TEST']['benign_fp']}/{m['TEST']['benign_n']}",f"{m['TEST']['malicious_correct']}/{m['TEST']['attack_n']}",f"{m['TEST']['spam_to_malicious']}/{m['TEST']['spam_n']}",f"{m['OOD']['spam_to_malicious']}/{m['OOD']['spam_n']}"] for m in repro['models'] if 'TEST' in m])+'''
**OBSERVED:** V4.3 exactly reproduces 1510/1556, 2/520 at τ=.61, TEST spam→malicious 90/188 (median pM=.786366), OOD spam→malicious 31/83. V2 current text-only feature pipeline produces 1403/1556 and 20/520, whereas September 6 report says 1402/1556 and 10/520. Same model identity does not ensure identical feature/sender/source pipeline; original version closure remains unresolved. The current inference follows the repo's benchmark_v2 text-only `sender_header=None` contract. This discrepancy is retained, not repaired by threshold selection.

'''+table(['URL clean TEST model/path','TP/attack','FP/benign','Recall','FPR'],[[m['model']+' '+m['mode'],f"{m['true_positive']}/{m['attack_n']}",f"{m['benign_fp']}/{m['benign_n']}",pct(m['recall']),pct(m['FPR'])] for m in urepro['measurements']])+'''
**OBSERVED:** clean split reconstruction uses repository domain_group, GroupShuffleSplit .4/seed42 then .5/seed43, label inversion, frozen feature extraction and models; test N=50,511. Exact argv/cwd, runtime, exit codes, split counts and index hash are in `url_reproduction_only_v2.command.json`/`urls_reproduction.json`. The old `reproduce_v7_champion.py` was read but not executed because it fits and overwrites models. New inference-only code reproduces its split without training. On the 174 comparison fixtures, current features/raw probabilities match exactly; final probability maximum difference is about 2.954e−8. This is parity reference evidence, not truth or a gate-tuning outcome.

'''+table(['URL historical HARD model/path','TP/attack','FP/benign','Recall','FPR'],[[m['model']+' '+m['mode'],f"{m['TP']}/{m['attack_n']}",f"{m['FP']}/{m['benign_n']}",pct(m['recall']),pct(m['FPR'])] for m in hard['results']])+'''
**OBSERVED:** this HARD source is `hard_dataset.csv` N=2,800, distinct from the protected 500 hard-benign URLs. It was evaluated as an additional reproduction reference after the clean reproduction gate; no gate/model choice depended on it.

## Simulation: raw versus adjudicated

**OBSERVED predictions / PROVISIONAL accuracy:** 8,040 message prediction rows (8 models×1005 events), 204 URL rows (2×102). Messages raw means class argmax; adjudication means frozen p(non-benign) threshold then max(spam,malicious), not Kotlin contact/group/fusion policy. URL raw means base probability at frozen τ; adjudication uses the current Python V7 gating or V8 URL-aware adjudicator. These current-source wrappers are not guaranteed historically shipped policy versions. Exact APK runtime execution was neither needed nor attempted; it requires separate authorization.

**PROVISIONAL main conditional table:** Messages uses all 816 available assumed/provisional benign and 72 authored attack events; URLs use 11 assumed-benign/5 authored attacks. Excluded unknown labels remain in denominator counts and alert-rate files. These challenge estimates are not real deployment rates.

'''+table(['Model / path','FP / available benign','TP / authored attack (any alert)','Alerts / 1,000 benign','FPR bootstrap 95% CI','Recall bootstrap 95% CI'],[[r['model']+' '+r['mode'],f"{r['FP']}/{r['benign_n']}",f"{r['TP']}/{r['attack_n']}",num(r['alerts_per_1000_benign']),interval(r.get('bootstrap_95CI_FPR'),True),interval(r.get('bootstrap_95CI_recall'),True)] for r in summary if r['scope']=='all'])+'''
**PROVISIONAL label-status table (adjudicated):**

'''+table(['Model','Label status','Labeled benign / attack','FP / TP','All-row alert rate'],[[r['model'],r['scope'].split('=',1)[1],f"{r['benign_n']} / {r['attack_n']}",f"{r['FP']} / {r['TP']}",pct(r['alert_rate_all'])] for r in summary if r['mode']=='adjudicated' and r['scope'].startswith('label_status=')])+'''
**PROVISIONAL natural-message burden:**

'''+table(['Model/path','Alerts / provisional benign','Alerts / 1,000 benign','False alerts/day at .1% attacks, V=300','Bootstrap 95% CI/day'],[[r['model']+' '+r['mode'],f"{r['FP']}/{r['benign_n']}",num(r['alerts_per_1000_benign']),num(r['prevalences'][0]['false_alerts_user_day']),interval(r['prevalences'][0].get('false_alerts_day_bootstrap95CI'))] for r in summary if r['scope']=='natural_provisional' and r['track']=='messages'])+'''
**ASSUMED transported message projections / authored-only URL projections:** Messages rows below transport authored attack recall to provisional natural benign FPR; URL rows use authored FPR/recall because natural URL truth is absent. Each scenario assumes stable class-conditional rates; no measured deployment precision is claimed. Every cell is not decision-grade, especially two message attack families or five URL attack domains. Degenerate bootstrap intervals must be read with cluster counts/zero-event bounds in JSON.

'''+table(['Model/path','Assumed attack prevalence','PPV [bootstrap 95% CI]','Recall [bootstrap 95% CI]','False alerts/day','Total alerts/day'],[[r['model']+' '+r['mode'],pct(p['assumed_prevalence']),pct(p['PPV'])+' '+interval(p.get('PPV_bootstrap95CI'),True),pct(p['recall'])+' '+interval(p.get('recall_bootstrap95CI'),True),num(p['false_alerts_user_day']),num(p['total_alerts_user_day'])] for r in summary if (r['track']=='messages' and r['scope']=='transported_projection') or (r['track']=='urls' and r['scope']=='synthetic_authored') for p in r['prevalences']])+'''
## Overlap, segments, calibration and failures

**PROVISIONAL:** all-model raw/adjudicated all/without-overlap/overlap-only metrics and intervals are in `metrics_summary.jsonl`. Selected no-drop comparisons:

'''+table(['Model/path','Scope','FP/benign','TP/attack'],[[r['model']+' '+r['mode'],r['scope'],f"{r['FP']}/{r['benign_n']}",f"{r['TP']}/{r['attack_n']}"] for r in summary if r['model'] in ('Messages_V4.3','URL_V8') and r['scope'] in ('without_overlap','overlap_only')])+'''
**OBSERVED:** `segment_metrics.jsonl` contains 988 raw/adjudicated cells across language/script, channel, conversation, family, label_status, overlap, pull and URL form/domain/popularity. Every cell includes class/cluster counts, uncertainty and not_decision_grade=true; the absence of decision-grade evidence is not hidden by aggregation. V4.3's without-overlap sample still has 24/803 conditional benign errors and 32/72 any-alert attack detections, showing the authored failure pattern is not removed by the overlap screen. URL V8 without-overlap has only 4 benign/3 attack cases: insufficient for a novel-domain safety claim.

**OBSERVED:** `calibration_reliability.jsonl` provides reliability-bin curves, ECE and Brier for all labeled, natural-provisional and authored scopes, with raw sample weighting and each assumed prevalence. `threshold_sensitivity.jsonl` lists diagnostic grid outcomes around the locked thresholds, never a selected alternative. `security_metrics_summary.jsonl` and `security_segment_metrics.jsonl` provide a second Messages endpoint requiring MALICIOUS class, rather than any spam/security alert. Its companion calibration/sensitivity files retain the same p(non-benign) diagnostic score; they are not p(M)-specific calibration or a new operating policy. Do not compare any-alert synthetic recall directly to historical three-class malicious recall.

**PROVISIONAL:** `failure_cluster_evidence.jsonl` gives every observed label-conditional error cluster and both FP/FN examples; `worst_failures.jsonl` ranks up to 30 failures/model/path, with score, script, label_status and overlap. Examples, current V8 adjudication: Ahmedabad government portal ≈.999928, Paytm ≈.956639, IRCTC ≈.887285, Tata Power billpay ≈.738310, bare `instagram.com` ≈.609370. Their assumed-benign labels are authored, not newly externally verified. The same fixture with explicit HTTPS or www can follow different structural paths, so neither old parser diagnosis nor a claimed universal canonicalization fix is assumed.

**OBSERVED:** 13,536 row-level logged/current comparisons and 80 per-pull/model/path summaries are recorded. They compare logged non-green app outcomes against model-only alerts, not truth. URL parent-message risk is not necessarily a URL verdict; group/contact/fusion effects and salvage corruption confound attribution. Counts/IDs/predictions/explanations are retained in `logged_comparison.jsonl`. No agreement score resolves the generation conflict.

## Preserved disagreements

'''+table(['Status','Conflicting figures/claims','Disposition'],[
['OBSERVED vs REPORTED','V2 current 20/520 FPs, 1403/1556 malicious correct; 6sep baseline 10/520 and 1402/1556','Feature/sender/source version closure unresolved; do not choose favorable report'],
['OBSERVED and REPORTED','V4.3 1510/1556, 2/520, spam→M 90/188 and 31/83','Reproduced exactly in current environment'],
['OBSERVED vs REPORTED','source_type out-of-schema 4047 now vs second forensic 4154; primary_type 3817 across 20 values now','Current schema enum and train hash retained; earlier denominator/schema definition unresolved'],
['OBSERVED vs REPORTED','V7 clean adjudicated 98.752%/.976%, hard .459%; V8 current URL-aware 98.605%/.962%, hard 3.369%; older V8 report 98.68%/1.17%, hard .36%','Different raw/gating/URL-aware policy and report versions; no averaging or assertion historically equivalent'],
['OBSERVED','V8 with URLs 22835 TP/263 FP; no-URL fallback 22825 TP/207 FP','Different callable paths in same frozen wrapper; both reported explicitly'],
['OBSERVED vs REPORTED','68 malicious,1 spam,0 benign Devanagari and 0 nonASCII char tokens now; earlier blackout 92%','Coverage gap reproduced, exact 92% not claimed for new authored texts'],
['OBSERVED vs REPORTED','21-corpus new simulation overlap 28/1005 and 66/102 URL source-domain flags; prior 9/294 and6/562','New sampling/normalization/corpus scope; not comparable row denominators; tags retained'],
['REPORTED','User three-pull mapping vs master installed V2/V7 and unsigned V4.3/V8','UNRESOLVED per pull despite APK asset identity'],
['REPORTED','V4.4 historical system FPR0/55 vs forensic25/55; zero exact collisions vs601 normalized rows','Historical audit retracts favorable claim; current study does not certify old holdouts independent'],
['REPORTED','V4.5 77.70% TEST recall/3.08% FPR vs V4.3 97.04%/.38%; source audit says strict leakage rejection despite307 aggressive collisions','Historical reference only; Step7 named baselines exclude V4.5; embedding/classifier closure not certified here'],
['REPORTED','URL reconciliation earlier4248/4254=99.853 vs4170/4254=98.025;681/682=99.853 separate cohort','Cohort conflation retained, not redefined'],
['REPORTED','Hard-benign draft304/500=60.8 vs419 raw/420 adjudicated; benign total43027 vs42941','Comparison-only historical disagreement; 500 not scored/tuned in this pass'],
['REPORTED','Master parityN500 vs174 URL fixtures; cold-start<15ms vs Gate9<20ms','Different fixtures/endpoints; no Android execution or hardware conclusion'],
['OBSERVED','New salvage568 October archive candidates vs older562 record recovery, only154 exact keys match','Snapshot/byte recovery differences unresolved; no complete-row claim']
])+'''
**OBSERVED limitation:** this ledger covers the specifically cited reports/hashes, not a claim of an exhaustive audit of every historical document. New inferences are reproducible, label correctness remains provisional, and no present simulation supports approving release today.
'''
write('SIMULATION_BASELINE_RESULTS.md',results)

diagnosis='# Failure diagnosis\n\n'+common+'''
**OBSERVED:** predictions and count evidence are in frozen inputs, reproduction JSON, schema/vocabulary rechecks and `failure_cluster_evidence.jsonl`. **PROVISIONAL:** natural/synthetic error labels and mechanistic causality. The study does not prove a larger model or fresh training will repair policy, recovery or annotation failures.

'''+table(['ID / class','Mechanism and observed evidence','Concrete example / limits','What would disprove the diagnosis','Required capability'],[
['F01 DATA / LABEL','715 strict serialized-record candidates; SQLite validation fails; 154 old-history exact-key matches; no per-row human review ledger','72/75/568 candidates; exact original missing-row total UNKNOWN; 117 simulation messages and84 natural URLs NEEDS_REVIEW','Pristine binary/WAL recovery with integrity and independently reviewed labels that reverse the implicated classifications','R01 source-byte lineage, recovery certification, independent label provenance'],
['F02 FEATURE / DATA','V4.3 vocab1500word/2500char; only3 nonASCIIword/0 nonASCIIchar; Devanagari train68M,1S,0B','Authored Indic mean char activations about4.6–5.4 vs English102; direct OTP/callback text in frozen scenarios','Adequate native benign/attack coverage and active script tokens with unchanged failure after matched controlled ablation would disprove starvation as sufficient cause','R02 script-inclusive fallback, native intent/negation data and measured lexical coverage'],
['F03 LABEL / FEATURE','V4.3 TEST90/188 spam→M, medianpM .786366; OOD31/83; TEST24M→B and22M→S','High-confidence promotional/commercial-spam confusion persists above nonbenign threshold; full errors retained','Independent label review removing ambiguity plus source-heldout evaluation with no residual confusion would weaken label/source hypothesis; supervised causal ablations still needed','R03 spam≠active_attack semantics, action/requested-secret/recipient features, source-disjoint tests'],
['F04 LABEL / DATA','3817/19672 train primary_type values outside current schema,20 distinct;4047 source_type out-of-enum','CONTROLLED_CONTRASTIVE3817 and INTERNAL_CURATED230; earlier source count4154 not reproduced','A hash-matched authoritative schema permitting these values and consistent adjudication would disprove current schema inconsistency; it would not prove labels correct','R04 versioned strict schema, migration ledger, review disagreement and provenance'],
['F05 FEATURE / RUNTIME-POLICY','Current authored V8 bareinstagram.com .609370 vs form-dependent outcomes; familiar gov/utility paths high','paytm .956639, irctc .887285, Ahmedabadportal .999928; URL known labelN11/5 only','Equivalent feature/score traces across forms, plus independently labeled representative novel-domain data with no excessFPR, would falsify form/coverage mechanism','R05 original host form +PSL domain +lexical path/query coverage; trace parser/feature/model versions'],
['F06 RUNTIME-POLICY / THRESHOLD','URL cleanV8 raw207FP/22825TP→URL-aware263FP/22835TP; V7 cleanadjud loses11TP relative raw','Same weights/features, different adjudication path; simulationV8 one added attack alert, no labeled benign change','Exact historically shipped Python-equivalent policy showing identical decisions and raw-only error concentration would disprove policy attribution for that build','R06 separate raw-score and policy error ledgers, payload precedence and bounded reputation context'],
['F07 THRESHOLD / FEATURE / DATA','V4.3 adjudication reduces raw conditionalFP44→24 but attack alerts36→32; naturalFP8/708','Threshold changes move both errors; multilingual authored attack clusters only2','Validation-only frontier meeting approved recall/false-alert budgets without representation/data change would weaken necessity of new training','R07 calibration and threshold chosen only on independent validation; keep diagnostic sweeps separate'],
['F08 ARCHITECTURE (unproven) / DATA','V4.4 variants on same simulation change naturalFP from6–35/708; V4.3=8; authored attack detections improve versus V2','No controlled architecture-only causal contrast: data, thresholds and vocabulary differ. V4.5 regression is REPORTED, not rerun','Matched fresh-weight architectures under identical clean sources/splits/budgets could show no architecture contribution','R08 at least sparse/tree and small sequence alternatives, matched ablations and kill criteria'],
['F09 RUNTIME-POLICY / DATA','Logged app/non-green comparisons differ from current model-only alerts; timestamps conflict with filename ordering','No history-to-APK identity or fused Kotlin run established; 13,536 comparisons are not truth confusion matrices','Hash-linked capturedAPK/source/policy and validated event metadata reproducing logged outcomes would resolve provenance/policy confounding','R09 per-build source/tokenizer/feature/model/policy manifests and independent track release states']
])+'''
## Cluster counts and representative evidence

**PROVISIONAL:** each row below counts event-level errors conditional on stated labels; translations/channel repeats share families. Full 260-cluster listing, raw/adjudication distinctions and all examples are in `failure_cluster_evidence.jsonl`.

'''+table(['Model / path','Error','Language','Family','Label status','Count','Example'],[[r['model']+' '+r['mode'],r['kind'],r['language'],r['family'],r['label_status'],r['count'],r['examples'][0]['example'][:180]] for r in failures if r['model'] in ('Messages_V4.3','URL_V8') and r['mode']=='adjudicated'])+'''
## Model errors versus policy errors

**OBSERVED:** `finding_summary.json` records decision changes: V4.3 threshold changes26 message decisions; V7 gating changes11 URLs; V8 adjudication changes1 simulation URL. Unknown-label policy changes are not declared fixes. The current wrapper is not the old APK; default HTTPS/form handling and later policy edits can explain conflicts with earlier probes, but exact historical attribution remains unproven. GROUP != WHITELIST, payload overrides context and popularity is not immunity are runtime requirements, not learned guarantees. No Kotlin/Gradle run was attempted. Any future exact fusion/severity/device verification requires separate user authorization; Python model/adjudicator traces are the present fallback.

**ASSUMED:** architecture is the least established causal explanation. Data coverage and representation loss are directly evidenced, but fresh training should proceed only after label/recovery/source controls can distinguish their effects from runtime policy. Requirements R01–R09 are traced to concrete future tests in the development plan.
'''
write('FAILURE_DIAGNOSIS.md',diagnosis)
print('wrote design, provenance, baseline and diagnosis',flush=True)
