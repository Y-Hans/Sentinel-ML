from preplib import *
guard()
inv=load(OUT/'B_original_source_inventory.json');review=load(OUT/'probe_review_audit.json');unique=load(OUT/'probe_full_uniqueness.json');groups=load(OUT/'variant_group_audit.json');overlap=load(OUT/'overlap_role_correction.json');spam=load(OUT/'historical_SPAM_group_summary.json');spams=load(OUT/'historical_SPAM_readiness_v2.json');coord=load(OUT/'B_COORDINATION_SNAPSHOT.json');pre=load(OUT/'preflight.json')
refpaths=[ROOT/'assistant_review_20261023/AGENT_A_NEXT.md',ROOT/'assistant_review_20261023/INDEPENDENT_REVIEW.md',ROOT/'assistant_review_20261023/ANNOTATED_REVIEW_SAMPLE_v2.csv',B/'assistant_review_20261023/DATASET_LABEL_TRIAGE.csv',B/'DONE.json',B/'CANDIDATES.md',B/'STATS.md',PREV/'PRE_REGISTRATION.md',PREV/'PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md',PREV/'frozen/probe_v2.csv']
save('PREPARATION_INPUT_HASHES.json',hashes(refpaths))
source_table=[]
for sid,s in inv['sources'].items():
 d=s['original_language_class'];source_table.append([sid,s['originals'],d.get('hinglish:MALICIOUS',0),d.get('hinglish:BENIGN',0),s['original_labels'].get('SPAM',0),s['original_labels'].get('UNMAPPED',0),s['sha256']])
readiness='''# DATA_READINESS_v2 — preparation complete; intake/fit NOT ready

Date23 October2026, Asia/Calcutta. OBSERVED means this run inspected/recomputed; REPORTED means a source/reviewer assertion; ASSUMED means design/estimate; PROVISIONAL means unresolved labels/lineage. No model inference, training, vocabulary/scaler/calibration fit, validation-threshold scan, export or Android execution occurred. All new outputs live only inside this Messages-ML preparation folder. Neither probe was changed or made training data.

## Incoming review reconciliation

OBSERVED: the annotated sample has120 rows (60M/40B/20S),119 distinct texts, and zero changes to inherited columns/labels versus the frozen sample. user_agree/user_note remain blank. HP2_00425 and HP2_00346 share identical benign text. Assistant statuses are118 scenario-plausible/not-independently-verified and2 duplicate flags. Comments include26 deliberately non-live .invalid URLs and one delivery-PIN context concern. The review is an AI analyst review, not independent human adjudication or evidence of endpoint safety. Zero explicit corrections is not a measured0% label-error rate; the >5% rule is neither passed nor waived.

OBSERVED broader probe quality:1,375 rows contain1,337 distinct full texts. Distinct strings still share one author,60 authored attack phrase pairs, inherited benign contrasts, persona frames and scenario vocabulary. Existing row-level Wilson intervals describe those rows; neither1,375 rows nor1,337 texts is a defensible independent-population sample size. Report family/template clusters and author count beside N; do not convert the set into independent heldout evidence. The generator allowed near-identical components up to3; it did not enforce zero exact duplicates. Earlier reporting should have surfaced this explicitly. V1 and v2 remain permanently evaluation-only; no tuning or labels from scores.

OBSERVED: DATASET_LABEL_TRIAGE.csv is absent from Sentinel's five-file assistant_review_20261023 folder, but located and hash-recorded in sibling sentinel_datasets/assistant_review_20261023. Its28 concerns are16 financial2025,9ridham,3sidzzz07. They are AI-selected triage candidates, not28 confirmed errors or a random population error estimate. No blanket label replacement occurred. Exact incoming hashes: PREPARATION_INPUT_HASHES.json; annotation/triage evidence: probe_review_audit.json, triage_counts.json.

## Original B collection: verified external snapshot, not new intake

OBSERVED: all202 listed files in B's original DONE.json match their SHA256. We rehashed before streaming original normalized files for this diagnostic. This certifies byte identity to that old manifest, not correctness, admissibility, or completion of B's active repair. No DATASETS MOVED signal or mutually exclusive copy/handoff occurred; no write to datasets_v5 or B's workspace. No new source is admitted to training. The source table is pre-remediation availability only; do not merge these counts with forthcoming corrected B counts.

'''+table(['Source','Original rows','Hinglish M','Hinglish B','SPAM','UNMAPPED','Normalized SHA256'],source_table)+'''
OBSERVED totals:5,999 original texts;9,903 rows with3,904 conversion variants. Original labels2,911 BENIGN/0SPAM/1,790MALICIOUS/1,298UNMAPPED. All3,904 variants have meaning_check=UNSURE. Every original/variant group has exactly one original and consistent inherited label, but that does not validate the label or conversion meaning. Groups/variants must remain together; each original contributes at most unit total weight after augmentation. Source-group audit and full source/language/class/conversion counts are saved.

PROVISIONAL dispositions: financial2025 all419 originals QUARANTINED pending taxonomy/jurisdiction review; do not rescue individual obvious examples while the source audit is unresolved. Its scam category includes receipt/advertising/service contexts in the supplied concerns, and Bangladesh BDT/locale material cannot be silently treated as Indian deployment evidence. ysangam all743 original rows remain UNMAPPED until numeric polarity is explicitly documented; repeated text/metadata is not independent evidence. ridham safe mixes BENIGN/promotional, and some scam rows need intent review. sidzzz07 is authored synthetic template intent, not captured natural attacks; callback-only or bank wording alone is not proof of deception. karan is small and template-like. No variant marked UNSURE is admitted to any untouched test.

## Source-heldout feasibility — gates remain UNPROVEN

OBSERVED old-source Hinglish attack counts: sidzzz07258, ridham234, total492. Neither source supplies300 original Hinglish attacks by itself. Adding transliterations to reach300 does not create independent observations; most original labels themselves need review. Hinglish BENIGN is502 sidzzz07 +10karan; sidzzz07 can meet a raw row target but not a claim of300 independently collected real messages. There is currently no certified independent natural Hinglish300M+300B holdout. We have inspected source documentation/triage and counts; these existing materials cannot be relabeled a pristine new exam after design decisions. B's remediated release may reduce admissible counts further.

PROPOSED: retain G3 as UNPROVEN when the independent-source/group requirement is unmet. Use source-disjoint synthetic stress tests only with that name; no waiver, pooled-source sleight of hand, converted variants as new independent N, or softened confidence gate. Do not select/fit using source test labels or model predictions. A later genuinely untouched source is required for a stronger deployment-generalization claim.

## Deduplication / leakage diagnostics

OBSERVED exact/Jaccard>=.85 original-source audit over5,999B originals: corrected confirmed evaluation overlaps are3financial2025 originals; historical training overlaps2financial2025 originals. Four financial originals also match raw/training-lineage/unclassified references; overlap categories may share rows and must not be summed. No cross-B-source matches at this lexical criterion. This is not proof of semantic/source independence. Variants inherit original overlap exclusions and additionally require their own exact/fuzzy audit after handoff, so this diagnostic is not a final split certificate.

OBSERVED own correction: the initial comparison role marked all non-training filenames as evaluation, including all_processed/raw corpora. This yielded5financial evaluation-like matches and falsely flagged all1,169 historical SPAM rows. We preserved that broad result and corrected roles to explicitly identified test/val/OOD/benchmark/holdout/probe/simulation paths. Authoritative files: overlap_matches_v2.jsonl, overlap_role_correction.json and historical_SPAM_overlap_v2.jsonl. The corrected historical SPAM unique-row union is136/1,169, with per-file hits79val/39test/33OOD (overlapping counts). Raw corpus lineage is retained separately, not misrepresented as test leakage.

OBSERVED historical SPAM: train.jsonl has1,169 SUSPICIOUS_SPAM rows (1,143 unique normalized strings):812IMC25,310Mendeley2022,47UCI. After excluding flagged template groups,1,033rows remain potential review candidates; zero are newly admitted. historical_SPAM_candidates_v3.csv uses canonical message_id/source_id/template_cluster_id and text hashes. Earlier diagnostics used id/source aliases and could show null/MISSING despite available canonical metadata; this was corrected, not treated as absent provenance. B's collection exclusion of already-used corpora does not automatically prohibit A's explicitly permitted established historical training reuse, but license/taxonomy/group leakage checks still apply. Keep SPAM as the third class; never fill a missing class with UNMAPPED or pseudo-labeled attacks.

OBSERVED: sentinel-ml/user_data/hardneg_train.csv is absent. Hard-negative overlap is UNPROVEN, not zero. Sealed exams were neither enumerated nor opened. Hash-only exam access cannot establish fuzzy content overlap; obtain an owner-generated exclusion index or separately approved deferred leakage check during the single final exam read. Missing hardneg/exam prerequisites do not become passing gates.

## Author/template split accounting

OBSERVED AUTHOR_TEMPLATE_SPLIT_LEDGER.csv records9,903original/variant IDs with original group_id, source, author/generator assertion, parsed template/family and exact normalized fingerprint. SOURCE_TEMPLATE_COUNTS.csv has193 source/author/template/family cells. Metadata author names/LLM provenance are REPORTED, not authenticity verified. Every assigned_split is NOT_ASSIGNED. No training/validation/test partition has been fabricated.

PROPOSED after admissible release: union original group_id, original source-template group, normalized exact/Jaccard links, genuine sender/thread and cross-source duplicate lineage. For unknown templates, use a conservative family/author block and mark unresolved groups rather than row-wise splitting. Do not group all unrelated messages solely because they share an author for the internal test, but reserve an entire author/source for the external source-heldout test; if only one usable author remains, that test is UNPROVEN. Emit actual source/author/template membership by split before fitting; current ledger is the required preparation scaffold, not a split approval.

## B coordination / handoff contract

OBSERVED: following AGENT_A_NEXT item3, a request was sent to the existing “Collect public SMS scam datasets” chat for immutable source manifests and quarantine lists. B was active in taxonomy repair at the recorded snapshot; no final corrected manifest was available to this run. B_COORDINATION_SNAPSHOT.json records the request/status. Its current commentary says financial review and ysangam polarity work are ongoing; this is REPORTED progress, not an accepted dataset.

PROPOSED handoff: B finishes source audit outside Sentinel and freezes a release with DONE/manifest hashes, per-source accepted/quarantined/UNMAPPED decisions, row-level original/variant/template linkage, license evidence and review-status columns. A announces paused intake, user authorizes B's copy, B alone creates a new non-existing datasets_v5/release_<uniqueID>/ and writes completion receipt last. No in-place replacement or simultaneous A read while B copies. A resumes only after explicit handoff completion/DATASETS MOVED, rehashes every listed file, rejects traversal/duplicate entries/mismatch, and audits admitted rows. Nothing in this preparation authorizes copying or fitting.
'''
write('DATA_READINESS_v2.md',readiness)
oldhash=sha(PREV/'PRE_REGISTRATION.md');clarhash=sha(PREV/'PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md')
amend=f'''# PRE_REGISTRATION_AMENDMENT_v2 — UNAPPROVED, no fit permission

OBSERVED parent registration SHA256 `{oldhash}`; parent clarification SHA256 `{clarhash}`. Both remain unapproved. This amendment supersedes only readiness, default experiment scope, independent-sample interpretation and source admission conditions below. All original fixed-model thresholds and model artifacts remain unchanged. No validation-threshold scan occurred.

## Primary candidate and Android compatibility

PROPOSED first candidate C1 only: same3-class HistGradientBoostingClassifier and exact4019 input contract =19 existing structural +1500word TF-IDF(1–2) +2500char_wb TF-IDF(2–5), same analyzers/sublinearTF/lowercase/L2norm, train-only vocabulary and StandardScaler, fresh weights, no warm start/pretrained/pseudo-labels. Train BENIGN/SPAM/MALICIOUS; map historical SUSPICIOUS_SPAM to SPAM explicitly. New asset content within the identical dimensions/settings can be data-only for the model representation. It does NOT fix Android's existing SPAM-as-threat policy; that separate patch remains a release blocker.

PROPOSED default fit request, only when prerequisites pass and user separately approves: twoC1seed runs20261023(primary) and20261024(robustness). Fixed primary seed, never choose the best seed after exams. HGB max_iter300,learning_rate.08,max_leaf_nodes31,l2=1,early_stopping=False, train-only balanced class weights capped5x per row. No feature/tokenization change, no fitted temperature (T=1), no larger vocabulary in this first fit scope. C2extraOTP/callback features, larger vocabulary, alternative weighting and temperature remain separately preregistered possibilities, inactive unless approved in a later revision. Adding numeric features/dimensions or temperature is not “data-only” and requires later Kotlin parity/runtime authorization. Do not consume the old10-fit ceiling as automatic permission for extra experiments.

PROPOSED new threshold selection remains validation-only MALICIOUS alert metric after explicit fit approval. Training/scaler/vocab use train only; calibration/selection partitions stay group-disjoint. With T=1 no calibration fit is needed. The original .01..99 feasibility search may be used only if separately approved along with fitting and adequate reviewed English/Hinglish validation is present. No feasible operating point => NO-GO; never tune on probes, historical TEST, source-heldout or sealed exams. No threshold scan is performed in this preparation.

## Data admission changes

PROPOSED financial2025 stays quarantined in full pending taxonomy adjudication. ysangam stays UNMAPPED pending documented polarity. Pending AI review suggestions do not become trusted labels merely because B maps them in a draft release. A must retain label_status distinguishing source label, AI proposal, human adjudication and unresolved state. Independent user check is required before promoting contested rows to trusted train/test labels; preparation and draft triage need no fabricated human approval.

PROPOSED SPAM remains a real third class. Prefer admissible independently reviewed promotional rows from B once available, supplemented by established historical SPAM with license/taxonomy and leakage review. Current historical1169rows have136unique row/template exclusions against known evaluation;1033remaining are only review candidates, not an approved source. No binary BENIGN/MALICIOUS fit disguised as3-class, no spam labels inferred from frozen scores.

PROPOSED keep source-heldout300Hinglish attack/300benign as an evidence target, not a guaranteed attainable quota. Current original sources do not furnish300Hinglish attacks in any one mapped source and are mainly synthetic; conversions add no independence. If an independent source cannot be secured, G3 external evidence remains UNPROVEN and release NO-GO. An approved experimental fit can still study grouped data if the user explicitly accepts this limitation, but cannot claim the unproven gate passed. Do not regenerate probes from model scores or move them into validation.

PROPOSED actual split manifests require complete B immutable handoff plus A's finalized admissibility/overlap audit. Union source original/variant and template groups, cross-source near duplicates and genuine sender/thread groups. Reserve author/source-heldout material before selection. Internal group partitions70/10/10/10 from original plan remain proposed, with exact IDs/hashes and source-author-template table frozen before fitting. With T=1 the10%calibration partition remains unused reserve, not opportunistically merged after seeing results. Where counts are too small, report insufficient segment/groupN; do not break groups to hit percentages. Current assigned splits are all NOT_ASSIGNED.

## Gates — unchanged numeric intent, stronger provenance interpretation

| Gate | PROPOSED threshold | Current status |
|---|---|---|
| G1 | English metadata TEST M recall>=96.5%, >=1497/1551; full historic TEST reported separately | New candidate NOT RUN; historic TEST is reused diagnostic, not fresh selection |
| G2 | English BENIGN+SPAM M-only false alerts<=92/707 baseline | NOT RUN; preserve per-class counts and same denominator |
| G3 | Hinglish point recall>=85%, Wilson lower>=80%, eachN>=30family>=70%; probe and independent public source separately | UNPROVEN independent-source target; synthetic row intervals not independent population evidence |
| G4 | Hinglish B+S false alerts<=5% and<=V4.3 on each probe and hardneg exam | Pilot only; missing hardneg and unadjudicated probe; no natural-traffic claim |
| G5 | SPAM->MALICIOUS<=25% each adequately sized set | New candidate NOT RUN; maintain actualSPAM training/eval taxonomy |
| G6 | URL-less recall>=URL-bearing minus10points | NOT RUN; group uncertainty and per-family strata required |
| G7 | Actual exported Android JSON assets<=8MiB | UNPROVEN; no export permission; representation same4019 does not itself prove asset size |
| Field objective | <=.2%nonmaliciousFPR (~.2false alerts/day at100notifications; declared priors) | Separate PROPOSED deployment goal, UNPROVEN; do not confuse withG4 |

PROPOSED confidence reporting: row Wilson values may accompany correlated synthetic outcomes but must be labeled descriptive. Use original/template-group bootstrap for comparisons, report distinct texts,originals,groups,authors. No claim of a reliable group CI when effective group count is inadequate. Random sample120contains119distinct texts, still one author. The >5% label-error trigger requires reviewed truth; 118AI-plausible statuses do not prove compliance.

## CPU / solo-work budget

OBSERVED existing topology10physical cores; max5threads per future fit; no GPU/install. Current preparation uses standard-library CPU diagnostics, no pilot fit. ASSUMED future C1 wall time20–60min/fit at5threads is a planning range, not measured training performance. Two fits could consume3.3–10aggregate CPU-hours at full utilization; stop earlier at actual10CPU-hour cap, never infer CPU-hours from wall time alone. Stop first fit if measured iteration timing projects>90wall minutes; also stop if remaining aggregate budget cannot complete the approved job. Background hidden process, immutable logs/status/checkpoints, fixed seeds and actual CPU/wall/RAM required. Checkpoint metadata does not authorize warm-start resume.

ASSUMED dense20,000×4019float32 matrix is321,520,000bytes (~306.6MiB) before copies/scaler/vectorizer/tree/bin work; reserve2GiB RAM budget per single fit process and record peak rather than claim Android RAM. Matrix size/iterations must not be reduced mid-run without a revised registration. Android size,latency,RAM remain unmeasured and require later authorized device parity/performance tests.

ASSUMED remaining solo effort after B handoff: manifest/admission/leakage2h; targeted mapping/provenance review4–8h; actual grouped split+registration1–2h; approved two-fit supervision1–2h plus background compute; final diagnostics/decision3–4h; contingency2h =13–20h. One150-row source review at30–60seconds/row alone costs1.25–2.5h; do not claim multiple thorough independent reviews fit into an hour. If effort exceeds24h, prioritize fewer admissible sources and keep unproven gates; do not rubber-stamp contested labels or accelerate by consuming exam material. Working-hour10 English-only fallback still requires explicit approval and data readiness; it is not active now.

## Hard prerequisites and release separation

No fit until explicit approval binds this amendment + parent registration hashes + accepted data manifest + split manifest + label review status. Pending repaired B manifest, hardneg availability, original/variant grouping, source holdout limitation and sealed exclusion strategy must be acknowledged/resolved explicitly. Model-fit approval never authorizes Android patch, Gradle, export, APK or promotion. Android release is NO-GO until MALICIOUS-only runtime policy is separately authorized and tested. Messages and URL release decisions stay separate; AgentC files remain outside our write scope.
'''
write('PRE_REGISTRATION_AMENDMENT_v2.md',amend)
write('BLOCKERS_v2.md','''# Blocking conditions — preparation finished, no training

OBSERVED B's immutable repaired manifest/accepted-quarantined release is pending in the last recorded snapshot; original DONE verification is not a repaired-data handoff. No DATASETS MOVED signal, exclusive copy or split freeze has occurred.

PROVISIONAL label readiness: financial2025 quarantined; ysangam UNMAPPED; ridham safe/spam separation and some scam labels unresolved; synthetic callback templates do not authenticate malicious intent; all3,904 old conversions UNSURE. Proposed label changes need review before becoming trusted data.

OBSERVED independent holdout evidence: no qualifying certified300M+300B natural Hinglish source-heldout set. Hardneg_train.csv absent; its overlap unproven. Sealed exam content unopened; exclusion-index/deferred-leakage strategy remains unapproved. No actual split assignment or threshold scan.

OBSERVED prerequisite to Android release: staticSPAM-as-threat path confirmed; two-file patch and12test groups proposed only. No Kotlin execution or source changes authorized. No new model has been trained.

User decisions are explicitly separated in PROPOSED_APPROVAL_TEXT.md. No self-approval. Preparation can be considered complete despite these documented external prerequisites; fitting and release cannot.
''')
write('PROPOSED_APPROVAL_TEXT.md','''# Proposed approval text — not an approval

## 1. Verification-only handoff, when B is ready

“I authorize Agent B, after its source audit is complete and Agent A is paused, to copy the immutable release identified by [B manifest SHA256] into a new non-existing sentinel-ml/datasets_v5/[release ID] folder. Do not overwrite anything. Agent B writes a completion receipt and source quarantine manifest. Agent A may then verify hashes, audit admissibility and create proposed grouped splits in its Messages folder. No training, threshold scan, sealed-exam content access, Android edit or export is authorized.”

The bracketed release identity is intentionally not invented; it must be filled with B's actual final hash/path at approval. After copy, send DATASETS MOVED with the receipt path.

## 2. Later Messages fit approval, only after verified inputs and splits

“I approve the parent registration plus PRE_REGISTRATION_AMENDMENT_v2 identified in PREPARATION_APPROVAL_BUNDLE.json, accepted data manifest [actual SHA256] and final split manifest [actual SHA256]. I authorize only the twoC1fresh CPU fits (seeds20261023/20261024) and validation-only threshold selection, within5threads and10CPU-hours, with the >90min first-fit projection stop. No new features, larger vocabulary, temperature, export, Kotlin/Gradle or promotion. I acknowledge any explicitly listedUNPROVEN source-heldout/hardneg gates; no deployment claim is authorized.”

Do not approve invented/unfilled hashes or treat this sample wording as consent. If prerequisite labels/holdouts remain contested, approve only further data preparation instead of fitting.

## 3. Independent Android authorization, optional later

“I authorize applying the exact proposed Android diff SHA256 from android_patch_preconditions.json after matching source hashes and running its12test groups plus existing regressions. Keep URL/fusion policies and model artifacts unchanged. This does not authorize training or promotion.”

No part of this document authorizes its own execution. Current task remains preparation-only.
''')
write('PROGRESS.md','# Preparation finished — NO TRAINING\n\nOBSERVED: supplied review reconciled;119distinct sample texts and1337distinct probe texts recorded; all202old B manifest hashes verified; source/variant/template and historicalSPAM audits complete; role/source-key errors corrected in versioned evidence; Android patch proposed only; data readiness/amendment/blockers written. Pending repaired B handoff, reviewed admissibility, actual splits, independent holdout/hardneg evidence, and separate user approval. No model inference or threshold scan performed.\n')
save('PREPARATION_APPROVAL_BUNDLE.json',{'status':'UNAPPROVED_PREPARATION_ONLY','parent_files':{str(p):sha(p) for p in [PREV/'PRE_REGISTRATION.md',PREV/'PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md']},'new_files':{p:sha(OUT/p) for p in ['DATA_READINESS_v2.md','PRE_REGISTRATION_AMENDMENT_v2.md','BLOCKERS_v2.md','PROPOSED_APPROVAL_TEXT.md','ANDROID_PATCH_PROPOSAL.md','PROPOSED_ANDROID_MALICIOUS_ONLY.patch','PROPOSED_ANDROID_TEST_MATRIX.csv']},'new_model_training_authorized':False,'validation_threshold_scan_authorized':False})
print('readiness/amendment/blockers written; approval bundle',sha(OUT/'PREPARATION_APPROVAL_BUNDLE.json'))
