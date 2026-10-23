# PRE_REGISTRATION_AMENDMENT_v2 — UNAPPROVED, no fit permission

OBSERVED parent registration SHA256 `f4b3b618c7116bc1647c4893de8a998fe3ee7c2665ee277e5420a10c272e3ef6`; parent clarification SHA256 `a5d0f8f5af906240b6015fa738b720eb1e527411937c2969a3d4ccaa05d6f9a7`. Both remain unapproved. This amendment supersedes only readiness, default experiment scope, independent-sample interpretation and source admission conditions below. All original fixed-model thresholds and model artifacts remain unchanged. No validation-threshold scan occurred.

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
