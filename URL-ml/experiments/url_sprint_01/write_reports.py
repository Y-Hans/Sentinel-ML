from common import *
import math,collections,re
def load(name):return json.loads(readtext(OUT/name))
clean=load('clean_test_results.json')['metrics'];probe=load('probe_results.json')['metrics'];burn=load('burned_regression_results.json');gates=load('gates.json');composition=load('data_composition.json');freeze=load('freeze.json');env=load('environment.json');apex=load('clean_test_apex_results.json')
def pct(v):return 'N/A' if v is None else f'{100*v:.3f}%'
def ci(v):return 'N/A' if v is None else '['+', '.join(pct(a) for a in v)+']'
def table(metrics):
    s='| Mode | FP / benign | FPR (Wilson 95%) | TP / attack | Recall (Wilson 95%) | False alerts / 1,000 benign | ASSUMED false alerts / day at 30 benign URLs |\n|---|---|---|---|---|---|---|\n'
    for n,m in metrics.items():s+=f"| {n} | {m['fp']}/{m['benign_n']} | {pct(m['fpr'])} {ci(m['fpr_wilson95'])} | {m['tp']}/{m['attack_n']} | {pct(m['recall'])} {ci(m['recall_wilson95'])} | {m['false_alerts_per_1000']:.2f} | {m['assumed_false_alerts_day_30_benign_urls']:.3f} |\n"
    return s
def ppvtable(metrics):
    s='| Mode | ASSUMED PPV at 0.1% attacks | at 1% | at 5% |\n|---|---|---|---|\n'
    for n,m in metrics.items():s+='| '+n+' | '+' | '.join(pct(m['assumed_ppv'][str(p)]) for p in (.001,.01,.05))+' |\n'
    return s
prior=probe['prior'];base=probe['v8_url_adjudicated'];reduction=(base['fp']-prior['fp'])/base['fp']
md=f'''# Baseline results — CPU only, frozen models
OBSERVED measurements; authored-probe labels are PROVISIONAL. No fit or threshold selection was performed. A score is never treated as a factual URL label. Models loaded directly from the required Python 3.11 venv, with hashes verified before inference; no portable-model fallback. V7 threshold is {load('models.json')['7']['threshold']}; V8 is 0.28. Sources, split hash, environment and row scores accompany this report.

Reproduction: the clean group split exactly reproduces 22,835/23,158 attacks and 263/27,353 benign false alerts with URL strings: 98.605% recall / 0.962% FPR. Without URL strings: 22,825 TP and 207 FP, 98.562% / 0.757%. Thus URL adjudication adds 10 TP and 56 FP. No-URL fallback matches raw alert decisions, but is a different runtime path. Report both, never substitute fallback for production URL adjudication.

Clean test (OBSERVED against existing REPORTED dataset labels; data label truth was not reverified):

{table(clean)}
ASSUMED prevalence calculations applied to clean-test rates:

{ppvtable(clean)}
New probe, SHA-256 `{freeze['probe_sha256']}`, 600 provisional benign / 300 authored attack scenarios:

{table(probe)}
ASSUMED PPV under deployment prevalences (not the probe's 1/3 attack mix):

{ppvtable(probe)}
PPV = prevalence*recall / (prevalence*recall + (1-prevalence)*FPR). At 30 total URLs/day rather than 30 benign URLs/day, false alerts/day = 30*(1-prevalence)*FPR. The table's conservative shorthand assumes all 30 opportunities are benign. These are scenario calculations, not measured traffic forecasts. All Wilson intervals use row counts and are descriptive; correlated template examples and uncertain labels prevent a deployment-level inference. Zero misses among 300 authors' syntax-rich attack scenarios is not proof of perfect recall. The attack set overrepresents explicit credential/payload/redirect cues and lacks an adequate low-signal malicious-root cohort. A separately sourced untouched exam is necessary.

Probe prior effect: {base['fp']} -> {prior['fp']} benign false alerts ({100*reduction:.2f}% relative reduction); clean attack recall {pct(clean['v8_url_adjudicated']['recall'])} -> {pct(clean['prior']['recall'])}. The frozen 0.25 cap does not eliminate high-score roots; no cap/threshold is tuned after observing this result. There are {load('probe_results.json')['prior_states']['KNOWN_SAFE_SHAPE']} KNOWN_SAFE_SHAPE rows; state membership does not promise a below-threshold outcome.

Per-form/category/platform and joint attributes: probe_breakdowns.csv/.json contain counts, confusion matrices, Wilson intervals and indicative-only markers for class denominator N<30. Missing class denominators are N/A. has_payload and tenant_hosted are authored attributes, not web observations. probe_failures.csv contains every false alert/missed attack, ranked worst first per model. Sample worst cases are below; no examples are selected to tune the policy.
'''
fail=list(rows(OUT/'probe_failures.csv'))
for mode in ('v8_url_adjudicated','prior'):
    md+=f'\n{mode}, highest benign alerts:\n\n'
    for r in [r for r in fail if r['model']==mode and r['failure']=='false_alert'][:8]:md+=f"- `{r['url']}` — score {float(r['score']):.4f}, {r['category']} / {r['form']}.\n"
    misses=[r for r in fail if r['model']==mode and r['failure']=='missed_attack'][:8]
    md+='\nAuthored attack misses: '+('none.' if not misses else '\n\n'+'\n'.join(f"- `{r['url']}` — {float(r['score']):.4f}" for r in misses))+'\n'
md+='''
REPORTED Phase 1C.1 comparison, reference only: burned benchmark FPR 84.00% (420/500), bare apex 100% (200/200), repo paths 96.67% (145/150), search 50% (75/150). This benchmark has a different deliberately difficult mixture from both clean data and the new probe; do not interpret a cross-corpus percentage difference as a model improvement. Historical B1 numbers differ; see HISTORICAL_EVIDENCE_NOTES.md.

Regression reports scored last, after freezing the policy: burned_regression_results.json, golden_regression_report.csv and burned_500_regression_report.csv. The 174 golden labels are frozen expected outputs, not established malicious/benign truth. Here “correct-to-wrong” means a new mismatch to that fixture contract. Do not use the fixture probabilities or labels as training targets. Changes that could represent a semantic correction still fail strict output parity. No policy revision follows these reports.

| Gate | Observed value | Status |
|---|---|---|
'''
for g in gates['gates']:md+=f"| {g['gate']} | {json.dumps(g['value'])} | {'PASS' if g['pass_gate'] else 'FAIL'} |\n"
md+=f"\nStrict golden output parity: {'PASS' if gates['strict_golden_output_parity_pass'] else 'FAIL'}; {burn['golden']['candidate_fixture_output_disagreements']} fixture-output disagreements. Golden baseline output disagreements: {burn['golden']['baseline_fixture_output_disagreements']}. Overall prototype verdict: {'gates pass but review still required' if gates['all_pass'] else 'REJECT for promotion; preserve frozen candidate and failures'}. No fit/deployment was performed.\n"
write(OUT/'BASELINE_RESULTS.md',md)

comp='''# From-scratch URL data and fit plan — APPROVAL REQUIRED
No training has occurred. Keep HistGradientBoostingClassifier and exactly the current 67 features in alphabetical order; fresh weights, warm_start=False. Feature extraction and the Kotlin contract stay frozen. The model cannot learn domain reputation or page content absent from its features. New composition is a falsifiable experiment, not a promise that these features can separate all apex threats.

OBSERVED streaming inventory (not a complete historical fit manifest):

| Data file | BENIGN | ATTACK | Approx. unique registrable domains | Cross-class domains | Domain duplicate excess rows |
|---|---|---|---|---|---|
'''
for r in composition['files']:comp+=f"| {r['path'].split('/')[-1]} | {r['class_counts'].get('BENIGN',0)} | {r['class_counts'].get('ATTACK',0)} | {r['unique_registrable_domains_approx']} | {r['cross_class_domain_count']} | {r['duplicate_domain_excess_rows']} |\n"
comp+='\nCleaned-data source/form skew:\n\n| Class | Dimension | Value | Rows |\n|---|---|---|---|\n'
for r in composition['files'][0]['shapes']:comp+=f"| {r['class']} | {r['dimension']} | {r['value']} | {r['n']} |\n"
comp+='''
All per-file source counts, domain concentration, exact URL duplicates, conflicts, path/query forms and hashes are in data_composition.json and the source/shape CSVs. cleaned_dataset.csv lacks source-family provenance, and data.csv mirrors its original source; final_dataset.csv has DatasetSource. Do not sum these overlapping files as independent evidence. Label mapping is recorded per file; original/cleaned 1 means benign and must be inverted. The counters use V8's short suffix table and are approximate for unlisted public/private suffixes. Domain mix (apex/www/subdomain) is separate from empty-path shape. Cross-class domains are plausible shared platforms; preserve and review them, not majority-vote them benign. Historical V8 export wraps the V7 base model; a row-level fit manifest is still missing.

Data program (user supplies offline files; no downloads/resolution/fetches in this sprint):
1. Supply deidentified navigation exports with URL, capture date, source family, label basis and review status. Sample actual bare roots, www roots, mobile/deep navigation, search/root queries, Indian regional/government/utility/bank/rail portals, software pages, shorteners and tenant links. Strip secrets consistently and record the transform; do not use altered syntax as labels. A known domain, rank or nonalerting model score does not establish endpoint truth.
2. Supply dated independently reviewed attack URLs with case/evidence IDs from internal confirmed incidents or user-obtained offline feeds. Include benign-looking malicious apexes with no credential tokens, same-brand lookalikes, new tenants, encoded payloads, open redirects, raw IP and IDN; evidence must support malicious destination/content when lexical syntax alone cannot. Keep conflicting labels/evidence as quarantined disputes. Record source date/hash and permission; model scores never supply labels.
3. Supply a dated offline full public suffix list including private suffixes and optional dated domains-only Tranco top-100k CSV. Hash before ingestion. Grouping can improve independently of the unchanged feature extractor. No suffix/rank update is silently inserted into the 67 features. Rank is sampling metadata and policy prior only.
4. Rebuild the pool from independent source families rather than append 15,000 benign roots. Desired minimum reviewed counts before fitting: 10,000 benign roots across >=5,000 parents; 10,000 evidence-backed low-signal apex attacks across >=5,000 parents; >=2,000 examples in each critical benign path/query/tenant family and attack payload/redirect/credential/IDN family where evidence allows. Cap rows per parent/source family (initial maximum 20, except separately documented platform holdouts) and cap near-duplicate templates at three. These minimums are provisional supply goals; if unmet, revise the registration for user review before any fit.
5. Join on canonical URL, normalized percent-decoding signatures and parent group; deduplicate within source and across sources before split. Audit cross-class exact URL conflicts, time validity and common template campaigns; quarantine conflicts. Never relabel all apexes from one source safe or all free tenants bad. A/B source families must both contribute path/query/host forms; report joint class x source x parent-shape x path/query cells and enforce minimum support.
6. Freeze new 70/15/15 parent-disjoint train/validation/test splits with a stable salted hash assignment and temporal/source audit. Use offline PSL registrable domains including private suffixes; all canonical variants and rows for a parent stay in one split. Ordinary github.com/docs.google.com share their registrable parent and stay together, even if that prevents platform-specific coverage in every split. Use an additional separate platform holdout report; do not break domain disjointness to populate cells. Existing clean test, this probe, the 500 and golden are now diagnostic/burned exclusions from new training/validation/test; exclude their parent groups from the new fitting pool. User-held exam remains unseen, including its URLs/domains; the user checks overlap privately and withholds conflicting rows without exposing exam identities.
7. The user holds a NEW untouched exam of >=2,000 benign +1,000 independently verified attacks, sampled from later dates and independent sources with joint attributes and >=100 low-signal malicious roots. The user authors/collects and labels it privately; neither this authored probe nor its review sample qualifies. One final candidate is submitted for a single evaluation. Pre-register the exam gates on supplied baseline denominators before the user unseals results. Do not create or inspect the exam here.

Avoiding Track A / S2-E: compose the whole dataset across source/parent/shape rather than add a big benign-root tranche or counter it with one malicious-root tranche. Preserve heterogeneous low-signal apex attacks, cap domain/source duplication, hold parents out, and evaluate apex recall separately. Validation uses worst-slice constraints and paired newly missed attacks, so gains on obvious hosted phishing cannot mask apex losses. Freeze data manifests before fitting and inspect feature collisions among disputed opposite-label examples; indistinguishable 67-feature examples define an accuracy limit. If that limit blocks gates, reject and propose features separately with Kotlin cost. Do not add the rejected B1 dictionary or rerun threshold-only apex rules.

Fit budget and selection: at most 8 fresh CPU fits and at most 4 aggregate CPU-hours, whichever comes first, one numerical thread (or <=floor(physical cores/4) after remeasurement), no GPU, installs or network. Stop workers before crossing the CPU budget using a supervisor that sums worker user+system CPU time. Reserve 15 minutes for final inference; no individual fit gets >25 CPU-minutes. Timeouts count toward the eight attempts; no hidden refits. Use 2 pre-hashed full-pool compositions (parent-capped equal source-family sampling; inverse-parent/source weights capped 3:1) x 2 conservative HGB parameter choices x 2 fixed seeds (42,20261023). Both compositions must meet the same reviewed cell minimums; these are not simple balanced-apex additions. Parameters: learning_rate=.06, max_iter=300, max_leaf_nodes in (31,40), min_samples_leaf=30, l2_regularization=5, early_stopping=False, warm_start=False, otherwise explicit defaults frozen with sklearn 1.9.0. Weights are fit-only. Use external domain-disjoint validation, never HGB random-row internal validation. No test, probe or burned set chooses composition/parameters/threshold.

Choose a global threshold using validation only: scan its unique raw probabilities and 0/1 boundaries; execute the frozen URL adjudicator at each candidate threshold without changing rule constants. Filter candidates by validation benign FPR <=1%, attack recall >=98.405%, and apex/low-signal recall within 0.2 percentage points of frozen V8 on the same validation. Prefer maximum minimum critical-slice recall, then lowest FPR, then fewer leaves, then earlier seed. Reject if no feasible threshold. Choose exactly one final model by validation criteria, freeze it and its threshold, and report the new domain-disjoint test, clean legacy test, current probe, red-team, 174 golden and 500 once. No revision or alternate candidate selection after these final reports. The safe-domain-prior prototype failed gates and is not bundled by default; any revised policy needs a fresh registration and unseen holdout. Any final report failure rejects promotion. Runtime export/Kotlin integration is a later separately approved task.

Final acceptance gates derived from the observed V8 URL adjudication baseline: at least 20% fewer probe benign false alerts (<=309/600 versus 387/600), no >0.2 percentage-point attack recall loss on clean test (>=22,789/23,158; baseline 22,835), no >0.2-point V8-normalized apex loss (>=4,162/4,254; baseline 4,170), <=46 newly missed clean attacks and <=8 newly missed apex attacks (paired, even if other recoveries offset them), clean FPR <=1.0% (<=273/27,353), probe attack recall no more than 0.2-point loss (requires 300/300 with this N), zero bypass/discount on payload/redirect/credential red-team cases, zero golden fixture regressions and no increase/new false alerts on burned 500. All class/slice N<30 results remain indicative. New domain-disjoint test must also satisfy validation numeric gates and critical-slice recall constraints against V8 on that same test. User-held exam gates must be frozen before its baseline scores are disclosed; target >=20% benign FP reduction and <=0.2-point recall loss, same hard-invariant zero bypass. Report uncertainty and all failures; do not tune from them.

The golden contract can call legitimate roots MALICIOUS. Correcting those predictions conflicts with strict zero fixture regression. Do not call fixture outputs threat truth, alter fixtures, waive gates, or overfit to fixture rows. Any requested semantic-fixture migration requires an explicit separate review by the user. A fit may be scientifically useful and still fail the sprint's promotion gates.

Two-day schedule after approval and data delivery: day 1 ingestion/provenance/conflict review/group split (CPU budget mostly untouched), freeze pool manifest; day 2 <=8 fits inside <=4 aggregate CPU-hours, validation selection, one final report and stop. If source evidence or private exam is missing, data work may continue but fitting/promotion remains gated. No training before the exact user reply APPROVED; approval alone does not manufacture missing data evidence.
'''
write(OUT/'URL_FROM_SCRATCH_PLAN.md',comp)

pi=sorted(rows(OUT/'permutation_importance.csv'),key=lambda r:-float(r['ap_drop_mean']))
write(OUT/'PERMUTATION_IMPORTANCE.md','''# OBSERVED permutation importance
Frozen raw V8; average precision on a pre-fixed stratified clean-test sample of 6,000 (3,000 per class), seed 20261023; 67 feature columns, 3 repeats each, one CPU thread, no fits. Full ordered results and repeated values are in permutation_importance.csv. Negative drops are retained. Correlated features/interactions can mask dependence. Importance is descriptive and cannot justify dropping/changing features in this sprint.

| Feature | Mean AP drop | Repeat SD |
|---|---|---|
'''+''.join(f"| {r['feature']} | {float(r['ap_drop_mean']):.6f} | {float(r['ap_drop_sd']):.6f} |\n" for r in pi))

# Evidence correction: do not silently make memory/materialization claims.
write(OUT/'METHOD_LIMITATIONS.md','''# Limitations and disclosed errors
- Initial rg inventory accidentally included venv filenames and produced truncated output, exit 1; it did not enumerate/read Messages-ml or datasets_v5 contents. Later searches were narrowed. An rg wildcard path in PowerShell also failed. Get-CimInstance core inventory was denied; the Windows processor-topology API established 10 physical cores instead. psutil was absent; nothing was installed.
- ledger.py first failed with a Windows backslash/forward-slash dictionary key mismatch. Corrected only the new sprint script and reran successfully before model evaluation. No protected file was edited.
- evaluate.py consumed cleaned_dataset.csv through csv.DictReader, but initially materialized the original rows before keeping URL/label columns. This was not strictly bounded-memory streaming. No pandas eager CSV read or full-file print occurred. The composition audit is strictly row-streamed with counters only. Treat the initial evaluator's loading implementation as a procedural shortcoming; a bounded read correction and streamed score audit are provided separately. Statistical results are unaffected by row loading mode.
- The fixed 1,750-entry protection manifest includes 501 files under explicitly prohibited directories. Those entries are SKIPPED_EXPLICIT_NO_READ, not claimed verified. The remaining entries are hashed using the fixed list only; no protected directory walk is performed. Old historical-manifest differences are separated from changes during this run.
- Provisional attack hostnames include long invented strings, but offline work cannot establish unregistered status, endpoint exploitability, benign shortener destinations, file safety, or page content. Main punycode scenarios include syntactic xn-- flags without validating that every label is a meaningful IDNA homoglyph. Preserve them as provisional hazard probes, not verified live attacks. Public-host download/credential/redirect URLs are adversarial scenarios on known hosts, not assertions about those providers.
- Golden label/isMalicious fields are expected frozen outputs; correctness labels in regression JSON mean fixture-contract agreement, never semantic URL truth. No model score has been used as a training/data truth label. Historical reports contain contradictory baselines and denominator errors; see historical evidence notes.
- The probe deliberately uses four canonical forms for each of 50 root domains; those are correlated, not 200 independent domain observations. Deep templates cap at three. Search terms and known platform rows also correlate. Wilson intervals do not account for author/template clustering or provisional label error. Perfect authored attack recall is not a generalization result. Main attacks overrepresent explicit credential/payload/redirect syntax; independently sourced low-signal apex cases are required before fitting.
- No Tranco input was supplied. Curated registry membership is not a real ranking and is never represented as one. No deployment, Kotlin execution, training or feature-contract modification occurred.
''')
pre=f'''# Pre-registration — STOP FOR APPROVAL
PROVISIONAL plan; written after baseline/policy evaluation and before any fresh fit. No fit is authorized by this document. Execute training only after the exact user reply APPROVED, delivery/review of the required evidence-backed new composition, and hashed split manifest. No existing artifact is replaced.

Approved scope sought: <=8 fresh HistGradientBoostingClassifier CPU fits, <=4 aggregate CPU-hours, the exact current 67 features/order, one numerical CPU thread, new domain/source-balanced pool with domain-disjoint splits, validation-only global threshold and candidate selection. No network, package install, GPU, Kotlin/build/Git mutation, architecture/feature change, Track A/S2-E replay, B1 dictionary, or apex-only threshold modulation. Output roots remain reports/url_sprint_01/ and sentinel-ml/URL-ml/experiments/url_sprint_01/. New stage-specific filenames must avoid overwriting sprint evidence.

Immutable plan: URL_FROM_SCRATCH_PLAN.md SHA-256 `{sha(OUT/'URL_FROM_SCRATCH_PLAN.md')}`.
Baseline report: BASELINE_RESULTS.md SHA-256 `{sha(OUT/'BASELINE_RESULTS.md')}`.
Feature order/source ledger: FEATURE_LEDGER.csv SHA-256 `{sha(OUT/'FEATURE_LEDGER.csv')}`.
Policy frozen gates: `{sha(OUT/'POLICY_GATES_BEFORE_EVALUATION.md')}`; prototype source: `{sha(EXP/'safe_domain_prior.py')}` (failed prototype is not automatically included in training output).
Probe: `{freeze['probe_sha256']}`. The probe is development evidence, not a private exam. If user review finds >5% wrong labels (>6/120), invalidate/regenerate and re-register before fitting.

Hard gates for the selected final model: probe benign FP <=309/600 and attack TP=300/300; clean TP>=22,789/23,158 with <=46 paired new misses; V8-normalized apex TP>=4,162/4,254 with <=8 paired new misses; clean FP<=273/27,353; zero payload/redirect/credential bypass; zero golden expected-output regression; no increase/new false alerts on the 500 (regression reports only). New domain-disjoint validation/test require FPR<=1%, recall>=98.405%, apex/critical-slice recall within 0.2 points of frozen V8 on the same split. Private exam: pre-register >=20% relative FP reduction, <=0.2-point recall loss and zero invariant bypass before its results/URLs are exposed. No candidate/threshold selection from clean test/probe/golden/500/private exam. No second chosen candidate after final report failure. All gates conjunctive; failure means reject promotion.

New pool requirements, conflict/source audit, private/public suffix grouping, 70/15/15 domain splits, two compositions x two leaf choices x two seeds, tie-breaks, CPU supervisor/timeouts and user-held exam are specified in the hashed plan. No data/source changes after freeze without a new user-reviewed registration. All <=8 attempted fits including timeouts count; budget exhaustion rejects additional fits. Keep model outputs out of labels. A feature change requires a separate written Python/Kotlin cost proposal and user authorization.

Outstanding user review/provision: REVIEW_SAMPLE.csv; dated domains-only Tranco top-100k and metadata; evidence-backed benign/attack URL sources including low-signal apex attacks; offline public/private suffix list; hidden exam independently held by user. Current safe-prior gate outcome is in gates.json; a failed candidate cannot be promoted. Golden expected-output/semantic safety conflict requires separate review; no implicit waiver.

STOP. Reply APPROVED to authorize this plan subject to the above data prerequisites. Until then, fit count remains zero.
'''
write(OUT/'PRE_REGISTRATION.md',pre)
write(OUT/'PRE_REGISTRATION.sha256',sha(OUT/'PRE_REGISTRATION.md')+'  PRE_REGISTRATION.md\n')
print('Reports written; PRE_REGISTRATION',sha(OUT/'PRE_REGISTRATION.md'),flush=True)
