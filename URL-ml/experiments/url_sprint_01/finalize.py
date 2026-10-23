from common import *
import collections, ast
expected=['FEATURE_LEDGER.md','FEATURE_LEDGER.csv','PROBE_DESIGN.md','probe.csv','REVIEW_SAMPLE.csv','BASELINE_RESULTS.md','SAFE_DOMAIN_PRIOR_SPEC.md','URL_FROM_SCRATCH_PLAN.md','PRE_REGISTRATION.md','PRE_REGISTRATION.sha256']
for n in expected:assert (OUT/n).is_file(),n
assert (EXP/'safe_domain_prior.py').is_file()
aud=json.loads(readtext(OUT/'streamed_audit.json'));assert aud['all_freeze_hashes_match'] and aud['pre_registration_hash_verified']
snapshot('after')
before=json.loads(readtext(OUT/'protected_before.json'))['entries'];after=json.loads(readtext(OUT/'protected_after.json'))['entries']
assert set(before)==set(after)
changed=[p for p in before if before[p]!=after[p]]
skipped=[p for p,v in before.items() if v.get('status')=='SKIPPED_EXPLICIT_NO_READ']
missing=[p for p,v in before.items() if v.get('status')=='MISSING']
historic=[p for p,v in before.items() if v.get('matches_prior') is False]
gb=json.loads(readtext(OUT/'git_before.json'));ga=json.loads(readtext(OUT/'git_after.json'))
def gitmap(obj):
    result={}
    for entry in obj['entries']:
        path=entry[3:]
        if path.startswith('"') and path.endswith('"'):
            try:path=json.loads(path)
            except json.JSONDecodeError:pass
        result[path]=entry[:2]
    return result
b=gitmap(gb);a=gitmap(ga)
allpaths=sorted(set(b)|set(a)|set(before))
csvout(OUT/'git_status_file_by_file.csv',({'path':p,'before_status':b.get(p,'NOT_LISTED_clean_or_ignored'),'after_status':a.get(p,'NOT_LISTED_clean_or_ignored'),'status_changed':int(b.get(p)!=a.get(p)),'fixed_protected_list':int(p in before),'protected_read_status':before.get(p,{}).get('status','HASHED' if p in before else 'NOT_IN_FIXED_LIST')} for p in allpaths))
git_changed=[p for p in set(a)|set(b) if a.get(p)!=b.get(p)]
outside=[p for p in git_changed if not p.startswith(('reports/url_sprint_01/','sentinel-ml/URL-ml/experiments/url_sprint_01/'))]
safe=[]
for p in EXP.glob('*.py'):
    source=readtext(p);tree=ast.parse(source)
    fits=[n.lineno for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ('fit','fit_transform','partial_fit')]
    assert not fits,(p,fits)
    safe.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'fit_calls':fits})
js(OUT/'integrity_results.json',{'status':'OBSERVED','fixed_entries':len(before),'hashed_entries':len(before)-len(skipped)-len(missing),'explicit_no_read_skips':len(skipped),'missing_at_start':missing,'protected_changes_during_sprint':changed,'different_from_historical_manifest_before_sprint':historic,'git_before_exit':gb['exit_code'],'git_after_exit':ga['exit_code'],'git_status_changed_outside_sprint_roots':outside,'script_static_no_fit_audit':safe,'no_network_tools_or_requests_used':True,'no_installs':True,'no_kotlin_or_build_execution':True,'fit_count':0})
js(OUT/'command_ledger.json',{'cwd':str(ROOT),'shell':'PowerShell','python':str(U/'venv/Scripts/python.exe'),'common_invocation':"$env:PYTHONDONTWRITEBYTECODE='1'; & 'sentinel-ml/URL-ml/venv/Scripts/python.exe' -B <script>",'commands':[{'script':str(EXP.relative_to(ROOT)/n),'exit_code':0,'log':log} for n,log in [('prepare.py',None),('ledger.py',None),('evaluate.py','reports/url_sprint_01/evaluate_run.log'),('composition.py','reports/url_sprint_01/composition_run.log'),('source_evidence.py',None),('write_reports.py',None),('streamed_audit.py','reports/url_sprint_01/streamed_audit_run.log')]],'exploration_errors':[{'command':'initial rg --files broad URL-ml/sentinel-ai inventory plus nonexistent .agents','shell_exit':1,'effect':'filename output included venv and was truncated; subsequent searches narrowed'},{'command':'ledger.py first attempt within multi-command PowerShell wrapper','shell_exit':0,'python_exit':'not separately captured; uncaught KeyError observed','effect':'new script Windows path-key mismatch corrected; successful rerun before model evaluation'},{'command':'Get-CimInstance Win32_Processor plus rg literal wildcard paths','shell_exit':1,'effect':'CIM denied; rg invalid Windows wildcard path; physical cores subsequently measured with kernel32 topology API'},{'command':'venv Python import psutil probe','shell_exit':1,'effect':'ModuleNotFoundError; no install; kernel32 fallback used'}],'evidence_rule':'Tool transcript is authoritative for shell exits. Artifact hashes, script source and logs supply reproducible substantive commands; intermediate read-only shell inspections are in the transcript.'})
gates=json.loads(readtext(OUT/'gates.json'));pri=json.loads(readtext(OUT/'probe_results.json'))['metrics'];clean=json.loads(readtext(OUT/'clean_test_results.json'))['metrics'];run=json.loads(readtext(OUT/'evaluation_completion.json'));fr=json.loads(readtext(OUT/'freeze.json'));reg=sha(OUT/'PRE_REGISTRATION.md')
write(OUT/'RUN_EVIDENCE.md',f'''# Sprint run evidence and stop state
OBSERVED offline execution on the existing Python 3.11 URL venv. Current user date: 2026-10-23 Asia/Calcutta. Machine-readable timestamps are UTC. All authored outputs live only under reports/url_sprint_01/ and sentinel-ml/URL-ml/experiments/url_sprint_01/. Production files/models and sentinel-ai have not been edited. No Gradle/build, Git mutation command, network request, DNS resolution, URL fetch, package install or GPU use was performed. Zero fit calls executed; static new-script fit-call audit is in integrity_results.json.

Commands: command_ledger.json records cwd, exact venv invocation, substantive script names, exits and logs. The tool transcript preserves intermediate reads and failures. Primary successful script exits are all zero. evaluate.py completed in {run['elapsed_seconds']:.2f} elapsed seconds; elapsed is not claimed CPU time. Composition used a separate single-thread process concurrently, at most two CPU workers total. Windows kernel32 GetLogicalProcessorInformationEx established 10 physical cores, quarter-core floor=2. Numerical pools were capped at one per process and CUDA_VISIBLE_DEVICES=-1. environment.json records runtime/library versions and measured thread pools. No extra inference followed PRE_REGISTRATION hashing: only streamed correspondence/statistics and integrity checks.

Frozen artifacts: V7 d414bf668484ea5ba6056b626f0d8e674e0085208ba23d964522b09557affdaa; V8 073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58. The model class is HistGradientBoostingClassifier with the exact 67-name order. models.json records parameters and warnings. The streamed score audit observes V7 and V8 raw probabilities identical on all 50,511 clean-test rows; threshold/adjudicator paths account for the differing alert counts. No learned weights changed.

Protection: fixed source list reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json, {len(before)} entries; {len(before)-len(skipped)-len(missing)} hashed before/after, {len(skipped)} explicitly unreadable-by-instruction entries skipped, {len(missing)} missing at start. This is a fixed-file pass, never a protected-directory walk. Conflicting instructions: hashing every listed file would read Messages-ml/datasets_v5; the explicit no-read prohibition was honored and those 501 entries are not claimed verified. During-run changed protected entries: {len(changed)}. Baseline differences from the historical manifest: {len(historic)} (preserved, not attributed to this sprint). Git status file by file is git_status_file_by_file.csv, with complete raw before/after entries in JSON. NOT_LISTED may mean clean or ignored. Git status changes outside authorized output roots: {len(outside)}; inspect integrity_results.json if nonzero. Existing user/other-agent changes were not reverted.

Probe label provenance: PROVISIONAL authored expectations, never model-generated labels. 600 benign/300 attack rows, 120 review rows and 160 separate red-team cases. probe.csv SHA-256 `{fr['probe_sha256']}` was frozen before any model load. evaluation_freeze.json records policy source, decision table, registry and gate hashes before inference. Frozen scores are archived by row; no thresholds/policy constants were changed after observing results. Burned 500/174 received regression reports only, last; their blind URL-membership exclusion was the sole pre-score access used to prevent probe reuse. The regression fixture outputs are not semantic threat labels.

Reproduction: V8 URL TP=22,835/23,158, FP=263/27,353; fallback TP=22,825, FP=207. Probe V8 URL FP=387/600, authored attack TP=300/300. Prior FP=354/600, authored TP=300/300; clean TP=22,853, FP=263. Reduction 8.527%, below pre-registered 20%. Red-team bypass/discount zero of 160. Golden fixture mismatch 1; burned benchmark FP 420->422, including two new false alerts. Promotion rejected on three gates. No repair/tuning from burned outcomes.

Labels on statements: OBSERVED denotes measured code/file/count/inference results; REPORTED denotes historical report or source-dataset labels/provenance; ASSUMED denotes prevalence and 30/day traffic calculations; PROVISIONAL denotes authored probe labels, domain/example registry membership, and proposed future data/fit design. Syntactic credential/redirect/payload hazard is not verified malicious content. Conflicts and procedural errors are preserved in METHOD_LIMITATIONS.md and HISTORICAL_EVIDENCE_NOTES.md. The initial evaluator temporarily materialized CSV rows; streamed_audit.py now re-reads a minimal projection row by row and verifies every score-row correspondence and confusion count. This correction does not erase the original shortcoming.

Feature ledger: 67 exact expressions plus helper definitions and pairwise collapse tests; static Python/Kotlin constants and divergences; 6,000 clean-test rows x 67 column permutations x 3 repeats, raw V8 average precision, one numerical thread. Repeated importance values and sample hash accompany the ledger. No feature change or causal claim.

Composition: nine existing URL CSVs were independently row-streamed with counters only. cleaned_dataset.csv has 134,850 benign, all www hosts, and 100,945 attack; source provenance cannot be reconstructed from counts alone. New full-pool data program, domain-disjoint validation, untouched user exam and guarded apex recalls replace rejected simple augmentation designs. Historical files can overlap and cannot be added as independent samples.

PRE_REGISTRATION.md SHA-256 `{reg}` (also PRE_REGISTRATION.sha256) is verified. Status: STOPPED BEFORE TRAINING. No fit until the exact reply APPROVED and required reviewed source evidence is supplied. Future work <=8 fits and <=4 aggregate CPU-hours, unchanged architecture/features, validation-only candidate/threshold selection, all registered gates. The user must review REVIEW_SAMPLE.csv (>6/120 wrong invalidates the probe), supply offline source evidence and private exam, and optionally provide the requested Tranco CSV and metadata. No Tranco CSV was present; no rank was fabricated.
''')
write(OUT/'DELIVERABLE_INDEX.md','''# URL sprint 01
Status: audit/evaluation complete, policy rejected, fresh fitting stopped for approval.

- FEATURE_LEDGER.md / FEATURE_LEDGER.csv — exact 67-feature contract and static parity findings.
- PERMUTATION_IMPORTANCE.md / permutation_importance.csv — measured raw-V8 importance.
- PROBE_DESIGN.md / probe.csv / freeze.json — provisional 900-row probe and immutable hashes.
- REVIEW_SAMPLE.csv — balanced 120-row human review, empty user_agree/user_note.
- BASELINE_RESULTS.md — clean reproduction, probe rates, PPV/day scenarios, intervals, failures and gate verdicts.
- probe_breakdowns.csv / probe_failures.csv — per-form/category/platform/joint-attribute tables and every failure.
- SAFE_DOMAIN_PRIOR_SPEC.md / ranked_domain_registry.json — fixed four-state decision table, scope and Tranco request.
- ../../sentinel-ml/URL-ml/experiments/url_sprint_01/safe_domain_prior.py — offline prototype.
- red_team.csv / red_team_results.csv — 160 pre-authored invariant cases.
- URL_FROM_SCRATCH_PLAN.md / PRE_REGISTRATION.md / PRE_REGISTRATION.sha256 — bounded data/fit plan; approval required.
- RUN_EVIDENCE.md / METHOD_LIMITATIONS.md / HISTORICAL_EVIDENCE_NOTES.md — provenance, errors and conflicts.
- integrity_results.json / git_status_file_by_file.csv / artifact_manifest.json — fixed-list integrity, file statuses and deliverable hashes.

Golden and 500 outputs are historical regression reports only. Read their output-contract caveat; no candidate was tuned on them. All probe expectations are provisional and require human review. No fitting occurred.
''')
manifest=[]
# Only walk the newly authored output roots, never any protected source tree.
for folder in (OUT,EXP):
    for p in sorted(folder.rglob('*')):
        if p.is_file() and p.name not in ('artifact_manifest.json','finalize_run.log'):
            manifest.append({'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)})
js(OUT/'artifact_manifest.json',{'status':'OBSERVED','time_utc':stamp(),'self_excluded':True,'excluded_log':'finalize_run.log because the shell is still writing it','artifacts':manifest})
assert not changed,changed
assert not outside,outside
print('Final checks passed; hashed',len(before)-len(skipped)-len(missing),'protected files; skipped',len(skipped),'no changes; artifacts',len(manifest),'PRE_REGISTRATION',reg,flush=True)
