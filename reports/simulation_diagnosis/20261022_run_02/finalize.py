from runlib import *
import datetime,difflib,textwrap
protect()
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
old=jload('protected_v2_before.json'); after={p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in old}; changes=[p for p in old if old[p]!=after[p]]
jsave('protected_after.json',after)
if changes:
    jsave('PROTECTED_HASH_HARD_STOP.json',{'changed':changes}); raise RuntimeError('HARD_STOP_PROTECTED_HASH_CHANGE '+str(changes))
r=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],cwd=ROOT,text=True,capture_output=True,env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'})
jsave('git_after.json',{'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
gb=jload('git_v2_before.json'); ge=jload('git_before.json'); same=gb['stdout']==r.stdout
if not same: raise RuntimeError('HARD_STOP_PROTECTED_GIT_STATUS_CHANGE: inspect before/after, no further writes')
files_before={line[3:]:line[:2] for line in gb['stdout'].splitlines()}; files_after={line[3:]:line[:2] for line in r.stdout.splitlines()}
freeze=jload('freeze_manifest_v2.json'); freezeok={k:sha(OUT/freeze[k]['path'])==freeze[k]['sha256'] for k in ('messages','urls','sealed_exam')}
assert all(freezeok.values())
oldrun=ROOT/'reports/simulation_diagnosis/20261022_preflight_01'; previous=json.loads((oldrun/'created_files_sha256.json').read_text(encoding='utf-8')); prior_changes=[p for p,v in previous.items() if sha(oldrun/p)!=v['sha256']]
assert not prior_changes
integrity={'status':'PASS','protected_existing_files':len(old),'changed_protected_files':changes,'git_identical':same,'git_earliest_status_identical':ge['stdout']==r.stdout,'git_exit_codes':[gb['exit_code'],r.returncode],'git_file_by_file':[{ 'path':p,'before_status':files_before.get(p),'after_status':files_after.get(p)} for p in sorted(set(files_before)|set(files_after))],'frozen_hashes':freezeok,'prior_preflight_manifest_files_checked':len(previous),'prior_preflight_changed':prior_changes,'new_source_or_model_writes':0,'candidate_training_fits':0,'model_exports':0,'threshold_changes':0,'Kotlin_Gradle_Android_runs':0}
jsave('final_integrity.json',integrity)
jsave('finalize_command.json',{'argv':sys.orig_argv,'cwd':str(ROOT),'python':sys.version,'executable':sys.executable,'started_UTC':start,'integrity_check_completed_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':0,'note':'Invocation exits0 only after final file/hash validation; external shell result is final confirmation. No dispatcher outputs are written after completion manifest.'})
commands=[]
for p in sorted(OUT.glob('*.command.json')): commands.append({'file':p.name,**jload(p.name)})
jsave('command_ledger.json',commands)
deliverables=['SIMULATION_DESIGN.md','PROVENANCE_AND_LABELS.md','REVIEW_SHEET.csv','SIMULATION_BASELINE_RESULTS.md','FAILURE_DIAGNOSIS.md','FROM_SCRATCH_DEVELOPMENT_PLAN.md','PLAN_AMENDMENT_TO_MASTER_PLAN.md','SIMULATION_RUN_EVIDENCE.md']
def table(h,rows):return '| '+' | '.join(h)+' |\n| '+' | '.join('---' for _ in h)+' |\n'+'\n'.join('| '+' | '.join(str(x).replace('|','/').replace('\n',' ') for x in row)+' |' for row in rows)+'\n'
commandtable=table(['Command record','Exact child argv','CWD','Exit','Seconds'],[[x['file'],' '.join('"'+str(a)+'"' for a in x['argv']),x['cwd'],x['exit_code'],round(x['seconds'],3)] for x in commands])
models=['sentinel-ml/6sep/messages/final/champion_v2_model.pkl','sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl','sentinel-ml/URL-ml/models/v7_champion.joblib','sentinel-ml/URL-ml/models/v8_champion.joblib']
hashrows=table(['Primary artifact','Before SHA-256','After SHA-256'],[[p,old[p]['sha256'],after[p]['sha256']] for p in models])
future=['SIMULATION_RUN_EVIDENCE.md','completion_manifest.json','FINAL_VALIDATION.json']
created=sorted(set([p.relative_to(OUT).as_posix() for p in OUT.rglob('*') if p.is_file()]+future))
evidence=f'''# Simulation run evidence — completed analysis/design pass

Date: October22,2026 (Asia/Calcutta). **OBSERVED:** frozen inference, provisional statistical analysis and all eight requested deliverables are written under `{OUT}`. No files in model/source directories were written. No candidate model or calibrator was fitted, exported or promoted. Frozen thresholds are unchanged. No Kotlin/Gradle/Android execution or Git mutation was performed.

## Scope and evidence status

**OBSERVED:** protected integrity checks PASS for {len(old)} existing source/model/data files, every before/after hash identical. Git porcelain is identical file by file ({len(files_before)} entries), including the earliest persisted run status. Original preflight files match {len(previous)} prior output-manifest hashes. SimulationMessages1005 andURLs102 were frozen before successful reproduction/inference; separate208-row exam has unchanged hash and zero inference rows. Detailed QA is in `quality_checks.json`; final integrity is in `final_integrity.json`. The independently certified final exam and record-level labels remain provisional; no complete original-database recovery or historical model-generation resolution is asserted.

**PROVISIONAL:** reported error rates depend on708 unreviewed benign-message assumptions and authored cases, not validated field truth. All117 sensitive/non-green simulation messages and84 naturalURLs remain NEEDS_REVIEW. No ADJUDICATED row was invented from the master plan's aggregate human-review claim. Review sheet contains1009 rows with blank reviewer fields. Author-created exam grammar/custody weaknesses are explicit in the design. Exact unrecoverable original-row totals are UNKNOWN; recovered candidate counts are exact observations of the strict carver, not certified SQLite table counts.

## Environment and commands

**OBSERVED:** Windows; working directory `{ROOT}`; Messages Python3.14.4/numpy2.5.2/sklearn1.9.0; URL venv Python3.11.15/numpy2.4.6/sklearn1.9.0. Interpreter paths/complete versions and unpickle-warning lists are in reproduction JSON. Messages cache tags include314 and311, not a full historical environment lock. URL joblibs and all eight Messages pickle bundles loaded without recorded unpickle warnings. No portable fallback was necessary. Standard-library/device read failures and compatibility attempts are retained, not relabeled as successful runs.

**OBSERVED exact substantive child commands:** `command_ledger.json` consolidates the individual command records below. Each record includes argv,cwd,environment overrides,exit code,duration and stdout/stderr SHA-256; adjacent stdout/stderr files preserve actual counts/exceptions. Script SHA-256s and all scientific inputs/outputs are in the protected/completion manifests. `dispatch.py` and `dispatch_v2.py` are logging launchers; the child argv is the precise procedure that computed the evidence. Commands used `-B`,explicit UTF-8 readers,OMP/BLAS thread1 andGIT_OPTIONAL_LOCKS=0. No network requests or package installations occurred.

{commandtable}

**OBSERVED direct bootstrap/verification commands (outside child ledger):**

```powershell
python -B reports/simulation_diagnosis/20261022_run_02/integrity.py before
python -B reports/simulation_diagnosis/20261022_run_02/snapshot_v2.py before
python -B reports/simulation_diagnosis/20261022_run_02/safe_entry.py finalize
```

The first inventory exited1 on an inaccessible/disappearing Gradle cache path. The second wrote the valid1750-file before snapshot and Git status, then exited1 during a platform query because the first guard falsely rejected the WindowsNUL device. That was not a source/model/data path or an actual protected write. The later NEW safe-entry correction admits onlyNUL while preserving the protected-filesystem guard. The final command performs before/after hashes and Git comparison, writes this evidence and validates manifests; its exact original argv/cwd/interpreter is in `finalize_command.json`,and external shell exit0 confirms completion. Read-only exploratory `Get-Content`, `rg`, `Get-ChildItem` and interpreter-version commands informed source discovery; scientific claims were then re-derived by the logged scripts or attributed to protected source reports. One exploratory Unicode read failed due to defaultCP1252 and is disclosed in the supplemental error ledger.

**OBSERVED internal verification commands:** `git -C "{ROOT/'sentinel-ai'}" status --porcelain` withoptional locks disabled; SQLite `PRAGMA integrity_check`,sqlite_master schema/count andthreat_records SELECT queries againstNEW read-only copies (`mode=ro&immutable=1`); strict serialized-record carving of rejected SQLite inputs; APKZipFile asset listings and SHA-256. Query definitions/exceptions, candidate counts and transforms are in recovery scripts/JSON. Failed data-format probes may be inside exit0 diagnostic runs: an exit0 does not imply SQLite integrity succeeded. Reproduction avoids executing old scripts that train or save models.

## Counts and data flow

**OBSERVED:**715 strict salvage candidates (72/75/568); exact-key dedup715,zero exact duplicates;154 match the old562 source by ID/time/contenthash. Natural labels are not trusted because of that match. The historical294 replay is a distinct REPORTED source. Review1009rows precedes sender-group reservation. Simulation1005messages =825natural/reported +180authored (45distinct texts,five template families);102URLs =84natural unreviewed +18authored(two unresolved). Reserved exam208rows includes24newly authored cases and is never scored.21Messages training corpora andeightURL source CSVs support overlap tagging; final flagged28messages/66URLs. All/flagged/unflagged results are delivered without dropping rows.

**OBSERVED:**8040Messages prediction rows fromV2,V4.3,sixV4.4variants;204URL rows fromV7/V8.180summary cells,988segment cells,2,000bootstrap replicates/cell,13,536logged comparisons,260error clusters. Each segment flags insufficient independent support. Full reliability-bin curves/ECE/Brier andthreshold sensitivity are files,not assumed conclusions. Plot-library unavailability triggered a documented curve-table fallback without installing dependencies. V4.5 remains REPORTED reference evidence with no invented inference; all explicitly named Step7 models were run. Exacthistorical APKfusion/severity is not claimed by the Python threshold/adjudicator fallback.

## Primary protected hashes

{hashrows}

**OBSERVED:** complete per-file before/after byte lengths and hashes are `protected_v2_before.json` and `protected_after.json`. Inventory excludes hidden/build/tool/venv caches andnew permitted experiment folders; no protected model/data source directory is excluded. It covers both ML andAndroid source/data/model artifacts,includingAPKs andbenchmark/golden files. This is a scoped filesystem audit,not a whole-disk snapshot. The protected500 benchmark was not scored;174golden fixtures were comparison-only parity input,not training/calibration/gate-setting material. Original master plan andold preflight deliverables remain unchanged.

## File-by-file Git status

**OBSERVED before** (`git_v2_before.json`,earliest`git_before.json`also matches):

```text
{gb['stdout'].rstrip()}
```

**OBSERVED after** (`git_after.json`):

```text
{r.stdout.rstrip()}
```

**OBSERVED:** `final_integrity.json` also lists each path with its before/after two-character status. Existing untracked directories remain untracked; no add/commit/reset/revert/checkout/stash/clean/build was used. Protected hash changes would produce a hard-stop record and prevent this completion evidence.

## Corrections and limitations

**OBSERVED:** all errors/retries are retained undernew filenames. See `AUDIT_CORRECTIONS_AND_COMPLETENESS.md` for initial scanner/selection failure,WindowsNUL guard false positive,incomplete snapshot invocation,URLnormalization error,broadened21-corpus inventory,Unicode exploratory-read error,legacyDB/raw-row comparisons,current URLform feature differences,and calibration/logged-detail tables. None was resolved by overwriting an artifact or choosing a convenient historical number. `SIMULATION_BASELINE_RESULTS.md` preserves conflicting V2,V8/schema/overlap/provenance reports explicitly.

**PROVISIONAL:** naturallabels,authorednative translations,original byte-level recovery,thread inference,actual traffic volume/base rate,popularity tiers,historical model generation,semantic grouping completeness,and independent-exam certification are not established. Those uncertainty labels are carried into reports andmetrics. A missingclass denominator isnull,neverzero. Narrowbootstrap intervals from two attack families orzeroFPevidence are not release assurance. No futuretraining should start merely because the provisional simulation finds errors.

## New files created (new folder only)

**OBSERVED:** all new files are within`reports/simulation_diagnosis/20261022_run_02/`; no experiment/source/model directory write was required. `completion_manifest.json` gives per-file SHA-256/size for every existing output except itself andthefinalvalidation anchor. `FINAL_VALIDATION.json` commits the completion-manifest digest; its own digest is printed in the final command output,avoiding a circular self-hash. This complete file list includes the forthcoming anchors:

'''+ '\n'.join('- `'+n+'`' for n in created)+'''

## Completion and decisions next

**OBSERVED:** the eight requested deliverables exist; frozen inference,provisional metrics,diagnosis,concrete separate development plans,traceability,PROPOSED numerical gates andintegrity evidence are complete. The study is not a release certification anddoes not assert perfect recovery/labels. **ASSUMED next user decisions:** complete independent review in a NEW ledger,approve or revise proposed supportedscope/gates/review+compute budgets,andauthorize anyfuture collection/training separately pertrack. ExactKotlin/Gradle/Android work requires separateauthorization. No such work isqueued orstarted.
'''
with (OUT/'SIMULATION_RUN_EVIDENCE.md').open('x',encoding='utf-8',newline='\n') as h:h.write(evidence)
for n in deliverables: assert (OUT/n).exists()
manifest={p.relative_to(OUT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file() and p.name not in ('completion_manifest.json','FINAL_VALIDATION.json')}
jsave('completion_manifest.json',manifest)
assert all(sha(OUT/p)==v['sha256'] for p,v in manifest.items())
final={'status':'COMPLETE_WITH_EXPLICIT_PROVISIONAL_EVIDENCE','deliverables':{n:sha(OUT/n) for n in deliverables},'protected_files_checked':len(old),'protected_hashes_unchanged':True,'git_file_by_file_unchanged':same,'simulation_and_exam_hashes_unchanged':freezeok,'candidate_training_fits':0,'completion_manifest_sha256':sha(OUT/'completion_manifest.json'),'manifest_output_files':len(manifest),'final_validation_self_hash_recorded':'external final command stdout'}
jsave('FINAL_VALIDATION.json',final)
print(json.dumps({'exit_code':0,'deliverables':len(deliverables),'protected_files_unchanged':len(old),'git_status_identical':same,'new_files':len(manifest)+2,'FINAL_VALIDATION_sha256':sha(OUT/'FINAL_VALIDATION.json'),'status':final['status']},indent=2))
