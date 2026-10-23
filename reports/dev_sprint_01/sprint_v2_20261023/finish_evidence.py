from sprintlib import *
from datetime import datetime,timezone
guard()
t0=time.time();argv=[sys.executable,'-B',str(Path(__file__).resolve())]
check=load(OUT/'integrity_checks.json');assert not check['protected_changed'] and not check['freeze_changes']
assert check['git_status_identical'] and check['v1_prior_parity_compared']==10560
# Explicitly settle seed/calibration bookkeeping without rewriting registration.
write('PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md','''# Execution clarification — PROPOSED, approval required

This supplements PRE_REGISTRATION.md; both hashes form the approval bundle. No candidate is fit now.

PROPOSED: fixed primary seed20261023 is the only seed eligible for final deployment nomination and temperature calibration. Seed20261024 is a robustness replicate for each of the final two configurations; do not pick whichever seed scores best. Report both seeds on selection validation and the one-shot final evaluation. Calibrate each primary model once on calibration rows; retain T=1 as the uncalibrated reference. The second-seed models are reported uncalibrated, using the primary model's frozen uncalibrated threshold rule/selected threshold; they cannot replace the primary after exam results. Thus8 HGB fits plus2 scalar temperature fits remain the maximum. Final decisions must disclose any seed sensitivity.

PROPOSED: if no reviewed Hinglish validation data arrive by the approved working-hour10 fallback, choose thresholds from English validation only; all Hinglish gates remain UNPROVEN and no Hinglish release claim is allowed. This fallback does not waive manifest checks or Stage4 approval. Training must not begin while the sealed-exam leakage strategy or source mappings remain unapproved.

PROPOSED: G2 compares the same English metadata rows (92/707 frozen V4.3 false alerts); full TEST92/708 remains a historical companion result. G4 is combined benign+spam <=5% per set, with separate BENIGN and SPAM cells always shown. No class-mix reweighting or pooling can convert a failure into a pass. G7 requires later authorized export for actual byte measurement; estimates remain UNPROVEN. The optional .2% deployment FPR target is a separate proposal and does not authorize release.
''')
save('approval_bundle.json',{'status':'PROPOSED_AWAITING_USER_APPROVAL','files':{p:sha(OUT/p) for p in ['PRE_REGISTRATION.md','PRE_REGISTRATION_EXECUTION_CLARIFICATIONS.md']},'prerequisites':['DATASETS MOVED and manifest verification or approved hour10 English fallback','reviewed labels/mappings','sealed exclusion-index or approved deferred leakage check'],'fits_so_far':0})
arithmetic={'G1_English_min_TP':math.ceil(.965*1551),'G1_full_TEST_min_TP':math.ceil(.965*1556),'G2_English_FAR':92/707,'G2_full_FAR':92/708,'G3_probe_Wilson_at_510_of_600':wilson(510,600),'G4_Wilson_at_25_of_500':wilson(25,500),'zero_FP_N_for_Wilson_upper_le_002':next(n for n in range(1,10000) if wilson(0,n)[1]<=.002),'scenarios':[]}
for prev in [.001,.01,.05]:
 for fpr in [.05,.002]:
  recall=.85;arithmetic['scenarios'].append({'ASSUMED_prevalence':prev,'ASSUMED_recall':recall,'ASSUMED_FPR':fpr,'ASSUMED_notifications_per_day':100,'projected_PPV':prev*recall/(prev*recall+(1-prev)*fpr),'false_alerts_per_user_day':100*(1-prev)*fpr})
save('gate_projection_arithmetic.json',arithmetic)
summary=list(rows(OUT/'probe_summary.jsonl'));comp=[]
for model in [r['model'] for r in load(OUT/'verdicts.json')]:
 for scope in ['all','no_overlap']:
  r=next(r for r in summary if r['model']==model and r['set']=='v2' and r['scope']==scope)
  comp.append([model,scope,r['MALICIOUS']['k'],r['MALICIOUS']['n'],r['BENIGN_SPAM']['k'],r['BENIGN_SPAM']['n'],json.dumps(r['confusion'])])
def table(head,rr):return '| '+' | '.join(head)+' |\n| '+' | '.join('---' for _ in head)+' |\n'+''.join('| '+' | '.join(map(str,r))+' |\n' for r in rr)
write('PROBE_V2_RESULTS_SUPPLEMENT.md','# Overlap sensitivity and confusion\n\nOBSERVED predictions / ASSUMED synthetic labels. Confusion rows=true BENIGN,SPAM,MALICIOUS; columns=predicted BENIGN,SPAM,MALICIOUS. Flagged rows are tagged, not deleted from frozen material. All base verdicts remain on the full v2.\n\n'+table(['Model','Scope','AttackTP','AttackN','NonmaliciousFP','NonmaliciousN','3-way confusion'],comp)+'\nOBSERVED same-author prior blind-pass disagreements were46 Hinglish MALICIOUS +25 English MALICIOUS =71 across languages. Its labels are not independent ground truth. V1 active-pattern subset is selection-biased.\n\nPROVISIONAL: neither high v2 recall nor low no-overlap FAR, if observed, demonstrates natural traffic performance. Shared phrasing and reserved-domain syntax remain limitations. Review frozen/REVIEW_SAMPLE_v2.csv before trust.\n')
commands=[load(p) for p in sorted(OUT.glob('*.command.json'))]
save('command_ledger.json',commands)
gb=load(OUT/'git_before.json');ga=load(OUT/'git_after.json');freeze=load(OUT/'freeze_manifest.json');env=load(OUT/'inference_manifest.json');top=load(OUT/'cpu_topology.json')
cmdtable=table(['Command argv','CWD','Exit','Wall seconds'],[[' '.join('"'+s+'"' for s in r['argv']),r['cwd'],r['exit_code'],f"{r['wall_seconds']:.3f}"] for r in commands])
modelhashes=[]
for m in env['models']:
 for p,s in m['files'].items():modelhashes.append([m['model'],p,s,s])
made=sorted(p.relative_to(OUT).as_posix() for p in OUT.rglob('*') if p.is_file())
evidence=f'''# Run evidence — Messages sprint v2 through Stage4

OBSERVED date23 October2026, Asia/Calcutta. Workdir `{ROOT}`. Outputs only under `{OUT}`. Zero candidate/calibration/vocabulary/scaler fits; no GPU request, installs, export, Android/Kotlin/Gradle execution, Git mutation or existing-file overwrite. datasets_v5/user_data never opened. URL-ml was not written. Protected file hashing deliberately uses the fixed run_02/protected_v2_before.json list, not a fresh directory walk.

## Integrity

OBSERVED: all {check['protected_count']} fixed protected files match before/after byte counts and SHA256; historical manifest also matched at entry. Full maps: protected_before.json and protected_after.json. File-list SHA is in environment.json. Git status file-by-file identical, both commands exit0. Frozen file hashes unchanged. V1 SHA remains {check['v1_sha256_after']}. Final integrity command `python -B reports/dev_sprint_01/sprint_v2_20261023/sprintlib.py validation` exited0; integrity_checks.json gives every check. Existing uncommitted Git state was preserved.

OBSERVED: freeze_manifest.json timestamp precedes inference process stdout-log creation, verified using filesystem nanosecond timestamps and source order. Reproduction gate was asserted before any probe scoring. probe_v2.csv final SHA `{freeze['files']['frozen/probe_v2.csv']}`; frozen design SHA `{freeze['files']['frozen/PROBE_V2_DESIGN.md']}`. The root probe_v2.csv/REVIEW_SAMPLE_v2.csv are preserved rejected-channel-balance drafts; the canonical deliverables are in frozen/. No text/label changed in the corrected version.

## Execution environment and provenance

OBSERVED Python `{sys.executable}`: {sys.version}. numpy {env['numpy']}; sklearn {env['sklearn']}; unpickle warnings in inference_manifest.json. All eight bundles loaded. CUDA_VISIBLE_DEVICES=-1, OMP/OPENBLAS/MKL threads1, PYTHONDONTWRITEBYTECODE=1, Python-B. Native Windows CPU topology reports {top['physical_cores']} physical cores, future-fit cap {top['fit_thread_cap']}; all current inference used1 thread. Initial CIM discovery was denied and psutil was absent; no installation/escalation occurred. CPU topology was subsequently read via GetLogicalProcessorInformationEx and recorded separately, preserving the original fallback record.

OBSERVED: 1,375 frozen v2 rows =600/400/100 Hinglish +150/100/25 English. All1,100 Hinglish texts have7–29 words;240/600 attacks URL-less;834 URL-containing and242 phone-containing rows across languages match legacy regexes. Eight persona batches, maximal normalized-Jaccard connected component3. Lexical audit85 sources,42,660 normalized texts,43 overlaps tagged. Final review120 random class-stratified rows, blank user fields. Earlier review202 rows has0marks. Synthetic labels ASSUMED, natural-traffic conclusions PROVISIONAL.

OBSERVED: 32,120 new predictions, eight models ×(1,320v1 +1,320normalized v1 +1,375v2). All10,560 original v1 text-only predictions reproduce prior classes and probabilities within1e-10; zero MALICIOUS-only alert invariant errors. V4.3 TEST1510/1556 and2/520 reproduced. English metadata TEST1506/1551 and92/707 combined false alerts; full TEST1510/1556 and92/708. Historical spam confusion90/188 reproduced. No historical number was substituted for a failed measured gate.

OBSERVED:6,089 input ledger entries;315 prediction-only permutations on588 historical heldout rows. Every run/seed and source hash saved. Permutation is diagnostic sensitivity, not training or independent future validation. New-feature candidates are design only. Training log records0fits. Data audit remains pending authorized handoff. Pre-registration plus execution clarification in approval_bundle.json require user approval; no continuation into Stage5.

## Errors and limitations preserved

OBSERVED: audit_freeze.py exited1 because the first generation assigned206/194 benign channels. repair_channel.py created corrected new files by changing six metadata rows; no model had seen either draft. audit_freeze_02.py passed. Failed source/log/draft remain. The normalized v1 transform jointly changes URLs/phones and removes scenario words from URLs; it cannot isolate each causal factor. Reused benign/context phrases and one author limit independence. Invented Indian-format numeric patterns are not verified unassigned; no call/resolution was made. Two JSON audit documents >=1MB were skipped and named in corpus_audit_manifest.json. Source review/probe labels are not human-adjudicated. V1 blind71 malicious disagreements split46 Hinglish/25English, contradicting any interpretation that all71 were Hinglish.

OBSERVED shell discovery issues: initial multi-file Get-Content/Get-ChildItem command exited1 because the optional messages_v5_sprint path was absent and its combined console output was truncated; relevant files were read in bounded follow-ups. CIM discovery command exited1 with access denied. An optional candidate_d/config.json read exited1 because that file is absent (V4.3 threshold comes from the frozen loader/.61 reproduction, not an invented config). None changed files. Numeric scientific evidence is captured by the script commands below. Discovery outputs are in this conversation tool transcript; they are not mislabeled as successful scientific commands.

## Exact scientific commands

OBSERVED commands launched with `python -B reports/dev_sprint_01/sprint_v2_20261023/sprintlib.py <target>`; table records resolved child argv, cwd, exit and wall time. Each has stdout/stderr files plus hashes, source hash and environment in <target>.command.json. Failed audit is included. No candidate fit command exists.

{cmdtable}

OBSERVED final evidence command: `python -B reports/dev_sprint_01/sprint_v2_20261023/finish_evidence.py`, cwd `{ROOT}`. It validates output hashes and prints COMPLETION digest; its actual exit is in the shell tool result and final_command.json upon successful completion.

## Model bundle hashes (before and after)

{table(['Model','Artifact','Before SHA256','After SHA256'],modelhashes)}

## Git before — exact porcelain lines

```text
{chr(10).join(gb['lines'])}
```

## Git after — exact porcelain lines

```text
{chr(10).join(ga['lines'])}
```

## Newly created files

OBSERVED list below records files present before this evidence/manifest finalization; output_manifest.json adds final evidence/command files. COMPLETION.json commits the manifest hash; its digest is emitted to stdout to avoid circular self-hashing. No prior output was overwritten. Progress uses immutable stage subdirectories plus a final PROGRESS.md snapshot.

'''+''.join('- '+p+'\n' for p in made)+'''
- RUN_EVIDENCE.md
- final_command.json
- output_manifest.json
- COMPLETION.json
'''
write('RUN_EVIDENCE.md',evidence)
save('final_command.json',{'argv':argv,'cwd':str(ROOT),'interpreter':sys.executable,'script_sha256':sha(__file__),'exit_code':0,'completion_checks':'required outputs exist; manifest recomputed; no protected/frozen changes in immediately preceding validation','wall_seconds_at_record':time.time()-t0,'UTC':datetime.now(timezone.utc).isoformat()})
manifest={p.relative_to(OUT).as_posix():{'sha256':sha(p),'bytes':p.stat().st_size} for p in OUT.rglob('*') if p.is_file()}
save('output_manifest.json',manifest)
assert all(sha(OUT/p)==v['sha256'] for p,v in manifest.items())
required=['frozen/PROBE_V2_DESIGN.md','frozen/probe_v2.csv','frozen/probe_v2.sha256','PROBE_V2_RESULTS.md','frozen/REVIEW_SAMPLE_v2.csv','FEATURE_LEDGER.md','FEATURE_LEDGER.csv','DATA_AUDIT.md','PRE_REGISTRATION.md','TRAINING_LOG.md','RESULTS.md','DECISION.md','RUN_EVIDENCE.md','PROGRESS.md','QUESTIONS_FOR_USER.md']
assert all((OUT/p).exists() for p in required)
save('COMPLETION.json',{'status':'STAGE4_APPROVAL_STOP','required_artifacts_present':required,'manifest_sha256':sha(OUT/'output_manifest.json'),'approval_bundle_sha256':sha(OUT/'approval_bundle.json'),'protected_unchanged':1750,'Git_identical':True,'candidate_fits':0,'intake_status':'PENDING_DATASETS_MOVED','new_file_count':len(manifest)+2})
print(json.dumps({'completion_sha256':sha(OUT/'COMPLETION.json'),'approval_bundle_sha256':sha(OUT/'approval_bundle.json'),'files_created':len(manifest)+2,'protected_unchanged':1750,'Git_identical':True,'status':'STOP_FOR_STAGE4_APPROVAL','candidate_fits':0}))
