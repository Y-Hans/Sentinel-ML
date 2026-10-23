from sprintlib import *
guard()
before=load(OUT/'protected_before.json');after=fixedhashes();save('protected_after.json',after);gb=load(OUT/'git_before.json');ga=gitstatus();save('git_after.json',ga)
changes=[{'path':p,'before':before[p],'after':after[p]} for p in before if before[p]!=after[p]]
frozen=load(OUT/'freeze_manifest.json');fchanges=[p for p,s in frozen['files'].items() if sha(OUT/p)!=s]
regsha=sha(OUT/'PRE_REGISTRATION.md');assert regsha==small(OUT/'PRE_REGISTRATION.sha256').split()[0]
oldpred={(r['id'],r['model']):r for r in rows(OLD/'probe_predictions.jsonl') if r['condition']=='text_only'}
parity=[];n=0;badalert=0
for r in rows(OUT/'probe_predictions.jsonl'):
 n+=1;badalert+=r['alert']!=(r['predicted']=='MALICIOUS')
 assert abs(r['p_benign']+r['p_spam']+r['p_malicious']-1)<1e-6
 if r['set']=='v1':
  old=oldpred[(r['id'],r['model'])]
  if r['predicted']!=old['predicted'] or max(abs(r[k]-old[k]) for k in ['p_benign','p_spam','p_malicious'])>1e-10:parity.append({'id':r['id'],'model':r['model']})
v2=list(rows(OUT/'frozen/probe_v2.csv'));review=list(rows(OUT/'frozen/REVIEW_SAMPLE_v2.csv'))
counts=dict(collections.Counter(r['language']+':'+r['expected'] for r in v2));rcounts=dict(collections.Counter(r['expected'] for r in review))
assert n==8*(1320+1320+1375);assert rcounts=={'MALICIOUS':60,'BENIGN':40,'SPAM':20};assert len({r['id'] for r in review})==120
assert all(not r['user_agree'] and not r['user_note'] for r in review)
assert not any(re.search(r'[\u0900-\u097f]',r['text']) for r in v2)
gate=load(OUT/'V43_reproduction_gate.json');assert gate['TP']==1510 and gate['FP_any_B']==2
dateorder=(OUT/'freeze_manifest.json').stat().st_mtime_ns<(OUT/'inference_02.stdout.txt').stat().st_ctime_ns
check={'protected_count':len(before),'protected_changed':changes,'git_status_identical':gb['lines']==ga['lines'],'git_exit_codes':[gb['exit_code'],ga['exit_code']],'git_added_lines':[s for s in ga['lines'] if s not in gb['lines']],'git_removed_lines':[s for s in gb['lines'] if s not in ga['lines']],'freeze_changes':fchanges,'freeze_before_inference_process_log_created':dateorder,'prediction_rows':n,'M_only_alert_errors':badalert,'v1_prior_parity_failures':parity,'v1_prior_parity_compared':len(oldpred),'probe_v2_counts':counts,'random_review_counts':rcounts,'PRE_REGISTRATION_sha256':regsha,'no_candidate_training':True,'datasets_v5_or_user_data_opened':False,'Kotlin_executed':False,'GPU_requested':False,'fixed_manifest_used':True,'directory_walk_for_protected_hashes':False,'v1_sha256_after':sha(OLD/'probe_set.csv')}
save('integrity_checks.json',check)
if changes or fchanges:raise RuntimeError('HARD STOP protected/frozen change: '+json.dumps(changes+fchanges))
assert not badalert and not parity and dateorder
print(json.dumps({k:v for k,v in check.items() if k not in ('probe_v2_counts',)},ensure_ascii=False))
