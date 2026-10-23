from preplib import *
guard()
fixed=load(ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json');fixedpaths=[ROOT/p for p in fixed]
bh=hashes(fixedpaths);save('fixed_protected_before.json',bh);save('git_before.json',status())
drift=[{'path':p,'historical_sha256':v['sha256'],'current_sha256':bh[str(ROOT/p)]['sha256']} for p,v in fixed.items() if v['sha256']!=bh[str(ROOT/p)]['sha256']]
extra=[]
for folder in [PREV,V1]:
 for p in load(folder/'output_manifest.json'):
  extra.append(folder/p)
 extra += [folder/'output_manifest.json',folder/'COMPLETION.json']
extra += list((ROOT/'assistant_review_20261023').glob('*'))
extra += [B/'assistant_review_20261023/DATASET_LABEL_TRIAGE.csv']
extra=[p for p in extra if p.is_file()]
save('a_evidence_before.json',hashes(extra))
manifest=load(B/'DONE.json');verification=[]
for e in manifest['files']:
 p=(B/e['path']).resolve();assert p.is_relative_to(B.resolve())
 actual=sha(p) if p.is_file() else None;verification.append({'path':e['path'],'declared_sha256':e['sha256'],'actual_sha256':actual,'match':actual==e['sha256']})
save('B_original_manifest_verification.json',{'path':str(B/'DONE.json'),'manifest_sha256':sha(B/'DONE.json'),'entries':verification,'mismatch_count':sum(not x['match'] for x in verification),'scope':'external archived collection diagnostics, NOT source admission or DATASETS MOVED','counts_are_old_not_remediated':True})
save('preflight.json',{'fixed_count':len(bh),'preexisting_evidence_count':len(extra),'historical_drift_at_entry':drift,'B_original_manifest_entries':len(verification),'B_mismatches':sum(not x['match'] for x in verification),'source_triage_location':str(B/'assistant_review_20261023/DATASET_LABEL_TRIAGE.csv'),'training_authorized':False,'threshold_scan_authorized':False})
print('fixed protected',len(bh),'historical drift',len(drift),'B manifest',len(verification),'mismatches',sum(not x['match'] for x in verification))
if drift:print(json.dumps(drift))
assert all(x['match'] for x in verification),'B original manifest mismatch; do not parse corpus'
