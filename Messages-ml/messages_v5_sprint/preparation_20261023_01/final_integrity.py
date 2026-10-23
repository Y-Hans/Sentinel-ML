from preplib import *
guard()
before=load(OUT/'fixed_protected_before.json');after=hashes(before);save('fixed_protected_after.json',after)
extra=load(OUT/'a_evidence_before.json');eafter=hashes(extra);save('a_evidence_after.json',eafter)
gb=load(OUT/'git_before.json');ga=status();save('git_after.json',ga)
fixedchanges=[p for p in before if before[p]!=after[p]];echanges=[p for p in extra if extra[p]!=eafter[p]]
manifest=load(OUT/'B_original_manifest_verification.json');bchanges=[]
for e in manifest['entries']:
 p=B/e['path'];current=sha(p)
 if current!=e['actual_sha256']:bchanges.append({'path':e['path'],'before':e['actual_sha256'],'after':current})
frozen=load(PREV/'freeze_manifest.json');frozenbad=[p for p,s in frozen['files'].items() if sha(PREV/p)!=s]
bundle=load(OUT/'PREPARATION_APPROVAL_BUNDLE.json');assert all(sha(OUT/p)==s for p,s in bundle['new_files'].items());assert all(sha(p)==s for p,s in bundle['parent_files'].items())
result={'fixed_protected_count':len(before),'fixed_changes':fixedchanges,'A_preexisting_evidence_count':len(extra),'A_evidence_changes':echanges,'B_original_manifest_files_rechecked':len(manifest['entries']),'B_original_changes':bchanges,'git_same_file_by_file':gb['lines']==ga['lines'],'git_before_exit':gb['exit_code'],'git_after_exit':ga['exit_code'],'git_added_lines':[s for s in ga['lines'] if s not in gb['lines']],'git_removed_lines':[s for s in gb['lines'] if s not in ga['lines']],'frozen_changes':frozenbad,'v1_sha256':sha(V1/'probe_set.csv'),'v2_sha256':sha(PREV/'frozen/probe_v2.csv'),'training_fits':0,'threshold_scans':0,'Kotlin_execution':False,'Android_patch_applied':False,'sealed_exam_opened':False,'data_intake_approved':False,'all_new_writes_confined_to':str(OUT)}
save('INTEGRITY_v2.json',result)
print(json.dumps(result))
assert not fixedchanges and not echanges and not bchanges and not frozenbad,'HARD STOP: changed protected/preexisting evidence'
assert result['git_same_file_by_file'] and gb['exit_code']==0 and ga['exit_code']==0
