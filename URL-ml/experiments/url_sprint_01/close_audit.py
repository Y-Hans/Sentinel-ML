"""Close the Git/file ledger after every substantive deliverable exists."""
from common import *
names=['git_final.json','git_status_final_file_by_file.csv','FINAL_AUDIT_ADDENDUM.md','artifact_manifest_final.json']
# Pre-create only this script's new outputs so Git observes their paths too.
for n in names:
    if (OUT/n).exists():assert readtext(OUT/n)=='pending final audit\n',n
    else:write(OUT/n,'pending final audit\n')
repos=[]
for repo in (ROOT/'sentinel-ai',U):
    cp=subprocess.run(['git','--no-optional-locks','status','--porcelain=v1','--untracked-files=all'],cwd=repo,capture_output=True,text=True)
    repos.append({'command':['git','--no-optional-locks','status','--porcelain=v1','--untracked-files=all'],'cwd':str(repo),'repository':repo.relative_to(ROOT).as_posix(),'exit_code':cp.returncode,'entries':cp.stdout.splitlines(),'stderr':cp.stderr})
    assert cp.returncode==(0 if repo==ROOT/'sentinel-ai' else 128),(str(repo),cp.stderr)
final={'time_utc':stamp(),'repositories':repos,'root_is_not_git_repository':True,'valid_before_snapshot_available':False}
(OUT/'git_final.json').write_text(json.dumps(final,indent=2)+'\n',encoding='utf-8')
before=json.loads(readtext(OUT/'git_before.json'))
def mapping(obj):
    result={}
    for line in obj['entries']:
        p=line[3:]
        if p.startswith('"'):
            try:p=json.loads(p)
            except json.JSONDecodeError:pass
        result[p]=line[:2]
    return result
a={r['repository']+'/'+p:s for r in repos for p,s in mapping(r).items()}
with open(OUT/'git_status_final_file_by_file.csv','w',encoding='utf-8',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['path','before_status','final_status','status_changed']);w.writeheader()
    for p in sorted(a):w.writerow(dict(path=p,before_status='UNAVAILABLE_root_git_snapshot_failed',final_status=a[p],status_changed='UNKNOWN'))
    w.writerow(dict(path='sentinel-ml/URL-ml/(repository unavailable)',before_status='UNAVAILABLE',final_status='UNAVAILABLE_git_exit_128',status_changed='UNKNOWN'))
pre=sha(OUT/'PRE_REGISTRATION.md')
(OUT/'FINAL_AUDIT_ADDENDUM.md').write_text(f'''# OBSERVED final closure
All substantive outputs already existed at the final Git snapshots. git_final.json and git_status_final_file_by_file.csv supersede the earlier Git snapshots. The workspace root is NOT a Git repository. git_before.json/git_after.json both recorded exit 128, with no entries; the earlier integrity_results.json/ RUN_EVIDENCE.md “outside-root Git changes=0” value was therefore unavailable evidence, not a valid invariant claim. This is an explicitly corrected audit error. No valid before-Git snapshot exists. Final file-by-file status was captured from sentinel-ai using --no-optional-locks, exit zero. URL-ml has a .git directory but it is unusable as a repository: its Git status and rev-parse both return 128. That failure is preserved, not repaired or represented as clean. All available dirty entries are preserved, but their origin cannot be inferred from this final snapshot. Protected-file content preservation is established separately by the 1,249 before/after hashes; 501 prohibited-directory entries are unverified.

The first close_audit.py attempt failed at the root-repository assertion, exit 1; close_audit_run.log preserves its traceback. The second incorrectly assumed URL-ml's .git directory was a valid repository, also exit 1; close_audit_run_02.log preserves that traceback. The corrective script changed only new sprint audit code and the four pre-created pending closure files. No protected source/model/data or Git metadata was modified. reports/url_sprint_01 is outside a valid Git repository, so its paths are recorded in the artifact manifest rather than Git status. The earlier git_status_file_by_file.csv NOT_LISTED values must be read as unavailable Git evidence, not clean/ignored proof. File-by-file Git status for URL-ml cannot be established from this checkout; do not claim that requirement fully verified.

artifact_manifest_final.json supersedes artifact_manifest.json and includes all new source/report artifacts except itself and the currently written close_audit_run_03.log. Earlier failed closure logs and finalize_run.log are complete and hashed in the final manifest. Closure command: required venv Python -B sentinel-ml/URL-ml/experiments/url_sprint_01/close_audit.py, cwd repository root. Script checks pass only with exit zero; the shell transcript records that result. Earlier source hashes/static audit reflect their timestamps; this corrected new closure script is included in the final manifest.

PRE_REGISTRATION.md SHA-256: {pre}. No model run, fitting, threshold/policy/data revision or design choice followed its hashing. Only correspondence/statistics, source/static checks, integrity and output-inventory closure followed. Stop for APPROVED remains in effect. All limitations and failed gates remain unchanged.
''',encoding='utf-8')
manifest=[]
for folder in (OUT,EXP):
    for p in sorted(folder.rglob('*')):
        if p.is_file() and p.name not in ('artifact_manifest_final.json','close_audit_run_03.log'):manifest.append(dict(path=p.relative_to(ROOT).as_posix(),bytes=p.stat().st_size,sha256=sha(p)))
(OUT/'artifact_manifest_final.json').write_text(json.dumps({'time_utc':stamp(),'artifacts':manifest,'self_and_active_log_excluded':True},indent=2)+'\n',encoding='utf-8')
print('Closure checks passed; final manifest',len(manifest),'files; sentinel-ai Git exit=0, URL-ml unavailable exit=128; no valid before-Git snapshot; pre-registration',pre,flush=True)
