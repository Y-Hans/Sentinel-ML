from sprintlib import *
guard()
before=fixedhashes();save('protected_before.json',before);save('git_before.json',gitstatus())
original=load(ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json')
delta=[p for p in before if before[p]!=original[p]]
review=list(rows(OLD/'REVIEW_SAMPLE.csv'));marked=[r for r in review if r.get('user_agree','').strip() or r.get('user_note','').strip()]
save('review_marks.json',{'source_sha256':sha(OLD/'REVIEW_SAMPLE.csv'),'rows':len(review),'marked_count':len(marked),'marks':marked})
try:
 import psutil
 cores=psutil.cpu_count(logical=False);method='existing psutil.cpu_count(logical=False)'
except ImportError:cores=None;method='CIM access denied; psutil unavailable; conservative one thread'
save('environment.json',{'python':sys.version,'executable':sys.executable,'physical_cores':cores,'cpu_cap':max(1,cores//2) if cores else 1,'inference_threads':1,'core_discovery':method,'historical_hash_differences':delta,'fixed_manifest_sha256':sha(ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json'),'v1_sha256':sha(OLD/'probe_set.csv')})
print('protected files',len(before),'historical differences',len(delta),'review marked',len(marked),'physical cores',cores)
if delta:print(json.dumps(delta))
