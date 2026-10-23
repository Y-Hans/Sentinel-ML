"""Bounded projected CSV reread and score-file audit; no model execution."""
from common import *
import collections,math
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from url_features import domain_group
from v7_features import V7_FEATURE_NAMES,canonicalize_url
from urllib.parse import urlsplit

# Read one row at a time and retain only the minimum split projection.
urls=[];labels=[];groups=[]
for r in rows(U/'data/cleaned_dataset.csv'):
    u=r['url'];urls.append(u);labels.append(1-int(r['label']));groups.append(domain_group(u))
y=np.array(labels);idx=np.arange(len(urls));gr=np.array(groups)
tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,gr))
vr,ter=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],gr[rest]));te=rest[ter]
counts=collections.defaultdict(collections.Counter);max_raw_diff=0.;n=0;new_misses=collections.Counter();new_apex=collections.Counter()
from v8_normalization import parse_v8_url
for r,i in zip(rows(OUT/'clean_test_scores.csv'),te,strict=True):
    assert int(r['test_index'])==i and r['url']==urls[i] and int(r['label'])==y[i]
    max_raw_diff=max(max_raw_diff,abs(float(r['v7_raw'])-float(r['v8_raw'])))
    b=float(r['v8_url_adjudicated'])>=.28;pr=float(r['prior'])>=.28
    if y[i]==1 and b and not pr:new_misses['prior']+=1
    if y[i]==1 and b and not pr and parse_v8_url(r['url']).subdomain_depth==0:new_apex['prior']+=1
    for mode,t in [('v7_raw',.22588719359679843),('v8_raw',.28),('v8_url_adjudicated',.28),('v8_no_url_fallback',.28),('prior',.28)]:
        pred=float(r[mode])>=t;counts[mode]['tp' if y[i] and pred else 'fn' if y[i] else 'fp' if pred else 'tn']+=1
    n+=1
ref=json.loads(readtext(OUT/'clean_test_results.json'))
for mode,c in counts.items():
    for k in ('tp','fp','tn','fn'):assert c[k]==ref['metrics'][mode][k]
assert len(te)==n==50511
probe=list(rows(OUT/'probe.csv'));review=list(rows(OUT/'REVIEW_SAMPLE.csv'));red=list(rows(OUT/'red_team.csv'))
assert len(probe)==900 and len({r['url'] for r in probe})==900
assert collections.Counter(r['expected'] for r in probe)=={'BENIGN':600,'ATTACK':300}
assert collections.Counter(r['expected'] for r in review)=={'BENIGN':60,'ATTACK':60}
assert all(r['user_agree']==r['user_note']=='' for r in review)
assert len(red)>=100
def key(u):
    p=urlsplit(canonicalize_url(u));return (p.netloc.lower(),p.path.rstrip('/') if p.path in ('','/') else p.path,p.query,p.fragment)
def walk(x):
    if isinstance(x,list):
        for a in x:yield from walk(a)
    elif isinstance(x,dict):
        if isinstance(x.get('url'),str):yield x['url']
        else:
            for a in x.values():yield from walk(a)
burn=set()
for p in [U/'data/hard_benign_benchmark_500.json',ROOT/'sentinel-ml/android-runtime/golden_test_data/golden_urls_v8.json']:burn.update(key(u) for u in walk(json.loads(readtext(p))))
assert not any(key(r['url']) in burn for r in probe)
feature_ledger=list(rows(OUT/'FEATURE_LEDGER.csv'));importance=list(rows(OUT/'permutation_importance.csv'))
assert [r['feature'] for r in feature_ledger]==V7_FEATURE_NAMES and [r['feature'] for r in importance]==V7_FEATURE_NAMES and len(feature_ledger)==67
frozen=json.loads(readtext(OUT/'evaluation_freeze.json'))
for name,digest in [('probe.csv',frozen['probe']),('red_team.csv',frozen['red_team']),('SAFE_DOMAIN_PRIOR_SPEC.md',frozen['spec']),('POLICY_GATES_BEFORE_EVALUATION.md',frozen['gates']),('ranked_domain_registry.json',frozen['registry'])]:assert sha(OUT/name)==digest
assert sha(EXP/'safe_domain_prior.py')==frozen['policy_source']
assert sha(OUT/'PRE_REGISTRATION.md')==readtext(OUT/'PRE_REGISTRATION.sha256').split()[0]
js(OUT/'streamed_audit.json',{'status':'OBSERVED','no_model_run':True,'stream_method':'CSV row iterator; retain projected URL/label/group arrays only, never original row dictionaries','clean_test_rows_verified':n,'test_index_sha256':hashlib.sha256(te.tobytes()).hexdigest(),'score_confusion_counts_verified':{k:dict(v) for k,v in counts.items()},'v7_v8_raw_max_abs_difference':max_raw_diff,'prior_paired_new_attack_misses':dict(new_misses),'prior_paired_new_apex_misses':dict(new_apex),'probe_counts':dict(collections.Counter(r['expected'] for r in probe)),'probe_canonical_unique_count':len({key(r['url']) for r in probe}),'burned_probe_overlap':0,'review_n':len(review),'review_empty_cells_verified':True,'red_team_n':len(red),'feature_count':len(feature_ledger),'all_freeze_hashes_match':True,'pre_registration_hash_verified':True,'known_limitation':'This verifies streaming correspondence and statistics; it does not erase the original evaluation ingestion materialization shortcoming or validate URL safety labels.'})
print('Streamed audit passed',n,'rows; raw V7/V8 max difference',max_raw_diff,flush=True)
