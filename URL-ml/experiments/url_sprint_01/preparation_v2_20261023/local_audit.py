from prep_common import *
import collections,re,ast
from urllib.parse import urlsplit
import numpy as np
from sklearn.model_selection import GroupShuffleSplit
from v7_features import V7_FEATURE_NAMES,canonicalize_url,extract_v7_features,TWO_LABEL_SUFFIXES
from v8_normalization import canonicalize_url as canonical_v8
from url_features import domain_group

# Preserve every inherited label and reviewer note; no model run or relabelling.
review=list(rows(ROOT/'assistant_review_20261023/ANNOTATED_REVIEW_SAMPLE.csv'))
old={r['id']:r for r in rows(ROOT/'reports/url_sprint_01/REVIEW_SAMPLE.csv')}
assert len(review)==120 and len({r['id'] for r in review})==120
triage=[]
for r in review:
    assert r['expected']==old[r['id']]['expected'] and r['url']==old[r['id']]['url']
    p=urlsplit(canonicalize_url(r['url']));short=r['assistant_review_status']=='UNVERIFIED_SHORTENER_DESTINATION'
    reason='SHORTENER_DESTINATION_UNKNOWN' if short else 'AUTHORED_ATTACK_NOT_EXTERNALLY_CONFIRMED' if r['expected']=='ATTACK' else 'AUTHORED_BENIGN_INTENT_NOT_ENDPOINT_VERIFICATION'
    if r['expected']=='ATTACK' and r['category']=='raw_ip':reason='DOCUMENTATION_RANGE_ATTACK_SCENARIO_NOT_LIVE_THREAT'
    if r['expected']=='ATTACK' and r['category'] in {'payload_popular','open_redirect','tenant_phishing'}:reason='IMAGINED_HOSTED_CONTENT_OR_REDIRECT_UNVERIFIED'
    triage.append({**r,'triage_reason_v2':reason,'confirmed_truth_label_v2':'','adjudication_status_v2':'UNADJUDICATED','training_use_v2':'EXCLUDE_AUTHORED_BURNED_PROBE','evidence_level_v2':'PROVISIONAL_SCENARIO_ONLY','human_review_required_for_truth_promotion_v2':'yes'})
csvout(OUT/'LABEL_TRIAGE_v2.csv',triage)
js(OUT/'label_review_counts_v2.json',{'status':'OBSERVED parsing; no adjudicated error rate available','n':len(review),'inherited_expected_counts':dict(collections.Counter(r['expected'] for r in review)),'assistant_review_status_counts':dict(collections.Counter(r['assistant_review_status'] for r in review)),'triage_reason_counts':dict(collections.Counter(r['triage_reason_v2'] for r in triage)),'human_agreement_cells':dict(collections.Counter(r['user_agree'] for r in review)),'inherited_labels_changed':0,'confirmed_wrong_labels':None,'wrong_label_rate':None,'review_threshold_outcome':'NOT_EVALUABLE; no independent human adjudication; do not assert 0% or >5%','source_sha256':sha(ROOT/'assistant_review_20261023/ANNOTATED_REVIEW_SAMPLE.csv')})

# Reconstruct the split by reading only URL/label projections row by row.
urls=[];y=[];groups=[]
for r in rows(U/'data/cleaned_dataset.csv'):
    urls.append(r['url']);y.append(1-int(r['label']));groups.append(domain_group(r['url']))
y=np.array(y);g=np.array(groups);idx=np.arange(len(y))
tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,g))
vr,ter=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],g[rest]));va=rest[vr];te=rest[ter]
counts=collections.Counter();split=np.empty(len(y),dtype='U10');split[tr]='train';split[va]='validation';split[te]='test'
for i,u in enumerate(urls):
    p=urlsplit(canonicalize_url(u));h=p.hostname or '';cl='ATTACK' if y[i] else 'BENIGN'
    shape='www' if h.startswith('www.') else 'apex_legacy' if domain_group(u)==h else 'subdomain'
    counts[(str(split[i]),cl,shape)]+=1
    counts[('full_clean_file',cl,shape)]+=1
csvout(OUT/'reconstructed_clean_membership_v2.csv',({'source_file':'cleaned_dataset.csv','source_row_index':i,'url_sha256':hashlib.sha256(u.encode()).hexdigest(),'legacy_group':groups[i],'split':str(split[i]),'dataset_reported_class':'ATTACK' if y[i] else 'BENIGN','status':'RECONSTRUCTED_FROM_CURRENT_SOURCE_NOT_HISTORICAL_ROW_MANIFEST'} for i,u in enumerate(urls)))
syn=collections.Counter();ns=0
for r in rows(U/'data/v7_structural_benign.csv'):
    p=urlsplit(canonicalize_url(r['url']));h=p.hostname or '';cl='ATTACK' if int(r['label']) else 'BENIGN';shape='www' if h.startswith('www.') else 'apex_legacy' if domain_group(r['url'])==h else 'subdomain'
    syn[(cl,shape)]+=1;ns+=1
auditpath=U/'reports/URL_V7_FINAL_RELEASE_AUDIT.json';audit=json.loads(read(auditpath));provenance=audit['provenance_hashes']['datasets']
sourcechecks=[]
for name in ('cleaned_dataset.csv','v7_structural_benign.csv','hard_dataset.csv'):
    p=U/'data'/name;actual=sha(p);sourcechecks.append(dict(path=p.relative_to(ROOT).as_posix(),actual_sha256=actual,reported_release_sha256=provenance[name],matches_release_report=actual==provenance[name]))
src=U/'scripts/reproduce_v7_champion.py';t=read(src)
assert 'train_urls + syn_urls' in t and 'fit_X = np.vstack([Xtr, Xs])' in t
js(OUT/'training_skew_audit_v2.json',{'status':'OBSERVED counts; historical fit attribution limited to current code + release-report hashes','clean_source_rows':len(y),'clean_full_benign_n':int((y==0).sum()),'clean_full_benign_www_n':counts[('full_clean_file','BENIGN','www')],'clean_train_benign_n':int((y[tr]==0).sum()),'clean_train_attack_n':int((y[tr]==1).sum()),'clean_split_sizes':{'train':len(tr),'validation':len(va),'test':len(te)},'clean_split_index_hashes':{k:hashlib.sha256(v.tobytes()).hexdigest() for k,v in [('train',tr),('validation',va),('test',te)]},'clean_form_counts':[{'split':s,'class':c,'host_shape':f,'n':n} for (s,c,f),n in sorted(counts.items())],'structural_source_rows':ns,'structural_counts':[{'class':c,'host_shape':f,'n':n} for (c,f),n in sorted(syn.items())],'reconstructed_total_fit_rows':len(tr)+ns,'reconstructed_total_fit_benign_rows':int((y[tr]==0).sum())+sum(n for (c,f),n in syn.items() if c=='BENIGN'),'historical_training_script':{'path':src.relative_to(ROOT).as_posix(),'sha256':sha(src),'executed':False,'fit_composition_observed':'clean train indices plus every structural benign row, not all 134850 clean benign rows'},'release_report':{'path':auditpath.relative_to(ROOT).as_posix(),'sha256':sha(auditpath),'model_hash_matches_frozen_v7':audit['provenance_hashes']['models']['v7_champion.joblib']==sha(U/'models/v7_champion.joblib')},'source_hash_checks':sourcechecks,'historical_row_manifest_available':False,'correction':'134850/134850 is the full cleaned-file benign host skew, not an independently proved count of all benign examples fitted by V7. The current script adds structural data; review its counts and any hash mismatch. Reconstructed membership is evidence of present code, not proof of historical execution.'})
old_features=[r['feature'] for r in rows(ROOT/'reports/url_sprint_01/FEATURE_LEDGER.csv')]
assert V7_FEATURE_NAMES==old_features and len(V7_FEATURE_NAMES)==67
cases=['example.com','//example.com','HTTPS://example.com',' https://example.com. ','https://example.com/a+b','https://example.com/?q=notes']
tests=[]
for u in cases:
    a=canonicalize_url(u);b=canonical_v8(u);assert a==b
    tests.append(dict(input=u,v7=a,v8=b,equal=True))
baseline=extract_v7_features('https://example.com')
assert all(extract_v7_features(u)==baseline for u in ('example.com','//example.com'))
js(OUT/'feature_contract_v2.json',{'status':'OBSERVED offline code/feature checks only; no estimator loaded','feature_count':67,'feature_order':V7_FEATURE_NAMES,'feature_order_sha256':hashlib.sha256(json.dumps(V7_FEATURE_NAMES,separators=(',',':')).encode()).hexdigest(),'exact_order_matches_prior_ledger':True,'canonicalization_tests':tests,'schemeless_protocol_relative_all_67_features_equal':True,'www_to_apex_differing_features':[n for n in V7_FEATURE_NAMES if extract_v7_features('https://www.example.com')[n]!=baseline[n]],'source_hashes':{str(p.relative_to(ROOT)):sha(p) for p in [U/'scripts/v7_features.py',U/'scripts/v8_normalization.py',U/'scripts/v8_classifier.py']},'no_feature_or_normalizer_edits':True})
print('Review triage 120 rows; clean full benign www',counts[('full_clean_file','BENIGN','www')],'/',int((y==0).sum()),'; reconstructed clean train benign',int((y[tr]==0).sum()),'; structural',ns,dict(syn),flush=True)
