from common import *
import time, math, collections, warnings, platform, importlib.metadata, random, re
from urllib.parse import urlsplit
from safe_domain_prior import registry_rows, classify

start=time.monotonic()
freeze=json.loads(readtext(OUT/'freeze.json'))
assert sha(OUT/'probe.csv')==freeze['probe_sha256']
assert sha(OUT/'red_team.csv')==freeze['red_team_sha256']
# Everything below is single-thread CPU inference, never fit.
import numpy as np, sklearn, joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import average_precision_score
from threadpoolctl import threadpool_limits, threadpool_info
threadpool_limits(limits=1)
from v7_features import V7_FEATURE_NAMES,vectorize_v7
from url_features import domain_group
from v8_normalization import parse_v8_url
from v8_classifier import V8RelationalURLClassifier
try:
    import psutil
    physical=psutil.cpu_count(logical=False)
except ImportError:
    import ctypes, struct
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    size=ctypes.c_ulong(0)
    kernel.GetLogicalProcessorInformationEx(0,None,ctypes.byref(size))
    buf=ctypes.create_string_buffer(size.value)
    assert kernel.GetLogicalProcessorInformationEx(0,buf,ctypes.byref(size))
    pos=0;physical=0
    while pos<size.value:
        relation,record_size=struct.unpack_from('II',buf.raw,pos)
        assert record_size>0
        physical+=int(relation==0);pos+=record_size
assert physical is not None and physical>=4, 'Cannot prove 1 thread <= quarter physical cores'
tranco_domains=[]
if freeze['tranco_candidates']:
    assert len(freeze['tranco_candidates'])==1,'Ambiguous Tranco CSVs; choose explicit input before evaluation'
    cand=freeze['tranco_candidates'][0];p=ROOT/cand['path'];assert sha(p)==cand['sha256']
    with open(p,encoding='utf-8-sig',newline='') as f:
        for row in csv.reader(f):
            if len(row)==1 and row[0].lower() in ('domain','domains'): continue
            assert len(row)==1 and re.fullmatch(r'[a-z0-9][a-z0-9.-]*\.[a-z]{2,}',row[0].strip().lower()),'Expected domains-only Tranco CSV'
            tranco_domains.append(row[0].strip().lower())
    assert len(tranco_domains)<=100000 and len(tranco_domains)==len(set(tranco_domains))
registry=registry_rows(tranco_domains)
js(OUT/'ranked_domain_registry.json',{'domains':list(registry.values()),'tranco_used':bool(tranco_domains),'rank_semantics':'null = curated prototype, no measured popularity'})
write(OUT/'SAFE_DOMAIN_PRIOR_SPEC.md','''# PROVISIONAL safe-domain prior — fixed before evaluation
Architecture unchanged: frozen HistGradientBoostingClassifier, exactly 67 sorted features; no fit, feature change, Kotlin change or runtime deployment. The policy operates only on frozen scores. Source and spec are hashed in evaluation_freeze.json before loading either joblib.

| Priority | Condition | State | Score action |
|---|---|---|---|
| 1 | After up to four percent-decode passes: payload extension, credential pattern, nested/redirect target, raw IP, IDN/punycode, existing feature brand impersonation or exact leet brand label | KNOWN_THREAT_PATTERN | max(V8 adjudicated score,0.95); never discount |
| 2 | Exact registry host or explicit www counterpart, https/default port, no userinfo/fragment; allowed page shape; no extra risk; not tenant/public content | KNOWN_SAFE_SHAPE | subtract at most 0.25, floor zero; alert threshold stays 0.28 |
| 3 | Remaining adjudicated score >=0.28 or port/@/nested/double-encoding/traversal/non-ASCII/suspicious-TLD/slash risk | UNKNOWN_HIGH_RISK | passthrough |
| 4 | Remaining low score | UNKNOWN_LOW_RISK | passthrough; unknown is not verified safe |

Allowed shapes: exact root with no query; claude.ai/chat/<4–64 alphanumeric/hyphen ID> with no query; google.com/bing.com/duckduckgo.com exact root/search with only q,hl,source, values <=120 and at least one q; limited docs-category wiki/abs/downloads/about paths without queries. All other paths are unknown. Registry membership never implies subdomain wildcard permission or arbitrary path safety. Public/user-content paths on GitHub/GitLab/Bitbucket/YouTube/Instagram/etc. get no discount. Docs/Forms/Drive, shorteners, public file storage, and listed free-hosting tenant suffixes get none. Full lists and matching semantics are in the prototype and registry JSON. Conservative credential matching also catches legitimate authentication and some ordinary queries; report this cost. Payload paths are hazards, not established malicious files. Redirect syntax is a hazard, not established endpoint exploitability. Four decode passes and lexical patterns do not prove complete semantic detection.

Registry provenance: existing v8_classifier.py dev/gaming/media/docs/search sets; claude.ai and instagram.com are explicit PROVISIONAL examples supplied in this task. No popularity ranks are invented. If one valid domains-only Tranco CSV is present, hash it, preserve file order as reported rank, and retain page-shape restrictions. Tranco ranking is not safety evidence. Adjusted scores are policy scores, not calibrated attack probabilities. A 0.25 absolute decrement is bounded, yet can cross 0.28; deployment requires all gates plus independent review. Root/rank membership alone cannot veto invariants. Existing V8 URL-string overrides remain present before the discount; strict lexical invariants prohibit discount for recognized payload, redirect and credential cases.

Gates are exactly POLICY_GATES_BEFORE_EVALUATION.md (hashed before inference). No iteration from burned regression outcomes. Golden reporting distinguishes correctness regression, all decision changes, and historical output parity; these can conflict. Never repair the candidate using burned examples. No deployment claim follows from 160 authored checks. Clean-test and this authored probe are now development diagnostics, not untouched exams.

If no Tranco CSV was provided: Please download a dated Tranco top-100,000 list yourself, export a one-column domains-only CSV (one domain per line, optional domain header, ranking order preserved), and place it at sentinel-ml/URL-ml/external/tranco/tranco_top_100000.csv. Provide the list ID/date and download source; do not include URLs or page content. Sentinel will hash and validate it offline before a separately registered evaluation.
''')
js(OUT/'evaluation_freeze.json',{'time_utc':stamp(),'probe':freeze['probe_sha256'],'red_team':freeze['red_team_sha256'],'policy_source':sha(EXP/'safe_domain_prior.py'),'spec':sha(OUT/'SAFE_DOMAIN_PRIOR_SPEC.md'),'gates':sha(OUT/'POLICY_GATES_BEFORE_EVALUATION.md'),'registry':sha(OUT/'ranked_domain_registry.json'),'fit_count':0})
env={'python':sys.version,'executable':sys.executable,'numpy':np.__version__,'sklearn':sklearn.__version__,'joblib':joblib.__version__,'physical_cores':physical,'cpu_thread_limit':1,'max_allowed_physical_cores':physical//4,'platform':platform.platform(),'threadpools':threadpool_info(),'environment':{k:os.environ[k] for k in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS','CUDA_VISIBLE_DEVICES')}}
js(OUT/'environment.json',env)
models={};mm={}
for n,expected in [('7','d414bf668484ea5ba6056b626f0d8e674e0085208ba23d964522b09557affdaa'),('8','073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58')]:
    p=U/f'models/v{n}_champion.joblib';assert sha(p)==expected
    with warnings.catch_warnings(record=True) as ww:
        warnings.simplefilter('always');models[n]=joblib.load(p)
    m=models[n];assert list(m.feature_names)==V7_FEATURE_NAMES and len(m.feature_names)==67
    assert type(m.base_model).__name__=='HistGradientBoostingClassifier'
    mm[n]={'path':str(p.relative_to(ROOT)),'sha256':sha(p),'threshold':m.threshold,'feature_names':m.feature_names,'class':type(m.base_model).__name__,'warnings':[str(w.message) for w in ww],'parameters':m.base_model.get_params()}
js(OUT/'models.json',mm)

def wilson(k,n):
    if not n:return None
    z=1.95996398454;p=k/n;den=1+z*z/n;center=(p+z*z/(2*n))/den;rad=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [center-rad,center+rad]
def metrics(y,p,t):
    y=np.asarray(y); pred=np.asarray(p)>=t;b=(y==0);a=(y==1);nb=int(b.sum());na=int(a.sum());fp=int(pred[b].sum());tp=int(pred[a].sum());f=fp/nb if nb else None;r=tp/na if na else None
    return dict(n=len(y),benign_n=nb,attack_n=na,fp=fp,tp=tp,tn=nb-fp,fn=na-tp,fpr=f,recall=r,fpr_wilson95=wilson(fp,nb),recall_wilson95=wilson(tp,na),false_alerts_per_1000=None if f is None else 1000*f,assumed_false_alerts_day_30_benign_urls=None if f is None else 30*f,assumed_ppv={str(v):None if f is None or r is None or v*r+(1-v)*f==0 else v*r/(v*r+(1-v)*f) for v in (.001,.01,.05)},small_cell='indicative only' if min(nb or 100000,na or 100000)<30 else '')
def score(urls,include_prior=True):
    X,names=vectorize_v7(urls)
    pr7=models['7'].base_model.predict_proba(X)[:,1];pr8=models['8'].base_model.predict_proba(X)[:,1]
    adj=np.asarray([models['8'].adjudicate_single(u,x,float(p))[0] for u,x,p in zip(urls,X,pr8)])
    fallback=models['8'].predict_proba(X)[:,1]
    policies=[classify(u,float(p),float(a),registry) for u,p,a in zip(urls,pr8,adj)] if include_prior else []
    scores={'v7_raw':pr7,'v8_raw':pr8,'v8_url_adjudicated':adj,'v8_no_url_fallback':fallback}
    if include_prior:scores['prior']=np.array([r['score'] for r in policies])
    return X,scores,policies
thresholds={'v7_raw':models['7'].threshold,**{n:models['8'].threshold for n in ('v8_raw','v8_url_adjudicated','v8_no_url_fallback','prior')}}

# Stream CSV input. Materialize only url/label/group columns needed to reproduce
# the original deterministic group split, never an eager pandas CSV read.
clean=list(rows(U/'data/cleaned_dataset.csv'));urls=[r['url'] for r in clean];y=np.array([1-int(r['label']) for r in clean]);del clean
groups=np.array([domain_group(u) for u in urls]);idx=np.arange(len(urls))
tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,groups))
vr,ter=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],groups[rest]));te=rest[ter]
assert len(te)==50511 and int((y[te]==0).sum())==27353 and int((y[te]==1).sum())==23158
print('Vectorizing/scoring clean test',len(te),flush=True)
testurls=[urls[i] for i in te];yt=y[te];Xtest,sc,pol=score(testurls)
cleanmetrics={n:metrics(yt,p,thresholds[n]) for n,p in sc.items()}
assert cleanmetrics['v8_url_adjudicated']['tp']==22835 and cleanmetrics['v8_url_adjudicated']['fp']==263
assert cleanmetrics['v8_no_url_fallback']['tp']==22825 and cleanmetrics['v8_no_url_fallback']['fp']==207
js(OUT/'clean_test_results.json',{'status':'OBSERVED','split':{'source_sha256':sha(U/'data/cleaned_dataset.csv'),'source_rows':len(urls),'train_n':len(tr),'validation_n':len(vr),'test_n':len(te),'test_index_sha256':hashlib.sha256(te.tobytes()).hexdigest(),'domain_group_source_sha256':sha(U/'scripts/url_features.py')},'metrics':cleanmetrics})
csvout(OUT/'clean_test_scores.csv',({'test_index':int(i),'url':u,'label':int(label),**{n:float(v[k]) for n,v in sc.items()},'prior_state':pol[k]['state'],'prior_reason':pol[k]['reason']} for k,(i,u,label) in enumerate(zip(te,testurls,yt))))
# Targeted apex-attack slice uses V8 parser, not legacy feature subdomain count.
apex=np.array([parse_v8_url(u).subdomain_depth==0 for u in testurls])
js(OUT/'clean_test_apex_results.json',{n:metrics(yt[apex],p[apex],thresholds[n]) for n,p in sc.items()})

probe=list(rows(OUT/'probe.csv'));py=np.array([int(r['expected']=='ATTACK') for r in probe])
print('Scoring new probe',len(probe),flush=True)
_,ps,pp=score([r['url'] for r in probe])
overall={n:metrics(py,p,thresholds[n]) for n,p in ps.items()}
js(OUT/'probe_results.json',{'status':'OBSERVED measurements conditional on PROVISIONAL labels','metrics':overall,'prior_states':dict(collections.Counter(p['state'] for p in pp))})
csvout(OUT/'probe_scores.csv',({**r,**{n:float(v[k]) for n,v in ps.items()},'prior_state':pp[k]['state'],'prior_reason':pp[k]['reason'],'prior_discount':pp[k]['discount']} for k,r in enumerate(probe)))
breakdowns=[]
for col in ('form','category','platform','has_payload','tenant_hosted'):
    for value in sorted(set(r[col] for r in probe)):
        sel=np.array([r[col]==value for r in probe])
        for n,p in ps.items():breakdowns.append(dict(dimension=col,value=value,model=n,**metrics(py[sel],p[sel],thresholds[n])))
js(OUT/'probe_breakdowns.json',breakdowns)
csvout(OUT/'probe_breakdowns.csv',({k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in breakdowns))
worst=[]
for n,p in ps.items():
    fp=sorted(np.flatnonzero((py==0)&(p>=thresholds[n])),key=lambda i:-p[i])
    fn=sorted(np.flatnonzero((py==1)&(p<thresholds[n])),key=lambda i:p[i])
    for kind,ii in [('false_alert',fp),('missed_attack',fn)]:
        for i in ii:worst.append(dict(model=n,failure=kind,score=float(p[i]),**probe[i]))
csvout(OUT/'probe_failures.csv',worst)
red=list(rows(OUT/'red_team.csv'));_,rs,rp=score([r['url'] for r in red])
csvout(OUT/'red_team_results.csv',({**r,'baseline_score':float(rs['v8_url_adjudicated'][i]),'prior_score':float(rs['prior'][i]),'prior_state':rp[i]['state'],'reason':rp[i]['reason'],'bypass':int(rs['prior'][i]<.28),'discount':rp[i]['discount']} for i,r in enumerate(red)))
red_bypass=int((rs['prior']<.28).sum());red_discount=sum(r['discount']>0 for r in rp)

# Permutation importance: pre-fixed stratified 6,000 clean-test rows, 3 repeats,
# raw V8 average precision. No fit, labels remain the data labels.
rng=np.random.default_rng(20261023)
pi=np.concatenate([rng.choice(np.flatnonzero(yt==c),3000,replace=False) for c in (0,1)])
Xp=Xtest[pi].copy();yp=yt[pi];base=average_precision_score(yp,models['8'].base_model.predict_proba(Xp)[:,1]);imp=[]
print('Permutation importance: 67 features x 3 repeats, 6000 clean-test rows',flush=True)
for j,name in enumerate(V7_FEATURE_NAMES):
    losses=[]
    for repeat in range(3):
        xx=Xp.copy();xx[:,j]=xx[rng.permutation(len(xx)),j]
        losses.append(float(base-average_precision_score(yp,models['8'].base_model.predict_proba(xx)[:,1])))
    imp.append(dict(index=j,feature=name,ap_drop_mean=float(np.mean(losses)),ap_drop_sd=float(np.std(losses)),repeats=3,n=6000,baseline_ap=float(base),drops=json.dumps(losses)))
csvout(OUT/'permutation_importance.csv',imp)
js(OUT/'permutation_metadata.json',{'status':'OBSERVED','model':'frozen V8 raw','metric':'average_precision','sample_n':6000,'class_n':[3000,3000],'seed':20261023,'repeats':3,'sample_test_positions_sha256':hashlib.sha256(pi.tobytes()).hexdigest(),'caveat':'Correlated interactions can mask importance; row permutation is not causal. Subsample is fixed before evaluating importance.'})

# Burned corpora are scored LAST, after all design is frozen; reporting only.
gold=json.loads(readtext(ROOT/'sentinel-ml/android-runtime/golden_test_data/golden_urls_v8.json'))
goldurls=[g['url'] for g in gold];_,gs,gp=score(goldurls)
print('Golden schema keys',list(gold[0]),flush=True)
gy=np.array([int(g['label'].upper()=='MALICIOUS') if isinstance(g.get('label'),str) else int(g.get('label',g.get('isMalicious',0))) for g in gold])
orig=np.array([g['finalProbability'] for g in gold])>=.28
baseline=gs['v8_url_adjudicated']>=.28;candidate=gs['prior']>=.28
gmetrics={'n':len(gold),'baseline_fixture_output_disagreements':int((baseline!=orig).sum()),'all_decision_changes':int((candidate!=baseline).sum()),'correct_to_wrong':int(((baseline==gy)&(candidate!=gy)).sum()),'wrong_to_correct':int(((baseline!=gy)&(candidate==gy)).sum()),'candidate_fixture_output_disagreements':int((candidate!=orig).sum()),'label_key':'label else isMalicious; inspect score file','metrics':{n:metrics(gy,p,thresholds[n]) for n,p in gs.items()}}
csvout(OUT/'golden_regression_report.csv',({'url':g['url'],'expected':int(gy[i]),'frozen_alert':int(orig[i]),'baseline_score':float(gs['v8_url_adjudicated'][i]),'prior_score':float(gs['prior'][i]),'correct_to_wrong':int(baseline[i]==gy[i] and candidate[i]!=gy[i]),'changed':int(baseline[i]!=candidate[i])} for i,g in enumerate(gold)))
benchobj=json.loads(readtext(U/'data/hard_benign_benchmark_500.json'))
def collect(x):
    if isinstance(x,list):
        for v in x:yield from collect(v)
    elif isinstance(x,dict):
        if isinstance(x.get('url'),str):yield x
        else:
            for v in x.values():yield from collect(v)
bench=list(collect(benchobj));assert len(bench)==500
_,bs,bp=score([r['url'] for r in bench]);bm={n:metrics(np.zeros(500,int),p,thresholds[n]) for n,p in bs.items()}
new_bfp=int(((bs['prior']>=.28)&(bs['v8_url_adjudicated']<.28)).sum())
csvout(OUT/'burned_500_regression_report.csv',({'url':r['url'],'baseline_score':float(bs['v8_url_adjudicated'][i]),'prior_score':float(bs['prior'][i]),'new_false_alert':int(bs['prior'][i]>=.28 and bs['v8_url_adjudicated'][i]<.28)} for i,r in enumerate(bench)))
js(OUT/'burned_regression_results.json',{'usage':'REPORT ONLY; design fixed before any inference; no revision based on these outputs','golden':gmetrics,'500_metrics':bm,'500_new_false_alerts':new_bfp})
reduction=1-overall['prior']['fp']/overall['v8_url_adjudicated']['fp']
loss=100*(cleanmetrics['v8_url_adjudicated']['recall']-cleanmetrics['prior']['recall'])
gates=[dict(gate='Probe false-alert reduction >=20% relative',value=reduction,pass_gate=reduction>=.2),dict(gate='Clean attack recall loss <=0.2 percentage points',value=loss,pass_gate=loss<=.2),dict(gate='Red-team bypass=0 and no discount',value={'n':len(red),'bypass':red_bypass,'discounted':red_discount},pass_gate=red_bypass==0 and red_discount==0),dict(gate='Golden correctness regressions=0 (REPORT ONLY)',value=gmetrics['correct_to_wrong'],pass_gate=gmetrics['correct_to_wrong']==0),dict(gate='500 false alerts no worse and no newly introduced (REPORT ONLY)',value={'baseline_fp':bm['v8_url_adjudicated']['fp'],'candidate_fp':bm['prior']['fp'],'new_fp':new_bfp},pass_gate=bm['prior']['fp']<=bm['v8_url_adjudicated']['fp'] and new_bfp==0)]
js(OUT/'gates.json',{'status':'PROVISIONAL authored-label evidence','gates':gates,'all_pass':all(g['pass_gate'] for g in gates),'strict_golden_output_parity_pass':gmetrics['candidate_fixture_output_disagreements']==0,'no_fit':True})
js(OUT/'evaluation_completion.json',{'time_utc':stamp(),'elapsed_seconds':time.monotonic()-start,'fit_count':0,'exit_code_expected':0,'probe_sha256_after':sha(OUT/'probe.csv'),'policy_sha256_after':sha(EXP/'safe_domain_prior.py')})
print(json.dumps({'clean':cleanmetrics['v8_url_adjudicated'],'probe':overall,'gates':gates,'golden':gmetrics,'elapsed_seconds':time.monotonic()-start},default=str),flush=True)
