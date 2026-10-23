from runlib import *
import pickle,warnings,collections,math
protect()
import numpy as np,pandas as pd,sklearn,joblib
from sklearn.model_selection import GroupShuffleSplit
U=ROOT/'sentinel-ml/URL-ml'; sys.path.insert(0,str(U/'scripts'))
from v7_features import vectorize_v7,V7_FEATURE_NAMES
from url_features import domain_group
from v7_classifier import V7GatedURLClassifier
from v8_classifier import V8RelationalURLClassifier
phase=sys.argv[1] if len(sys.argv)>1 else 'reproduction'
class Portable:
    def __init__(self,obj): self.obj=obj
    def predict_proba(self,X):
        o=self.obj; bins=np.stack([np.searchsorted(np.asarray(t),X[:,j],side='left') for j,t in enumerate(o['bin_thresholds'])],axis=1); z=np.full(len(X),float(o['base_score']))
        for tree in o['trees']:
            for r in range(len(X)):
                idx=0
                while not tree[idx][5]:
                    n=tree[idx]; idx=int(n[2] if (bool(n[6]) if np.isnan(X[r,int(n[0])]) else bins[r,int(n[0])]<=int(n[1])) else n[3])
                z[r]+=tree[idx][4]
        p=1/(1+np.exp(-np.clip(z,-700,700))); return np.column_stack([1-p,p])
def load(name):
    p=U/'models'/('v'+name+'_champion.joblib'); meta={'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p)}
    try:
        with warnings.catch_warnings(record=True) as ww:
            warnings.simplefilter('always'); model=joblib.load(p); meta['warnings']=[str(x.message) for x in ww]
        model.base_model.predict_proba(np.zeros((1,67),dtype=np.float32)); meta['mode']='OBSERVED_JOBLIB'
    except Exception as e:
        meta['load_error']=repr(e); pp=U/'models'/('v'+name+'_champion_portable.json'); obj=json.loads(pp.read_text(encoding='utf-8')); base=Portable(obj)
        model=V7GatedURLClassifier(base,obj['feature_names'],obj['decision_threshold']) if name=='7' else V8RelationalURLClassifier(base,obj['feature_names'],obj['decision_threshold'])
        meta.update(mode='PORTABLE_JSON_FALLBACK',portable_sha256=sha(pp))
    return model,meta
models={}; metadata={}
for name in ('7','8'): models[name],metadata[name]=load(name)
env={'python':sys.version,'executable':sys.executable,'numpy':np.__version__,'sklearn':sklearn.__version__,'joblib':joblib.__version__}
if phase=='reproduction':
    data=pd.read_csv(U/'data/cleaned_dataset.csv',usecols=['url','label']); data['label']=1-data.label.astype(int); groups=data.url.map(domain_group); y=data.label.to_numpy(); idx=np.arange(len(data))
    tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,groups)); vr,ter=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],groups.iloc[rest])); te=rest[ter]
    tt=data.url.iloc[te].tolist(); yt=y[te]; X,_=vectorize_v7(tt)
    results={'environment':env,'models':metadata,'split':{'train':len(tr),'validation':len(vr),'test':len(te),'group_function_source_sha256':sha(U/'scripts/url_features.py'),'cleaned_sha256':sha(U/'data/cleaned_dataset.csv'),'test_index_sha256':hashlib.sha256(te.tobytes()).hexdigest()},'measurements':[]}
    for name,model in models.items():
        raw=model.base_model.predict_proba(X)[:,1]; adj=model.predict_proba(X,urls=tt)[:,1] if name=='8' else model.predict_proba(X)[:,1]
        modes=[('raw',raw),('adjudicated',adj)]
        if name=='8': modes.append(('adjudicated_without_url_strings',model.predict_proba(X)[:,1]))
        for mode,p in modes:
            pred=p>=float(model.threshold); results['measurements'].append({'model':'URL_V'+name,'mode':mode,'threshold':float(model.threshold),'n':len(te),'benign_n':int((yt==0).sum()),'attack_n':int((yt==1).sum()),'benign_fp':int(((yt==0)&pred).sum()),'true_positive':int(((yt==1)&pred).sum()),'FPR':float(pred[yt==0].mean()),'recall':float(pred[yt==1].mean())})
    # Frozen golden fixtures are comparison-only parity references, never used for model/gate decisions.
    gp=ROOT/'sentinel-ml/android-runtime/golden_test_data/golden_urls_v8.json'; gg=json.loads(gp.read_text(encoding='utf-8')); GX=np.array([g['features'] for g in gg],dtype=np.float32); fresh,_=vectorize_v7([g['url'] for g in gg]); m=models['8']; gr=m.base_model.predict_proba(GX)[:,1]; ga=m.predict_proba(GX,urls=[g['url'] for g in gg])[:,1]
    results['golden_reference_comparison']={'path':gp.relative_to(ROOT).as_posix(),'sha256':sha(gp),'n':len(gg),'feature_max_abs_difference':float(np.max(np.abs(fresh-GX))),'raw_probability_max_abs_difference':float(np.max(np.abs(gr-np.array([g['rawProbability'] for g in gg])))),'final_probability_max_abs_difference':float(np.max(np.abs(ga-np.array([g['finalProbability'] for g in gg])))),'raw_matches_at_1e_4':int((np.abs(gr-np.array([g['rawProbability'] for g in gg]))<1e-4).sum())}
    jsave('urls_reproduction.json',results); print(json.dumps(results,indent=2),flush=True)
else:
    manifest=jload('freeze_manifest_v2.json'); assert sha(OUT/manifest['urls']['path'])==manifest['urls']['sha256']; sim=readrows(OUT/manifest['urls']['path']); tt=[r['url'] for r in sim]; X,_=vectorize_v7(tt); predrows=[]
    for name,m in models.items():
        raw=m.base_model.predict_proba(X)[:,1]; adj=m.predict_proba(X,urls=tt)[:,1] if name=='8' else m.predict_proba(X)[:,1]
        for i,r in enumerate(sim):
            reason=m.adjudicate_single(tt[i],X[i],float(raw[i]))[2] if name=='8' else 'V7 safe-brand gating'
            predrows.append({'uid':r['uid'],'model':'URL_V'+name,'score':float(raw[i]),'raw_score':float(raw[i]),'adjudicated_score':float(adj[i]),'raw_alert':int(raw[i]>=float(m.threshold)),'adjudicated_alert':int(adj[i]>=float(m.threshold)),'threshold':float(m.threshold),'policy_reason':reason})
    jsonl('url_predictions.jsonl',predrows); jsave('url_simulation_environment.json',{'environment':env,'models':metadata,'simulation_hash':sha(OUT/manifest['urls']['path'])}); print('URL prediction rows',len(predrows))
