"""Fresh source-diverse hard-negative challengers; frozen champion is never written."""
from __future__ import annotations
import hashlib, json, pickle, sys, time
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE = Path(__file__).resolve(); ROOT = HERE.parents[1]; DATA = ROOT / "data"; REPORTS = ROOT / "reports"
sys.path.insert(0, str(HERE.parent))
from url_features import FULL_FEATURES, domain_group, extract_url_features
SEED = 42

def metric(y, p, t):
    y=np.asarray(y,dtype=int); p=np.asarray(p); pred=p>=t; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return {"n":int(len(y)),"benign_n":int(tn+fp),"malicious_n":int(fn+tp),"benign_fpr":float(fp/max(1,tn+fp)),"malicious_recall":float(tp/max(1,fn+tp)),"confusion_matrix":[[int(tn),int(fp)],[int(fn),int(tp)]],"roc_auc":float(roc_auc_score(y,p)) if len(np.unique(y))==2 else None}

def dense_threshold(y,p,max_fpr=.01):
    grid=np.linspace(0.0005,.9995,1999); y=np.asarray(y); safe=np.sort(p[y==0]); bad=np.sort(p[y==1]); fp=safe.size-np.searchsorted(safe,grid,'left'); tp=bad.size-np.searchsorted(bad,grid,'left'); fpr=fp/max(1,safe.size); rec=tp/max(1,bad.size); ok=np.flatnonzero(fpr<=max_fpr)
    if not len(ok): ok=np.arange(len(grid))
    i=ok[np.lexsort((grid[ok],fpr[ok],-rec[ok]))[0]]; return float(grid[i])

def main():
    REPORTS.mkdir(exist_ok=True); (ROOT/'model'/'challengers').mkdir(exist_ok=True)
    df=pd.read_csv(DATA/'final_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v1.csv')
    groups=df.url.map(domain_group); X=df[FULL_FEATURES].astype(np.float32); y=df.label.astype(int).to_numpy()
    first,rest=next(GroupShuffleSplit(n_splits=1,test_size=.40,random_state=SEED).split(X,y,groups)); vr,tr=next(GroupShuffleSplit(n_splits=1,test_size=.50,random_state=SEED).split(X.iloc[rest],y[rest],groups.iloc[rest])); train_idx, val_idx, test_idx=first,rest[vr],rest[tr]
    scaler=StandardScaler().fit(X.iloc[train_idx]); Xs=scaler.transform(X).astype(np.float32)
    remX=pd.DataFrame([extract_url_features(u,FULL_FEATURES) for u in rem.url],columns=FULL_FEATURES).astype(np.float32); remXs=scaler.transform(remX).astype(np.float32); remy=rem.label.astype(int).to_numpy()
    original_train_idx=np.asarray([i for i in train_idx if df.iloc[i].DatasetSource=='original'],dtype=int); hard=df.DatasetSource.to_numpy()=='hard'
    configs=[('challenger_hardsource_v1_full_w1',list(FULL_FEATURES),1.0),('challenger_hardsource_v1_full_w5',list(FULL_FEATURES),5.0),('challenger_hardsource_v1_full_w10',list(FULL_FEATURES),10.0),('challenger_hardsource_v1_structural_w5',[f for f in FULL_FEATURES if f not in {'KnownBrandDomain','BrandImpersonationScore','SuspiciousTLD'}],5.0)]
    results={}
    for name,features,weight in configs:
        ix=[FULL_FEATURES.index(f) for f in features]; fitX=np.vstack([Xs[train_idx][:,ix],np.repeat(remXs[:,ix],1,axis=0)]); fity=np.concatenate([y[train_idx],remy]); weights=np.concatenate([np.ones(len(train_idx)),np.full(len(remy),weight)])
        model=RandomForestClassifier(n_estimators=80,max_depth=18,min_samples_leaf=2,n_jobs=1,class_weight='balanced_subsample',random_state=SEED)
        start=time.perf_counter(); model.fit(fitX,fity,sample_weight=weights); fit_s=time.perf_counter()-start
        pv=model.predict_proba(Xs[val_idx][:,ix])[:,1]; t=dense_threshold(y[val_idx],pv); pt=model.predict_proba(Xs[test_idx][:,ix])[:,1]; ph=model.predict_proba(Xs[hard][:,ix])[:,1]
        path=ROOT/'model'/'challengers'/name; path.mkdir(exist_ok=True); joblib.dump(model,path/'model.joblib'); joblib.dump(scaler,path/'scaler.joblib')
        metadata={'experiment_id':name,'architecture':'RandomForestClassifier','features':features,'seed':SEED,'threshold':t,'remediation_dataset_sha256':hashlib.sha256((DATA/'remediation_hard_negatives_v1.csv').read_bytes()).hexdigest(),'remediation_rows':len(remy),'remediation_weight':weight,'fit_seconds':fit_s,'artifact':'model/challengers/'+name+'/model.joblib'}; (path/'metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
        results[name]={**metadata,'validation':metric(y[val_idx],pv,t),'test':metric(y[test_idx],pt,t),'hard_source_holdout':metric(y[hard],ph,t),'serialized_model_bytes':int((path/'model.joblib').stat().st_size)}
        print(name, json.dumps(results[name],indent=2),flush=True)
    registry=REPORTS/'EXPERIMENT_REGISTRY.jsonl'; stamp=datetime.now(timezone.utc).isoformat()
    with registry.open('a',encoding='utf-8') as f:
        for name,r in results.items(): f.write(json.dumps({'experiment_id':name,'timestamp':stamp,'dataset_version':r['remediation_dataset_sha256'],'decision':'challenger','architecture':r['architecture'],'features':r['features'],'seed':SEED,'threshold':r['threshold'],'remediation_weight':r['remediation_weight'],'validation':r['validation'],'test':r['test'],'hard_source_holdout':r['hard_source_holdout'],'model_size_bytes':r['serialized_model_bytes']})+'\n')
    (REPORTS/'URL_REMEDIATION_EXPERIMENTS.json').write_text(json.dumps({'generated_at':stamp,'dataset_sha256':r['remediation_dataset_sha256'],'experiments':results,'frozen_champion_untouched':True},indent=2),encoding='utf-8')
    lines=['# URL-ML Remediation Experiments','', 'All challengers were trained from scratch. The frozen champion artifact was not used as a training starting point and no TEST/OOD/hard-source row was added to training. Thresholds were selected by a dense validation-only sweep under 1% benign FPR.','']
    for n,r in results.items(): lines.append(f"- **{n}**: remediation weight {r['remediation_weight']:g}; threshold {r['threshold']:.4f}; validation FPR/recall {r['validation']['benign_fpr']:.4f}/{r['validation']['malicious_recall']:.4f}; TEST FPR/recall {r['test']['benign_fpr']:.4f}/{r['test']['malicious_recall']:.4f}; hard-source FPR/recall {r['hard_source_holdout']['benign_fpr']:.4f}/{r['hard_source_holdout']['malicious_recall']:.4f}; size {r['serialized_model_bytes']:,} bytes.")
    (REPORTS/'URL_REMEDIATION_EXPERIMENTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')

if __name__=='__main__': main()
