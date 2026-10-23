from __future__ import annotations
import hashlib, json, sys, time
from datetime import datetime, timezone
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REPORTS=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import FULL_FEATURES, domain_group, extract_url_features
SEED=42
def metric(y,p,t):
    y=np.asarray(y,dtype=int); pred=np.asarray(p)>=t; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]],'roc_auc':float(roc_auc_score(y,p)) if len(np.unique(y))==2 else None}
def thresh(y,p):
    grid=np.linspace(.0005,.9995,1999); y=np.asarray(y); s=np.sort(p[y==0]); b=np.sort(p[y==1]); fp=s.size-np.searchsorted(s,grid,'left'); tp=b.size-np.searchsorted(b,grid,'left'); fpr=fp/max(1,s.size); rec=tp/max(1,b.size); ok=np.flatnonzero(fpr<=.01); ok=ok if len(ok) else np.arange(len(grid)); i=ok[np.lexsort((grid[ok],fpr[ok],-rec[ok]))[0]]; return float(grid[i])
def main():
    df=pd.read_csv(DATA/'final_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v1.csv'); X=df[FULL_FEATURES].astype(np.float32); y=df.label.astype(int).to_numpy(); g=df.url.map(domain_group)
    train,rest=next(GroupShuffleSplit(n_splits=1,test_size=.40,random_state=SEED).split(X,y,g)); vr,tr=next(GroupShuffleSplit(n_splits=1,test_size=.50,random_state=SEED).split(X.iloc[rest],y[rest],g.iloc[rest])); vi,tei=rest[vr],rest[tr]
    scaler=StandardScaler().fit(X.iloc[train]); Xs=scaler.transform(X).astype(np.float32); rx=pd.DataFrame([extract_url_features(u,FULL_FEATURES) for u in rem.url],columns=FULL_FEATURES).astype(np.float32); rX=scaler.transform(rx).astype(np.float32); ry=rem.label.astype(int).to_numpy(); hard=df.DatasetSource.to_numpy()=='hard'; fitX=np.vstack([Xs[train],rX]); fity=np.concatenate([y[train],ry]); sw=np.concatenate([np.ones(len(train)),np.full(len(ry),5.)])
    configs=[('challenger_source_invariant_v2_rf40',RandomForestClassifier(n_estimators=40,max_depth=18,min_samples_leaf=2,n_jobs=1,class_weight='balanced_subsample',random_state=SEED)),('challenger_source_invariant_v2_extra40',ExtraTreesClassifier(n_estimators=40,max_depth=18,min_samples_leaf=2,n_jobs=1,class_weight='balanced',random_state=SEED)),('challenger_source_invariant_v2_gb',GradientBoostingClassifier(n_estimators=80,learning_rate=.06,max_depth=2,subsample=.8,random_state=SEED)),('challenger_source_invariant_v2_hgb',HistGradientBoostingClassifier(max_iter=120,learning_rate=.08,max_leaf_nodes=15,l2_regularization=1.0,random_state=SEED))]
    results={}; stamp=datetime.now(timezone.utc).isoformat()
    for name,model in configs:
        start=time.perf_counter(); model.fit(fitX,fity,sample_weight=sw); fit_s=time.perf_counter()-start; pv=model.predict_proba(Xs[vi])[:,1]; t=thresh(y[vi],pv); pt=model.predict_proba(Xs[tei])[:,1]; ph=model.predict_proba(Xs[hard])[:,1]; path=ROOT/'model'/'challengers'/name; path.mkdir(exist_ok=True); joblib.dump(model,path/'model.joblib'); joblib.dump(scaler,path/'scaler.joblib')
        r={'experiment_id':name,'architecture':type(model).__name__,'features':FULL_FEATURES,'seed':SEED,'threshold':t,'remediation_dataset_sha256':hashlib.sha256((DATA/'remediation_hard_negatives_v1.csv').read_bytes()).hexdigest(),'remediation_weight':5.0,'fit_seconds':fit_s,'artifact':'model/challengers/'+name+'/model.joblib','validation':metric(y[vi],pv,t),'test':metric(y[tei],pt,t),'hard_source_holdout':metric(y[hard],ph,t),'serialized_model_bytes':int((path/'model.joblib').stat().st_size)}; (path/'metadata.json').write_text(json.dumps(r,indent=2),encoding='utf-8'); results[name]=r; print(name,json.dumps(r,indent=2),flush=True)
    with (REPORTS/'EXPERIMENT_REGISTRY.jsonl').open('a',encoding='utf-8') as f:
        for n,r in results.items(): f.write(json.dumps({'experiment_id':n,'timestamp':stamp,'dataset_version':r['remediation_dataset_sha256'],'decision':'challenger','architecture':r['architecture'],'features':r['features'],'seed':SEED,'threshold':r['threshold'],'remediation_weight':5.0,'validation':r['validation'],'test':r['test'],'hard_source_holdout':r['hard_source_holdout'],'model_size_bytes':r['serialized_model_bytes']})+'\n')
    (REPORTS/'URL_REMEDIATION_V2_EXPERIMENTS.json').write_text(json.dumps({'generated_at':stamp,'experiments':results,'frozen_champion_untouched':True},indent=2),encoding='utf-8')
    lines=['# URL-ML Remediation V2 Architecture Challengers','','Fresh compact learners trained on the source-diverse v1 remediation set. Thresholds are dense validation-only selections.','']
    for n,r in results.items(): lines.append(f"- **{n}** ({r['architecture']}): threshold {r['threshold']:.4f}; validation FPR/recall {r['validation']['benign_fpr']:.4f}/{r['validation']['malicious_recall']:.4f}; TEST FPR/recall {r['test']['benign_fpr']:.4f}/{r['test']['malicious_recall']:.4f}; hard-source FPR/recall {r['hard_source_holdout']['benign_fpr']:.4f}/{r['hard_source_holdout']['malicious_recall']:.4f}; size {r['serialized_model_bytes']:,} bytes.")
    (REPORTS/'URL_REMEDIATION_V2_EXPERIMENTS.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
if __name__=='__main__': main()
