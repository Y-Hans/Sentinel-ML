from __future__ import annotations
import hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.linear_model import LogisticRegression,SGDClassifier
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REPORTS=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import FULL_FEATURES,domain_group,extract_url_features
def metric(y,p,t):
 y=np.asarray(y,dtype=int); pred=np.asarray(p)>=t; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel(); return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]],'roc_auc':float(roc_auc_score(y,p))}
def thresh(y,p):
 grid=np.linspace(.0005,.9995,1999); y=np.asarray(y); s=np.sort(p[y==0]); b=np.sort(p[y==1]); f=s.size-np.searchsorted(s,grid,'left'); tp=b.size-np.searchsorted(b,grid,'left'); fr=f/max(1,s.size); re=tp/max(1,b.size); ok=np.flatnonzero(fr<=.01); i=(ok if len(ok) else np.arange(len(grid)))[np.lexsort((grid[ok],fr[ok],-re[ok]))[0]] if len(ok) else 0; return float(grid[i])
def main():
 df=pd.read_csv(DATA/'final_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v1.csv'); X=df[FULL_FEATURES].astype(np.float32); y=df.label.astype(int).to_numpy(); g=df.url.map(domain_group); tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.40,random_state=42).split(X,y,g)); vr,te=next(GroupShuffleSplit(n_splits=1,test_size=.50,random_state=42).split(X.iloc[rest],y[rest],g.iloc[rest])); vi,tei=rest[vr],rest[te]; sc=StandardScaler().fit(X.iloc[tr]); Xs=sc.transform(X); rx=sc.transform(pd.DataFrame([extract_url_features(u,FULL_FEATURES) for u in rem.url],columns=FULL_FEATURES)); hard=df.DatasetSource.to_numpy()=='hard'; fitX=np.vstack([Xs[tr],rx]); fity=np.concatenate([y[tr],rem.label.astype(int)]); sw=np.concatenate([np.ones(len(tr)),np.full(len(rem),5.)]); configs=[('challenger_source_invariant_v3_logistic',LogisticRegression(C=1.0,class_weight='balanced',max_iter=300,random_state=42)),('challenger_source_invariant_v3_sgd',SGDClassifier(loss='log_loss',alpha=1e-5,max_iter=100,tol=1e-4,class_weight='balanced',random_state=42))]; out={}
 for name,m in configs:
  m.fit(fitX,fity,sample_weight=sw); pv=m.predict_proba(Xs[vi])[:,1]; t=thresh(y[vi],pv); pt=m.predict_proba(Xs[tei])[:,1]; ph=m.predict_proba(Xs[hard])[:,1]; p=ROOT/'model'/'challengers'/name; p.mkdir(exist_ok=True); joblib.dump(m,p/'model.joblib'); joblib.dump(sc,p/'scaler.joblib'); r={'experiment_id':name,'architecture':type(m).__name__,'features':FULL_FEATURES,'seed':42,'threshold':t,'remediation_dataset_sha256':hashlib.sha256((DATA/'remediation_hard_negatives_v1.csv').read_bytes()).hexdigest(),'remediation_weight':5.0,'artifact':'model/challengers/'+name+'/model.joblib','validation':metric(y[vi],pv,t),'test':metric(y[tei],pt,t),'hard_source_holdout':metric(y[hard],ph,t),'serialized_model_bytes':int((p/'model.joblib').stat().st_size)}; (p/'metadata.json').write_text(json.dumps(r,indent=2),encoding='utf-8'); out[name]=r; print(name,json.dumps(r,indent=2))
 stamp=datetime.now(timezone.utc).isoformat()
 with (REPORTS/'EXPERIMENT_REGISTRY.jsonl').open('a',encoding='utf-8') as f:
  for n,r in out.items(): f.write(json.dumps({'experiment_id':n,'timestamp':stamp,'dataset_version':r['remediation_dataset_sha256'],'decision':'challenger','architecture':r['architecture'],'features':r['features'],'seed':42,'threshold':r['threshold'],'remediation_weight':5.0,'validation':r['validation'],'test':r['test'],'hard_source_holdout':r['hard_source_holdout'],'model_size_bytes':r['serialized_model_bytes']})+'\n')
 (REPORTS/'URL_REMEDIATION_V3_EXPERIMENTS.json').write_text(json.dumps({'generated_at':stamp,'experiments':out,'frozen_champion_untouched':True},indent=2),encoding='utf-8')
if __name__=='__main__': main()
