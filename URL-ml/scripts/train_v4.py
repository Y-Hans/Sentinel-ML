"""V4 staged ablations and architecture comparison.

Protected TEST/hard rows are never used for fitting or selecting thresholds.
Outputs are unique V4 artifacts/reports; the frozen champion is read-only.
"""
from __future__ import annotations
import hashlib,json,os,sys,time
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.feature_extraction import FeatureHasher
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REP=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import domain_group
from v4_features import deterministic_v4,char_tokens,vectorize_deterministic

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def metrics(y,p,t):
 y=np.asarray(y); p=np.asarray(p); z=p>=t; tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel()
 return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)),'roc_auc':float(roc_auc_score(y,p)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}
def threshold(y,p):
 grid=np.linspace(.0005,.9995,1999); y=np.asarray(y); s=np.sort(p[y==0]); b=np.sort(p[y==1]); f=s.size-np.searchsorted(s,grid,'left'); r=b.size-np.searchsorted(b,grid,'left'); fr=f/max(1,s.size); rr=r/max(1,b.size); ok=np.flatnonzero(fr<=.01); ok=ok if len(ok) else np.arange(len(grid)); i=ok[np.lexsort((grid[ok],fr[ok],-rr[ok]))[0]]; return float(grid[i])
def pareto(yv,pv,yt,pt,yh,ph):
 rows=[]
 for t in np.linspace(.001,.999,999): rows.append({'threshold':float(t),'validation':metrics(yv,pv,t),'test':metrics(yt,pt,t),'hard_source':metrics(yh,ph,t)})
 return rows
def main():
 original=pd.read_csv(DATA/'cleaned_dataset.csv',usecols=['url','label']); original['label']=1-original.label.astype(int)
 hard=pd.read_csv(DATA/'hard_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v3.csv')
 g=original.url.map(domain_group); y=original.label.to_numpy(); idx=np.arange(len(original))
 tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,g)); va_rel,te_rel=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],g.iloc[rest])); va,te=rest[va_rel],rest[te_rel]
 urls=original.url.tolist(); hurls=hard.url.tolist(); rurls=rem.url.tolist(); all_urls=urls+rurls+hurls
 configs=[('host_path_query_interactions',('host','path','query','interactions'),False),('host_path_query',('host','path','query'),False),('host_path',('host','path'),False),('deterministic_only',(),False),('char_full_1000',('host','path','query','interactions'),True),('char_scopes_1500',('host','path','query','interactions'),True)]
 results=[]; registry=[]; rem_y=rem.label.to_numpy(); fit_y=np.concatenate([y[tr],rem_y]);
 for cfg,families,chars in configs:
  name='v4_'+cfg; t0=time.perf_counter(); X,names=vectorize_deterministic([urls[i] for i in tr]+rurls+ [urls[i] for i in va]+[urls[i] for i in te]+hurls,families)
  ntr=len(tr)+len(rurls); nva=len(va); nte=len(te); Xtr,Xv,Xt,Xh=X[:ntr],X[ntr:ntr+nva],X[ntr+nva:ntr+nva+nte],X[ntr+nva+nte:]
  sc=StandardScaler(); Xtr=sc.fit_transform(Xtr); Xv=sc.transform(Xv); Xt=sc.transform(Xt); Xh=sc.transform(Xh)
  if chars:
   dims=1000 if cfg.endswith('1000') else 1500
   hasher=FeatureHasher(n_features=dims,input_type='string',alternate_sign=False)
   def hx(us): return hasher.transform([{x:1 for scope in ('full','host','path','query') for x in char_tokens(u,scope)} for u in us])
   Htr=hx([urls[i] for i in tr]+rurls); Hv=hx([urls[i] for i in va]); Ht=hx([urls[i] for i in te]); Hh=hx(hurls)
   from scipy.sparse import hstack
   Xtr=hstack([Xtr,Htr]).tocsr(); Xv=hstack([Xv,Hv]).tocsr(); Xt=hstack([Xt,Ht]).tocsr(); Xh=hstack([Xh,Hh]).tocsr()
   model=LogisticRegression(C=1.0,max_iter=100,n_jobs=1,class_weight='balanced',solver='liblinear',random_state=42)
  else:
   model=ExtraTreesClassifier(n_estimators=80,max_depth=22,min_samples_leaf=2,n_jobs=1,class_weight='balanced',random_state=42)
  model.fit(Xtr,fit_y); pv=model.predict_proba(Xv)[:,1]; pt=model.predict_proba(Xt)[:,1]; ph=model.predict_proba(Xh)[:,1]; th=threshold(y[va],pv)
  art=ROOT/'model'/'challengers'/name; art.mkdir(parents=True,exist_ok=False)
  joblib.dump(model,art/'model.joblib'); joblib.dump(sc,art/'scaler.joblib')
  meta={'experiment_id':name,'architecture':type(model).__name__,'families':list(families),'char_features':bool(chars),'feature_count':int(Xtr.shape[1]),'feature_schema_hash':hashlib.sha256('\n'.join(names).encode()).hexdigest(),'seed':42,'threshold':th,'train_rows':int(len(tr)),'remediation_rows':int(len(rem)),'remediation_sha256':sha(DATA/'remediation_hard_negatives_v3.csv'),'source_dataset_sha256':sha(DATA/'cleaned_dataset.csv'),'hard_dataset_sha256':sha(DATA/'hard_dataset.csv'),'validation':metrics(y[va],pv,th),'test':metrics(y[te],pt,th),'hard_source_holdout':metrics(hard.label.to_numpy(),ph,th),'threshold_pareto':pareto(y[va],pv,y[te],pt,hard.label.to_numpy(),ph),'fit_seconds':time.perf_counter()-t0,'model_size_bytes':int(sum(x.stat().st_size for x in art.iterdir())),'artifact':'model/challengers/'+name}
  (art/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8'); results.append(meta); registry.append(meta.copy()); print(name,json.dumps({k:meta[k] for k in ('feature_count','threshold','validation','test','hard_source_holdout','model_size_bytes')},separators=(',',':')))
 out={'campaign':'URL-ML V4','protocol':{'train_source':'cleaned_dataset.csv','threshold_selection':'validation_only','protected_evaluation':['hard_dataset.csv','fixed_domain_disjoint_test'],'ood':'unavailable','champion_sha256':sha(ROOT/'model/champion/model.joblib')},'splits':{'train':len(tr),'validation':len(va),'test':len(te),'hard_source':len(hard)},'experiments':results}
 (REP/'URL_V4_EXPERIMENT_REGISTRY.json').write_text(json.dumps(out,indent=2),encoding='utf-8');
 with (REP/'EXPERIMENT_REGISTRY.jsonl').open('a',encoding='utf-8') as f:
  for r in registry:
   f.write(json.dumps({'campaign':'V4',**{k:r[k] for k in ('experiment_id','architecture','families','feature_count','threshold','validation','test','hard_source_holdout','model_size_bytes')}})+'\n')
 print('WROTE',REP/'URL_V4_EXPERIMENT_REGISTRY.json')
if __name__=='__main__': main()
