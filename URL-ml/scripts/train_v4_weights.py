from __future__ import annotations
import hashlib,json,sys
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REP=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import domain_group
from v4_features import vectorize_deterministic
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def met(y,p,t):
 y=np.asarray(y); z=np.asarray(p)>=t; tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel(); return {'n':int(len(y)),'benign_fpr':fp/max(1,tn+fp),'malicious_recall':tp/max(1,fn+tp),'roc_auc':roc_auc_score(y,p),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}
def th(y,p):
 grid=np.linspace(.0005,.9995,1999); y=np.asarray(y); s=np.sort(p[y==0]); b=np.sort(p[y==1]); f=s.size-np.searchsorted(s,grid,'left'); r=b.size-np.searchsorted(b,grid,'left'); fr=f/max(1,s.size); rr=r/max(1,b.size); ok=np.flatnonzero(fr<=.01); ok=ok if len(ok) else np.arange(len(grid)); i=ok[np.lexsort((grid[ok],fr[ok],-rr[ok]))[0]]; return float(grid[i])
def main():
 d=pd.read_csv(DATA/'cleaned_dataset.csv',usecols=['url','label']); d.label=1-d.label.astype(int); hard=pd.read_csv(DATA/'hard_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v3.csv'); y=d.label.to_numpy(); g=d.url.map(domain_group); ix=np.arange(len(d)); tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(ix,y,g)); vr,te_r=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],g.iloc[rest])); va,te=rest[vr],rest[te_r]
 X,names=vectorize_deterministic(d.url.iloc[np.r_[tr,va,te]].tolist()+rem.url.tolist()+hard.url.tolist(),('host','path','query','interactions')); ntr=len(tr); nva=len(va); nte=len(te); nr=len(rem); Xtr,Xv,Xt,Xr,Xh=X[:ntr],X[ntr:ntr+nva],X[ntr+nva:ntr+nva+nte],X[ntr+nva+nte:ntr+nva+nte+nr],X[ntr+nva+nte+nr:]; sc=StandardScaler().fit(Xtr); Xtr=sc.transform(Xtr); Xv=sc.transform(Xv); Xt=sc.transform(Xt); Xr=sc.transform(Xr); Xh=sc.transform(Xh); out=[]
 for w in (5.,10.,20.,40.,80.,160.):
  name=f'v4_weight{int(w)}_extra40'; p=ROOT/'model'/'challengers'/name
  if p.exists(): continue
  m=ExtraTreesClassifier(n_estimators=40,max_depth=18,min_samples_leaf=2,n_jobs=1,class_weight='balanced',random_state=42); m.fit(np.vstack([Xtr,Xr]),np.r_[y[tr],rem.label.to_numpy()],sample_weight=np.r_[np.ones(ntr),np.full(nr,w)]); pv=m.predict_proba(Xv)[:,1]; pt=m.predict_proba(Xt)[:,1]; ph=m.predict_proba(Xh)[:,1]; t=th(y[va],pv); p.mkdir(parents=True,exist_ok=False); joblib.dump(m,p/'model.joblib'); joblib.dump(sc,p/'scaler.joblib'); meta={'experiment_id':name,'architecture':'ExtraTreesClassifier','families':['host','path','query','interactions'],'feature_count':len(names),'seed':42,'remediation_weight':w,'threshold':t,'source_dataset_sha256':sha(DATA/'cleaned_dataset.csv'),'remediation_sha256':sha(DATA/'remediation_hard_negatives_v3.csv'),'hard_dataset_sha256':sha(DATA/'hard_dataset.csv'),'validation':met(y[va],pv,t),'test':met(y[te],pt,t),'hard_source_holdout':met(hard.label.to_numpy(),ph,t),'model_size_bytes':sum(x.stat().st_size for x in p.iterdir()),'artifact':'model/challengers/'+name}; (p/'metadata.json').write_text(json.dumps(meta,indent=2)); out.append(meta); print(name,json.dumps({k:meta[k] for k in ('threshold','validation','test','hard_source_holdout','model_size_bytes')},separators=(',',':')))
 (REP/'URL_V4_WEIGHTED_EXPERIMENTS.json').write_text(json.dumps(out,indent=2))
if __name__=='__main__':main()
