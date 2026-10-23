from __future__ import annotations
import hashlib,json,sys,time,re
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REPORTS=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import domain_group
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def norm(u): return re.sub(r'\d+','#',str(u).strip().lower())
def met(y,p,t):
 y=np.asarray(y); p=np.asarray(p); z=p>=t; tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel(); return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)),'roc_auc':float(roc_auc_score(y,p)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}
def th(y,p):
 y=np.asarray(y); p=np.asarray(p); grid=np.linspace(.0005,.9995,1999); b=np.sort(p[y==0]); m=np.sort(p[y==1]); f=(b.size-np.searchsorted(b,grid,'left'))/max(1,b.size); r=(m.size-np.searchsorted(m,grid,'left'))/max(1,m.size); ok=np.flatnonzero(f<=.01); ok=ok if len(ok) else np.arange(len(grid)); return float(grid[ok[np.lexsort((grid[ok],f[ok],-r[ok]))[0]]])
def main():
 d=pd.read_csv(DATA/'cleaned_dataset.csv',usecols=['url','label']); d['label']=1-d.label.astype(int); rem=pd.read_csv(DATA/'remediation_hard_negatives_v3.csv'); hard=pd.read_csv(DATA/'hard_dataset.csv'); y=d.label.to_numpy(); g=d.url.map(domain_group); ix=np.arange(len(d)); tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(ix,y,g)); vr,te_r=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],g.iloc[rest])); va,te=rest[vr],rest[te_r]
 urls=d.url.tolist(); train=[urls[i] for i in tr]+rem.url.tolist(); train_y=np.r_[y[tr],rem.label.to_numpy()]
 v=TfidfVectorizer(analyzer='char',ngram_range=(2,5),min_df=2,max_features=60000,sublinear_tf=True); A=v.fit_transform([norm(x) for x in train]); V=v.transform([norm(urls[i]) for i in va]); T=v.transform([norm(urls[i]) for i in te]); H=v.transform(hard.url.map(norm))
 model=LogisticRegression(C=3.0,class_weight='balanced',max_iter=250,solver='liblinear',random_state=42); start=time.perf_counter(); model.fit(A,train_y); pv=model.predict_proba(V)[:,1]; t=th(y[va],pv); pt=model.predict_proba(T)[:,1]; ph=model.predict_proba(H)[:,1]; adv=pd.read_csv(REPORTS/'URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv',usecols=['url','label']); pa=model.predict_proba(v.transform(adv.url.map(norm)))[:,1]
 name='v6_char_tfidf_logreg'; out=ROOT/'model'/'challengers'/name; out.mkdir(parents=True,exist_ok=False); joblib.dump(model,out/'model.joblib'); joblib.dump(v,out/'vectorizer.joblib'); meta={'campaign':'URL-ML V6','experiment_id':name,'hypothesis':'normalized character morphology can provide domain-independent separation missed by scalar structural features','architecture':'TfidfVectorizer(char 2-5)+LogisticRegression','feature_count':int(len(v.vocabulary_)),'seed':42,'threshold':t,'source_dataset_sha256':sha(DATA/'cleaned_dataset.csv'),'remediation_sha256':sha(DATA/'remediation_hard_negatives_v3.csv'),'hard_dataset_sha256':sha(DATA/'hard_dataset.csv'),'train_rows':len(tr),'remediation_rows':len(rem),'validation':met(y[va],pv,t),'test':met(y[te],pt,t),'hard_source_holdout':met(hard.label.to_numpy(),ph,t),'adversarial':met(adv.label.to_numpy(),pa,t),'fit_seconds':time.perf_counter()-start,'artifact':str(out.relative_to(ROOT)).replace('\\','/'),'model_size_bytes':sum(p.stat().st_size for p in out.iterdir()),'promotion_status':'challenger_only'}; (out/'metadata.json').write_text(json.dumps(meta,indent=2)); print(json.dumps(meta,indent=2))
if __name__=='__main__': main()
