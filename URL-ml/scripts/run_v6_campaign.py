from __future__ import annotations
import hashlib, json, os, sys, time
from pathlib import Path
os.environ.setdefault('OMP_NUM_THREADS','1'); os.environ.setdefault('MKL_NUM_THREADS','1'); os.environ.setdefault('OPENBLAS_NUM_THREADS','1')
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REPORTS=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from v4_features import vectorize_deterministic
from url_features import domain_group

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def met(y,p,t):
    y=np.asarray(y,dtype=int); p=np.asarray(p,float); z=p>=t
    tn,fp,fn,tp=confusion_matrix(y,z,labels=[0,1]).ravel()
    return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)), 'roc_auc':float(roc_auc_score(y,p)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]]}
def threshold(y,p):
    y=np.asarray(y); p=np.asarray(p); grid=np.linspace(.0005,.9995,1999); b=np.sort(p[y==0]); m=np.sort(p[y==1])
    f=(b.size-np.searchsorted(b,grid,'left'))/max(1,b.size); r=(m.size-np.searchsorted(m,grid,'left'))/max(1,m.size)
    ok=np.flatnonzero(f<=.01); ok=ok if len(ok) else np.arange(len(grid)); i=ok[np.lexsort((grid[ok],f[ok],-r[ok]))[0]]; return float(grid[i])
def synthetic_v6():
    # New, explicitly synthetic, domain-disjoint benign coverage. No protected URL is
    # copied, transformed, or used to construct these rows.
    domains=['alpinejournal.example','civicservices.example','northstarhealth.example','openlearning.example','greenvalley.example','harbortransit.example','communitybank.example','researchcommons.example','localmarket.example','publiclibrary.example','cloudstatus.example','regionalenergy.example','artisanworks.example','citywater.example','travelcollective.example','memberportal.example','softwarecatalog.example','universitypress.example','museumarchive.example','farmerscoop.example']
    paths=['/','/about','/contact','/help/center','/account/sign-in','/account/settings','/security/verification','/billing/payment-methods','/checkout/order-confirmation','/track/order/12345','/redirect?target=home','/search?q=account+security','/en-us/account/profile','/de-de/zahlung/abrechnung','/download/reports/2025/annual-report.pdf','/api/v2/users/12345/preferences','/auth/callback?code=example-code&state=abc123','/news/article/2025/10/long-descriptive-title','/services/online-payment/secure-access','/resources/documentation/getting-started?utm_source=newsletter&utm_medium=email']
    rows=[]
    for i,d in enumerate(domains):
        for j,path in enumerate(paths):
            scheme='http' if (i+j)%7==0 else 'https'; host=('www.' if j%3 else 'portal.')+d
            rows.append({'url':scheme+'://'+host+path,'label':0,'source_family':'v6_synthetic_structural_benign','registrable_domain':d})
    return pd.DataFrame(rows).drop_duplicates('url')
def main():
    synth=DATA/'v6_synthetic_benign.csv'; synthetic_v6().to_csv(synth,index=False)
    clean=pd.read_csv(DATA/'cleaned_dataset.csv',usecols=['url','label']); clean['label']=1-clean.label.astype(int)
    rem=pd.read_csv(DATA/'remediation_hard_negatives_v3.csv'); syn=pd.read_csv(synth); hard=pd.read_csv(DATA/'hard_dataset.csv')
    y=clean.label.to_numpy(); groups=clean.url.map(domain_group); idx=np.arange(len(clean)); tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.4,random_state=42).split(idx,y,groups)); vr,te_r=next(GroupShuffleSplit(n_splits=1,test_size=.5,random_state=43).split(rest,y[rest],groups.iloc[rest])); va,te=rest[vr],rest[te_r]
    urls=clean.url.tolist(); allurls=[urls[i] for i in tr]+rem.url.tolist()+syn.url.tolist()+[urls[i] for i in va]+[urls[i] for i in te]+hard.url.tolist(); X,names=vectorize_deterministic(allurls,('host','path','query','interactions'))
    ntr,nr,ns,nv,nt=len(tr),len(rem),len(syn),len(va),len(te); cuts=np.cumsum([ntr,nr,ns,nv,nt]); Xtr,Xr,Xs,Xv,Xt,Xh=np.split(X,cuts); sc=StandardScaler().fit(Xtr); Xtr,Xr,Xs,Xv,Xt,Xh=[sc.transform(z) for z in (Xtr,Xr,Xs,Xv,Xt,Xh)]
    results=[]
    configs=[('v6_et_rem3_syn1_w20',ExtraTreesClassifier(n_estimators=120,max_depth=20,min_samples_leaf=2,n_jobs=1,class_weight='balanced',random_state=42),20.,1.),('v6_hgb_rem3_syn1_w20',HistGradientBoostingClassifier(max_iter=240,learning_rate=.06,max_leaf_nodes=31,min_samples_leaf=20,l2_regularization=1.,random_state=42),20.,1.),('v6_et_rem3_syn2_w10',ExtraTreesClassifier(n_estimators=120,max_depth=20,min_samples_leaf=2,n_jobs=1,class_weight='balanced',random_state=43),10.,2.)]
    fitX=np.vstack([Xtr,Xr,Xs]); fitY=np.r_[y[tr],rem.label.to_numpy(),syn.label.to_numpy()]
    for name,model,rw,sw in configs:
        start=time.perf_counter(); model.fit(fitX,fitY,sample_weight=np.r_[np.ones(ntr),np.full(nr,rw),np.full(ns,sw)]); pv=model.predict_proba(Xv)[:,1]; t=threshold(y[va],pv); pt=model.predict_proba(Xt)[:,1]; ph=model.predict_proba(Xh)[:,1]
        out=ROOT/'model'/'challengers'/name; out.mkdir(parents=True,exist_ok=False); joblib.dump(model,out/'model.joblib'); joblib.dump(sc,out/'scaler.joblib')
        adv=pd.read_csv(REPORTS/'URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv',usecols=['url','label']); ax,_=vectorize_deterministic(adv.url.tolist(),('host','path','query','interactions')); pa=model.predict_proba(sc.transform(ax))[:,1]
        meta={'campaign':'URL-ML V6','experiment_id':name,'hypothesis':'domain-disjoint benign structural coverage can reduce source-shift false positives','architecture':type(model).__name__,'feature_count':len(names),'feature_schema_sha256':sha(HERE.parent/'v4_features.py'),'seed':getattr(model,'random_state',42),'remediation_weight':rw,'synthetic_weight':sw,'threshold':t,'source_dataset_sha256':sha(DATA/'cleaned_dataset.csv'),'remediation_sha256':sha(DATA/'remediation_hard_negatives_v3.csv'),'synthetic_sha256':sha(synth),'hard_dataset_sha256':sha(DATA/'hard_dataset.csv'),'train_rows':ntr,'remediation_rows':nr,'synthetic_rows':ns,'validation':met(y[va],pv,t),'test':met(y[te],pt,t),'hard_source_holdout':met(hard.label.to_numpy(),ph,t),'adversarial':met(adv.label.to_numpy(),pa,t),'fit_seconds':time.perf_counter()-start,'artifact':str(out.relative_to(ROOT)).replace('\\','/'),'model_size_bytes':sum(p.stat().st_size for p in out.iterdir()),'promotion_status':'challenger_only'}
        (out/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8'); results.append(meta); print(json.dumps(meta,indent=2))
    stamp=pd.Timestamp.now(tz='UTC').isoformat(); reg={'campaign':'URL-ML V6','protocol':{'train_source':'cleaned_dataset.csv + remediation_v3 + explicitly synthetic domain-disjoint benign rows','threshold_selection':'validation_only','protected_evaluation':['hard_dataset.csv','URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv'],'frozen_champion_untouched':True,'champion_sha256':sha(ROOT/'model/champion/model.joblib')},'generated_at':stamp,'experiments':results}
    (REPORTS/'URL_V6_EXPERIMENT_REGISTRY.json').write_text(json.dumps(reg,indent=2),encoding='utf-8')
if __name__=='__main__': main()
