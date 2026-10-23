from __future__ import annotations
import hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
import joblib,numpy as np,pandas as pd
from sklearn.metrics import confusion_matrix,roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
HERE=Path(__file__).resolve(); ROOT=HERE.parents[1]; DATA=ROOT/'data'; REPORTS=ROOT/'reports'; sys.path.insert(0,str(HERE.parent))
from url_features import FULL_FEATURES,domain_group,extract_url_features
def metric(y,p,t):
 y=np.asarray(y,dtype=int); pred=p>=t; tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel(); return {'n':int(len(y)),'benign_fpr':float(fp/max(1,tn+fp)),'malicious_recall':float(tp/max(1,fn+tp)),'confusion_matrix':[[int(tn),int(fp)],[int(fn),int(tp)]],'roc_auc':float(roc_auc_score(y,p))}
def thresh(y,p):
 grid=np.linspace(.0005,.9995,1999); y=np.asarray(y); s=np.sort(p[y==0]); b=np.sort(p[y==1]); fp=s.size-np.searchsorted(s,grid,'left'); tp=b.size-np.searchsorted(b,grid,'left'); f=fp/max(1,s.size); r=tp/max(1,b.size); ok=np.flatnonzero(f<=.01); ok=ok if len(ok) else np.arange(len(grid)); i=ok[np.lexsort((grid[ok],f[ok],-r[ok]))[0]]; return float(grid[i])
def main():
 df=pd.read_csv(DATA/'final_dataset.csv'); rem=pd.read_csv(DATA/'remediation_hard_negatives_v1.csv'); X=df[FULL_FEATURES].astype(np.float32); y=df.label.astype(int).to_numpy(); g=df.url.map(domain_group); tr,rest=next(GroupShuffleSplit(n_splits=1,test_size=.40,random_state=42).split(X,y,g)); vr,te=next(GroupShuffleSplit(n_splits=1,test_size=.50,random_state=42).split(X.iloc[rest],y[rest],g.iloc[rest])); vi,tei=rest[vr],rest[te]; sc=StandardScaler().fit(X.iloc[tr]); Xs=sc.transform(X); hard=df.DatasetSource.to_numpy()=='hard'; ef=joblib.load(ROOT/'model/challengers/challenger_source_invariant_v2_extra40/model.joblib'); lm=joblib.load(ROOT/'model/challengers/challenger_source_invariant_v3_logistic/model.joblib'); pe_v=ef.predict_proba(Xs[vi])[:,1]; pl_v=lm.predict_proba(Xs[vi])[:,1]; pe_t=ef.predict_proba(Xs[tei])[:,1]; pl_t=lm.predict_proba(Xs[tei])[:,1]; pe_h=ef.predict_proba(Xs[hard])[:,1]; pl_h=lm.predict_proba(Xs[hard])[:,1]; best=None
 for alpha in np.linspace(0,1,21):
  pv=alpha*pe_v+(1-alpha)*pl_v; t=thresh(y[vi],pv); r=metric(y[vi],pv,t); key=(r['malicious_recall'],-r['benign_fpr'])
  if best is None or key>best[0]: best=(key,float(alpha),t)
 _,alpha,t=best; out={'experiment_id':'challenger_hybrid_v4_extra_logistic','architecture':'weighted_score_hybrid','features':FULL_FEATURES,'seed':42,'threshold':t,'extra_trees_weight':alpha,'logistic_weight':1-alpha,'remediation_dataset_sha256':hashlib.sha256((DATA/'remediation_hard_negatives_v1.csv').read_bytes()).hexdigest(),'validation':metric(y[vi],alpha*pe_v+(1-alpha)*pl_v,t),'test':metric(y[tei],alpha*pe_t+(1-alpha)*pl_t,t),'hard_source_holdout':metric(y[hard],alpha*pe_h+(1-alpha)*pl_h,t),'component_artifacts':['model/challengers/challenger_source_invariant_v2_extra40/model.joblib','model/challengers/challenger_source_invariant_v3_logistic/model.joblib']}
 stamp=datetime.now(timezone.utc).isoformat(); (REPORTS/'URL_HYBRID_V4_EVALUATION.json').write_text(json.dumps({'generated_at':stamp,'result':out,'alpha_search':'validation-only grid 0.05','frozen_champion_untouched':True},indent=2),encoding='utf-8'); (REPORTS/'URL_HYBRID_V4_EVALUATION.md').write_text(f"# URL-ML Hybrid V4\n\nValidation-only blend selection chose ExtraTrees weight {alpha:.2f} and Logistic weight {1-alpha:.2f}, with threshold {t:.4f}.\n\n- Validation hard constraint: FPR {out['validation']['benign_fpr']:.4f}; recall {out['validation']['malicious_recall']:.4f}.\n- TEST: FPR {out['test']['benign_fpr']:.4f}; recall {out['test']['malicious_recall']:.4f}.\n- Hard-source: FPR {out['hard_source_holdout']['benign_fpr']:.4f}; recall {out['hard_source_holdout']['malicious_recall']:.4f}.\n\nNo holdout or TEST/OOD score was used for blend or threshold selection.\n",encoding='utf-8');
 with (REPORTS/'EXPERIMENT_REGISTRY.jsonl').open('a',encoding='utf-8') as f: f.write(json.dumps({'experiment_id':out['experiment_id'],'timestamp':stamp,'dataset_version':out['remediation_dataset_sha256'],'decision':'challenger','architecture':out['architecture'],'features':out['features'],'seed':42,'threshold':t,'validation':out['validation'],'test':out['test'],'hard_source_holdout':out['hard_source_holdout'],'blend_weights':{'extra_trees':alpha,'logistic':1-alpha}})+'\n')
 print(json.dumps(out,indent=2))
if __name__=='__main__': main()
