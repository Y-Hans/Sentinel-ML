from runlib import *
import ast,collections,pickle,warnings
protect()
import numpy as np,sklearn
M=ROOT/'sentinel-ml/Messages-ml'
sys.path[:0]=[str(M/'scripts'),str(M/'messages_v4_3/models')]
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from candidate_d_v4_3 import extract_structural_signals
# Explicitly prohibit any fit call on these inference paths.
from sklearn.base import BaseEstimator
manifest=jload('freeze_manifest_v2.json')
assert sha(OUT/manifest['messages']['path'])==manifest['messages']['sha256']
sim=readrows(OUT/manifest['messages']['path']); test=readrows(M/'data/processed/test.jsonl'); ood=readrows(M/'data/processed/ood.jsonl')
def metrics(rows,probs,tau):
    y=np.array([{'BENIGN':0,'SUSPICIOUS_SPAM':1,'MALICIOUS':2}[r['security_label']] for r in rows]); nb=probs[:,1]+probs[:,2]; pred=np.where(nb>=tau,np.where(probs[:,2]>=probs[:,1],2,1),0)
    return {'n':len(rows),'confusion':[[int(((y==a)&(pred==b)).sum()) for b in range(3)] for a in range(3)],'benign_n':int((y==0).sum()),'benign_fp':int(((y==0)&(pred!=0)).sum()),'attack_n':int((y==2).sum()),'malicious_correct':int(((y==2)&(pred==2)).sum()),'spam_n':int((y==1).sum()),'spam_to_malicious':int(((y==1)&(pred==2)).sum()),'spam_to_malicious_median_pM':float(np.median(probs[(y==1)&(pred==2),2])) if ((y==1)&(pred==2)).any() else None}
configs=[('Messages_V2',M.parent/'6sep/messages/final',.704,True),('Messages_V4.3',M/'messages_v4_3/models/candidate_d',.61,False)]
for d in sorted((M/'messages_v4_4/models').iterdir()):
    if d.is_dir() and (d/'model.pkl').exists():
        cfg=json.loads((d/'config.json').read_text(encoding='utf-8')); configs.append(('Messages_V4.4_'+d.name,d,float(cfg.get('threshold',cfg.get('validation_threshold',.63))),False))
repro={'environment':{'python':sys.version,'executable':sys.executable,'numpy':np.__version__,'sklearn':sklearn.__version__},'models':[],'cache_tags':dict(collections.Counter(p.suffixes[-2] if len(p.suffixes)>1 else p.name for p in (M/'messages_v4_3').rglob('*.pyc')))}
predrows=[]; errors=[]; vocab={}
for name,d,tau,v2 in configs:
    meta={'model':name,'threshold':tau,'directory':str(d.relative_to(ROOT)),'artifact_hashes':{p.name:sha(p) for p in d.glob('*.pkl')}}
    try:
        with warnings.catch_warnings(record=True) as ww:
            warnings.simplefilter('always'); names=['champion_v2_model.pkl','champion_v2_scaler.pkl','champion_v2_tfidf_word.pkl','champion_v2_tfidf_char.pkl'] if v2 else ['model.pkl','scaler.pkl','word_vec.pkl','char_vec.pkl']; model,scaler,w,c=[pickle.load((d/n).open('rb')) for n in names]
            meta['unpickle_warnings']=[str(x.message) for x in ww]
        def predict(rr):
            result=[]
            for off in range(0,len(rr),128):
                batch=rr[off:off+128]; tt=[text(r) for r in batch]
                st=np.asarray([extract_feature_vector(t,None,FeatureConfig()) if v2 else extract_structural_signals(t) for t in tt],dtype=np.float32)
                X=np.hstack([st,w.transform(tt).toarray(),c.transform(tt).toarray()]); X=X if v2 else X.astype(np.float32)
                result.append(model.predict_proba(scaler.transform(X)))
            return np.vstack(result)
        pt=predict(test); po=predict(ood); meta['TEST']=metrics(test,pt,tau); meta['OOD']=metrics(ood,po,tau); meta['load_status']='OBSERVED_PICKLE'
        for split,rr,pp in [('TEST',test,pt),('OOD',ood,po)]:
            for i,(r,p) in enumerate(zip(rr,pp)):
                pd=0 if p[1]+p[2]<tau else (2 if p[2]>=p[1] else 1)
                if r['security_label']=='SUSPICIOUS_SPAM' and pd==2: errors.append({'model':name,'split':split,'index':i,'id':r['message_id'],'true':r['security_label'],'prediction':'MALICIOUS','pM':float(p[2]),'primary_type':r.get('primary_type'),'source_id':r.get('source_id'),'text':text(r)})
        if name=='Messages_V4.3':
            vocab={'word_size':len(w.vocabulary_),'char_size':len(c.vocabulary_),'nonASCII_word_tokens':sum(any(ord(x)>127 for x in k) for k in w.vocabulary_),'nonASCII_char_tokens':sum(any(ord(x)>127 for x in k) for k in c.vocabulary_),'script_coverage':[]}
            for r in sim:
                if r.get('synthetic'): vocab['script_coverage'].append({'uid':r['uid'],'language':r['language'],'y':r['y'],'word_nonzero':int(w.transform([r['text']]).nnz),'char_nonzero':int(c.transform([r['text']]).nnz)})
        pp=predict(sim)
        for r,p in zip(sim,pp):
            nb=float(p[1]+p[2]); raw=int(np.argmax(p)); adj=0 if nb<tau else 2 if p[2]>=p[1] else 1
            predrows.append({'uid':r['uid'],'model':name,'p_benign':float(p[0]),'p_spam':float(p[1]),'p_malicious':float(p[2]),'score':nb,'raw_class':raw,'adjudicated_class':adj,'raw_alert':int(raw!=0),'adjudicated_alert':int(adj!=0),'threshold':tau,'adjudicator':'frozen P(non-benign) threshold + max spam/malicious only; no Android context/fusion'})
        print(name,meta['TEST'],flush=True)
    except Exception as e: meta['load_status']='FAILED'; meta['error']=repr(e); print(name,'FAILED',repr(e),flush=True)
    repro['models'].append(meta)
jsonl('message_predictions.jsonl',predrows); jsonl('spam_confusion_recheck.jsonl',errors); jsave('messages_reproduction.json',repro); jsave('indic_vocabulary_recheck.json',vocab)
# Schema checks independent of any model labels.
schema=json.loads((M/'data/schemas/message_record_schema.json').read_text(encoding='utf-8'))
train=readrows(M/'messages_v4_3/data/train_v4_3.jsonl'); props=schema.get('properties',{}); audits={}
for field in ('primary_type','source_type'):
    enums=props.get(field,{}).get('enum',[]); bad=collections.Counter(str(r.get(field)) for r in train if enums and r.get(field) not in enums)
    audits[field]={'schema_enum':enums,'invalid_rows':sum(bad.values()),'invalid_values':dict(bad)}
audits['Devanagari_train_labels']=dict(collections.Counter(r['security_label'] for r in train if any('\u0900'<=x<='\u097f' for x in text(r))))
audits['schema_sha256']=sha(M/'data/schemas/message_record_schema.json'); jsave('label_schema_recheck.json',audits)
print('predictions',len(predrows),flush=True)
