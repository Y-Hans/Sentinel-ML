from probe_lib import *
import collections,pickle,warnings
protect()
import numpy as np,sklearn
M=ROOT/'sentinel-ml/Messages-ml';sys.path[:0]=[str(M/'scripts'),str(M/'messages_v4_3/models')]
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from candidate_d_v4_3 import extract_structural_signals
frozen=load('freeze_manifest.json');assert sha(OUT/frozen['path'])==frozen['sha256'];assert (OUT/'HINGLISH_PROBE_DESIGN.md').exists()
rows=csvread('probe_set.csv');test=readjsonl(M/'data/processed/test.jsonl');baselinehash=load('protected_before.json')
configs=[('V2',M.parent/'6sep/messages/final',.704,True),('V4.3',M/'messages_v4_3/models/candidate_d',.61,False)]
for d in sorted((M/'messages_v4_4/models').iterdir()):
    if d.is_dir() and(d/'model.pkl').exists():
        cfg=json.loads((d/'config.json').read_text(encoding='utf-8'));configs.append(('V4.4_'+d.name,d,float(cfg.get('threshold',cfg.get('validation_threshold',.63))),False))
def decision(pp,tau):return np.where(pp[:,1]+pp[:,2]>=tau,np.where(pp[:,2]>=pp[:,1],2,1),0)
loaded={};metas=[]
for name,d,tau,v2 in configs:
    names=['champion_v2_model.pkl','champion_v2_scaler.pkl','champion_v2_tfidf_word.pkl','champion_v2_tfidf_char.pkl'] if v2 else ['model.pkl','scaler.pkl','word_vec.pkl','char_vec.pkl']
    for n in names:assert sha(d/n)==baselinehash[(d/n).relative_to(ROOT).as_posix()]['sha256']
    with warnings.catch_warnings(record=True) as ww:
        warnings.simplefilter('always');items=[pickle.load((d/n).open('rb')) for n in names]
    loaded[name]=(items,tau,v2);metas.append({'model':name,'threshold':tau,'v2_sender_header_supported':v2,'files':{str((d/n).relative_to(ROOT)):sha(d/n) for n in names},'unpickle_warnings':[str(w.message) for w in ww]})
def predict(bundle,rr,with_sender=False):
    (model,scaler,w,c),tau,v2=bundle;output=[]
    for off in range(0,len(rr),128):
        bb=rr[off:off+128];tt=[r.get('text',r.get('raw_text','')) for r in bb]
        st=np.asarray([extract_feature_vector(t,(r.get('sender_header') or None) if with_sender else None,FeatureConfig()) if v2 else extract_structural_signals(t) for t,r in zip(tt,bb)],dtype=np.float32)
        X=np.hstack([st,w.transform(tt).toarray(),c.transform(tt).toarray()]);X=X if v2 else X.astype(np.float32);output.append(model.predict_proba(scaler.transform(X)))
    return np.vstack(output)
# Required reproduction gate BEFORE any model predicts on the probe.
gate=predict(loaded['V4.3'],test);gd=decision(gate,.61);y=np.array([{'BENIGN':0,'SUSPICIOUS_SPAM':1,'MALICIOUS':2}[r['security_label']] for r in test]);tp=int(((y==2)&(gd==2)).sum());fpany=int(((y==0)&(gd!=0)).sum());fpm=int(((y==0)&(gd==2)).sum())
save('V43_reproduction_gate.json',{'source':str((M/'data/processed/test.jsonl').relative_to(ROOT)),'source_sha256':sha(M/'data/processed/test.jsonl'),'threshold':.61,'malicious_correct':tp,'malicious_n':int((y==2).sum()),'benign_FP_any':fpany,'benign_FP_M_only':fpm,'benign_n':int((y==0).sum()),'passed':tp==1510 and fpany==2,'confusion':[[int(((y==a)&(gd==b)).sum()) for b in range(3)] for a in range(3)],'probe_scored_before_gate':False})
assert tp==1510 and fpany==2,'REPRODUCTION_GATE_FAILED; no probe scored'
repro=[]
for name,bundle in loaded.items():
    pp=gate if name=='V4.3' else predict(bundle,test);dd=decision(pp,bundle[1]);eng=np.array([str(r.get('language','')).lower() in ('en','english') for r in test])
    for scope,mask in [('TEST_all',np.ones(len(test),dtype=bool)),('TEST_English_metadata',eng)]:
        a=(y==2)&mask;b=(y==0)&mask;sp=(y==1)&mask;repro.append({'model':name,'scope':scope,'n':int(mask.sum()),'malicious_n':int(a.sum()),'TP_M_only':int(((dd==2)&a).sum()),'benign_n':int(b.sum()),'benign_FP_M_only':int(((dd==2)&b).sum()),'spam_n':int(sp.sum()),'spam_FP_M_only':int(((dd==2)&sp).sum())})
save('English_TEST_comparison.json',repro)
predictions=[]
for name,bundle in loaded.items():
    conditions=[('text_only',rows)]
    if bundle[2]:conditions.append(('SMS_with_sender_header',[r for r in rows if r['channel_style']=='SMS']))
    for cond,rr in conditions:
        pp=predict(bundle,rr,cond=='SMS_with_sender_header');dd=decision(pp,bundle[1]);raw=np.argmax(pp,axis=1)
        for r,p,d,arg in zip(rr,pp,dd,raw):predictions.append({'id':r['id'],'model':name,'condition':cond,'p_benign':float(p[0]),'p_spam':float(p[1]),'p_malicious':float(p[2]),'p_nonbenign':float(p[1]+p[2]),'raw_argmax':['BENIGN','SPAM','MALICIOUS'][int(arg)],'predicted':['BENIGN','SPAM','MALICIOUS'][int(d)],'alert':bool(d==2),'raw_argmax_alert':bool(arg==2),'threshold':bundle[1],'sender_header_used':r['sender_header'] if cond=='SMS_with_sender_header' else None})
        print(name,cond,'rows',len(rr),'M-only alerts',int((dd==2).sum()),flush=True)
jsonl('probe_predictions.jsonl',predictions)
save('inference_manifest.json',{'python':sys.version,'interpreter':sys.executable,'numpy':np.__version__,'sklearn':sklearn.__version__,'CPU_only':True,'GPU_requested':False,'CUDA_VISIBLE_DEVICES':os.environ['CUDA_VISIBLE_DEVICES'],'model_configurations':metas,'probe_sha256':sha(OUT/'probe_set.csv'),'design_sha256_before_probe':sha(OUT/'HINGLISH_PROBE_DESIGN.md'),'prediction_rows':len(predictions),'label_order':['BENIGN','SPAM','MALICIOUS'],'primary_alert':'thresholded_predicted == MALICIOUS; SPAM never alerts','no_training':True,'Condition2_excluded':'V4.3 and sixV4.4 feature extractors accept text only; metadata not injected into text'})
print('predictions',len(predictions),'CPU only',flush=True)
