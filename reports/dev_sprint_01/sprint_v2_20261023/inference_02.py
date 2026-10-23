from sprintlib import *
guard()
from runtime import *
frozen=load(OUT/'freeze_manifest.json');assert all(sha(OUT/p)==s for p,s in frozen['files'].items())
loaded,meta=bundles();test=list(rows(M/'data/processed/test.jsonl'));labels={'BENIGN':0,'SPAM':1,'SUSPICIOUS_SPAM':1,'MALICIOUS':2}
y=np.array([labels[r['security_label']] for r in test]);p=predict(loaded['V4.3'],test);d=decision(p,.61)
gate={'TP':int(((y==2)&(d==2)).sum()),'M_N':int((y==2).sum()),'FP_any_B':int(((y==0)&(d!=0)).sum()),'B_N':int((y==0).sum()),'source_sha256':sha(M/'data/processed/test.jsonl'),'before_probe':True}
save('V43_reproduction_gate.json',gate);assert gate['TP']==1510 and gate['FP_any_B']==2
sets={'v1':list(rows(OLD/'probe_set.csv')),'v1_normalized':list(rows(OUT/'probe_v1_normalized.csv')),'v2':list(rows(OUT/'frozen/probe_v2.csv'))}
result=[];baselines=[]
for name,b in loaded.items():
 pt=p if name=='V4.3' else predict(b,test);dt=decision(pt,b[1])
 for scope,mask in [('full_historical_TEST',np.ones(len(test),dtype=bool)),('English_metadata_TEST',np.array([str(r.get('language','')).lower() in ('en','english') for r in test]))]:
  conf=[[int(((y==a)&(dt==c)&mask).sum()) for c in range(3)] for a in range(3)]
  baselines.append({'model':name,'scope':scope,'confusion':conf,'n':int(mask.sum())})
 for setname,rr in sets.items():
  pp=predict(b,rr);dd=decision(pp,b[1])
  for r,pr,dc in zip(rr,pp,dd):result.append({'set':setname,'id':r['id'],'model':name,'p_benign':float(pr[0]),'p_spam':float(pr[1]),'p_malicious':float(pr[2]),'raw_argmax':['BENIGN','SPAM','MALICIOUS'][int(np.argmax(pr))],'predicted':['BENIGN','SPAM','MALICIOUS'][int(dc)],'alert':bool(dc==2),'threshold':b[1],'sender_used':None})
  print(name,setname,len(rr),'alerts',int((dd==2).sum()),flush=True)
jsonl('probe_predictions.jsonl',result);save('English_TEST_baselines.json',baselines)
save('inference_manifest.json',{'models':meta,'python':sys.version,'numpy':np.__version__,'sklearn':sklearn.__version__,'threads':1,'CPU_only':True,'prediction_rows':len(result),'freeze_sha256':sha(OUT/'freeze_manifest.json'),'no_training':True})
