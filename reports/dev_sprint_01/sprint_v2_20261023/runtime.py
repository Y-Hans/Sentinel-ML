from sprintlib import *
import ast,pickle,warnings
import numpy as np,sklearn
sys.path.insert(0,str(M/'scripts'))
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector,extract_message_features
source=ast.parse(small(M/'messages_v4_3/models/candidate_d_v4_3.py'))
nodes=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='extract_structural_signals' or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('RE_URL','RE_PHONE') for t in n.targets)]
exec(compile(ast.Module(body=nodes,type_ignores=[]),'candidate_d_structural_readonly','exec'))
def decision(p,tau):return np.where(p[:,1]+p[:,2]>=tau,np.where(p[:,2]>=p[:,1],2,1),0)
def bundles():
 configs=[('V2',M.parent/'6sep/messages/final',.704,True),('V4.3',M/'messages_v4_3/models/candidate_d',.61,False)]
 for d in sorted((M/'messages_v4_4/models').iterdir()):
  if d.is_dir() and (d/'model.pkl').exists():
   cfg=load(d/'config.json');configs.append(('V4.4_'+d.name,d,float(cfg.get('threshold',cfg.get('validation_threshold',.63))),False))
 meta=[];result={};protected=load(OUT/'protected_before.json')
 for name,d,tau,v2 in configs:
  names=['champion_v2_model.pkl','champion_v2_scaler.pkl','champion_v2_tfidf_word.pkl','champion_v2_tfidf_char.pkl'] if v2 else ['model.pkl','scaler.pkl','word_vec.pkl','char_vec.pkl']
  files={str((d/n).relative_to(ROOT)).replace('\\','/'):sha(d/n) for n in names}
  assert all(protected[p]['sha256']==s for p,s in files.items())
  with warnings.catch_warnings(record=True) as ww:
   warnings.simplefilter('always')
   items=[]
   for n in names:
    with (d/n).open('rb') as f:items.append(pickle.load(f))
  result[name]=(items,tau,v2);meta.append({'model':name,'threshold':tau,'files':files,'warnings':[str(w.message) for w in ww],'class_order':items[0].classes_.tolist()})
 return result,meta
def matrix(bundle,rr,senders=False):
 (model,scaler,w,c),tau,v2=bundle;tt=[r.get('text',r.get('raw_text','')) for r in rr]
 st=np.asarray([extract_feature_vector(t,r.get('sender_header') if senders else None,FeatureConfig()) if v2 else extract_structural_signals(t) for t,r in zip(tt,rr)],dtype=np.float32)
 X=np.hstack([st,w.transform(tt).toarray(),c.transform(tt).toarray()]);X=X if v2 else X.astype(np.float32)
 return scaler.transform(X)
def predict(bundle,rr):
 return np.vstack([bundle[0][0].predict_proba(matrix(bundle,rr[i:i+128])) for i in range(0,len(rr),128)])
