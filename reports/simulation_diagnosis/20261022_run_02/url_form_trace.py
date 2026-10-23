from runlib import *
protect()
import numpy as np
sys.path.insert(0,str(ROOT/'sentinel-ml/URL-ml/scripts'))
from v7_features import vectorize_v7
rows=readrows(OUT/'simulation_urls_v2.jsonl'); pp=readrows(OUT/'url_predictions.jsonl'); wanted=[r for r in rows if r.get('synthetic') and 'instagram.com' in r['url']]; X,names=vectorize_v7([r['url'] for r in wanted]); base=next(i for i,r in enumerate(wanted) if r['url']=='https://www.instagram.com'); trace=[]
for i,r in enumerate(wanted):
    trace.append({'uid':r['uid'],'url':r['url'],'feature_differences_vs_https_www':[{ 'feature':names[j],'reference':float(X[base,j]),'value':float(X[i,j])} for j in range(len(names)) if X[base,j]!=X[i,j]],'predictions':[p for p in pp if p['uid']==r['uid']]})
jsave('url_form_feature_trace.json',{'source_sha256':sha(ROOT/'sentinel-ml/URL-ml/scripts/v7_features.py'),'trace':trace,'limitation':'These are current-source feature vectors and frozen weights, not historical APK proof; no new probes authored after freeze'})
print(json.dumps([{'url':r['url'],'different_features':len(r['feature_differences_vs_https_www']),'V8':next(p['adjudicated_score'] for p in r['predictions'] if p['model']=='URL_V8')} for r in trace],indent=2))
