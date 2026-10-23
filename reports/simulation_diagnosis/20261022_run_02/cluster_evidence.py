from runlib import *
import collections
protect()
out=[]; logs=[]
for track,pfile,sfile in [('messages','message_predictions.jsonl','simulation_messages_v2.jsonl'),('urls','url_predictions.jsonl','simulation_urls_v2.jsonl')]:
    rr={r['uid']:r for r in readrows(OUT/sfile)}; pp=readrows(OUT/pfile); clusters=collections.defaultdict(list)
    for p in pp:
        r=rr[p['uid']]
        for mode in ('raw','adjudicated'):
            if r['y'] in (0,1) and p[mode+'_alert']!=r['y']:
                e={'model':p['model'],'mode':mode,'uid':r['uid'],'kind':'FP' if r['y']==0 else 'FN','label_status':r['label_status'],'language':r['language'],'family':r['attack_family'],'example':r.get('text',r.get('url')),'score':p.get(mode+'_score',p['score']),'synthetic':r['synthetic'],'overlap_flag':r['overlap_flag']}
                clusters[(p['model'],mode,e['kind'],r['label_status'],r['language'],r['attack_family'])].append(e)
    for k,v in clusters.items(): out.append({'track':track,'model':k[0],'mode':k[1],'kind':k[2],'label_status':k[3],'language':k[4],'family':k[5],'count':len(v),'examples':v[:3],'evidence':'PROVISIONAL label-conditional errors; OBSERVED frozen predictions'})
for r in readrows(OUT/'logged_comparison.jsonl'): logs.append(r)
loggroups=collections.defaultdict(list)
for r in logs: loggroups[(r['track'],r['model'],r['mode'],str(r['pull_id']))].append(r)
jsave('logged_comparison_summary.json',[{'track':k[0],'model':k[1],'mode':k[2],'pull_id':k[3],'n':len(v),'logged_alerts':sum(x['logged_alert'] for x in v),'current_alerts':sum(x['new_alert'] for x in v),'disagreements':sum(x['disagrees'] for x in v),'note':'not a confusion matrix against truth; current model-only alert vs logged fused app result; salvage may affect fields'} for k,v in loggroups.items()])
jsonl('failure_cluster_evidence.jsonl',out)
print('clusters',len(out),'logged groups',len(loggroups))
