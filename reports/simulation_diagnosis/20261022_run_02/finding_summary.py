from runlib import *
protect()
import collections
ms=readrows(OUT/'simulation_messages_v2.jsonl'); us=readrows(OUT/'simulation_urls_v2.jsonl'); mp=readrows(OUT/'message_predictions.jsonl'); up=readrows(OUT/'url_predictions.jsonl'); sm=readrows(OUT/'metrics_summary.jsonl'); seg=readrows(OUT/'segment_metrics.jsonl'); policies=readrows(OUT/'policy_changes.jsonl')
byuid={r['uid']:r for r in ms+us}; modelpol={}
for m in sorted(set(p['model'] for p in policies)):
    pp=[p for p in policies if p['model']==m]; modelpol[m]={'changed_rows':len(pp),'known_benign':sum(byuid[p['uid']]['y']==0 for p in pp),'known_attack':sum(byuid[p['uid']]['y']==1 for p in pp),'unknown':sum(byuid[p['uid']]['y'] is None for p in pp)}
probes=[]
for p in up:
    r=byuid[p['uid']]
    if r['synthetic']: probes.append({**r,**p})
jsave('finding_summary.json',{'model_policy_changes':modelpol,'URL_authored_predictions':probes,'label_counts':dict(collections.Counter(r['label_status'] for r in ms)),'unique_synthetic_message_texts':len(set(r['text'] for r in ms if r['synthetic'])),'synthetic_message_families':len(set(r['group'] for r in ms if r['synthetic'])),'script_support':dict(collections.Counter(r['script'] for r in ms)),'channels':dict(collections.Counter(r['channel'] for r in ms)),'model_count':len(set(p['model'] for p in mp+up)),'V45_status':'REPORTED artifact presence; not one of Step 7 named required baselines; classifier/embedding dependency closure not certified, no V4.5 result invented','small_cells':sum(r['not_decision_grade'] for r in seg),'segment_cells':len(seg)})
print(json.dumps({'model_policy_changes':modelpol,'message_label_counts':dict(collections.Counter(r['label_status'] for r in ms)),'small_cells':sum(r['not_decision_grade'] for r in seg)},indent=2))
