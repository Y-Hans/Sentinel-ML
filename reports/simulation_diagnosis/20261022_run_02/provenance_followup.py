from runlib import *
import collections,datetime
protect()
recovery=jload('recovery_v2.json'); out=[]
for pull in recovery['pulls']:
    rr=readrows(OUT/(pull['pull_id']+'.v2.rows.jsonl')); b=(OUT/(pull['pull_id']+'.v2.newline_normalized.bin')).read_bytes(); uu=list(re.finditer(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',b))
    patterns=collections.Counter(re.sub(r'\d+(?:\.\d+)?','<N>',str(r.get('explanation'))) for r in rr)
    times=[datetime.datetime.fromtimestamp(r['timestamp']/1000,datetime.timezone.utc).isoformat() for r in rr]
    out.append({'pull_id':pull['pull_id'],'model_generation':'UNRESOLVED','valid_candidate_rows':len(rr),'UUID_occurrences':len(uu),'candidate_offsets_not_accepted':len(uu)-len(rr),'unrecoverable_total':'UNKNOWN: candidate offsets include index copies, no reliable table count; not an estimate of missing threat records','timestamp_min_UTC':min(times) if times else None,'timestamp_max_UTC':max(times) if times else None,'explanation_patterns':dict(patterns),'explicit_version_strings':sorted(set(re.findall(r'\b(?:v[12478](?:\.\d+)*|champion|Candidate.D)\b',' '.join(str(r.get('explanation')) for r in rr),flags=re.I))),'reason':'Explanation scores/name templates do not uniquely identify model artifact; content/metadata transfer corruption and runtime policy can alter scores; APK asset contents prove packages, not historical installed generation'})
old=jload('recovery_provenance.json'); inv=jload('protected_v2_before.json')
paths=['sentinel-ml/6sep/messages/final/champion_v2_model.pkl','sentinel-ml/Messages-ml/messages_v4/artifacts/messages_v4_model.pkl','sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl','sentinel-ml/URL-ml/models/v7_champion.joblib','sentinel-ml/URL-ml/models/v8_champion.joblib']
jsave('provenance_followup.json',{'pulls':out,'canonical_artifacts':{p:inv[p] for p in paths},'apk_assets':old['apk_assets'],'claims':{'user':'pull1 Messages v1/URLv7; pull2,pull3 Messagesv2/URLv8','master':'562-row history V2/V7; unsigned 2.1.0 V4.3/V8'},'adjudication':'aggregate master-plan claim found; record-level independent annotation map not found'})
print(json.dumps([{k:p[k] for k in ('pull_id','valid_candidate_rows','UUID_occurrences','candidate_offsets_not_accepted','timestamp_min_UTC','timestamp_max_UTC','explicit_version_strings')} for p in out],indent=2))
