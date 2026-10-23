from runlib import *
import ast,collections,datetime,io,math,sqlite3,struct,tarfile
protect()
SCHEMA=['id','recordType','source','senderDisplayName','senderIdentifier','content','riskLevel','riskScore','explanation','recommendation','timestamp']
# Reuse only pure decoder definitions; do not rerun the earlier module's top-level writes.
tree=ast.parse((OUT/'recover.py').read_text(encoding='utf-8'))
for node in tree.body:
    if isinstance(node,ast.FunctionDef) and node.name in ('vint','record','scan','sqlite_probe','wal_overlay'): exec(compile(ast.Module(body=[node],type_ignores=[]),'recover.py','exec'))
def carve(b):
    found={}; attempts=0
    for m in re.finditer(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',b):
        for start in range(max(0,m.start()-40),m.start()):
            attempts+=1
            try:
                vv=record(b,start,min(len(b),start+20000))
                if len(vv)!=11 or vv[0]!=m.group().decode() or vv[1]!='SCAN_RESULT' or not isinstance(vv[10],int) or not 1500000000000<vv[10]<2000000000000 or vv[6] not in ('GREEN','YELLOW','ORANGE','RED') or not isinstance(vv[5],str) or not isinstance(vv[2],str): continue
                rr=dict(zip(SCHEMA,vv)); rr['_byte_offset']=start; found[(rr['id'],rr['timestamp'],rr['content'])]=rr
            except Exception: pass
    return list(found.values()),attempts
summary={'correction':'Initial recovery selected by aligned length/member count, insufficient for newline-transformed data; zero recovered rows was not evidence of zero records. This revision carves only strict SQLite serialized rows by UUID and 11-column schema. Original CR and LF cannot be distinguished; resulting content/timestamp bytes may be altered, all rows PROVISIONAL_SALVAGE.','pulls':[],'legacy_comparisons':[]}
allrows=[]
for pull,rel in [('pull_1','sentinel-ml/Databases/sentinel_db'),('pull_2','sentinel-ml/Databases/sentinel_db(1)'),('pull_3','sentinel-ml/Databases/22oct_pull/sentinel-history.tar')]:
    raw=(ROOT/rel).read_bytes(); b=raw[2:].decode('utf-16-le').encode('cp437').replace(b'\r\n',b'\n'); (OUT/(pull+'.v2.newline_normalized.bin')).open('xb').write(b)
    rows,attempts=carve(b); probes=[]
    if pull!='pull_3': _,probes=sqlite_probe(b,pull+'.v2')
    else:
        with tarfile.open(fileobj=io.BytesIO(b),mode='r:') as t:
            for idx,m in enumerate(t.getmembers()):
                if m.isfile() and m.name.endswith('sentinel_db'):
                    _,pp=sqlite_probe(t.extractfile(m).read(),pull+'.v2.main'); probes+=pp
    for r in rows:
        r['pull_id']=pull; r['content_sha256']=hashlib.sha256(r['content'].encode()).hexdigest(); r['recovery_status']='PROVISIONAL_SALVAGE'; r['model_generation']='UNRESOLVED'
    jsonl(pull+'.v2.rows.jsonl',rows); allrows+=rows
    summary['pulls'].append({'pull_id':pull,'source':rel,'source_sha256':sha(ROOT/rel),'transformed_bytes_sha256':hashlib.sha256(b).hexdigest(),'rows_recovered':len(rows),'carve_attempts':attempts,'probes':probes,'logged_levels':dict(collections.Counter(r['riskLevel'] for r in rows)),'timestamp_min':min((r['timestamp'] for r in rows),default=None),'timestamp_max':max((r['timestamp'] for r in rows),default=None),'unrecoverable_exact_count':None,'count_limitation':'source table count not trusted; exact missing total unknowable; count of validated recovered candidates exact','model_generation':'UNRESOLVED'})
def key(r): return (r.get('id'),r.get('recordType'),r.get('timestamp'),hashlib.sha256(str(r.get('content','')).encode()).hexdigest())
merged={}
for r in allrows:
    k=key(r)
    if k not in merged: merged[k]={**r,'pull_ids':[],'logged_predictions':[]}
    merged[k]['pull_ids'].append(r['pull_id']); merged[k]['logged_predictions'].append({x:r.get(x) for x in ('pull_id','riskLevel','riskScore','explanation')})
jsonl('merged_recovered_v2.jsonl',list(merged.values())); summary['dedup']={'input_rows':len(allrows),'unique_rows':len(merged),'duplicates':len(allrows)-len(merged)}
for rel in ('sentinel-ml/New_history/bench_real_history_562.jsonl','sentinel-ml/investigation/sentinel_db_parsed.jsonl','sentinel-ml/investigation/sentinel_db1_parsed.jsonl'):
    legacy=readrows(ROOT/rel); ours={key(r):r for r in allrows}; legacykeys={key(r) for r in legacy}; match=legacykeys&set(ours)
    summary['legacy_comparisons'].append({'source':rel,'sha256':sha(ROOT/rel),'legacy_rows':len(legacy),'matching_keys':len(match),'legacy_only_unique':len(legacykeys-set(ours)),'new_only_unique':len(set(ours)-legacykeys)})
    jsonl('v2_compare_'+Path(rel).stem+'.jsonl',[{'id':r.get('id'),'timestamp':r.get('timestamp'),'content_sha256':key(r)[3],'match':key(r) in ours} for r in legacy])
jsave('recovery_v2.json',summary)
print(json.dumps({'pulls':[{k:p[k] for k in ('pull_id','rows_recovered','logged_levels')} for p in summary['pulls']],'dedup':summary['dedup'],'comparisons':summary['legacy_comparisons']},indent=2))
