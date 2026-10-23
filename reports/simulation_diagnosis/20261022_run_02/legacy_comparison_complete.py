from runlib import *
import ast,struct,collections
protect()
SCHEMA=['id','recordType','source','senderDisplayName','senderIdentifier','content','riskLevel','riskScore','explanation','recommendation','timestamp']
for file,names in [('recover.py',('vint','record')),('recover_v2.py',('carve',))]:
    for node in ast.parse((OUT/file).read_text(encoding='utf-8')).body:
        if isinstance(node,ast.FunctionDef) and node.name in names: exec(compile(ast.Module(body=[node],type_ignores=[]),file,'exec'))
def key(r):return (r.get('id'),r.get('recordType'),r.get('timestamp'),hashlib.sha256(str(r.get('content','')).encode()).hexdigest())
ours=readrows(OUT/'merged_recovered_v2.jsonl'); kk={key(r) for r in ours}; byid=collections.defaultdict(list)
for r in ours: byid[r['id']].append(key(r))
inputs=[]
for name in ('sentinel_db.recovered.db','sentinel_db(1).recovered.db'):
    p=ROOT/'sentinel-ml/investigation'/name; rr,attempts=carve(p.read_bytes()); inputs.append((p,rr,{'source_bytes':p.stat().st_size,'strict_candidates':len(rr),'carve_attempts':attempts}))
for name in ('sentinel_db_rows.jsonl','sentinel_db1_rows.jsonl'):
    p=ROOT/'sentinel-ml/investigation'/name; raw=readrows(p); rr=[]; rejected=0
    for row in raw:
        vals=row.get('values',[])
        if len(vals)==11 and re.fullmatch(r'[a-f0-9-]{36}',str(vals[0])) and vals[1]=='SCAN_RESULT' and isinstance(vals[10],int) and isinstance(vals[5],str): rr.append(dict(zip(SCHEMA,vals)))
        else: rejected+=1
    inputs.append((p,rr,{'source_rows':len(raw),'strict_candidates':len(rr),'rejected_nonconforming':rejected}))
summ=[]
for p,rr,info in inputs:
    compared=[]
    for r in rr:
        k=key(r); candidates=byid[r['id']]
        compared.append({'id':r['id'],'timestamp':r['timestamp'],'content_sha256':k[3],'exact_match':k in kk,'same_id_new_keys':[list(x) for x in candidates]})
    jsonl('legacy_'+p.name.replace('.','_')+'.comparison.jsonl',compared)
    summ.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'status':'REPORTED legacy recovery; not independent source',**info,'exact_matching_candidates':sum(key(r) in kk for r in rr),'same_id_candidates':sum(bool(byid[r['id']]) for r in rr)})
jsave('legacy_all_inputs_comparison.json',summ); print(json.dumps(summ,indent=2))
