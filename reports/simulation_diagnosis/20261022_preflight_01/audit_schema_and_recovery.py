"""Schema-aware correction and lossless-only in-memory recovery probe."""
import collections, hashlib, io, json, re, sqlite3, tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def rows(p): return [json.loads(x) for x in p.read_text(encoding='utf-8-sig').splitlines() if x.strip()]
def text(r):
    for k in ('raw_text','content','text','message','body'):
        if k in r and r[k] is not None: return str(r[k])
    raise ValueError('No recognized text field: '+str(r.keys()))
def norm(s):
    s=re.sub(r'https?://\S+|www\.\S+|<URL>', ' <url> ',s.casefold(),flags=re.I)
    s=re.sub(r'\d+','<num>',s)
    return ' '.join(s.split())
old=json.loads((OUT/'preflight_findings.json').read_text(encoding='utf-8'))
train=set(); inv=[]
for f in old['training_files']:
    p=ROOT/f['path']; rr=rows(p); kk={norm(text(r)) for r in rr}; train.update(kk)
    inv.append({'path':f['path'],'sha256':sha(p),'count':len(rr),'labels':dict(collections.Counter(r.get('security_label',r.get('label','MISSING')) for r in rr)),'template_keys':len(kk),'missing_template_id':sum(not r.get('template_cluster_id') for r in rr)})
result={'supersedes':'preflight_findings.json training text/labels and replay overlap ONLY: first parser did not recognize raw_text/security_label; its zero-overlap result is INVALID. Database errors and hashes remain valid.','training_inventory':inv,'sources':[],'recovery_probes':[]}
for rel in ('sentinel-ml/7sep_messages_v3/data/bench_sentinel_replay.jsonl','sentinel-ml/New_history/bench_real_history_562.jsonl','sentinel-ml/investigation/sentinel_db_parsed.jsonl','sentinel-ml/investigation/sentinel_db1_parsed.jsonl'):
    p=ROOT/rel; rr=rows(p)
    try:
        hits=[i for i,r in enumerate(rr,1) if norm(text(r)) in train]
        result['sources'].append({'path':rel,'sha256':sha(p),'count':len(rr),'keys':list(rr[0]) if rr else [],'labels':dict(collections.Counter(r.get('security_label','MISSING') for r in rr)),'normalized_overlap_rows':len(hits),'overlap_1based_rows':hits,'channel_counts':dict(collections.Counter(str(r.get('source','MISSING')) for r in rr)),'missing_template_id':sum(not r.get('template_cluster_id') for r in rr)})
    except Exception as e: result['sources'].append({'path':rel,'sha256':sha(p),'count':len(rr),'keys':list(rr[0]),'error':repr(e)})
for rel in ('sentinel-ml/Databases/sentinel_db','sentinel-ml/Databases/sentinel_db(1)','sentinel-ml/Databases/22oct_pull/sentinel-history.tar'):
    p=ROOT/rel; raw=p.read_bytes(); r={'path':rel,'sha256':sha(p),'operation':'decode UTF-16LE strictly, inspect code points; no lossy substitution or source writes'}
    try:
        s=raw.removeprefix(b'\xff\xfe').decode('utf-16-le',errors='strict')
        r.update({'replacement_characters':s.count('\ufffd'),'non_latin1_codepoints':sum(ord(x)>255 for x in s),'decoded_characters':len(s),'non_latin1_histogram':dict(collections.Counter(hex(ord(x)) for x in s if ord(x)>255))})
        if all(ord(x)<=255 for x in s):
            b=s.encode('latin-1'); r['reversed_sha256']=hashlib.sha256(b).hexdigest()
            if rel.endswith('.tar'):
                with tarfile.open(fileobj=io.BytesIO(b)) as t: r['members']=[{'name':m.name,'bytes':m.size} for m in t.getmembers()]
            else:
                con=sqlite3.connect(':memory:'); con.deserialize(b)
                r['tables']=con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(); con.close()
        else: r['blocked']='Cannot establish lossless byte reversal; existing text encoding contains code points outside Latin-1. Do not fabricate recovered records.'
    except Exception as e: r['error']=repr(e)
    result['recovery_probes'].append(r)
with (OUT/'schema_recovery_findings.json').open('x',encoding='utf-8') as f: json.dump(result,f,ensure_ascii=False,indent=2)
print(json.dumps({'training_files':len(inv),'sources':result['sources'],'recovery_probes':result['recovery_probes']},ensure_ascii=False,indent=2))
