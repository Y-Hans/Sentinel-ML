"""Read-only preflight. No imports from project code, model loading, or training."""
import collections, hashlib, json, os, platform, re, sqlite3, subprocess, sys, tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()
def save(name, obj):
    with (OUT/name).open('x', encoding='utf-8') as f: json.dump(obj, f, ensure_ascii=False, indent=2)
def git_status():
    r = subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'], capture_output=True, text=True, env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'})
    return {'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
def files():
    for base in ('sentinel-ml','sentinel-ai'):
        for d, dirs, names in os.walk(ROOT/base):
            dirs[:] = [x for x in dirs if x not in ('venv','.venv','.git','__pycache__','.gradle','build','node_modules')]
            for n in names:
                p=Path(d)/n
                if p.suffix in ('.pkl','.joblib','.apk') or (p.suffix=='.json' and any(x in n.lower() for x in ('portable','vocab','scaler','trees','manifest'))) or 'Databases' in p.parts or n=='SENTINEL_MASTER_PLAN.md':
                    yield p
def snapshot(paths):
    return {str(p.relative_to(ROOT)).replace('\\','/'): {'bytes':p.stat().st_size,'sha256':sha(p)} for p in paths}
mode=sys.argv[1]
if mode=='before':
    save('environment.json',{'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'cwd':str(ROOT),'argv':sys.argv,'GIT_OPTIONAL_LOCKS':'0','project_modules_imported':False})
    save('git_before.json',git_status())
    paths=sorted(set(files()))
    save('hashes_before.json',snapshot(paths))
    result={'database_files':[], 'archives':[], 'json_record_sources':[], 'training_files':[]}
    for p in sorted((ROOT/'sentinel-ml/Databases').rglob('*')):
        if not p.is_file(): continue
        record={'path':str(p.relative_to(ROOT)), 'bytes':p.stat().st_size,'sha256':sha(p)}
        with p.open('rb') as f: record['header_hex']=f.read(32).hex()
        if p.suffix=='.tar':
            try:
                with tarfile.open(p,'r:*') as t:
                    record['members']=[{'name':m.name,'bytes':m.size,'type':str(m.type)} for m in t.getmembers()]
            except Exception as e: record['error']=repr(e)
            result['archives'].append(record)
        else:
            if bytes.fromhex(record['header_hex']).startswith(b'SQLite format 3\0'):
                try:
                    con=sqlite3.connect(p.as_uri()+'?mode=ro&immutable=1',uri=True)
                    tables=con.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
                    record['tables']=[]
                    for name, sql in tables:
                        safe='"'+name.replace('"','""')+'"'
                        record['tables'].append({'name':name,'sql':sql,'count':con.execute('SELECT count(*) FROM '+safe).fetchone()[0]})
                    con.close()
                    record['caveat']='Immutable read excludes WAL; not a recovered or merged database.'
                except Exception as e: record['error']=repr(e)
            result['database_files'].append(record)
    def norm(t):
        t=re.sub(r'https?://\S+|www\.\S+', ' <URL> ', str(t).casefold())
        t=re.sub(r'\d+', '<NUM>', t)
        return ' '.join(t.split())
    train_keys=set()
    for d, dirs, names in os.walk(ROOT/'sentinel-ml'):
        dirs[:]=[x for x in dirs if x not in ('venv','.git','__pycache__')]
        for name in names:
            p=Path(d)/name
            if p.suffix=='.jsonl' and 'train' in name.lower() and 'Messages-ml' in p.parts:
                count=0; labels=collections.Counter(); keys=set(); errors=[]
                with p.open(encoding='utf-8-sig') as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            r=json.loads(line); count+=1; labels[str(r.get('label',r.get('class','MISSING')))]+=1
                            text=r.get('text',r.get('message',r.get('body')))
                            if text is not None: keys.add(norm(text))
                        except Exception as e: errors.append(str(e))
                train_keys.update(keys)
                result['training_files'].append({'path':str(p.relative_to(ROOT)),'sha256':sha(p),'count':count,'labels':dict(labels),'template_keys':len(keys),'errors':errors[:3]})
    replay=ROOT/'sentinel-ml/7sep_messages_v3/data/bench_sentinel_replay.jsonl'
    if replay.exists():
        rows=[json.loads(x) for x in replay.read_text(encoding='utf-8-sig').splitlines() if x.strip()]
        hits=[i for i,r in enumerate(rows,1) if norm(r.get('text',r.get('message',r.get('body','')))) in train_keys]
        result['replay_overlap']={'path':str(replay.relative_to(ROOT)),'sha256':sha(replay),'count':len(rows),'columns':sorted(set().union(*(r.keys() for r in rows))),'labels':dict(collections.Counter(str(r.get('label','MISSING')) for r in rows)),'normalization':'casefold; URL -> <URL>; digits -> <NUM>; whitespace collapse','union_training_file_count':len(result['training_files']),'matched_rows':len(hits),'matched_1based_rows':hits,'limitation':'Conservative screen, not complete template lineage or semantic grouping; no domain overlap clearance.'}
    for d, dirs, names in os.walk(ROOT/'sentinel-ml/New_history'):
        dirs[:]=[x for x in dirs if x!='__pycache__']
        for name in names:
            if 'record' in name.lower() and name.endswith('.json'):
                p=Path(d)/name
                try:
                    obj=json.loads(p.read_text(encoding='utf-8-sig'))
                    result['json_record_sources'].append({'path':str(p.relative_to(ROOT)),'sha256':sha(p),'type':type(obj).__name__,'count':len(obj),'keys_or_first_row':list(obj.keys())[:10] if isinstance(obj,dict) else list(obj[0].keys()) if obj and isinstance(obj[0],dict) else None})
                except Exception as e: result['json_record_sources'].append({'path':str(p),'error':repr(e)})
    save('preflight_findings.json',result)
    print(json.dumps({'protected_files_hashed':len(paths),'training_files':len(result['training_files']),'replay_overlap':result.get('replay_overlap'),'database_files':result['database_files'],'archives':result['archives'],'history':result['json_record_sources']},ensure_ascii=False,indent=2))
elif mode=='after':
    before=json.loads((OUT/'hashes_before.json').read_text(encoding='utf-8'))
    after=snapshot([ROOT/p for p in before])
    save('hashes_after.json',after)
    status=git_status(); save('git_after.json',status)
    old=json.loads((OUT/'git_before.json').read_text(encoding='utf-8'))
    comparison={'hashed_files':len(before),'changed_files':[p for p in before if before[p]!=after[p]],'git_stdout_identical':old['stdout']==status['stdout'],'git_exit_codes':[old['exit_code'],status['exit_code']],'git_lines':len(status['stdout'].splitlines())}
    save('integrity_comparison.json',comparison); print(json.dumps(comparison,indent=2))
