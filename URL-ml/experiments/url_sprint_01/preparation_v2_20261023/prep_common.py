"""Agent C URL-only preparation. No training, inference, network or installs."""
import os,sys,json,csv,hashlib,datetime,subprocess
from pathlib import Path
os.environ.update(PYTHONDONTWRITEBYTECODE='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',NUMEXPR_NUM_THREADS='1',CUDA_VISIBLE_DEVICES='-1')
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[5]
U=ROOT/'sentinel-ml/URL-ml'
EXP=U/'experiments/url_sprint_01/preparation_v2_20261023'
OUT=ROOT/'reports/url_sprint_01/preparation_v2_20261023'
OUT.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(U/'scripts'))
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def read(p):
    p=Path(p);assert p.stat().st_size<1_000_000,p
    return p.read_text(encoding='utf-8-sig')
def write(p,s):
    p=Path(p);assert p.is_relative_to(OUT) or p.is_relative_to(EXP),p
    assert not p.exists(),p
    p.write_text(s,encoding='utf-8')
def js(p,o):write(p,json.dumps(o,ensure_ascii=False,indent=2,default=str)+'\n')
def rows(p):
    with open(p,encoding='utf-8-sig',newline='') as f:yield from csv.DictReader(f)
def csvout(p,data,fields=None):
    data=iter(data);first=next(data,None);assert first is not None
    fields=fields or list(first)
    assert not Path(p).exists(),p
    with open(p,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerow(first);w.writerows(data)
def prohibited(name):
    n=name.replace('\\','/').lower()
    return n.startswith(('sentinel-ml/messages-ml/','sentinel-ml/datasets_v5/'))
def git_observe(stage):
    repo=ROOT/'sentinel-ai'
    cmd=['git','--no-optional-locks','status','--porcelain=v1','--untracked-files=all','-z']
    cp=subprocess.run(cmd,cwd=repo,capture_output=True)
    chunks=cp.stdout.decode('utf-8',errors='surrogateescape').split('\0');entries=[];i=0
    while i<len(chunks):
        item=chunks[i];i+=1
        if not item:continue
        r={'status':item[:2],'path':item[3:]}
        if ('R' in r['status'] or 'C' in r['status']) and i<len(chunks):r['original_path']=chunks[i];i+=1
        entries.append(r)
    obj={'time_utc':stamp(),'cwd':str(repo),'command':cmd,'exit_code':cp.returncode,'stderr':cp.stderr.decode(errors='replace'),'entries':entries}
    js(OUT/f'git_sentinel_ai_{stage}.json',obj)
    assert cp.returncode==0,'Cannot claim valid current-run Git baseline'
    return obj
def universe():
    old=ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json'
    fixed=json.loads(read(old));names=set(fixed);orig=set(fixed)
    excluded=set()
    for base in (U,ROOT/'reports/url_sprint_01'):
        for directory,dirs,files in os.walk(base,followlinks=False):
            parent=Path(directory)
            dirs[:]=[d for d in dirs if d not in {'venv','.git','__pycache__','.pytest_cache'} and not (parent/d).is_relative_to(OUT) and not (parent/d).is_relative_to(EXP)]
            if parent.is_relative_to(OUT) or parent.is_relative_to(EXP):continue
            for n in files:names.add((parent/n).relative_to(ROOT).as_posix())
    for n in ('AGENT_C_NEXT.md','INDEPENDENT_REVIEW.md','ANNOTATED_REVIEW_SAMPLE.csv'):
        names.add('assistant_review_20261023/'+n)
    for n in names:
        if prohibited(n):excluded.add(n)
    return {'created_utc':stamp(),'definition':'Union of original fixed manifest paths, every existing file under URL-ml excluding venv/.git/__pycache__/.pytest_cache and this run, prior reports/url_sprint_01 excluding this run, and three supplied Agent C review inputs. Freeze once; after uses exact same paths. Hashing binary files is permitted integrity work; no CSV/JSON data parsing via hashes.','old_fixed_manifest_sha256':sha(old),'fixed_list_count':len(fixed),'excluded_501_explicit_no_read':sorted(excluded),'out_of_scope':'Agent A files outside fixed manifest are not enumerated; prohibited directories are neither enumerated nor opened. Runtime/venv/.git/cache/new outputs excluded. sentinel-ai is hashed only by fixed file list and Git is observation only.','files':[{'path':n,'origin':'original_fixed_list' if n in orig else 'additional_URL_or_review_scope','read_policy':'EXPLICIT_NO_READ' if n in excluded else 'HASH'} for n in sorted(names)]}
def snapshot(stage):
    if stage=='before':
        scope=universe();js(OUT/'FILE_UNIVERSE_v2.json',scope)
    else:scope=json.loads(read(OUT/'FILE_UNIVERSE_v2.json'))
    items=[]
    for r in scope['files']:
        p=ROOT/r['path']
        if r['read_policy']=='EXPLICIT_NO_READ':items.append({'path':r['path'],'status':'SKIPPED_EXPLICIT_NO_READ'});continue
        if not p.is_file():items.append({'path':r['path'],'status':'MISSING'});continue
        items.append({'path':r['path'],'status':'HASHED','bytes':p.stat().st_size,'sha256':sha(p)})
    js(OUT/f'INTEGRITY_{stage}_v2.json',{'time_utc':stamp(),'universe_sha256':sha(OUT/'FILE_UNIVERSE_v2.json'),'entries':items})
    git=git_observe(stage)
    print(stage,'hashed',sum(r['status']=='HASHED' for r in items),'skipped',sum(r['status']=='SKIPPED_EXPLICIT_NO_READ' for r in items),'missing',sum(r['status']=='MISSING' for r in items),'sentinel-ai Git exit',git['exit_code'],flush=True)
if __name__=='__main__':snapshot(sys.argv[1])
