"""Offline sprint utilities. No training or network operations."""
import os, sys, json, csv, hashlib, subprocess, datetime
from pathlib import Path
os.environ.update(OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1', NUMEXPR_NUM_THREADS='1', VECLIB_MAXIMUM_THREADS='1', PYTHONDONTWRITEBYTECODE='1', CUDA_VISIBLE_DEVICES='-1')
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[4]
U = ROOT/'sentinel-ml/URL-ml'
OUT = ROOT/'reports/url_sprint_01'
EXP = U/'experiments/url_sprint_01'
OUT.mkdir(exist_ok=True, parents=True)
sys.path.insert(0, str(U/'scripts'))
def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def readtext(p):
    p=Path(p); assert p.stat().st_size < 1_000_000, str(p)
    return p.read_text(encoding='utf-8-sig')
def write(p,s):
    p=Path(p); assert not p.exists(), str(p)
    assert p.is_relative_to(OUT) or p.is_relative_to(EXP)
    p.write_text(s,encoding='utf-8')
def js(p,x): write(p,json.dumps(x,indent=2,ensure_ascii=False,default=str)+'\n')
def csvout(p,rows,fields=None):
    rows=list(rows); fields=fields or list(rows[0])
    assert not Path(p).exists(), str(p)
    with open(p,'w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def rows(p):
    with open(p,encoding='utf-8-sig',newline='') as f: yield from csv.DictReader(f)
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def snapshot(stage):
    fixed=ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json'
    entries=json.loads(readtext(fixed)); result={}
    for name,old in entries.items():
        if name.startswith(('sentinel-ml/Messages-ml/','sentinel-ml/datasets_v5/')):
            result[name]={'status':'SKIPPED_EXPLICIT_NO_READ'}; continue
        p=ROOT/name
        result[name]={'sha256':sha(p),'bytes':p.stat().st_size,'matches_prior':sha(p)==old['sha256']} if p.is_file() else {'status':'MISSING'}
    js(OUT/f'protected_{stage}.json',{'fixed_list_sha256':sha(fixed),'time_utc':stamp(),'entries':result})
    cp=subprocess.run(['git','status','--porcelain=v1','--untracked-files=all'],cwd=ROOT,capture_output=True,text=True)
    js(OUT/f'git_{stage}.json',{'command':['git','status','--porcelain=v1','--untracked-files=all'],'cwd':str(ROOT),'exit_code':cp.returncode,'entries':cp.stdout.splitlines(),'stderr':cp.stderr})
    print(stage,'protection entries',len(result),'skipped',sum(x.get('status')=='SKIPPED_EXPLICIT_NO_READ' for x in result.values()),flush=True)
