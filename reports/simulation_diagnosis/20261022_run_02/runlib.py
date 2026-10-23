import csv, hashlib, json, os, re, subprocess, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
ALLOWED=[OUT,ROOT/'sentinel-ml/Messages-ml/experiments/simulation_run_02',ROOT/'sentinel-ml/URL-ml/experiments/simulation_run_02']
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()
def jsave(name,obj):
    p=OUT/name
    with p.open('x',encoding='utf-8') as f: json.dump(obj,f,ensure_ascii=False,indent=2,default=str)
def jload(name): return json.loads((OUT/name).read_text(encoding='utf-8'))
def jsonl(name,rows):
    with (OUT/name).open('x',encoding='utf-8') as f:
        for r in rows: f.write(json.dumps(r,ensure_ascii=False,default=str)+'\n')
def readrows(p): return [json.loads(x) for x in Path(p).read_text(encoding='utf-8-sig').splitlines() if x.strip()]
def protect():
    os.environ.update(PYTHONDONTWRITEBYTECODE='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',GIT_OPTIONAL_LOCKS='0')
    def hook(event,args):
        if event=='open':
            path,mode,flags=args
            if isinstance(path,int): return
            writing=(mode is not None and any(x in mode for x in 'wax+')) or (flags is not None and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
            if writing:
                p=Path(path).resolve()
                if not any(p.is_relative_to(a) for a in ALLOWED): raise RuntimeError('HARD_STOP_PROTECTED_WRITE_ATTEMPT: '+str(p))
        elif event in ('os.remove','os.rename','os.rmdir','shutil.move','shutil.copyfile'):
            raise RuntimeError('HARD_STOP_MUTATION: '+event+' '+str(args))
    sys.addaudithook(hook)
def text(r): return str(next((r[k] for k in ('raw_text','content','text','message','body') if r.get(k) is not None),''))
def norm(s):
    import unicodedata
    s=unicodedata.normalize('NFKC',s).casefold()
    s=re.sub(r'https?://\S+|www\.\S+|<url>',' <url> ',s)
    s=re.sub(r'\d+',' <num> ',s)
    return ' '.join(re.findall(r'\w+|<url>|<num>',s))
def run(argv,name,timeout=1800):
    t=time.time(); env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','GIT_OPTIONAL_LOCKS':'0','PYTHONUTF8':'1'}
    r=subprocess.run(argv,cwd=ROOT,env=env,text=True,encoding='utf-8',errors='replace',capture_output=True,timeout=timeout)
    (OUT/(name+'.stdout.txt')).open('x',encoding='utf-8').write(r.stdout)
    (OUT/(name+'.stderr.txt')).open('x',encoding='utf-8').write(r.stderr)
    jsave(name+'.command.json',{'argv':argv,'cwd':str(ROOT),'exit_code':r.returncode,'seconds':time.time()-t,'environment_overrides':{k:env[k] for k in ('PYTHONDONTWRITEBYTECODE','OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','GIT_OPTIONAL_LOCKS','PYTHONUTF8')},'stdout_sha256':sha(OUT/(name+'.stdout.txt')),'stderr_sha256':sha(OUT/(name+'.stderr.txt'))})
    print(name,'exit',r.returncode, r.stdout[-1000:],r.stderr[-500:],flush=True)
    if 'HARD_STOP_' in r.stderr: raise RuntimeError(r.stderr)
    return r
