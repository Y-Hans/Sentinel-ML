import csv,hashlib,json,os,re,subprocess,sys,time,unicodedata
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]; OUT=Path(__file__).resolve().parent
EXP=ROOT/'sentinel-ml/Messages-ml/messages_v5_sprint/hinglish_probe'
BLOCKED={'datasets_v5','user_data'}
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def save(n,o):
    with (OUT/n).open('x',encoding='utf-8') as f:json.dump(o,f,ensure_ascii=False,indent=2,default=str)
def load(n):return json.loads((OUT/n).read_text(encoding='utf-8'))
def jsonl(n,rr):
    with (OUT/n).open('x',encoding='utf-8') as f:
        for r in rr:f.write(json.dumps(r,ensure_ascii=False,default=str)+'\n')
def readjsonl(p):return [json.loads(s) for s in Path(p).read_text(encoding='utf-8-sig').splitlines() if s.strip()]
def csvwrite(n,rr,fields=None):
    with (OUT/n).open('x',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields or list(rr[0]));w.writeheader();w.writerows(rr)
def csvread(n):
    with (OUT/n).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def norm(s):
    s=unicodedata.normalize('NFKC',s).casefold();s=re.sub(r'(?:https?|hxxps?)://\S+|www\.\S+|\b\S+\.invalid\S*',' <url> ',s)
    s=re.sub(r'\+?\d[\d\s()-]{6,}\d',' <phone> ',s);s=re.sub(r'\d+',' <num> ',s)
    return ' '.join(re.findall(r'\w+|<url>|<phone>|<num>',s))
def protect():
    os.environ.update(PYTHONDONTWRITEBYTECODE='1',CUDA_VISIBLE_DEVICES='-1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',GIT_OPTIONAL_LOCKS='0')
    def hook(event,args):
        if event=='open':
            p,mode,flags=args
            if isinstance(p,int) or str(p).lower().rstrip('\\') in ('nul','\\\\.\\nul'):return
            pp=Path(p).resolve()
            if set(pp.parts)&BLOCKED:raise RuntimeError('PROHIBITED_INPUT_PATH: '+str(pp))
            writing=(mode is not None and any(x in mode for x in 'wax+')) or (flags is not None and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
            if writing and not any(pp.is_relative_to(a) for a in (OUT,EXP)):raise RuntimeError('HARD_STOP_PROTECTED_WRITE_ATTEMPT: '+str(pp))
        elif event in ('os.rename','os.remove','os.rmdir','shutil.copyfile','shutil.move'):raise RuntimeError('HARD_STOP_MUTATION: '+event)
    sys.addaudithook(hook)
def command(target):
    t=time.time();argv=[sys.executable,'-B',str(OUT/(target+'.py'))];env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','PYTHONUTF8':'1','CUDA_VISIBLE_DEVICES':'-1','OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','GIT_OPTIONAL_LOCKS':'0'}
    r=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
    (OUT/(target+'.stdout.txt')).open('x',encoding='utf-8').write(r.stdout);(OUT/(target+'.stderr.txt')).open('x',encoding='utf-8').write(r.stderr)
    save(target+'.command.json',{'argv':argv,'cwd':str(ROOT),'exit_code':r.returncode,'seconds':time.time()-t,'CPU_only':True,'environment':{k:env[k] for k in ('CUDA_VISIBLE_DEVICES','OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','PYTHONDONTWRITEBYTECODE','PYTHONUTF8')},'stdout_sha256':sha(OUT/(target+'.stdout.txt')),'stderr_sha256':sha(OUT/(target+'.stderr.txt'))})
    print(target,'exit',r.returncode,r.stdout[-1600:],r.stderr[-600:],flush=True)
    if r.returncode:sys.exit(r.returncode)
