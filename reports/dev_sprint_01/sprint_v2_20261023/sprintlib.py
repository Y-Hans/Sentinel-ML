import csv,json,hashlib,os,sys,re,time,subprocess,unicodedata,collections,math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
OLD=ROOT/'reports/dev_sprint_01/hinglish_probe'
M=ROOT/'sentinel-ml/Messages-ml'
os.environ.update(PYTHONDONTWRITEBYTECODE='1',CUDA_VISIBLE_DEVICES='-1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',GIT_OPTIONAL_LOCKS='0')
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def small(p):
 p=Path(p);assert p.stat().st_size<1000000,str(p)
 return p.read_text(encoding='utf-8-sig')
def load(p):return json.loads(small(p))
def rows(p):
 with Path(p).open(encoding='utf-8-sig',newline='') as f:
  if Path(p).suffix=='.csv':yield from csv.DictReader(f)
  else:
   for line in f:
    if line.strip():yield json.loads(line)
def write(n,s):
 p=OUT/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('x',encoding='utf-8',newline='') as f:f.write(s)
def save(n,o):write(n,json.dumps(o,ensure_ascii=False,indent=2,default=str))
def csvwrite(n,rr,fields=None):
 rr=list(rr)
 with (OUT/n).open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields or list(rr[0]));w.writeheader();w.writerows(rr)
def jsonl(n,rr):
 with (OUT/n).open('x',encoding='utf-8') as f:
  for r in rr:f.write(json.dumps(r,ensure_ascii=False,default=str)+'\n')
def guard():
 def hook(event,args):
  if event=='open':
   p,mode,flags=args
   if isinstance(p,int) or str(p).lower() in ('nul','\\\\.\\nul'):return
   pp=Path(p).resolve()
   if 'datasets_v5' in pp.parts or 'user_data' in pp.parts:raise RuntimeError('INTAKE_NOT_AUTHORIZED: '+str(pp))
   writing=(mode and any(c in mode for c in 'wax+')) or (flags and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
   if writing and not pp.is_relative_to(OUT):raise RuntimeError('PROTECTED_WRITE: '+str(pp))
  if event in ('os.remove','os.rename','os.rmdir'):raise RuntimeError('MUTATION_FORBIDDEN: '+event)
 sys.addaudithook(hook)
def norm(s):
 s=unicodedata.normalize('NFKC',s).casefold();s=re.sub(r'(?:https?|hxxps?)://\S+|www\.\S+',' URL ',s)
 s=re.sub(r'\+?\d[\d\s()-]{6,}\d',' PHONE ',s);s=re.sub(r'\d+',' NUM ',s)
 return ' '.join(re.findall(r'\w+',s))
def wilson(k,n):
 if not n:return [None,None]
 z=1.959963984540054;p=k/n;d=1+z*z/n;c=(p+z*z/(2*n))/d;a=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
 return [c-a,c+a]
def gitstatus():
 r=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8')
 return {'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'lines':r.stdout.splitlines(),'stderr':r.stderr}
def fixedhashes():
 fixed=load(ROOT/'reports/simulation_diagnosis/20261022_run_02/protected_v2_before.json')
 return {p:{'sha256':sha(ROOT/p),'bytes':(ROOT/p).stat().st_size} for p in fixed}
if __name__=='__main__':
 target=sys.argv[1];t=time.time();argv=[sys.executable,'-B',str(OUT/(target+'.py'))]
 env={**os.environ,'PYTHONUTF8':'1'}
 with (OUT/(target+'.stdout.txt')).open('x',encoding='utf-8') as o,(OUT/(target+'.stderr.txt')).open('x',encoding='utf-8') as e:
  r=subprocess.run(argv,cwd=ROOT,env=env,stdout=o,stderr=e)
 save(target+'.command.json',{'argv':argv,'cwd':str(ROOT),'exit_code':r.returncode,'wall_seconds':time.time()-t,'script_sha256':sha(OUT/(target+'.py')),'environment':{k:env[k] for k in ['CUDA_VISIBLE_DEVICES','OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','PYTHONDONTWRITEBYTECODE']},'stdout_sha256':sha(OUT/(target+'.stdout.txt')),'stderr_sha256':sha(OUT/(target+'.stderr.txt'))})
 print(target,'exit',r.returncode,'seconds',round(time.time()-t,2));print(small(OUT/(target+'.stdout.txt'))[-3000:]);print(small(OUT/(target+'.stderr.txt'))[-2000:]);sys.exit(r.returncode)
