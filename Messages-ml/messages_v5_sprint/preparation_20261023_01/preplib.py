import csv,json,hashlib,os,re,sys,time,subprocess,unicodedata,collections,math
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[3]
PREV=ROOT/'reports/dev_sprint_01/sprint_v2_20261023';V1=ROOT/'reports/dev_sprint_01/hinglish_probe';B=ROOT.parent/'sentinel_datasets'
os.environ.update(PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1',CUDA_VISIBLE_DEVICES='-1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',GIT_OPTIONAL_LOCKS='0')
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
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
 with (OUT/n).open('x',encoding='utf-8',newline='') as f:f.write(s)
def save(n,o):write(n,json.dumps(o,ensure_ascii=False,indent=2,default=str))
def jsonl(n,rr):
 with (OUT/n).open('x',encoding='utf-8') as f:
  for r in rr:f.write(json.dumps(r,ensure_ascii=False,default=str)+'\n')
def csvwrite(n,rr):
 rr=list(rr)
 with (OUT/n).open('x',encoding='utf-8-sig',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rr[0]));w.writeheader();w.writerows(rr)
def guard():
 def audit(event,args):
  if event=='open':
   p,mode,flags=args
   if isinstance(p,int) or str(p).lower() in ('nul','\\\\.\\nul'):return
   pp=Path(p).resolve()
   writing=(mode and any(c in mode for c in 'wax+')) or(flags and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
   if writing and not pp.is_relative_to(OUT):raise RuntimeError('PROTECTED_WRITE '+str(pp))
   if ('exam_sealed' in pp.parts or 'datasets_v5' in pp.parts or 'user_data' in pp.parts) and not globals().get('HASH_ONLY',False):raise RuntimeError('UNAUTHORIZED_CONTENT_READ '+str(pp))
  elif event in ('os.rename','os.remove','os.rmdir'):raise RuntimeError('NO_MUTATION '+event)
 sys.addaudithook(audit)
def status():
 r=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8')
 return {'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'lines':r.stdout.splitlines(),'stderr':r.stderr}
def hashes(paths):return {str(p):{'bytes':Path(p).stat().st_size,'sha256':sha(p)} for p in paths}
def norm(s):
 s=unicodedata.normalize('NFKC',s).casefold();s=re.sub(r'(?:https?|hxxps?)://\S+|www\.\S+',' URL ',s);s=re.sub(r'\+?\d[\d\s()-]{6,}\d',' PHONE ',s);s=re.sub(r'\d+',' NUM ',s)
 return ' '.join(re.findall(r'\w+',s))
def table(head,rr):return '| '+' | '.join(head)+' |\n| '+' | '.join('---' for _ in head)+' |\n'+''.join('| '+' | '.join(str(x).replace('|',' / ').replace('\n',' ') for x in r)+' |\n' for r in rr)
if __name__=='__main__':
 target=sys.argv[1];argv=[sys.executable,'-B',str(OUT/(target+'.py'))];start=time.time()
 with (OUT/(target+'.stdout.txt')).open('x',encoding='utf-8') as o,(OUT/(target+'.stderr.txt')).open('x',encoding='utf-8') as e:r=subprocess.run(argv,cwd=ROOT,env=os.environ.copy(),stdout=o,stderr=e)
 save(target+'.command.json',{'argv':argv,'cwd':str(ROOT),'interpreter':sys.executable,'python':sys.version,'exit_code':r.returncode,'start_epoch':start,'wall_seconds':time.time()-start,'script_sha256':sha(OUT/(target+'.py')),'stdout_sha256':sha(OUT/(target+'.stdout.txt')),'stderr_sha256':sha(OUT/(target+'.stderr.txt')),'environment':{k:os.environ[k] for k in ['CUDA_VISIBLE_DEVICES','OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','PYTHONDONTWRITEBYTECODE']}})
 print(target,'exit',r.returncode,'wall',round(time.time()-start,2));print(small(OUT/(target+'.stdout.txt'))[-4000:]);print(small(OUT/(target+'.stderr.txt'))[-1500:]);sys.exit(r.returncode)
