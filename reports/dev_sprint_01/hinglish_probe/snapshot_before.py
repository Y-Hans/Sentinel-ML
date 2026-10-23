from probe_lib import *
protect()
inv={}
for base in ('sentinel-ml','sentinel-ai'):
    for d,dirs,names in os.walk(ROOT/base):
        dirs[:]=[x for x in dirs if x not in BLOCKED|{'venv','tools','build','node_modules','messages_v5_sprint','simulation_run_02'} and not x.startswith('.')]
        for n in names:
            p=Path(d)/n;inv[p.relative_to(ROOT).as_posix()]={'bytes':p.stat().st_size,'sha256':sha(p)}
save('protected_before.json',inv)
r=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],cwd=ROOT,capture_output=True,text=True,env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'})
save('git_before.json',{'argv':r.args,'cwd':str(ROOT),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
save('environment.json',{'python':sys.version,'executable':sys.executable,'cwd':str(ROOT),'CPU_only':True,'CUDA_VISIBLE_DEVICES':os.environ['CUDA_VISIBLE_DEVICES'],'excluded_inputs':['datasets_v5','user_data'],'inventory_exclusions':'hidden/build/tool/venv/cache dirs and permitted new experiment dirs; no datasets_v5 or user_data opened'})
print('protected files hashed',len(inv),'git exit',r.returncode)
