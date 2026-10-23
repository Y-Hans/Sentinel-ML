from runlib import *
import platform
protect()
phase=sys.argv[1]
g=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],capture_output=True,text=True)
jsave('git_v2_'+phase+'.json',{'argv':g.args,'cwd':str(ROOT),'exit_code':g.returncode,'stdout':g.stdout,'stderr':g.stderr})
if phase=='before':
    inv={}; failures=[]
    for base in ('sentinel-ml','sentinel-ai'):
        for d,dirs,names in os.walk(ROOT/base):
            dirs[:]=[x for x in dirs if x not in ('venv','tools','build','node_modules','simulation_run_02') and not x.startswith('.')]
            for n in names:
                p=Path(d)/n
                try: inv[p.relative_to(ROOT).as_posix()]={'bytes':p.stat().st_size,'sha256':sha(p)}
                except OSError as e: failures.append({'path':str(p),'error':str(e)})
    jsave('protected_v2_before.json',inv); jsave('inventory_read_failures.json',failures)
    jsave('environment_v2.json',{'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'cwd':str(ROOT),'exclusions':'hidden dirs, venv, tools, build, node_modules, new simulation_run_02; no protected model/data directory excluded'})
else:
    old=jload('protected_v2_before.json'); inv={p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in old}
    jsave('protected_v2_'+phase+'.json',inv)
    comp={'protected_files':len(old),'changed':[p for p in old if old[p]!=inv[p]],'git_identical':jload('git_v2_before.json')['stdout']==g.stdout,'git_lines':len(g.stdout.splitlines()),'git_exit_code':g.returncode}
    jsave('integrity_v2_'+phase+'.json',comp)
    if comp['changed']: raise RuntimeError('HARD_STOP_PROTECTED_HASH_CHANGE: '+str(comp['changed']))
print(json.dumps({'phase':phase,'files':len(inv),'git_exit_code':g.returncode}))
