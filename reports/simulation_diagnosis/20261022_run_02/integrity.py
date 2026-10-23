from runlib import *
import platform
protect()
def inventory():
    out={}
    for base in ('sentinel-ml','sentinel-ai'):
        for d,dirs,names in os.walk(ROOT/base):
            dirs[:]=[x for x in dirs if x not in ('venv','.venv','.git','.gradle','build','node_modules','__pycache__','.pytest_cache','simulation_run_02')]
            for n in names:
                p=Path(d)/n
                out[p.relative_to(ROOT).as_posix()]={'bytes':p.stat().st_size,'sha256':sha(p)}
    return out
phase=sys.argv[1]
g=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],text=True,capture_output=True)
jsave('git_'+phase+'.json',{'argv':g.args,'cwd':str(ROOT),'exit_code':g.returncode,'stdout':g.stdout,'stderr':g.stderr})
if phase=='before':
    inv=inventory(); jsave('protected_before.json',inv)
    jsave('environment.json',{'python':sys.version,'executable':sys.executable,'platform':platform.platform(),'cwd':str(ROOT),'phase':phase})
else:
    old=jload('protected_before.json'); inv={p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in old}
    jsave('protected_'+phase+'.json',inv)
    diff=[p for p in old if old[p]!=inv[p]]
    comp={'protected_files':len(old),'changed':diff,'git_identical':jload('git_before.json')['stdout']==g.stdout,'git_lines':len(g.stdout.splitlines()),'git_exit_code':g.returncode}
    jsave('integrity_'+phase+'.json',comp)
    if diff: raise RuntimeError('HARD_STOP_PROTECTED_HASH_CHANGE: '+str(diff))
print(json.dumps({'phase':phase,'files':len(inv),'git_exit_code':g.returncode}))
