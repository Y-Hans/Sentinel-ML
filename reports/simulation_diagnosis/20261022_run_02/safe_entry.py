"""Append-only correction: the original write guard falsely classified Windows NUL as a file."""
import os,sys
from pathlib import Path
import runlib
def safe_protect():
    os.environ.update(PYTHONDONTWRITEBYTECODE='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',MKL_NUM_THREADS='1',GIT_OPTIONAL_LOCKS='0')
    def hook(event,args):
        if event=='open':
            path,mode,flags=args
            if isinstance(path,int): return
            # NUL is an OS null device, not a protected filesystem path. No source-write exception.
            if str(path).lower().rstrip('\\') in ('nul','\\\\.\\nul'): return
            writing=(mode is not None and any(x in mode for x in 'wax+')) or (flags is not None and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
            if writing and not any(Path(path).resolve().is_relative_to(a) for a in runlib.ALLOWED): raise RuntimeError('HARD_STOP_PROTECTED_WRITE_ATTEMPT: '+str(path))
        elif event in ('os.remove','os.rename','os.rmdir','shutil.move','shutil.copyfile'): raise RuntimeError('HARD_STOP_MUTATION: '+event+' '+str(args))
    sys.addaudithook(hook)
runlib.protect=safe_protect
target=sys.argv[1]; sys.argv=[str(runlib.OUT/(target+'.py'))]+sys.argv[2:]
exec(compile((runlib.OUT/(target+'.py')).read_text(encoding='utf-8'),str(runlib.OUT/(target+'.py')),'exec'))
