from runlib import *
protect()
target=sys.argv[1]; interpreter=sys.argv[2] if len(sys.argv)>2 else sys.executable
run([interpreter,'-B',str(OUT/(target+'.py'))],target)
