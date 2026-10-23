from runlib import *
target=sys.argv[1]; interpreter=sys.argv[2] if len(sys.argv)>2 else sys.executable
run([interpreter,'-B',str(OUT/'safe_entry.py'),target],target+'_v2')
