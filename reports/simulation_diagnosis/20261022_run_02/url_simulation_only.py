from runlib import *
protect()
sys.argv=['infer_urls.py','simulation']
exec(compile((OUT/'infer_urls.py').read_text(encoding='utf-8'),'infer_urls.py','exec'))
