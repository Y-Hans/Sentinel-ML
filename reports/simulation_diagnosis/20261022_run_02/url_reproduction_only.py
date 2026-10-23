from runlib import *
protect()
exec(compile((OUT/'infer_urls.py').read_text(encoding='utf-8'),'infer_urls.py','exec'))
