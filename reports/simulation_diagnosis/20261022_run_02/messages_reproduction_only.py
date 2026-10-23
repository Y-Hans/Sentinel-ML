from runlib import *
protect()
s=(OUT/'infer_messages.py').read_text(encoding='utf-8')
a=s.index('        pp=predict(sim)'); b=s.index('        print(name,meta',a)
s=s[:a]+s[b:]
for name in ('message_predictions.jsonl','spam_confusion_recheck.jsonl','messages_reproduction.json','indic_vocabulary_recheck.json','label_schema_recheck.json'): s=s.replace("'"+name+"'","'gate_"+name+"'")
exec(compile(s,'infer_messages.py (reproduction-only phase)','exec'))
