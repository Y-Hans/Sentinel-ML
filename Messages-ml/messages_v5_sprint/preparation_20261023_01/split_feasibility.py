from preplib import *
guard()
inv=load(OUT/'B_original_source_inventory.json')['sources'];ledger=[];counts=collections.Counter()
def note(s,key):
 m=re.search(r'(?:^|[; ])'+re.escape(key)+r'=([^;]+)',s)
 return m.group(1).strip().rstrip('.') if m else 'UNKNOWN'
for sid,ent in inv.items():
 p=B/'normalized'/f'{sid}.jsonl';assert sha(p)==ent['sha256']
 for r in rows(p):
  notes=str(r.get('notes',''));template=note(notes,'source_template_group')
  author={'sidzzz07':'Siddharth Rane / deterministic synthetic generator','ridham':'Ridham115 / '+note(notes,'generator'),'ysangam':'ysangam / generation not documented','karan':'karanverma19 / template provenance unverified','financial2025':'Al Rafi Ahmed; Gazi Faizul Islam / collection claim not independently verified'}[sid]
  family=note(notes,'source_intent') if sid=='sidzzz07' else note(notes,'scam_type')
  status='QUARANTINED_TAXONOMY' if sid=='financial2025' else 'UNMAPPED_POLARITY' if sid=='ysangam' else 'PENDING_SOURCE_REVIEW'
  if r['conversion']!='none':status+=';VARIANT_UNSURE'
  ledger.append({'id':r['id'],'source_id':sid,'group_id':r['group_id'],'conversion':r['conversion'],'language':r['language'],'author_generator_REPORTED':author,'template_group_from_source':template,'family_from_source':family,'normalized_text_fingerprint':hashlib.sha256(norm(r['text']).encode()).hexdigest(),'assigned_split':'NOT_ASSIGNED','admission_status':status})
  if r['conversion']=='none':counts[(sid,author,template,family)]+=1
csvwrite('AUTHOR_TEMPLATE_SPLIT_LEDGER.csv',ledger)
csvwrite('SOURCE_TEMPLATE_COUNTS.csv',[{'source_id':k[0],'author_generator':k[1],'template_group':k[2],'family':k[3],'original_rows':n,'split':'NOT_ASSIGNED'} for k,n in sorted(counts.items())])
# Inspect established historical SPAM labels without accepting them as trusted new data.
path=ROOT/'sentinel-ml/Messages-ml/data/processed/train.jsonl';spam=[];lc=collections.Counter();sc=collections.Counter()
for r in rows(path):
 label=r.get('security_label',r.get('label','MISSING'));lc[str(label)]+=1
 if label in ('SPAM','SUSPICIOUS_SPAM'):
  spam.append(r);sc[str(r.get('source',r.get('dataset_source','MISSING')))]+=1
evals={};evpaths=[]
for ent in load(PREV/'corpus_audit_manifest.json')['sources']:
 p=ROOT/ent['path']
 if ent['role']=='training' or p.suffix not in ('.csv','.jsonl') or 'sealed' in str(p).lower() or 'url' in p.name.lower():continue
 evpaths.append({'path':ent['path'],'sha256':sha(p)})
 for r in rows(p):
  text=r.get('text',r.get('raw_text',r.get('content','')))
  if isinstance(text,str) and text:evals.setdefault(norm(text),set()).add(ent['path'])
for p in [V1/'probe_set.csv',PREV/'frozen/probe_v2.csv',ROOT/'reports/simulation_diagnosis/20261022_run_02/simulation_messages_v2.jsonl']:
 for r in rows(p):
  text=r.get('text',r.get('raw_text',''))
  if text:evals.setdefault(norm(text),set()).add(p.relative_to(ROOT).as_posix())
keys=list(evals);tt=[frozenset(s.split()) for s in keys];idx=collections.defaultdict(list)
for i,t in enumerate(tt):
 for w in t:idx[w].append(i)
flags=[]
for r in spam:
 n=norm(r.get('raw_text',r.get('text','')));t=frozenset(n.split());hits=[]
 for i,inter in collections.Counter(i for w in t for i in idx[w]).items():
  u=tt[i]
  if min(len(t),len(u))<.85*max(len(t),len(u)):continue
  jac=inter/(len(t)+len(u)-inter)
  if jac>=.85:hits.append({'jaccard':jac,'exact':n==keys[i],'evaluation_files':sorted(evals[keys[i]])})
 flags.append({'id':r.get('id'),'source':r.get('source',r.get('dataset_source','MISSING')),'overlap_flag':bool(hits),'hits':hits})
jsonl('historical_SPAM_overlap.jsonl',flags)
save('historical_SPAM_readiness.json',{'path':str(path),'sha256':sha(path),'training_label_counts':dict(lc),'spam_rows':len(spam),'spam_unique_normalized_texts':len({norm(r.get('raw_text',r.get('text',''))) for r in spam}),'spam_source_counts':dict(sc),'spam_flagged_against_observed_evaluation':sum(r['overlap_flag'] for r in flags),'comparison_files':evpaths,'rows_admitted_now':0,'status':'historically labeled SPAM candidates only; provenance/label/group exclusions still required; no replacement by UNMAPPED or malicious rows'})
allp=list(rows(PREV/'frozen/probe_v2.csv'));raw=collections.defaultdict(list)
for r in allp:raw[(r['language'],r['expected'],r['text'])].append(r['id'])
save('probe_full_uniqueness.json',{'rows':len(allp),'unique_exact_texts':len({r['text'] for r in allp}),'unique_language_label_text_keys':len(raw),'duplicate_groups':[{'language':k[0],'expected':k[1],'text_sha256':hashlib.sha256(k[2].encode()).hexdigest(),'ids':v} for k,v in raw.items() if len(v)>1],'independent_authors':1,'all_probes_evaluation_only':True,'note':'Distinct text count is not independent observation count; original Wilson intervals describe row outcomes only.'})
print('source author-template rows',len(ledger),'template cells',len(counts),'historical SPAM',len(spam),'eval overlap',sum(r['overlap_flag'] for r in flags),'probe unique',len({r['text'] for r in allp}))
