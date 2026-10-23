from preplib import *
guard()
inventory=load(OUT/'B_original_source_inventory.json')['sources'];originals=[]
for sid,s in inventory.items():
 p=B/'normalized'/f'{sid}.jsonl';assert sha(p)==s['sha256']
 originals.extend(r for r in rows(p) if r['conversion']=='none')
keys={};meta=collections.defaultdict(list)
def put(text,m):
 n=norm(text)
 if n not in keys:keys[n]=len(keys)
 meta[n].append(m)
for r in originals:put(r['text'],{'role':'B_original','source_id':r['source_id'],'id':r['id'],'group_id':r['group_id'],'label':r['mapped_class']})
training=load(PREV/'sender_training_files.json');sourcecounts=[]
for ent in training:
 p=ROOT/ent['path']
 if p.suffix not in ('.jsonl','.csv'):continue
 n=0
 for r in rows(p):
  text=r.get('raw_text',r.get('text',''))
  if not text:continue
  put(text,{'role':'historical_training','path':ent['path'],'id':str(r.get('id',n)),'label':r.get('security_label',r.get('label','MISSING'))});n+=1
 sourcecounts.append({'path':ent['path'],'sha256':sha(p),'rows':n})
evalpaths=[V1/'probe_set.csv',PREV/'frozen/probe_v2.csv',ROOT/'reports/simulation_diagnosis/20261022_run_02/simulation_messages_v2.jsonl']
for ent in load(PREV/'corpus_audit_manifest.json')['sources']:
 p=ROOT/ent['path']
 if ent['role']!='training' and p.suffix in ('.csv','.jsonl') and 'sealed' not in str(p).lower() and 'url' not in p.name.lower():evalpaths.append(p)
for p in sorted(set(evalpaths)):
 n=0
 for r in rows(p):
  text=r.get('raw_text',r.get('text',r.get('content','')))
  if not isinstance(text,str) or not text:continue
  put(text,{'role':'evaluation','path':p.relative_to(ROOT).as_posix(),'id':str(r.get('id',n)),'label':r.get('expected',r.get('security_label',r.get('label','MISSING')))});n+=1
 sourcecounts.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'rows':n})
strings=list(keys);tokens=[frozenset(n.split()) for n in strings];inv=collections.defaultdict(list)
for i,t in enumerate(tokens):
 for w in t:inv[w].append(i)
matches=[];counts=collections.Counter();summary=collections.defaultdict(collections.Counter)
for ri,r in enumerate(originals):
 n=norm(r['text']);t=frozenset(n.split());candidates=collections.Counter(i for w in t for i in inv[w]);flags=set()
 for i,inter in candidates.items():
  u=tokens[i]
  if min(len(t),len(u))<.85*max(len(t),len(u)):continue
  jac=inter/(len(t)+len(u)-inter)
  if jac<.85:continue
  for m in meta[strings[i]]:
   if m['role']=='B_original' and m['source_id']==r['source_id']:continue
   typ=m['role'];flags.add(typ)
   matches.append({'source_id':r['source_id'],'id':r['id'],'group_id':r['group_id'],'expected_label':r['mapped_class'],'match_role':typ,'match_source':m.get('source_id',m.get('path')),'match_id':m['id'],'match_label':m['label'],'normalized_exact':n==strings[i],'jaccard':jac})
 for typ in flags:summary[r['source_id']][typ]+=1
 if ri%1000==0:print('audited',ri,'/',len(originals),flush=True)
jsonl('overlap_matches.jsonl',matches)
save('overlap_summary.json',{'rows_audited':len(originals),'unique_index_texts':len(strings),'matching_pairs':len(matches),'flagged_rows_by_source':{s:dict(v) for s,v in summary.items()},'comparison_sources':sourcecounts,'method':'NFKC casefold; URL/phone/numeric masks; normalized exact or token-set Jaccard>=.85; B original-vs-other source, historic training, and observed evaluation JSONL/CSV','variants':'No extra independent rows; all groups must inherit any source-original overlap exclusion; conversion text still needs post-handoff exact/fuzzy audit before use','hardneg_overlap':'UNPROVEN missing file','sealed_exam':'not accessed','new_source_admission':False,'limitation':'lexical resemblance is not lineage proof; known training lineage may evade lexical search; skip JSON audit documents to respect read/stream contract'})
print('pairs',len(matches),'source flags',{s:dict(v) for s,v in summary.items()})
