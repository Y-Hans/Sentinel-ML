from sprintlib import *
from datetime import datetime,timezone
guard()
rr=list(rows(OUT/'frozen/probe_v2.csv'));tt=[frozenset(norm(r['text']).split()) for r in rr];parent=list(range(len(rr)))
def find(i):
 while parent[i]!=i:parent[i]=parent[parent[i]];i=parent[i]
 return i
near=[]
for i,t in enumerate(tt):
 for j,u in enumerate(tt[:i]):
  if min(len(t),len(u))<.85*max(len(t),len(u)):continue
  v=len(t&u)/len(t|u)
  if v>=.85:near.append({'a':rr[i]['id'],'b':rr[j]['id'],'jaccard':v});parent[find(i)]=find(j)
groups=collections.Counter(find(i) for i in range(len(rr)))
save('intra_probe_audit_audit02.json',{'near_edges':near,'max_component_size':max(groups.values()),'cap':3,'pass':max(groups.values())<=3})
assert max(groups.values())<=3,'near duplicate cap failed before scoring'
urlrx=re.compile(r'https?://\S+|www\.\S+',re.I);phrx=re.compile(r'(?:\+91|0)?[6-9]\d{9}')
assert all(bool(urlrx.search(r['text']))==(r['has_url']=='true') for r in rr)
assert all(bool(phrx.search(r['text']))==(r['has_phone']=='true') for r in rr)
hg=[r for r in rr if r['language']=='Hinglish'];attack=[r for r in hg if r['expected']=='MALICIOUS']
assert sum(r['has_url']=='false' for r in attack)==240
assert all(sum(r['channel_style']=='SMS' for r in hg if r['expected']==lab)==n//2 for lab,n in [('MALICIOUS',600),('BENIGN',400),('SPAM',100)])
# Stream corpus objects; no complete corpus read_text/json.load.
def json_objects(p):
 with p.open(encoding='utf-8-sig') as f:
  stack=[];quoted=False;escape=False
  for line in f:
   for c in line:
    if stack:
     for b in stack:b.append(c)
    if quoted:
     if escape:escape=False
     elif c=='\\':escape=True
     elif c=='"':quoted=False
    elif c=='"':quoted=True
    elif c=='{':stack.append(['{'])
    elif c=='}' and stack:
     buf=stack.pop()
     try:yield json.loads(''.join(buf))
     except ValueError:pass
def texts(p):
 for r in (rows(p) if p.suffix in ('.csv','.jsonl') else json_objects(p)):
  if not isinstance(r,dict):continue
  s=next((r[k] for k in ('raw_text','text','message','content','cleaned_text') if isinstance(r.get(k),str)),None)
  if s:yield s
paths={c['path'] for c in load(OLD/'corpus_audit_manifest.json')['corpora']}
for p in load(OUT/'protected_before.json'):
 if any(part in p for part in ('Messages-ml/','7sep_messages_v3/','6sep/messages/')) and p.endswith(('.jsonl','.csv')) and not any(x in p.lower() for x in ('sealed','vocab','scaler','tree','user_data','datasets_v5')):paths.add(p)
paths.add(str((OLD/'probe_set.csv').relative_to(ROOT)).replace('\\','/'))
sim=ROOT/'reports/simulation_diagnosis/20261022_run_02'
for p in sim.glob('*'):
 if p.suffix in ('.csv','.jsonl') and 'simulation' in p.name and 'sealed' not in p.name.lower():paths.add(p.relative_to(ROOT).as_posix())
source_texts=collections.defaultdict(set);sources=[];skip=[]
for rel in sorted(paths):
 p=ROOT/rel
 if p.suffix=='.json' and p.stat().st_size>=1000000:skip.append({'path':rel,'reason':'JSON >=1MB prohibited by reading limit'});continue
 if any(x in rel.lower() for x in ('sealed','predictions')):continue
 n=0
 for s in texts(p):source_texts[norm(s)].add(rel);n+=1
 sources.append({'path':rel,'sha256':sha(p),'rows':n,'role':'training' if 'train' in p.name.lower() else 'evaluation_or_report'})
keys=list(source_texts);tokens=[frozenset(k.split()) for k in keys];idx=collections.defaultdict(list)
for i,t in enumerate(tokens):
 for w in t:idx[w].append(i)
tags=[]
for r,t in zip(rr,tt):
 hits=[]
 counts=collections.Counter(i for w in t for i in idx.get(w,()))
 for i,inter in counts.items():
  u=tokens[i]
  if min(len(t),len(u))<.85*max(len(t),len(u)):continue
  v=inter/(len(t)+len(u)-inter)
  if v>=.85:hits.append({'jaccard':v,'normalized_exact':norm(r['text'])==keys[i],'sources':sorted(source_texts[keys[i]])})
 tags.append({'id':r['id'],'overlap_flag':bool(hits),'hits':hits})
jsonl('overlap_tags.jsonl',tags)
save('corpus_audit_manifest.json',{'sources':sources,'skipped':skip,'unique_normalized_texts':len(keys),'flagged_rows':sum(t['overlap_flag'] for t in tags),'normalization':'NFKC casefold URL/phone/numeric masking, word tokens, Jaccard >= .85','limitation':'lexical audit only; shared author/context grammar remains; sealed exams unopened'})
save('probe_quality.json',{'hinglish_n':len(hg),'attack_n':len(attack),'URLless_attack_n':240,'phone_regex_matching_n':sum(r['has_phone']=='true' for r in rr),'url_regex_matching_n':sum(r['has_url']=='true' for r in rr),'words_6_30_n':sum(6<=int(r['word_count'])<=30 for r in hg),'words_over30_n':sum(int(r['word_count'])>30 for r in hg),'min_words':min(int(r['word_count']) for r in hg),'max_words':max(int(r['word_count']) for r in hg),'near_max_component':max(groups.values()),'model_scores_seen':False})
write('frozen/probe_v2.sha256',sha(OUT/'frozen/probe_v2.csv')+'  probe_v2.csv\n')
save('freeze_manifest.json',{'frozen_utc':datetime.now(timezone.utc).isoformat(),'files':{n:sha(OUT/n) for n in ['frozen/PROBE_V2_DESIGN.md','frozen/probe_v2.csv','probe_v1_normalized.csv','frozen/REVIEW_SAMPLE_v2.csv','generation_manifest.json','intra_probe_audit_audit02.json','overlap_tags.jsonl']},'models_run':False,'rows':len(rr)})
print('frozen',len(rr),'max near component',max(groups.values()),'corpora',len(sources),'overlap flagged',sum(t['overlap_flag'] for t in tags))
