from probe_lib import *
import collections,random,math
protect()
rows=csvread('draft_probe_set.csv');texts=[norm(r['text']) for r in rows];tokens=[frozenset(t.split()) for t in texts];inverted=collections.defaultdict(set)
for i,tt in enumerate(tokens):
    for w in tt:inverted[w].add(i)
parent=list(range(len(rows)))
def find(x):
    while parent[x]!=x:parent[x]=parent[parent[x]];x=parent[x]
    return x
def union(a,b):parent[find(a)]=find(b)
near=[]
for i,tt in enumerate(tokens):
    counts=collections.Counter(j for w in tt for j in inverted[w] if j<i)
    for j,inter in counts.items():
        if min(len(tt),len(tokens[j]))<.85*max(len(tt),len(tokens[j])):continue
        v=inter/len(tt|tokens[j])
        if v>=.85:near.append({'id1':rows[i]['id'],'id2':rows[j]['id'],'jaccard':v,'exact':texts[i]==texts[j]});union(i,j)
components=collections.defaultdict(list)
for i,r in enumerate(rows):components[find(i)].append(r['id'])
save('intra_probe_audit.json',{'source_sha256':sha(OUT/'draft_probe_set.csv'),'near_edges':near,'components_gt1':[v for v in components.values() if len(v)>1],'max_component_size':max(map(len,components.values())),'cap':3,'cap_pass':max(map(len,components.values()))<=3,'normalization':'NFKC casefold; URL/phone/digit masks; Unicode word tokens; token-set Jaccard>=.85, connected components (conservative)'} )
print('near-identical maximum component',max(map(len,components.values())),'edges',len(near),flush=True)
# Corpus discovery deliberately does not visit prohibited dirs or prior sealed-exam output folders.
corpora=[];source_texts={};errors=[]
def records(obj):
    if isinstance(obj,list):
        for x in obj:yield from records(x)
    elif isinstance(obj,dict):
        s=next((obj[k] for k in ('raw_text','text','message','content','cleaned_text') if isinstance(obj.get(k),str)),None)
        if s:yield s
        else:
            for v in obj.values():
                if isinstance(v,(list,dict)):yield from records(v)
bases=[ROOT/'sentinel-ml/Messages-ml',ROOT/'sentinel-ml/7sep_messages_v3',ROOT/'sentinel-ml/6sep/messages',ROOT/'sentinel-ml/android-runtime/messages',ROOT/'sentinel-ml/android-runtime/golden_test_data']
for base in bases:
    for d,dirs,names in os.walk(base):
        dirs[:]=[x for x in dirs if x not in BLOCKED|{'messages_v5_sprint','venv','__pycache__','simulation_run_02','models','model','android','android_assets','artifacts','final'} and not x.startswith('.')]
        for name in names:
            p=Path(d)/name
            if p.suffix not in ('.jsonl','.json','.csv') or any(t in name.lower() for t in ('vocab','scaler','trees','portable','sealed','config','manifest','taxonomy','schema')):continue
            if p.stat().st_size>30000000:errors.append({'path':p.relative_to(ROOT).as_posix(),'reason':'oversized non-JSONL/unknown corpus; not opened'});continue
            try:
                if p.suffix=='.jsonl':rr=readjsonl(p)
                elif p.suffix=='.csv':
                    with p.open(encoding='utf-8-sig',newline='') as f:rr=list(csv.DictReader(f))
                else:rr=json.loads(p.read_text(encoding='utf-8-sig'))
                ss=list(records(rr))
                if not ss:continue
                role='training' if 'train' in name.lower() else 'evaluation_or_reported_examples'
                rel=p.relative_to(ROOT).as_posix();corpora.append({'path':rel,'sha256':sha(p),'text_rows':len(ss),'role':role})
                for s in ss:source_texts.setdefault(norm(s),set()).add(rel)
            except Exception as e:errors.append({'path':p.relative_to(ROOT).as_posix(),'error':repr(e)})
keys=list(source_texts);tok=[frozenset(k.split()) for k in keys];idx=collections.defaultdict(set)
for i,t in enumerate(tok):
    for w in t:idx[w].add(i)
tags=[]
for ri,r in enumerate(rows):
    t=tokens[ri];n=texts[ri];best=1. if n in source_texts else 0.;hit=n if best else None
    if not best:
        counts=collections.Counter(i for w in t for i in idx.get(w,()))
        for i,c in counts.items():
            if min(len(t),len(tok[i]))<.85*max(len(t),len(tok[i])):continue
            v=c/len(t|tok[i])
            if v>best:best=v;hit=keys[i]
    tags.append({'id':r['id'],'overlap_flag':bool(n in source_texts or best>=.85),'normalized_exact':n in source_texts,'jaccard_max':best,'matched_corpora':sorted(source_texts.get(hit,())) if best>=.85 else [],'intra_near_component_size':len(components[find(ri)]),'intra_near_flag':len(components[find(ri)])>1})
jsonl('overlap_tags.jsonl',tags);save('corpus_audit_manifest.json',{'corpora':corpora,'unique_normalized_texts':len(keys),'unsupported_or_errors':errors,'rows_tagged':len(tags),'cross_corpus_flagged':sum(t['overlap_flag'] for t in tags),'excluded_prohibited_paths':['datasets_v5','user_data'],'sealed_exam_accessed':False,'training_files':sum(c['role']=='training' for c in corpora),'limitation':'conservative text-bearing evaluation/report superset; semantic paraphrase/source lineage not certified'})
blind={r['blind_id']:r for r in csvread('blind_classification.csv')};idmap=load('blind_id_map.json');byid={r['id']:r for r in rows};disagreements=[]
for bid,b in blind.items():
    r=byid[idmap[bid]]
    if b['blind_label']!=r['expected']:disagreements.append({**r,**b})
csvwrite('blind_disagreements.csv',disagreements,fields=list(rows[0])+['blind_id','blind_label','blind_rationale']);save('blind_QA_summary.json',{'rows':len(rows),'disagreements':len(disagreements),'original_labels_changed':0,'blind_output_sha256':sha(OUT/'blind_classification.csv'),'method':'join performed after independent file-level blind classification; disagreements preserved for user review','independent_human_review':False})
rng=random.Random(202610221);sample=[]
for label,n in [('MALICIOUS',50),('BENIGN',50),('SPAM',25)]:sample+=rng.sample([r for r in rows if r['expected']==label and r['language']=='Hinglish'],n)
chosen={r['id'] for r in sample};sample += [byid[r['id']] for r in disagreements if r['id'] not in chosen]
bymap={idmap[b]:v for b,v in blind.items()};review=[]
for r in sample:review.append({**r,'blind_label':bymap[r['id']]['blind_label'],'blind_rationale':bymap[r['id']]['blind_rationale'],'user_agree':'','user_note':''})
csvwrite('REVIEW_SAMPLE.csv',review);save('review_sample_manifest.json',{'base_samples':{'MALICIOUS':50,'BENIGN':50,'SPAM':25},'blind_disagreement_rows':len(disagreements),'rows_after_union':len(review),'user_fields_blank':True,'sha256':sha(OUT/'REVIEW_SAMPLE.csv')})
print('cross corpus',sum(t['overlap_flag'] for t in tags),'training files',sum(c['role']=='training' for c in corpora),'blind disagreements',len(disagreements),'review rows',len(review),flush=True)
