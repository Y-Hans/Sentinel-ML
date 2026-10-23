from runlib import *
from data_utils import *
import collections,unicodedata
protect()
manifest=jload('freeze_manifest.json'); ms=readrows(OUT/'simulation_messages.jsonl'); us=readrows(OUT/'simulation_urls.jsonl')
corpus=[]; train={}
for d,dirs,names in os.walk(ROOT/'sentinel-ml/Messages-ml'):
    dirs[:]=[x for x in dirs if x not in ('__pycache__','simulation_run_02')]
    for n in names:
        if 'train' in n.lower() and n.endswith('.jsonl'):
            p=Path(d)/n; rr=readrows(p); corpus.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'rows':len(rr)})
            for r in rr: train.setdefault(norm(text(r)),set()).add(p.relative_to(ROOT).as_posix())
tok=[frozenset(k.split()) for k in train]; keys=list(train); inv=collections.defaultdict(set)
for i,t in enumerate(tok):
    for w in t: inv[w].add(i)
for r in ms:
    n=norm(r['text']); ts=frozenset(n.split()); best=1. if n in train else 0.; hit=n if n in train else None
    if best<1:
        ct=collections.Counter(i for w in ts for i in inv.get(w,()))
        for i,c in ct.items():
            if min(len(ts),len(tok[i]))>=.85*max(len(ts),len(tok[i])) and len(ts|tok[i]):
                v=c/len(ts|tok[i])
                if v>best: best=v; hit=keys[i]
    r['overlap_exact']=n in train; r['jaccard_max']=best; r['overlap_flag']=bool(n in train or best>=.85); r['overlap_evidence']={'normalized_sha256':hashlib.sha256((hit or '').encode()).hexdigest(),'corpora':sorted(train.get(hit,set())) if r['overlap_flag'] else []}
def unorm(u): return unicodedata.normalize('NFKC',u).casefold().strip().rstrip('.,;')
uu=set(); dd=set()
for entry in manifest['url_training_sources']:
    with (ROOT/entry['path']).open(encoding='utf-8-sig',newline='') as f:
        for r in csv.DictReader(f):
            u=r.get('url',r.get('URL',''))
            if u: uu.add(unorm(u)); dd.add(domain(u))
ut=[frozenset(re.findall(r'\w+',u)) for u in uu]; ui=collections.defaultdict(set)
for i,ts in enumerate(ut):
    for w in ts: ui[w].add(i)
for r in us:
    ts=frozenset(re.findall(r'\w+',unorm(r['url']))); best=0.; ct=collections.Counter(i for w in ts for i in ui.get(w,()))
    for i,c in ct.items():
        if min(len(ts),len(ut[i]))>=.85*max(len(ts),len(ut[i])) and len(ts|ut[i]): best=max(best,c/len(ts|ut[i]))
    r['overlap_exact']=unorm(r['url']) in uu; r['overlap_jaccard']=best; r['overlap_domain']=domain(r['url']) in dd; r['overlap_flag']=bool(r['overlap_exact'] or best>=.85 or r['overlap_domain'])
jsonl('simulation_messages_v2.jsonl',ms); jsonl('simulation_urls_v2.jsonl',us)
manifest['message_training_corpora']=corpus
for track,rr in [('messages',ms),('urls',us)]: manifest[track].update({'path':'simulation_'+('messages' if track=='messages' else 'urls')+'_v2.jsonl','sha256':sha(OUT/('simulation_'+('messages' if track=='messages' else 'urls')+'_v2.jsonl')),'overlap_rows':sum(r['overlap_flag'] for r in rr)})
manifest['corrections']=['Previous URL overlap used message normalization masking full URLs; invalid URL overlap counts superseded. URL exact now NFKC/casefold/strip with content preserved; Jaccard on word tokens. Domain check unchanged.','Messages inventory broadened startswith(train) to substring train to include every historical training JSONL.','Earlier freeze retained; this final manifest supersedes overlap tags before any model inference. Sealed exam unchanged and not opened.']
jsave('freeze_manifest_v2.json',manifest)
print(json.dumps({'messages':len(ms),'urls':len(us),'message_overlap':sum(r['overlap_flag'] for r in ms),'url_overlap':sum(r['overlap_flag'] for r in us),'message_corpora':len(corpus),'sealed_exam_unchanged':True}))
