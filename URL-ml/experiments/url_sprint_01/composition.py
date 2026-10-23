from common import *
import collections,re
from urllib.parse import urlsplit
from v7_features import canonicalize_url
from v8_normalization import extract_parent_domain

def summarize(path,invert=False):
    c=collections.Counter();domains=collections.defaultdict(collections.Counter);urlcounts=collections.Counter();sources=collections.Counter();shape=collections.Counter();bad=0
    for r in rows(path):
        fields={k.lower():v for k,v in r.items()};u=fields.get('url','');lab=fields.get('label','')
        if lab not in ('0','1'): c['unmapped_label:'+lab]+=1;continue
        y=1-int(lab) if invert else int(lab);cl='ATTACK' if y else 'BENIGN';c[cl]+=1
        try:
            p=urlsplit(canonicalize_url(u));h=(p.hostname or '').lower().rstrip('.');parent=extract_parent_domain(h)
        except ValueError:bad+=1;continue
        domains[parent][cl]+=1;urlcounts[(u,cl)]+=1
        hostmix='www' if h.startswith('www.') else 'apex' if h==parent else 'other_subdomain'
        pathshape='empty_path' if p.path in ('','/') else 'deep_path' if len([a for a in p.path.split('/') if a])>=3 else 'short_path'
        queryshape='root_query' if p.query and p.path in ('','/') else 'path_query' if p.query else 'no_query'
        schemeform='protocol_relative' if u.startswith('//') else 'schemeless' if '://' not in u else p.scheme
        for dim,value in [('host_mix',hostmix),('path_shape',pathshape),('query_shape',queryshape),('scheme_form',schemeform)]:shape[(cl,dim,value)]+=1
        source=fields.get('datasetsource') or fields.get('source_family') or 'UNREPORTED'
        sources[(cl,source)]+=1
    cross=[d for d,v in domains.items() if len(v)>1]
    return {'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path),'label_mapping':'1-original_label' if invert else 'label directly (0 benign,1 attack)','class_counts':dict(c),'parse_errors':bad,'unique_registrable_domains_approx':len(domains),'cross_class_domain_count':len(cross),'duplicate_domain_excess_rows':sum(sum(v.values())-1 for v in domains.values()),'exact_url_class_duplicate_excess_rows':sum(v-1 for v in urlcounts.values()),'cross_class_exact_url_count':len({u for u,cl in urlcounts if (u,'ATTACK') in urlcounts and (u,'BENIGN') in urlcounts}),'top_domains':[{'domain':d,'class_counts':dict(v),'n':sum(v.values())} for d,v in sorted(domains.items(),key=lambda x:-sum(x[1].values()))[:25]],'source_counts':[{'class':cl,'source':s,'n':n} for (cl,s),n in sorted(sources.items())],'shapes':[{'class':cl,'dimension':dim,'value':v,'n':n} for (cl,dim,v),n in sorted(shape.items())],'per_class_domain_counts':{cl:sum(v.get(cl,0)>0 for v in domains.values()) for cl in ('BENIGN','ATTACK')}}
results=[]
for name in ('cleaned_dataset.csv','data.csv','final_dataset.csv','v7_structural_benign.csv','hard_dataset.csv','remediation_hard_negatives_v1.csv','remediation_hard_negatives_v2.csv','remediation_hard_negatives_v3.csv','v6_synthetic_benign.csv'):
    p=U/'data'/name
    result=summarize(p,name in ('cleaned_dataset.csv','data.csv'));results.append(result)
    print(name,result['class_counts'],'domains',result['unique_registrable_domains_approx'],flush=True)
js(OUT/'data_composition.json',{'status':'OBSERVED counts; dataset label provenance REPORTED, not re-verified truth','method':'CSV DictReader streaming row by row, retain counters only; V8 fixed suffix table approximate registrable groups (not full PSL). Host mix is independent of path shape; hostname apex does not imply empty path. Data files are not assumed disjoint. Original/cleaned labels inverted per existing code; final and authored/structural files use direct labels.','files':results})
csvout(OUT/'data_composition_shapes.csv',({'file':r['path'],**s} for r in results for s in r['shapes']))
csvout(OUT/'data_composition_sources.csv',({'file':r['path'],**s} for r in results for s in r['source_counts']))
sources=[U/'scripts/export_v8_joblib.py',U/'scripts/train_v8_candidates.py']
js(OUT/'training_provenance_limits.json',{'source_hashes':{p.relative_to(ROOT).as_posix():sha(p) for p in sources},'observed_export_behavior':'export_v8_joblib.py wraps frozen V7 base_model with V8 adjudicator and threshold 0.28; it is not a fresh V8 fit. Its smoke-test assertion conflicts with the current closed-phase high-score guard, so do not execute it. train_v8_candidates.py explores additional features and writes existing artifacts; it is neither executed nor adopted.','limitation':'Historical source and file counts do not prove the complete row manifest actually used for the frozen base model. Require a training manifest; do not sum overlapping CSV counts into a claimed independent dataset.'})
