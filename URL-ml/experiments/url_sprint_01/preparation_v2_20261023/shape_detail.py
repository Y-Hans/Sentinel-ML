from prep_common import *
import collections
from urllib.parse import urlsplit
from v7_features import canonicalize_url
from v8_normalization import extract_parent_domain
out=[]
for name in ('cleaned_dataset.csv','v7_structural_benign.csv'):
    c=collections.Counter()
    for r in rows(U/'data'/name):
        benign=(r['label']=='1') if name=='cleaned_dataset.csv' else r['label']=='0'
        if not benign:continue
        p=urlsplit(canonicalize_url(r['url']));h=p.hostname or '';parent=extract_parent_domain(h)
        host='www' if h.startswith('www.') else 'apex_host' if h==parent else 'subdomain'
        shape='empty_root_no_query' if p.path in ('','/') and not p.query else 'root_query' if p.path in ('','/') else 'path_no_query' if not p.query else 'path_and_query'
        c[(host,shape)]+=1
    out.extend(dict(file=name,reported_class='BENIGN',host_shape=h,page_shape=s,n=n) for (h,s),n in sorted(c.items()))
js(OUT/'BENIGN_HOST_VS_PAGE_SHAPE_v2.json',{'status':'OBSERVED counters, dataset labels REPORTED','counts':out,'definitions':'apex_host means host==V8 normalizer parent, regardless of path. empty_root_no_query is empty or / path and empty query, regardless of host. Do not interchange these cohorts. Fixed feature suffix handling remains unchanged; full PSL grouping is separately audited.'})
print(out,flush=True)
