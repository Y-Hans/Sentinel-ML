from prep_common import *
import collections
parent={}
def find(x):
    parent.setdefault(x,x)
    while x!=parent[x]:parent[x]=parent[parent[x]];x=parent[x]
    return x
def union(a,b):
    a=find(a);b=find(b)
    if a!=b:parent[max(a,b)]=min(a,b)
families={};boundary=[]
for r in rows(OUT/'candidate_intake_v2.csv'):
    p=r['registrable_domain'];find(p)
    if r['source_id'].startswith(('UK_GDS_','US_CISA_')):
        family=r['source_id']+'|'+r['source_row_id']
        if family in families:union(p,families[family])
        else:families[family]=p
    if p==r['public_suffix']:boundary.append({'id':r['id'],'source':r['source_id'],'domain':p,'rule':r['suffix_rule'],'reason':'PUBLIC_SUFFIX_BOUNDARY_NOT_ORDINARY_REGISTRABLE_HOST; quarantine family, never split guessed www counterpart separately'})
components=collections.defaultdict(set)
for p in list(parent):components[find(p)].add(p)
component_ids={p:hashlib.sha256('|'.join(sorted(ps)).encode()).hexdigest() for ps in components.values() for p in ps}
strict=len(sys.argv)>1 and sys.argv[1]=='strict'
suffix='_STRICT' if strict else ''
representatives={};summary=collections.Counter();component_classes=collections.defaultdict(set);max_rows=collections.Counter();templates=set()
group_rows=[]
for r in rows(OUT/('candidate_strict_dedup_v2.csv' if strict else 'candidate_dedup_v2.csv')):
    c=component_ids[r['registrable_domain']];cl=r['source_reported_class'];component_classes[c].add(cl);max_rows[c]+=1;templates.add(r['template_group'])
    summary[cl]+=1
    k=(c,cl)
    if k not in representatives or r['canonical_url_sha256']<representatives[k]['representative_url_sha256']:
        representatives[k]=dict(component_id=c,source_reported_class=cl,representative_id=r['id'],representative_url_sha256=r['canonical_url_sha256'],registrable_domain=r['registrable_domain'],use='DOMAIN_AUDIT_ONLY_NOT_A_TRAINING_ROW')
    group_rows.append(dict(id=r['id'],registrable_domain=r['registrable_domain'],group_component_id=c,template_group=r['template_group'],source_id=r['source_id'],source_row_id=r['source_row_id'],partition='QUARANTINE_NOT_SPLIT',fit_eligible=0))
csvout(OUT/f'GROUP_MEMBERSHIP_v2{suffix}.csv',group_rows)
csvout(OUT/f'DOMAIN_DEDUP_REPRESENTATIVES_v2{suffix}.csv',representatives.values())
if boundary:csvout(OUT/f'PUBLIC_SUFFIX_BOUNDARY_TRIAGE_v2{suffix}.csv',boundary)
js(OUT/f'GROUPING_COUNTS_v2{suffix}.json',{'status':'OBSERVED grouping audit; no final split','unique_PSL_registrable_domain_keys':len(parent),'connected_parent_components':len(components),'variant_families':len(families),'multi_parent_components':sum(len(v)>1 for v in components.values()),'template_group_count':len(templates),'rows_grouped':len(group_rows),'domain_dedup_representatives_by_reported_class':dict(collections.Counter(r['source_reported_class'] for r in representatives.values())),'cross_class_components':sum(len(c)>1 for c in component_classes.values()),'maximum_dedup_rows_in_one_component':max(max_rows.values()),'public_suffix_boundary_variant_rows':len(boundary),'grouping_rule':'Union all records with the same full-PSL registrable parent; union all four syntactic variants from each authoritative registry source row, including PSL public-suffix boundary cases. Every component must stay in one future partition. Domain-scoped templates remain in the same component; cross-domain campaign links remain unestablished and require source evidence. Do not merge every unrelated / root into one campaign. No final partition until label/license readiness.','public_suffix_boundary_action':'Quarantine these rows/families; authoritative registration and private-suffix roles may differ. Do not assign independent apex/www groups to related variants.'})
print('Grouping',len(parent),'PSL keys ->',len(components),'components;',len(boundary),'public-suffix-boundary variant rows; all partitions quarantine',flush=True)
