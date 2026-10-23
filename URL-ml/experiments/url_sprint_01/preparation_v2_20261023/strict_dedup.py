from prep_common import *
import collections
from v7_features import canonicalize_url
selected={};n=0;conflicts=set();parentclasses=collections.defaultdict(set)
for r in rows(OUT/'candidate_intake_v2.csv'):
    n+=1
    # Preserve the actual frozen canonicalization contract, including scheme,
    # authority/port/userinfo and empty-vs-slash path length. Coarser host/path
    # matching remains only a conservative leakage/grouping diagnostic.
    key=hashlib.sha256(canonicalize_url(r['url']).encode()).hexdigest()
    r['transport_preserving_url_sha256']=key
    r['dedup_contract']='frozen_v7_canonicalize_url_raw_string; scheme_port_userinfo_query_retained'
    if key in selected:
        if r['source_reported_class']!=selected[key]['source_reported_class']:conflicts.add(key)
    else:selected[key]=r
for r in selected.values():parentclasses[r['registrable_domain']].add(r['source_reported_class'])
csvout(OUT/'candidate_strict_dedup_v2.csv',selected.values())
representatives={}
for r in selected.values():representatives.setdefault((r['registrable_domain'],r['source_reported_class']),r['id'])
js(OUT/'STRICT_DEDUP_COUNTS_v2.json',{'status':'OBSERVED; primary row-dedup census for readiness reports','raw_rows':n,'canonical_contract_distinct_rows':len(selected),'class_counts':dict(collections.Counter(r['source_reported_class'] for r in selected.values())),'canonical_duplicate_excess':n-len(selected),'unique_parent_keys':len(parentclasses),'parent_representatives_by_class':dict(collections.Counter(c for p,c in representatives)),'cross_class_exact_conflicts':len(conflicts),'novel_parent_rows_by_class':dict(collections.Counter(r['source_reported_class'] for r in selected.values() if not int(r['legacy_parent_excluded']))),'fit_eligible_rows':0,'dedup_definition':'Hash the frozen canonicalize_url string, preserving scheme, port, userinfo, query and empty-vs-slash length. No feature changes. Published raw records remain in candidate_intake_v2.csv.','earlier_diagnostic_correction':'candidate_dedup_v2.csv/INTAKE_COUNTS_v2.json used a coarser host/path/query/fragment equivalence that omitted scheme/port/userinfo and merged empty vs / roots. Its 71208 count is a near-duplicate/leakage diagnostic, NOT exact canonical URL identity. Use this strict file for row census; never use the coarser signature to erase transport/authority distinctions in a future training pool. No fit/split/score was based on either.'})
print('Strict frozen-contract dedup',n,'raw ->',len(selected),'distinct;',dict(collections.Counter(r['source_reported_class'] for r in selected.values())),'fit eligible 0',flush=True)
