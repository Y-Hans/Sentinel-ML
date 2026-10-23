from prep_common import *
import re,collections,ipaddress
from urllib.parse import urlsplit,parse_qsl,unquote
from v7_features import canonicalize_url,extract_v7_features
from v8_normalization import extract_parent_domain
PSLPATH=U/'experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat'
class PSL:
    def __init__(self,path):
        self.exact={};self.wild={};self.exceptions={};section='UNKNOWN';self.header=[]
        for line in read(path).splitlines():
            if line.startswith('// VERSION:') or line.startswith('// COMMIT:'):self.header.append(line)
            if 'BEGIN ICANN DOMAINS' in line:section='ICANN'
            if 'BEGIN PRIVATE DOMAINS' in line:section='PRIVATE'
            if not line or line.startswith('//'):continue
            val=line.strip();target=self.exceptions if val.startswith('!') else self.wild if val.startswith('*.') else self.exact
            val=val.removeprefix('!').removeprefix('*.')
            try:val=val.encode('idna').decode('ascii').lower()
            except UnicodeError:raise AssertionError('Invalid PSL rule')
            target[val]=section
    def details(self,host):
        h=host.lower().rstrip('.')
        try:ipaddress.ip_address(h);return dict(parent=h,suffix='',rule='IP',section='IP')
        except ValueError:pass
        try:h=h.encode('idna').decode('ascii')
        except UnicodeError:return dict(parent=h,suffix='',rule='INVALID_IDNA',section='UNKNOWN')
        labels=h.split('.');match=(1,'*','UNKNOWN');exception=None
        for i in range(len(labels)):
            suffix='.'.join(labels[i:]);n=len(labels)-i
            if suffix in self.exceptions:exception=(n-1,'!'+suffix,self.exceptions[suffix]);break
            if suffix in self.exact and n>=match[0]:match=(n,suffix,self.exact[suffix])
            if i>0 and suffix in self.wild and n+1>=match[0]:match=(n+1,'*.'+suffix,self.wild[suffix])
        n,rule,section=exception or match
        return dict(parent='.'.join(labels[-(n+1):]) if len(labels)>n else h,suffix='.'.join(labels[-n:]),rule=rule,section=section)
    def parent(self,h):return self.details(h)['parent']
psl=PSL(PSLPATH)
tests=[('a.b.co.uk','b.co.uk'),('a.tenant.blogspot.com','tenant.blogspot.com'),('x.tenant.github.io','tenant.github.io'),('x.tenant.pages.dev','tenant.pages.dev'),('a.b.ck','a.b.ck'),('x.www.ck','www.ck'),('www.city.kawasaki.jp','city.kawasaki.jp')]
for h,expected in tests:assert psl.parent(h)==expected,(h,psl.details(h))
def parts(u):
    p=urlsplit(canonicalize_url(u));h=(p.hostname or '').lower().rstrip('.');return p,h,psl.details(h)
def urlkey(u):
    p,h,d=parts(u);return h,p.path.rstrip('/') if p.path in ('','/') else p.path,p.query,p.fragment
def urlhash(u):return hashlib.sha256(repr(urlkey(u)).encode()).hexdigest()
def template(u):
    p,h,d=parts(u);path=unquote(p.path).lower()
    path=re.sub(r'[a-f0-9]{8,}|\d+','{id}',path)
    query=','.join(sorted(set(k for k,v in parse_qsl(p.query,keep_blank_values=True))))
    return d['parent']+'|'+path+'|'+query

# Exclusion is metadata-only: no prior labels, scores or thresholds are consulted.
excluded_parents=set();excluded_urls=set();exclusion_counts={}
def exclude_file(p,json_input=False):
    n=0
    if json_input:
        def walk(o):
            if isinstance(o,list):
                for x in o:yield from walk(x)
            elif isinstance(o,dict):
                if isinstance(o.get('url'),str):yield o['url']
                else:
                    for x in o.values():yield from walk(x)
        seq=walk(json.loads(read(p)))
    else:seq=(r.get('url') or r.get('URL') or '' for r in rows(p))
    for u in seq:
        try:
            pp,h,d=parts(u)
            if not h:continue
            excluded_parents.add(d['parent']);excluded_urls.add(urlhash(u));n+=1
        except ValueError:continue
    exclusion_counts[p.relative_to(ROOT).as_posix()]=dict(rows=n,sha256=sha(p))
for name in ('cleaned_dataset.csv','v7_structural_benign.csv','hard_dataset.csv','remediation_hard_negatives_v1.csv','remediation_hard_negatives_v2.csv','remediation_hard_negatives_v3.csv','v6_synthetic_benign.csv'):
    exclude_file(U/'data'/name)
exclude_file(ROOT/'reports/url_sprint_01/probe.csv')
exclude_file(U/'reports/URL_REMEDIATION_ADVERSARIAL_PREDICTIONS.csv')
exclude_file(U/'data/hard_benign_benchmark_500.json',True)
exclude_file(ROOT/'sentinel-ml/android-runtime/golden_test_data/golden_urls_v8.json',True)
js(OUT/'EXCLUSION_LEDGER_v2.json',{'policy':'Exclude every parent in legacy clean pool (train AND validation/test), structural/hard/remediation data, burned probe, golden and 500. Do not reuse any row/parent for a new fit; no performance labels consulted. Private exam overlap must be checked by its independent custodian later.','private_PSL_included':True,'parent_count':len(excluded_parents),'canonical_url_hash_count':len(excluded_urls),'source_inputs':exclusion_counts})

# Official rank prefix is derived from a fully hashed official list, not labelled.
rankpath=OUT/'sources/tranco_56Z8N_top1m.csv';ranked=[]
with open(rankpath,encoding='utf-8-sig',newline='') as f:
    for i,r in enumerate(csv.reader(f),1):
        assert len(r)==2 and int(r[0])==i
        if i>100000:break
        domain=r[1].strip().lower();assert '://' not in domain and '/' not in domain
        ranked.append(dict(domain=domain))
assert len(ranked)==100000 and len({r['domain'] for r in ranked})==100000
csvout(OUT/'tranco_56Z8N_top100k_domains.csv',ranked)
js(OUT/'tranco_prefix_manifest_v2.json',{'status':'OBSERVED official-file prefix extraction; rank is not safety evidence','list_id':'56Z8N','configuration':json.loads(read(OUT/'sources/tranco_56Z8N_metadata.json')),'source_sha256':sha(rankpath),'derived_domains_only_path':(OUT/'tranco_56Z8N_top100k_domains.csv').relative_to(ROOT).as_posix(),'derived_sha256':sha(OUT/'tranco_56Z8N_top100k_domains.csv'),'rows':100000,'transform':'Keep domains from ranks 1..100000, preserve order, remove rank column; no model/policy evaluation or label assignment','terms_status':'COMPOSITE_UPSTREAM_TERMS_REVIEW_REQUIRED_BEFORE_PRODUCT_USE'})

pool=[];source_domain_rows=[]
def candidate(u,cl,source,source_row,license,evidence,derivation='NONE',published_date=''):
    try:p,h,d=parts(u)
    except (ValueError,UnicodeError):return None
    if not h:return None
    root=p.path in ('','/') and not p.query and not p.fragment
    r=dict(id=f'I{len(pool)+1:07d}',url=u,source_reported_class=cl,truth_status=evidence,source_id=source,source_row_id=str(source_row),published_or_confirmed_date=published_date,license_status=license,derivation=derivation,registrable_domain=d['parent'],public_suffix=d['suffix'],suffix_rule=d['rule'],suffix_section=d['section'],host_form='www' if h.startswith('www.') else 'apex' if h==d['parent'] else 'subdomain',url_form='root' if root else 'deep_or_query',template_group=hashlib.sha256(template(u).encode()).hexdigest(),domain_group=hashlib.sha256(d['parent'].encode()).hexdigest(),canonical_url_sha256=urlhash(u),legacy_parent_excluded=int(d['parent'] in excluded_parents),legacy_exact_url_excluded=int(urlhash(u) in excluded_urls),partition='QUARANTINE_NOT_SPLIT',fit_eligible=0,exclusion_reason='REVIEWED_LABEL_AND_LICENSE_PREREQUISITES_NOT_COMPLETE')
    pool.append(r);return r

govsources=[('govuk_registry_20260331.csv','UK_GDS_20260331','OGL-3.0',lambda r:next(iter(r.values())).strip().lower(),'.gov.uk'),('cisagov_current_full.csv','US_CISA_PINNED','CC0-1.0',lambda r:r['Domain name'].strip().lower(),'.gov')]
for name,source,lic,getdomain,ending in govsources:
    p=OUT/'sources'/name;seen=set()
    for i,r in enumerate(rows(p),1):
        domain=getdomain(r)
        if not domain.endswith(ending) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]+',domain) or domain in seen:continue
        seen.add(domain)
        source_domain_rows.append(dict(source_id=source,source_row=i,domain=domain,source_file_sha256=sha(p) if i==1 else '',license=lic,evidence='OBSERVED_OFFICIAL_REGISTRY_IDENTITY_NOT_ENDPOINT_SAFETY'))
        for u,derivation in [('https://'+domain+'/','ASSUMED_HTTPS_APEX_ROOT'),('https://www.'+domain+'/','ASSUMED_WWW_COUNTERPART'),(domain,'ASSUMED_SCHEMELESS_ROOT'),('//'+domain,'ASSUMED_PROTOCOL_RELATIVE_ROOT')]:
            candidate(u,'BENIGN',source,i,lic,'ASSUMED_AUTHORITATIVE_DOMAIN_NAVIGATION_NOT_ADJUDICATED',derivation,'2026-03-31' if source.startswith('UK') else 'pinned_repository_revision')
csvout(OUT/'authoritative_domain_inventory_v2.csv',source_domain_rows)

# These exact trusted source endpoints were downloaded as data/license metadata.
# Do not invent arbitrary government paths or extrapolate a hosted-domain whitelist.
for ledgerfile in ('DOWNLOAD_LEDGER_v2_attempt02.json','DOWNLOAD_RESEARCH_LEDGER_v2.json'):
    obj=json.loads(read(OUT/ledgerfile))
    for item in obj['files']:
        if item['status']!='DOWNLOADED':continue
        n=Path(item['local_path']).name
        if n not in {'govuk_registry_20260331.csv','cisagov_current_full.csv','cisagov_LICENSE.txt','jpcert_README_metadata.txt'}:continue
        candidate(item['final_url'],'BENIGN','OBSERVED_OFFICIAL_SOURCE_TEXT_ENDPOINT',n,item['license'],'PROVISIONAL_TEXT_ENDPOINT_NOT_INDEPENDENT_NAVIGATION_ADJUDICATION','OBSERVED_APPROVED_METADATA_DOWNLOAD',item['finished_utc'][:10])

for p in sorted((OUT/'sources').glob('jpcert_2026*.csv')):
    for i,r in enumerate(rows(p),1):
        u=r.get('URL','').strip()
        if not u:continue
        record=candidate(u,'ATTACK','JPCERTCC_'+p.stem.removeprefix('jpcert_'),i,'UNESTABLISHED_REUSE_LICENSE','REPORTED_JPCERT_CONFIRMED_NOT_RETESTED','NONE',r.get('date',''))
        if record:record['source_brand_description']=r.get('description','')
fields=list(pool[0])+['source_brand_description']
for r in pool:r.setdefault('source_brand_description','')
csvout(OUT/'candidate_intake_v2.csv',pool,fields)
unique={};duplicates=0;conflicts=[]
for r in pool:
    k=r['canonical_url_sha256']
    if k in unique:
        duplicates+=1
        if r['source_reported_class']!=unique[k]['source_reported_class']:conflicts.append(k)
    else:unique[k]=r
dedup=list(unique.values());csvout(OUT/'candidate_dedup_v2.csv',dedup,fields)
rootattacks=[r for r in dedup if r['source_reported_class']=='ATTACK' and r['url_form']=='root']
low=[]
quiet_names=('BrandImpersonationScore','PathSuspiciousWords','QuerySuspiciousWords','PathSuspiciousExtension','QueryRedirect','IsDomainIP','HostPunycode','HasNestedURL','SuspiciousTLD','HasAtSymbol','HasNonAscii','HasPort')
for r in rootattacks:
    f=extract_v7_features(r['url'])
    if all(f[n]==0 for n in quiet_names):low.append(r)
if low:csvout(OUT/'reported_low_signal_malicious_roots_v2.csv',low,fields)
else:write(OUT/'reported_low_signal_malicious_roots_v2.csv',','.join(fields)+'\n')
hosted=[r for r in dedup if r['source_id']=='OBSERVED_OFFICIAL_SOURCE_TEXT_ENDPOINT' and 'githubusercontent.com' in (urlsplit(r['url']).hostname or '')]
if hosted:csvout(OUT/'hosted_text_contrasts_v2.csv',hosted,fields)
domain_classes=collections.defaultdict(set)
for r in dedup:domain_classes[r['registrable_domain']].add(r['source_reported_class'])
stats={'status':'OBSERVED source intake counts; source labels REPORTED or ASSUMED, not independently adjudicated','raw_candidate_rows':len(pool),'raw_class_counts':dict(collections.Counter(r['source_reported_class'] for r in pool)),'canonical_dedup_rows':len(dedup),'canonical_dedup_class_counts':dict(collections.Counter(r['source_reported_class'] for r in dedup)),'canonical_duplicate_excess':duplicates,'unique_registrable_domains':len(domain_classes),'cross_class_domain_count':sum(len(c)>1 for c in domain_classes.values()),'cross_class_exact_url_conflicts':len(set(conflicts)),'dedup_unique_domains_by_class':{c:len({r['registrable_domain'] for r in dedup if r['source_reported_class']==c}) for c in ('BENIGN','ATTACK')},'dedup_class_x_source':[{'class':c,'source':s,'n':n} for (c,s),n in sorted(collections.Counter((r['source_reported_class'],r['source_id']) for r in dedup).items())],'dedup_class_x_host_form':[{'class':c,'host_form':s,'n':n} for (c,s),n in sorted(collections.Counter((r['source_reported_class'],r['host_form']) for r in dedup).items())],'legacy_parent_excluded_rows':sum(int(r['legacy_parent_excluded']) for r in dedup),'legacy_exact_excluded_rows':sum(int(r['legacy_exact_url_excluded']) for r in dedup),'novel_parent_rows_by_class':dict(collections.Counter(r['source_reported_class'] for r in dedup if not r['legacy_parent_excluded'])),'reported_attack_exact_roots':len(rootattacks),'reported_low_signal_attack_roots':len(low),'novel_parent_low_signal_attack_roots':sum(not r['legacy_parent_excluded'] for r in low),'quiet_feature_definition':quiet_names,'hosted_text_contrasts':len(hosted),'training_eligible_rows':0,'adjudicated_trusted_benign_rows':0,'licensed_eligible_confirmed_attack_rows':0,'partition_created':False,'reason':'Official registries are identity evidence, not benign endpoint labels; JPCERT labels are institution-reported but no explicit reuse license established. No final split or fit while those prerequisites and independent exam are missing.'}
js(OUT/'INTAKE_COUNTS_v2.json',stats)
psldiff=[]
for h in sorted({urlsplit(canonicalize_url(r['url'])).hostname or '' for r in dedup}):
    d=psl.details(h);old=extract_parent_domain(h)
    if d['parent']!=old:psldiff.append(dict(host=h,full_psl_parent=d['parent'],v8_fixed_table_parent=old,rule=d['rule'],section=d['section']))
if psldiff:csvout(OUT/'suffix_grouping_differences_v2.csv',psldiff)
js(OUT/'SUFFIX_AUDIT_v2.json',{'status':'OBSERVED offline list and parser tests','path':PSLPATH.relative_to(ROOT).as_posix(),'sha256':sha(PSLPATH),'header':psl.header,'license':'Mozilla Public License 2.0 (observed header)','listed_official_origin':'https://publicsuffix.org/list/public_suffix_list.dat','network_refetch':False,'provenance_limit':'Existing locally stored source reports date/commit; no independent publisher checksum or signature verified this run.','rule_counts':{'exact':len(psl.exact),'wildcards':len(psl.wild),'exceptions':len(psl.exceptions)},'private_rules_included':True,'tests':[{'host':h,'expected_parent':p,'actual':psl.details(h)} for h,p in tests],'candidate_hosts_different_from_v8_short_table':len(psldiff),'grouping_only':'Do not change v7/v8 extractors, normalization or Kotlin. Builtin Python IDNA normalization is grouping metadata, not a feature change; retain original URL.','template_grouping':'Canonical-form variants share a parent. Template IDs include parent plus normalized path/id patterns/query-key set; generic / roots across unrelated domains are not treated as one campaign. Cross-parent campaign identity requires source evidence and is not proved here.'})
print('Intake',len(pool),'raw;',len(dedup),'canonical unique;',len(domain_classes),'parents; reported exact attack roots',len(rootattacks),'low signal',len(low),'novel low signal',stats['novel_parent_low_signal_attack_roots'],'fit eligible 0',flush=True)
