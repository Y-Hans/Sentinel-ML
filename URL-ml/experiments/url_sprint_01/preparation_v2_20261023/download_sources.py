"""Only explicitly verified public dataset/metadata endpoints; never IOC URLs."""
from prep_common import *
import urllib.request,urllib.parse,urllib.error,re
RAW=OUT/'sources';RAW.mkdir(exist_ok=True)
ALLOWED={'tranco-list.eu','api.data.mendeley.com','data.mendeley.com','raw.githubusercontent.com','api.github.com','assets.publishing.service.gov.uk'}
ledger=[]
class SourceOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        p=urllib.parse.urlsplit(newurl)
        if p.scheme!='https' or p.hostname not in ALLOWED:raise RuntimeError('Unverified redirect source host: '+str(p.hostname))
        return super().redirect_request(req,fp,code,msg,headers,newurl)
opener=urllib.request.build_opener(SourceOnlyRedirect)
def fetch(url,name,role,license,license_source,maximum=60000000):
    assert urllib.parse.urlsplit(url).hostname in ALLOWED
    target=RAW/name;assert not target.exists()
    item=dict(requested_url=url,local_path=target.relative_to(ROOT).as_posix(),role=role,license=license,license_source=license_source,started_utc=stamp(),authorization='User limited public dataset and metadata download approval, 2026-10-23; NOT model training')
    try:
        req=urllib.request.Request(url,headers={'User-Agent':'Sentinel-offline-data-preparation/2.0','Accept':'application/json,text/csv,text/plain,application/octet-stream'})
        with opener.open(req,timeout=25) as response:
            mime=response.headers.get('Content-Type','');assert 'html' not in mime.lower(),'Refusing website HTML; metadata/dataset only'
            item.update(final_url=response.geturl(),http_status=response.status,content_type=mime,headers={k:response.headers[k] for k in ('Last-Modified','ETag','Content-Length') if k in response.headers})
            h=hashlib.sha256();n=0
            with open(target,'xb') as f:
                for chunk in iter(lambda:response.read(65536),b''):
                    n+=len(chunk);assert n<=maximum,'Source file size bound exceeded'
                    h.update(chunk);f.write(chunk)
            item.update(status='DOWNLOADED',bytes=n,sha256=h.hexdigest(),finished_utc=stamp())
    except Exception as e:
        item.update(status='MISSING_DOWNLOAD_FAILED',error=repr(e),finished_utc=stamp())
        if target.exists():item.update(partial_file_bytes=target.stat().st_size,partial_file_sha256=sha(target),partial_file_not_usable=True)
    ledger.append(item);print(name,item['status'],item.get('bytes',0),item.get('error',''),flush=True)
    return item
TR_LICENSE='Composite upstream attribution/terms: Umbrella free, Majestic CC-BY-3.0, CrUX CC-BY-SA-4.0, Radar CC-BY-NC-4.0, Farsight terms not fully established; research metadata only, product reuse not cleared'
fetch('https://tranco-list.eu/api/lists/id/56Z8N','tranco_56Z8N_metadata.json','official reproducible ranking metadata',TR_LICENSE,'https://tranco-list.eu/?from_column=20421',900000)
fetch('https://tranco-list.eu/download/56Z8N/1000000','tranco_56Z8N_top1m.csv','official domains ranking; never safety labels',TR_LICENSE,'https://tranco-list.eu/?from_column=20421')
fetch('https://assets.publishing.service.gov.uk/media/69cbd582024cdf09254f3f7d/List_of_.gov.uk_domain_names_as_of_31_March_2026_1.csv','govuk_registry_20260331.csv','authoritative .gov.uk registered domains, not endpoint safety','Open Government Licence v3.0; attribution required; registry identity only','https://www.gov.uk/government/publications/list-of-gov-uk-domain-names',2000000)
fetch('https://api.github.com/repos/cisagov/dotgov-data/commits/main','cisagov_revision.json','official registry repository revision metadata','GitHub public repository metadata; dataset CC0-1.0','https://github.com/cisagov/dotgov-data',900000)
rev=next(r for r in ledger if r['local_path'].endswith('cisagov_revision.json'))
if rev['status']=='DOWNLOADED':
    commit=json.loads(read(ROOT/rev['local_path']))['sha'];assert re.fullmatch('[0-9a-f]{40}',commit)
    # The official get.gov data page links cisagov/dotgov-data, whose Raw CSV
    # source was verified before this request. Pin that file to the fetched revision.
    fetch(f'https://raw.githubusercontent.com/cisagov/dotgov-data/{commit}/current-full.csv','cisagov_current_full.csv','authoritative registered .gov domains, not endpoint safety','CC0-1.0','https://github.com/cisagov/dotgov-data/blob/main/LICENSE',10000000)
    fetch(f'https://raw.githubusercontent.com/cisagov/dotgov-data/{commit}/LICENSE','cisagov_LICENSE.txt','dataset license metadata','CC0-1.0','https://github.com/cisagov/dotgov-data/blob/main/LICENSE',100000)
fetch('https://api.data.mendeley.com/datasets/c2gw7fy2j4?version=3','mendeley_c2gw7fy2j4_v3_metadata.json','publisher public research dataset metadata; 2020 collection/2021 release','CC-BY-4.0 dataset; retain author/DOI attribution','https://data.mendeley.com/datasets/c2gw7fy2j4/3',900000)
fetch('https://api.data.mendeley.com/datasets/c2gw7fy2j4/files?version=3','mendeley_c2gw7fy2j4_v3_files.json','publisher public file catalogue; inspect before selecting CSV only','CC-BY-4.0 dataset metadata','https://data.mendeley.com/datasets/c2gw7fy2j4/3',900000)
ledger_name='DOWNLOAD_LEDGER_v2.json' if os.environ.get('URL_PREP_DOWNLOAD_ATTEMPT','01')=='01' else 'DOWNLOAD_LEDGER_v2_attempt02.json'
js(OUT/ledger_name,{'time_utc':stamp(),'request_policy':'Allowlisted official source hosts only; HTTPS; validate redirects; reject HTML; no URL from a dataset is ever requested. No executables/scripts/DOM archives or page content downloaded.','files':ledger})
