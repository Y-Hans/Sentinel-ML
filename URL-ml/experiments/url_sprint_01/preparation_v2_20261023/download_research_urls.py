from prep_common import *
import urllib.request,urllib.parse,re
RAW=OUT/'sources';ledger=[]
allowed={'api.github.com','raw.githubusercontent.com','data.mendeley.com','api.data.mendeley.com'}
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        p=urllib.parse.urlsplit(newurl);assert p.scheme=='https' and p.hostname in allowed,p.hostname
        return super().redirect_request(req,fp,code,msg,headers,newurl)
opener=urllib.request.build_opener(Redirect)
def get(url,name,license,role,limit=10000000):
    assert urllib.parse.urlsplit(url).hostname in allowed
    p=RAW/name;assert not p.exists()
    r=dict(requested_url=url,local_path=p.relative_to(ROOT).as_posix(),license=license,role=role,started_utc=stamp())
    try:
        with opener.open(urllib.request.Request(url,headers={'User-Agent':'Sentinel-offline-prep/2','Accept':'application/json,text/csv,text/plain'}),timeout=20) as response:
            mime=response.headers.get('Content-Type','');assert 'html' not in mime.lower(),'Refuse website HTML'
            r.update(http_status=response.status,final_url=response.geturl(),content_type=mime,etag=response.headers.get('ETag'),last_modified=response.headers.get('Last-Modified'))
            n=0
            with open(p,'xb') as f:
                for b in iter(lambda:response.read(65536),b''):n+=len(b);assert n<=limit;f.write(b)
            r.update(status='DOWNLOADED',bytes=n,sha256=sha(p))
    except Exception as e:r.update(status='MISSING_DOWNLOAD_FAILED',error=repr(e))
    r['finished_utc']=stamp();ledger.append(r);print(name,r['status'],r.get('bytes',0),r.get('error',''),flush=True)
    return p if r['status']=='DOWNLOADED' else None
# Public publisher frontend metadata only, not a guessed dataset download UUID.
p=get('https://data.mendeley.com/public-api/datasets/c2gw7fy2j4/versions/3','mendeley_public_v3.json','CC-BY-4.0 dataset metadata','Publisher frontend public dataset catalogue',900000)
if p:
    obj=json.loads(read(p))
    # Print only metadata keys; never content/URLs from dataset records.
    print('Mendeley metadata keys',list(obj) if isinstance(obj,dict) else 'list',flush=True)
rev=get('https://api.github.com/repos/JPCERTCC/phishurl-list/commits/main','jpcert_revision.json','No explicit dataset reuse license established; quarantine pending terms review','Official JPCERTCC repository revision',900000)
if rev:
    commit=json.loads(read(rev))['sha'];assert re.fullmatch('[0-9a-f]{40}',commit)
    tree=get(f'https://api.github.com/repos/JPCERTCC/phishurl-list/git/trees/{commit}?recursive=1','jpcert_tree.json','Public repository metadata; data reuse license unestablished','File catalogue, CSV dataset paths only',900000)
    get(f'https://raw.githubusercontent.com/JPCERTCC/phishurl-list/{commit}/README.md','jpcert_README_metadata.txt','Copyright JPCERT/CC; no explicit dataset license stated in README','Source label/column/date definitions; not executable',100000)
    if tree:
        obj=json.loads(read(tree));assert not obj.get('truncated')
        candidates=[x['path'] for x in obj['tree'] if x['type']=='blob' and re.fullmatch(r'2026/[^/]+\.csv',x['path'])]
        print('JPCERT 2026 CSV files',candidates,flush=True)
        for path in sorted(candidates):
            get(f'https://raw.githubusercontent.com/JPCERTCC/phishurl-list/{commit}/{path}','jpcert_'+Path(path).name,'LICENSE_UNESTABLISHED; research intake quarantine, do not train/redistribute','Official JPCERT/CC reported-confirmed phishing URLs and dates, dataset text only',15000000)
js(OUT/'DOWNLOAD_RESEARCH_LEDGER_v2.json',{'time_utc':stamp(),'policy':'Allowlisted publisher metadata and official JPCERT CSV files only. Never request a URL from any dataset. No HTML/DOM bundles or unknown scripts.','files':ledger})
