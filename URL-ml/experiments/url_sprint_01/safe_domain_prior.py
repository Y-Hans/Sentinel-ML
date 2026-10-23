"""PROVISIONAL offline policy; frozen 67-feature models remain untouched."""
import re, ipaddress
from urllib.parse import urlsplit, unquote, parse_qsl
from v7_features import canonicalize_url, extract_v7_features
from v8_classifier import DEV_DOMAINS, GAMING_DOMAINS, MEDIA_DOMAINS, DOCS_DOMAINS, SEARCH_DOMAINS, PAYLOAD_EXTENSIONS

CURATED=set().union(DEV_DOMAINS,GAMING_DOMAINS,MEDIA_DOMAINS,DOCS_DOMAINS,SEARCH_DOMAINS)
# User-provided platform examples: identity and ownership still require review.
EXAMPLE_DOMAINS={'claude.ai','instagram.com'}
TENANT_SUFFIXES={'github.io','gitlab.io','firebaseapp.com','pages.dev','blogspot.com','web.app','netlify.app','vercel.app','herokuapp.com','azurewebsites.net','workers.dev','weebly.com','wordpress.com','wixsite.com','readthedocs.io'}
TENANT_HOSTS={'docs.google.com','forms.google.com','drive.google.com','forms.gle','bit.ly','t.co','tinyurl.com','aka.ms','amzn.to','youtu.be','dropbox.com','notion.so','sites.google.com','storage.googleapis.com','raw.githubusercontent.com','gist.github.com','githubusercontent.com'}
PUBLIC_CONTENT={'github.com','gitlab.com','bitbucket.org','youtube.com','instagram.com','twitch.tv','vimeo.com','soundcloud.com','dailymotion.com','stackoverflow.com','wikipedia.org','itch.io','steamcommunity.com','roblox.com'}
PAYLOAD=set(PAYLOAD_EXTENSIONS)|{'.zip','.7z','.rar','.deb','.rpm','.pkg','.appx','.xpi','.crx','.com','.pif','.hta'}
CREDS=re.compile(r'(password|passwd|credential|signin|login|verify|verification|otp|kyc|seedphrase|recoveryphrase|authenticate|walletconnect)')

def decode(s):
    for _ in range(4):
        n=unquote(s)
        if n==s: break
        s=n
    return s

def registry_rows(tranco_rows=None):
    # Tranco file is domains only, in ranking order. Mere membership never
    # supplies a page-shape permission. No reputation service is contacted.
    result={d:dict(domain=d,rank=None,source='OBSERVED curated v8_classifier.py domain membership') for d in sorted(CURATED)}
    for d in EXAMPLE_DOMAINS: result[d]=dict(domain=d,rank=None,source='PROVISIONAL user platform example')
    if tranco_rows:
        for rank,d in enumerate(tranco_rows,1):
            result[d]=dict(domain=d,rank=rank,source='REPORTED user-supplied Tranco CSV order; no endpoint safety claim')
    return result

def classify(url,raw_p,adjudicated_p,registry=None):
    registry=registry if registry is not None else registry_rows()
    p=urlsplit(canonicalize_url(url)); h=(p.hostname or '').lower().rstrip('.')
    text=decode(p.path+'?'+p.query+'#'+p.fragment).lower()
    path=decode(p.path).lower(); compact=re.sub(r'[^a-z0-9]','',text)
    reasons=[]
    # Check decoded original spelling and a separator-normalized path. Restrict
    # extension boundaries so .com in arbitrary nested domains is not a payload.
    if any(re.search(re.escape(ext)+r'(?:$|[/?&#;=\s])',text) for ext in PAYLOAD): reasons.append('payload_extension')
    if CREDS.search(compact): reasons.append('credential_path_or_query')
    if re.search(r'https?://|https?:|(?:^|[=&])//',decode(p.query).lower()) or re.search(r'https?://',decode(p.path).lower()): reasons.append('nested_or_redirect_target')
    if re.search(r'(redirect|return_to|next|dest|target|url|link)\s*=',decode(p.query).lower()) and '//' in text: reasons.append('redirect_parameter')
    try: ipaddress.ip_address(h); reasons.append('raw_ip')
    except ValueError: pass
    if 'xn--' in h or any(ord(c)>127 for c in h): reasons.append('punycode_or_idn')
    f=extract_v7_features(url)
    if f['BrandImpersonationScore']>0: reasons.append('brand_lookalike')
    # Leet exact labels must also override: the 67-feature brand extractor can
    # identify leet-normalized brands as known, suppressing impersonation.
    from v7_features import COMMON_BRANDS, LEET_TRANSLATION
    for label in h.split('.'):
        translated=label.translate(LEET_TRANSLATION)
        if translated!=label and translated in COMMON_BRANDS: reasons.append('leet_brand_lookalike')
    if reasons: return dict(state='KNOWN_THREAT_PATTERN',score=max(float(adjudicated_p),.95),discount=0.,reason=';'.join(sorted(set(reasons))))
    tenant=(h in TENANT_HOSTS or any(h==s or h.endswith('.'+s) for s in TENANT_SUFFIXES) or any(h==d or h.endswith('.'+d) for d in TENANT_HOSTS) or (h.removeprefix('www.') in PUBLIC_CONTENT and p.path not in ('','/')))
    shape=False
    base=h.removeprefix('www.')
    exact=(h==base or h=='www.'+base) and base in registry
    # Safe registry roots get no wildcard subdomain permission.
    if exact and not tenant and not p.username and p.port in (None,443) and p.scheme=='https' and not p.fragment:
        if p.path in ('','/') and not p.query: shape=True
        elif base=='claude.ai' and re.fullmatch(r'/chat/[a-zA-Z0-9-]{4,64}/?',p.path) and not p.query: shape=True
        elif base in SEARCH_DOMAINS and p.path in ('','/','/search','/search/'):
            qs=parse_qsl(p.query,keep_blank_values=True)
            shape=bool(qs) and all(k in {'q','hl','source'} and len(v)<=120 for k,v in qs) and any(k=='q' for k,v in qs)
        elif base in DOCS_DOMAINS and not p.query and re.fullmatch(r'/(wiki/[a-zA-Z0-9_-]+|abs/\d+\.\d+|downloads/|about/?)',p.path): shape=True
    extra_risk=any(f[n]>0 for n in ('HasPort','HasAtSymbol','HasNestedURL','PathDoubleEncoded','PathConsecutiveSlashes','PathTraversalCount','HasNonAscii','SuspiciousTLD'))
    if shape and not extra_risk:
        adjusted=max(0.,float(adjudicated_p)-.25)
        return dict(state='KNOWN_SAFE_SHAPE',score=adjusted,discount=float(adjudicated_p)-adjusted,reason='exact_registry_host_and_allowlisted_shape;bounded_0.25')
    high=extra_risk or float(adjudicated_p)>=.28
    return dict(state='UNKNOWN_HIGH_RISK' if high else 'UNKNOWN_LOW_RISK',score=float(adjudicated_p),discount=0.,reason='tenant_no_discount' if tenant else 'no_registered_shape_or_remaining_risk')
