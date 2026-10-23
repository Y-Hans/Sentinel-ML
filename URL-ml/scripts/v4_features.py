"""Deterministic, domain-independent V4 URL representation.

The extractor intentionally keeps the historical 15 scalars and adds structural
families. Character features are emitted as hashing tokens so the vocabulary
cannot memorize a complete host and remains Kotlin-portable in principle.
"""
from __future__ import annotations
import ipaddress, math, re
from collections import Counter
from urllib.parse import unquote, urlsplit
import numpy as np
from url_features import FULL_FEATURES, extract_url_features

DETERMINISTIC_FEATURES = list(FULL_FEATURES)
_SUSP_EXT = (".exe", ".scr", ".zip", ".apk", ".js", ".html", ".php")

def _parts(url):
    raw = str(url).strip(); p = urlsplit(raw if "://" in raw else "//" + raw, scheme="http")
    host = (p.hostname or "").lower().rstrip("."); path=p.path or ""; query=p.query or ""
    return raw,p,host,path,query

def _stats(values, prefix):
    a=np.asarray(values,dtype=float)
    if not len(a): return {prefix+"_mean":0.,prefix+"_max":0.,prefix+"_min":0.,prefix+"_var":0.}
    return {prefix+"_mean":float(a.mean()),prefix+"_max":float(a.max()),prefix+"_min":float(a.min()),prefix+"_var":float(a.var())}

def _density(s, pred): return float(sum(pred(c) for c in s)/max(1,len(s)))
def _entropy(s):
    if not s:return 0.
    c=Counter(s); n=len(s)
    return float(-sum((v/n)*math.log2(v/n) for v in c.values()))
def _encoded(s): return len(re.findall(r"%[0-9a-fA-F]{2}",s))

def deterministic_v4(url, families=("host","path","query","interactions")):
    raw,p,host,path,query=_parts(url); out=extract_url_features(url,FULL_FEATURES)
    labels=[x for x in host.split(".") if x]; seg=[x for x in path.split("/") if x]
    if "host" in families:
        lens=[len(x) for x in labels]; chars=host
        out.update({"host_length":len(host),"host_labels":len(labels),"host_max_label":max(lens,default=0),
          "host_digit_count":sum(c.isdigit() for c in chars),"host_digit_density":_density(chars,str.isdigit),
          "host_alpha_density":_density(chars,str.isalpha),"host_hyphen_count":chars.count("-"),
          "host_hyphen_density":chars.count("-")/max(1,len(chars)),"host_underscore_count":chars.count("_"),
          "host_entropy":_entropy(chars),"host_numeric_labels":sum(x.isdigit() for x in labels),
          "host_numeric_label_ratio":sum(x.isdigit() for x in labels)/max(1,len(labels)),
          "host_punycode":float("xn--" in host),"host_encoded":float(_encoded(host)>0),
          "host_repeated_char":sum(v for v in Counter(chars).values() if v>1)/max(1,len(chars)),
          "host_vowel_density":_density(chars,lambda c:c in "aeiou"),"host_ip_v4":float(_is_ip4(host)),
          "host_ip_v6":float(":" in host and _is_ip(host))})
        out.update(_stats(lens,"host_label_length"))
    if "path" in families:
        lens=[len(x) for x in seg]; decoded=unquote(path); allp=path
        out.update({"path_length":len(path),"path_depth":path.count("/"),"path_segments":len(seg),
          "path_digit_density":_density(allp,str.isdigit),"path_alpha_density":_density(allp,str.isalpha),
          "path_symbol_density":_density(allp,lambda c:not c.isalnum()),"path_numeric_segments":sum(x.isdigit() for x in seg),
          "path_numeric_ratio":sum(x.isdigit() for x in seg)/max(1,len(seg)),"path_empty_segments":path.count("//"),
          "path_repeated_segments":len(seg)-len(set(seg)),"path_entropy":_entropy(decoded),
          "path_encoded_count":_encoded(path),"path_encoded_density":_encoded(path)/max(1,len(path)),
          "path_delim_count":sum(path.count(x) for x in "-_._;,@"),
          "path_suspicious_extension":float(any(path.lower().endswith(x) for x in _SUSP_EXT)),
          "path_file_like":float(bool(re.search(r"/[^/]+\.[a-z0-9]{1,6}(?:/|$)",path.lower()))),
          "path_decoded_length":len(decoded)})
        out.update(_stats(lens,"path_segment_length"))
    if "query" in families:
        params=query.split("&") if query else []; names=[]; vals=[]
        for item in params:
            n,v=(item.split("=",1)+[""])[:2] if "=" in item else (item,""); names.append(n); vals.append(v)
        out.update({"query_present":float(bool(query)),"query_params":len(params),"query_unique_params":len(set(names)),
          "query_max_param_length":max((len(x) for x in params),default=0),"query_delimiter_count":sum(query.count(x) for x in "=&;%"),
          "query_equals":query.count("="),"query_ampersand":query.count("&"),"query_semicolon":query.count(";"),
          "query_encoded_count":_encoded(query),"query_encoded_density":_encoded(query)/max(1,len(query)),
          "query_empty_params":sum(not x for x in params),"query_repeated_params":len(names)-len(set(names)),
          "query_numeric_ratio":sum(x.isdigit() for x in vals)/max(1,len(vals)),"query_entropy":_entropy(query),
          "query_long_value":float(max((len(x) for x in vals),default=0)>=64)})
        out.update(_stats([len(x) for x in names],"query_name_length")); out.update(_stats([len(x) for x in vals],"query_value_length"))
    if "interactions" in families:
        hc=out.get("host_length",len(host)); hd=out.get("host_entropy",_entropy(host)); pd=out.get("path_depth",path.count("/")); ql=len(query)
        out.update({"ix_http_path_depth":float(p.scheme.lower()=="http")*pd,"ix_http_host_complexity":float(p.scheme.lower()=="http")*hc,
          "ix_http_query_complexity":float(p.scheme.lower()=="http")*ql,"ix_path_host_entropy":pd*hd,
          "ix_path_host_length":pd*hc,"ix_query_host_complexity":ql*hc,"ix_numeric_host_deep_path":float(_is_ip(host))*pd,
          "ix_numeric_path_deep_path":out.get("path_numeric_ratio",0.)*pd,"ix_encoded_query_long_url":float(_encoded(query)>0)*len(raw),
          "ix_suspicious_http":out.get("HasSuspiciousWords",0.)*float(p.scheme.lower()=="http"),"ix_subdomain_path_depth":out.get("NoOfSubDomain",0.)*pd})
    return out

def _is_ip(host):
    try: ipaddress.ip_address(host); return True
    except ValueError:return False
def _is_ip4(host):
    try:return isinstance(ipaddress.ip_address(host),ipaddress.IPv4Address)
    except ValueError:return False

def char_tokens(url, scope):
    raw,p,host,path,query=_parts(url); text={"full":raw,"host":host,"path":path,"query":query}[scope].lower()
    text=re.sub(r"\d+","#",text); text=re.sub(r"\s+"," ",text)
    for n in (3,4,5):
        for i in range(max(0,len(text)-n+1)): yield f"{scope}_{n}_{text[i:i+n]}"

def vectorize_deterministic(urls, families):
    rows=[deterministic_v4(u,families) for u in urls]; names=sorted(set().union(*(r.keys() for r in rows)))
    return np.asarray([[r.get(n,0.) for n in names] for r in rows],dtype=np.float32),names
