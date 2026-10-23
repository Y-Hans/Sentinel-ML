from runlib import *
import ipaddress,unicodedata
from urllib.parse import urlsplit
PSL=ROOT/'sentinel-ml/URL-ml/experiments/phase_1c_2b_2a_s2_f/public_suffix_list.dat'
rules=set(); wild=set(); exceptions=set()
for line in PSL.read_text(encoding='utf-8').splitlines():
    s=line.strip()
    if not s or s.startswith('//'): continue
    if s.startswith('!'): exceptions.add(s[1:])
    elif s.startswith('*.'): wild.add(s[2:])
    else: rules.add(s)
def host(u):
    try: return (urlsplit(u if '://' in u else 'https:'+u if u.startswith('//') else 'https://'+u).hostname or '').lower().rstrip('.')
    except ValueError: return ''
def domain(u):
    h=host(u)
    try: ipaddress.ip_address(h); return h
    except ValueError: pass
    labels=h.split('.'); ns=1
    for i in range(len(labels)):
        suffix='.'.join(labels[i:])
        if suffix in exceptions: ns=len(labels)-i-1; break
        if suffix in rules: ns=max(ns,len(labels)-i)
        if i+1<len(labels) and '.'.join(labels[i+1:]) in wild: ns=max(ns,len(labels)-i)
    return '.'.join(labels[-min(len(labels),ns+1):])
URL_RE=re.compile(r'(?:https?://|//|www\.)[^\s<>"\)\]]+|\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|in|gov|edu|xyz|top|co|io|ly|me|app|game)(?:/[^\s<>"\)\]]*)?',re.I)
def urls(s): return list(dict.fromkeys(m.group().rstrip('.,;!?') for m in URL_RE.finditer(s)))
def script(s):
    blocks=[('Devanagari',0x900,0x97f),('Gujarati',0xa80,0xaff),('Tamil',0xb80,0xbff),('Telugu',0xc00,0xc7f),('Bengali',0x980,0x9ff),('Punjabi',0xa00,0xa7f)]
    for n,a,b in blocks:
        if any(a<=ord(c)<=b for c in s): return n
    return 'Latin' if any(c.isalpha() for c in s) else 'Other'
def language(s):
    sc=script(s)
    if sc=='Devanagari': return 'Hindi_or_Marathi_UNRESOLVED'
    if sc not in ('Latin','Other'): return sc
    if re.search(r'\b(hai|bhai|nahi|kya|kar|aaj|kal|bhej|mat|haan|toh)\b',s,re.I): return 'Hinglish_ASSUMED'
    return 'English_or_other_Latin_UNRESOLVED'
def groupguess(r):
    h=str(r.get('senderDisplayName',r.get('sender_header','')))
    return 'group_INFERRED' if re.search(r'\(\d+ messages?\)|: ~|~\s|\bgroup\b',h,re.I) else 'UNKNOWN'
def form(u):
    if u.startswith('//'): return 'protocol_relative'
    if u.startswith('www.'): return 'schemeless_www'
    if '://' not in u: return 'schemeless_apex_or_path'
    return 'explicit_'+u.split(':')[0]
