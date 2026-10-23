from runlib import *
import collections, datetime, io, math, sqlite3, struct, tarfile, zipfile
protect()
SCHEMA=['id','recordType','source','senderDisplayName','senderIdentifier','content','riskLevel','riskScore','explanation','recommendation','timestamp']
def vint(b,i):
    v=0
    for k in range(9):
        x=b[i+k]
        if k==8: return (v<<8)|x,i+9
        v=(v<<7)|(x&127)
        if x<128: return v,i+k+1
    raise ValueError('varint')
def record(b,i,end):
    n,j=vint(b,i); he=i+n
    if he>end or n<1: raise ValueError('header')
    ss=[]
    while j<he: s,j=vint(b,j); ss.append(s)
    if j!=he: raise ValueError('serial header')
    vals=[]; d=he
    for s in ss:
        n=0
        if s==0: v=None
        elif s in (8,9): v=s-8
        elif 1<=s<=6:
            n={1:1,2:2,3:3,4:4,5:6,6:8}[s]; v=int.from_bytes(b[d:d+n],'big',signed=True)
        elif s==7: n=8; v=struct.unpack('>d',b[d:d+8])[0]
        elif s>=12:
            n=(s-12)//2; v=b[d:d+n].decode('utf-8','strict') if s%2 else b[d:d+n].hex()
        else: raise ValueError('reserved')
        d+=n
        if d>end: raise ValueError('overflow')
        vals.append(v)
    return vals
def scan(b):
    ps=int.from_bytes(b[16:18],'big'); ps=65536 if ps==1 else ps
    found=[]; errors=[]; cells=0
    for page in range(len(b)//ps):
        base=page*ps; off=base+(100 if page==0 else 0)
        if b[off]!=13: continue
        nc=int.from_bytes(b[off+3:off+5],'big')
        if nc>ps//2: continue
        for c in range(nc):
            cells+=1; ptr=int.from_bytes(b[off+8+2*c:off+10+2*c],'big'); start=base+ptr
            try:
                size,j=vint(b,start); rowid,j=vint(b,j)
                vv=record(b,j,min(base+ps,j+size))
                if len(vv)==11 and re.fullmatch(r'[0-9a-fA-F-]{36}',str(vv[0])) and vv[1] in ('SCAN_RESULT','THREAT_EVENT','THREAT_DETECTED','NOTIFICATION') and isinstance(vv[10],int) and 1500000000000<vv[10]<2000000000000 and isinstance(vv[5],str):
                    rr=dict(zip(SCHEMA,vv)); rr['_page']=page+1; rr['_rowid']=rowid; found.append(rr)
            except Exception as e: errors.append({'page':page+1,'cell':c,'error':str(e)})
    return found,{'leaf_cells_seen':cells,'parse_errors':errors,'valid_threat_rows':len(found),'completeness':'PROVISIONAL; table-root count/SQLite validation recorded separately'}
def sqlite_probe(b,prefix):
    # Exact recovered bytes preserved; a separate NEW standalone view removes WAL journal flags only.
    p=OUT/(prefix+'.recovered.db'); p.open('xb').write(b)
    views=[('exact',b),('standalone_header',b[:18]+b'\x01\x01'+b[20:])]
    out=[]; rows=[]
    for tag,bb in views:
        q=OUT/(prefix+'.'+tag+'.readonly_copy.db'); q.open('xb').write(bb)
        rr={'view':tag,'path':q.name,'sha256':sha(q),'transformation':'none' if tag=='exact' else 'bytes 18/19 WAL version -> rollback version in new view only; no WAL implied applied'}
        try:
            con=sqlite3.connect(q.as_uri()+'?mode=ro&immutable=1',uri=True)
            rr['integrity_check']=con.execute('PRAGMA integrity_check').fetchall()
            rr['schemas']=con.execute("SELECT name,rootpage,sql FROM sqlite_master WHERE type='table'").fetchall()
            rr['counts']={n:con.execute('SELECT count(*) FROM "'+n.replace('"','""')+'"').fetchone()[0] for n,_,_ in rr['schemas']}
            for n,_,_ in rr['schemas']:
                if n=='threat_records':
                    cur=con.execute('SELECT * FROM threat_records'); cols=[x[0] for x in cur.description]; rows=[dict(zip(cols,v)) for v in cur]
            con.close()
        except Exception as e: rr['error']=repr(e)
        out.append(rr)
    if not rows:
        rows,sc=scan(b); out.append({'fallback':'strict table-leaf scanner; validated UUID, 11 columns, record type/timestamp/content; no arbitrary column guessing',**sc})
    return rows,out
def wal_overlay(db,wal):
    ps=int.from_bytes(wal[8:12],'big'); frames=[]; valid=0; salt=wal[16:24]; size=24+ps
    # Verify frame checksums with the byte order encoded in WAL magic.
    endian='<' if int.from_bytes(wal[:4],'big')==0x377f0682 else '>'
    def checksum(data,s0,s1):
        ww=struct.unpack(endian+str(len(data)//4)+'I',data)
        for i in range(0,len(ww),2): s0=(s0+ww[i]+s1)&0xffffffff; s1=(s1+ww[i+1]+s0)&0xffffffff
        return s0,s1
    s0,s1=checksum(wal[:24],0,0); header_ok=struct.pack('>II',s0,s1)==wal[24:32]
    last_commit=0
    for i in range(32,len(wal)-size+1,size):
        h=wal[i:i+24]; page=wal[i+24:i+size]; pg,commit=struct.unpack('>II',h[:8]); cs=checksum(h[:8]+page,s0,s1)
        ok=(h[8:16]==salt and struct.pack('>II',*cs)==h[16:24]); frames.append({'page':pg,'commit_size':commit,'checksum_ok':ok})
        if not ok: break
        valid+=1; s0,s1=cs
        if commit: last_commit=valid
    result=bytearray(db)
    for idx in range(last_commit):
        i=32+idx*size; pg=frames[idx]['page']; end=pg*ps
        if len(result)<end: result.extend(b'\0'*(end-len(result)))
        result[(pg-1)*ps:end]=wal[i+24:i+size]
    if last_commit: result=result[:frames[last_commit-1]['commit_size']*ps]
    return bytes(result),{'page_size':ps,'header_checksum_ok':header_ok,'valid_frames':valid,'frames_to_last_commit':last_commit,'frames':frames,'trailing_bytes':max(0,(len(wal)-32)%size)}
result={'pulls':[],'apk_assets':[],'legacy_comparisons':[]}; allrows=[]
for pull,rel in [('pull_1','sentinel-ml/Databases/sentinel_db'),('pull_2','sentinel-ml/Databases/sentinel_db(1)'),('pull_3','sentinel-ml/Databases/22oct_pull/sentinel-history.tar')]:
    raw=(ROOT/rel).read_bytes(); b=raw[2:].decode('utf-16-le').encode('cp437','strict')
    variants=[('cp437',b),('cp437_crlf_reversed',b.replace(b'\r\n',b'\n'))]
    candidates=[]; rr={'pull_id':pull,'source':rel,'source_sha256':sha(ROOT/rel),'model_generation':'UNRESOLVED','variants':[]}
    for tag,bb in variants:
        (OUT/(pull+'.'+tag+'.bin')).open('xb').write(bb)
        entry={'tag':tag,'bytes':len(bb),'sha256':hashlib.sha256(bb).hexdigest(),'crlf_count':bb.count(b'\r\n')}
        if rel.endswith('.tar'):
            try:
                with tarfile.open(fileobj=io.BytesIO(bb),mode='r:') as t:
                    mem={m.name:t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
                entry['members']=[{'name':n,'bytes':len(x),'sha256':hashlib.sha256(x).hexdigest()} for n,x in mem.items()]
                candidates.append((len(mem),tag,mem))
            except Exception as e: entry['error']=repr(e)
        else: candidates.append((int(len(bb)%4096==0),tag,{'sentinel_db':bb}))
        rr['variants'].append(entry)
    _,tag,mem=max(candidates,key=lambda x:x[0]); rr['chosen_transform']=tag
    db=next((x for n,x in mem.items() if n.endswith('sentinel_db')),b''); wal=next((x for n,x in mem.items() if n.endswith('-wal')),None)
    for i,(n,x) in enumerate(mem.items()): (OUT/(pull+'.member_'+str(i)+'.bin')).open('xb').write(x)
    rows,probes=sqlite_probe(db,pull+'.main'); rr['main_probes']=probes
    if wal:
        merged,wm=wal_overlay(db,wal); rr['wal']=wm
        wr,wp=sqlite_probe(merged,pull+'.wal_merged'); rr['wal_probes']=wp
        if wm['header_checksum_ok'] and wm['frames_to_last_commit']>0: rows=wr; rr['row_view']='validated-WAL overlay to last committed frame'
        else: rr['row_view']='main snapshot; WAL could not be certified'
    else: rr['row_view']='main snapshot; no usable WAL member'
    for r in rows:
        r['pull_id']=pull; r['content_sha256']=hashlib.sha256(str(r.get('content','')).encode()).hexdigest(); r['recovery_status']='OBSERVED_SQLITE' if any(p.get('counts') for p in probes) else 'PROVISIONAL_SALVAGE'
    jsonl(pull+'.rows.jsonl',rows); rr['rows_recovered']=len(rows)
    rr['logged_levels']=dict(collections.Counter(str(r.get('riskLevel')) for r in rows)); rr['explanation_patterns']=dict(collections.Counter(re.sub(r'\d+(?:\.\d+)?','<N>',str(r.get('explanation'))) for r in rows))
    rr['timestamp_min']=min((r['timestamp'] for r in rows),default=None); rr['timestamp_max']=max((r['timestamp'] for r in rows),default=None)
    rr['unrecoverable_count']='UNKNOWN: no independently trusted source row-count; no fabricated total'
    allrows+=rows; result['pulls'].append(rr)
def key(r): return (r.get('id'),r.get('recordType'),r.get('timestamp'),r.get('content_sha256') or hashlib.sha256(str(r.get('content','')).encode()).hexdigest())
merged={}
for r in allrows:
    k=key(r)
    if k not in merged: merged[k]={**r,'pull_ids':[r['pull_id']],'logged_predictions':[]}
    if r['pull_id'] not in merged[k]['pull_ids']: merged[k]['pull_ids'].append(r['pull_id'])
    merged[k]['logged_predictions'].append({k:r.get(k) for k in ('pull_id','riskLevel','riskScore','explanation')})
jsonl('merged_recovered.jsonl',list(merged.values())); result['dedup']={'input_rows':len(allrows),'unique_rows':len(merged),'duplicates':len(allrows)-len(merged),'key':'id,recordType,timestamp,UTF8-content-SHA256'}
for rel in ('sentinel-ml/New_history/bench_real_history_562.jsonl','sentinel-ml/investigation/sentinel_db_parsed.jsonl','sentinel-ml/investigation/sentinel_db1_parsed.jsonl'):
    legacy=readrows(ROOT/rel); kk={key(r):r for r in legacy}; ours={key(r):r for r in allrows}
    matches=set(kk)&set(ours)
    result['legacy_comparisons'].append({'source':rel,'sha256':sha(ROOT/rel),'legacy_rows':len(legacy),'matching_id_timestamp_content_keys':len(matches),'legacy_only':len(set(kk)-set(ours)),'new_only':len(set(ours)-set(kk))})
    jsonl('compare_'+Path(rel).stem+'.jsonl',[{'key':list(k),'match':k in ours,'legacy_content_sha256':k[3]} for k in kk])
for rel in ('sentinel-ai/installed-sentinel.apk','sentinel-ml/Messages-ml/release/apk/SentinelAI-2.1.0-release-unsigned.apk'):
    p=ROOT/rel
    with zipfile.ZipFile(p) as z:
        assets=[{'name':n,'bytes':z.getinfo(n).file_size,'sha256':hashlib.sha256(z.read(n)).hexdigest()} for n in z.namelist() if '/assets/' in '/'+n and any(t in n for t in ('champion','messages_v4','v7_','v8_'))]
    result['apk_assets'].append({'apk':rel,'sha256':sha(p),'assets':assets})
jsave('recovery_provenance.json',result)
print(json.dumps({'pulls':[{k:p[k] for k in ('pull_id','rows_recovered','chosen_transform','logged_levels')} for p in result['pulls']],'dedup':result['dedup'],'comparisons':result['legacy_comparisons']},indent=2))
