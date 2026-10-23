"""Test OEM encoding hypotheses with strict round trips and format validation, in memory."""
import hashlib, io, json, sqlite3, tarfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]; OUT=Path(__file__).resolve().parent
result=[]
for rel in ('sentinel-ml/Databases/sentinel_db','sentinel-ml/Databases/sentinel_db(1)','sentinel-ml/Databases/22oct_pull/sentinel-history.tar'):
    raw=(ROOT/rel).read_bytes(); s=raw[2:].decode('utf-16-le'); item={'path':rel,'hypotheses':[]}
    for codec in ('cp437','cp850','cp1252'):
        r={'codec':codec}
        try:
            b=s.encode(codec,errors='strict'); r['roundtrip']=b.decode(codec)==s; r['bytes']=len(b); r['sha256']=hashlib.sha256(b).hexdigest()
            if rel.endswith('.tar'):
                with tarfile.open(fileobj=io.BytesIO(b),mode='r:') as t:
                    r['members']=[]
                    for m in t.getmembers():
                        row={'name':m.name,'bytes':m.size}
                        if m.isfile():
                            mb=t.extractfile(m).read(); row['sha256']=hashlib.sha256(mb).hexdigest(); row['header_hex']=mb[:16].hex()
                            if mb.startswith(b'SQLite format 3\x00'):
                                try:
                                    con=sqlite3.connect(':memory:'); con.deserialize(mb)
                                    row['quick_check']=con.execute('PRAGMA quick_check').fetchall()
                                    row['tables']=con.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
                                    row['table_counts']={n:con.execute('SELECT count(*) FROM "'+n.replace('"','""')+'"').fetchone()[0] for n,_ in row['tables']}
                                    con.close()
                                except Exception as e: row['db_error']=repr(e)
                        r['members'].append(row)
            else:
                con=sqlite3.connect(':memory:'); con.deserialize(b); r['quick_check']=con.execute('PRAGMA quick_check').fetchall(); r['tables']=con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(); con.close()
        except Exception as e: r['error']=repr(e)[:300]
        item['hypotheses'].append(r)
    result.append(item)
with (OUT/'oem_recovery_findings.json').open('x',encoding='utf-8') as f: json.dump(result,f,indent=2)
print(json.dumps(result,indent=2))
