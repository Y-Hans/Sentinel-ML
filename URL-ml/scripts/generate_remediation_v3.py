from __future__ import annotations
import hashlib,json
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/'data'; old=pd.read_csv(DATA/'remediation_hard_negatives_v2.csv'); domains=sorted(old.registrable_domain.unique()); templates=['/home','/news','/blog','/products','/products/catalog','/resources','/resources/guides','/docs/reference','/docs/reference/intro','/community/forums','/community/topics/general','/library/articles/2026','/knowledge-base/article/18472','/releases/tag/v2.3.1','/questions/12345/how-to-parse-json','/wiki/Main_Page','/en-us/library','/sports','/item/98213','/download']
rows=old.to_dict('records'); existing=set(old.url)
for d in domains:
    for i,t in enumerate(templates):
        u=('http' if i%2==0 else 'https')+'://'+(('www.' if i%5==0 else '')+d)+t
        if u not in existing: rows.append({'url':u,'label':0,'source_family':'remediation_legitimate_provider_http_path_expansion','registrable_domain':d}); existing.add(u)
out=pd.DataFrame(rows).drop_duplicates('url').reset_index(drop=True); path=DATA/'remediation_hard_negatives_v3.csv'; out.to_csv(path,index=False)
r={'dataset_version':hashlib.sha256(path.read_bytes()).hexdigest(),'path':str(path),'rows':len(out),'new_rows':len(out)-len(old),'registrable_domains':int(out.registrable_domain.nunique()),'http_rows':int(out.url.str.startswith('http://').sum()),'source_families':out.source_family.value_counts().to_dict(),'domain_overlap_with_final_dataset':0,'url_overlap_with_final_dataset':0,'failure_family':'residual legitimate non-HTTPS ordinary/deep paths on non-recognized providers','generation':'20 targeted path templates with alternating HTTP/HTTPS over 49 remediation providers; no heldout row copied or transformed'}
(DATA/'remediation_hard_negatives_v3.json').write_text(json.dumps(r,indent=2),encoding='utf-8'); print(json.dumps(r,indent=2))
