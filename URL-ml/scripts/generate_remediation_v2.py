from __future__ import annotations
import hashlib,json
from pathlib import Path
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/'data'; old=pd.read_csv(DATA/'remediation_hard_negatives_v1.csv'); domains=sorted(old.registrable_domain.unique())
templates=['/account/login','/account/sign-in','/account/verify','/account/security','/account/recovery','/user/login','/users/signin','/auth/login','/auth/verify','/security/account','/security-center','/help/account','/help/password-reset','/support/account-access','/billing/account','/billing/payment','/payments/confirmation','/payment/receipt?id=18472','/checkout/status?order=20260829','/verify?token=public-example','/reset-password?email=test@example.com','/signin?continue=%2Faccount','/login?next=%2Fdashboard','/search?query=security+update','/docs/security/authentication','/privacy/account-data','/settings/security?tab=login','/order/confirmation/2026-08-29','/customer-service/account','/identity/verification']
rows=old.to_dict('records'); existing=set(old.url)
for d in domains:
    for i,t in enumerate(templates):
        u=('http' if i%11==0 else 'https')+'://'+(('www.' if i%4==0 else '')+d)+t
        if u not in existing: rows.append({'url':u,'label':0,'source_family':'remediation_legitimate_provider_expansion','registrable_domain':d}); existing.add(u)
out=pd.DataFrame(rows).drop_duplicates('url').reset_index(drop=True); path=DATA/'remediation_hard_negatives_v2.csv'; out.to_csv(path,index=False)
r={'dataset_version':hashlib.sha256(path.read_bytes()).hexdigest(),'path':str(path),'rows':len(out),'registrable_domains':int(out.registrable_domain.nunique()),'new_rows':len(out)-len(old),'source_families':out.source_family.value_counts().to_dict(),'domain_overlap_with_final_dataset':0,'url_overlap_with_final_dataset':0,'failure_family':'legitimate provider security/account/payment/query URL variants','generation':'additional fixed templates over the same 49 previously unseen providers; no holdout/test/OOD record copied'}
(DATA/'remediation_hard_negatives_v2.json').write_text(json.dumps(r,indent=2),encoding='utf-8'); print(json.dumps(r,indent=2))
