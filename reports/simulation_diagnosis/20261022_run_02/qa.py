from runlib import *
import collections
protect()
f=jload('freeze_manifest_v2.json'); findings=[]
for track,predfile in [('messages','message_predictions.jsonl'),('urls','url_predictions.jsonl')]:
    assert sha(OUT/f[track]['path'])==f[track]['sha256']
    rows=readrows(OUT/f[track]['path']); pred=readrows(OUT/predfile); uids={r['uid'] for r in rows}; assert len(uids)==len(rows)
    assert all(p['uid'] in uids for p in pred)
    groups=collections.Counter(p['model'] for p in pred); assert all(n==len(rows) for n in groups.values())
    assert all(0<=p['score']<=1 for p in pred)
    findings.append({'track':track,'rows':len(rows),'models':dict(groups),'frozen_hash_verified':True})
assert sha(OUT/f['sealed_exam']['path'])==f['sealed_exam']['sha256']
with (OUT/'REVIEW_SHEET.csv').open(encoding='utf-8-sig',newline='') as h:
    rows=list(csv.DictReader(h)); assert len(rows)==1009; assert all(not r['reviewer_label'] and not r['reviewer_note'] for r in rows)
repro=jload('messages_reproduction.json'); v=next(m for m in repro['models'] if m['model']=='Messages_V4.3'); assert v['TEST']['malicious_correct']==1510 and v['TEST']['benign_fp']==2 and v['TEST']['spam_to_malicious']==90
assert jload('urls_reproduction.json')['models']['8']['sha256']=='073e70f215c0c3279288ec69a692ed5cab7e99a443ed7b4f87da51ae67cf0e58'
for r in readrows(OUT/'metrics_summary.jsonl'):
    if r['benign_n']: assert abs(r['FPR']-r['FP']/r['benign_n'])<1e-12
    else: assert r['FPR'] is None
    if r['attack_n']: assert abs(r['recall_any_alert']-r['TP']/r['attack_n'])<1e-12
    else: assert r['recall_any_alert'] is None
jsave('quality_checks.json',{'checks':'PASS','prediction_coverage':findings,'review_sheet_rows':len(rows),'review_fields_blank':True,'freeze_and_exam_hashes_verified':True,'V43_reproduction_targets_match':True,'V8_artifact_target_match':True,'metric_denominators_recomputed':True,'sealed_exam_score_rows':0,'sealed_exam_content_opened_by_QA':False,'limitations':'No label truth validation or Android certification; hash bytes only for sealed exam'})
print('QA PASS: prediction coverage, frozen hashes, blank review fields, target reproduction and rate denominators')
