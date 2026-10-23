from probe_lib import *
import collections,math
protect()
paths=['sentinel-ml/Messages-ml/SENTINEL_MASTER_PLAN.md','sentinel-ml/7sep_messages_v3/reports/HINGLISH_520_ATTACK_AUDIT.json','sentinel-ml/7sep_messages_v3/reports/HINGLISH_ROBUSTNESS_REPORT.md','sentinel-ml/7sep_messages_v3/data/bench_hinglish_robustness.jsonl']
source=ROOT/paths[1];audit=json.loads(source.read_text(encoding='utf-8'));old=readjsonl(ROOT/paths[3]);counts=collections.Counter(r.get('security_label',r.get('label','UNKNOWN')) for r in old)
save('historical_87_1_lead.json',{'status':'REPORTED historical model outcomes; OBSERVED files/counts/hashes','sources':{p:{'sha256':sha(ROOT/p),'bytes':(ROOT/p).stat().st_size} for p in paths},'master_claim':'section6.2 attributes87.1% and67/520misses toV2Champion','underlying_520_source':paths[1],'dataset_location':paths[1]+'::detailed_eval (embedded520authored attack records; no separate source-file provenance certified)','embedded_records':len(audit['detailed_eval']),'embedded_fields':list(audit['detailed_eval'][0]),'reported_v2_recall':audit['v2_overall_recall'],'reported_v2_detected':sum(bool(r['v2_detected']) for r in audit['detailed_eval']),'reported_V3_two_stage_recall':audit['v3_ts_overall_recall'],'reported_V3_two_stage_detected':sum(bool(r['v3_ts_detected']) for r in audit['detailed_eval']),'category_counts':{k:v['total'] for k,v in audit['category_summary'].items()},'misattribution':'87.115%=453/520 belongs toV3two-stage, notV2;V2reported327/520=62.885%. Master figure is preserved but not treated as a V2 baseline.','historical_100_slice':{'path':paths[3],'rows':len(old),'stored_labels':dict(counts),'reported_V2_recall_from_report':.14,'report_denominator':50},'prior_never_intentionally_tested_premise':'Contradicted forV2 by existing100row slice and520row audit; not claiming every currentvariant previouslytested','new_probe_reused_historical_text':False})
rr=csvread('probe_set.csv');pred=readjsonl(OUT/'probe_predictions.jsonl');index={r['id']:r for r in rr};assert len(index)==len(rr)==1320
f=load('freeze_manifest.json');assert sha(OUT/'probe_set.csv')==f['sha256'];inf=load('inference_manifest.json');assert sha(OUT/'HINGLISH_PROBE_DESIGN.md')==inf['design_sha256_before_probe']
assert load('V43_reproduction_gate.json')['passed']
assert all(p['alert']==(p['predicted']=='MALICIOUS') for p in pred);assert all(not p['alert'] for p in pred if p['predicted']=='SPAM')
for p in pred:assert abs(sum(p[k] for k in ('p_benign','p_spam','p_malicious'))-1)<1e-7
groups=collections.Counter((p['model'],p['condition']) for p in pred)
assert all(n==1320 for (m,c),n in groups.items() if c=='text_only')
assert len([1 for m,c in groups if c=='text_only'])==8
assert all(p['model']=='V2' and index[p['id']]['channel_style']=='SMS' for p in pred if p['condition']=='SMS_with_sender_header')
review=csvread('REVIEW_SAMPLE.csv');assert all(not r['user_agree'] and not r['user_note'] for r in review)
for stat in readjsonl(OUT/'probe_metrics.jsonl'):
    if 'confusion_true_by_pred_B_S_M' in stat:assert sum(map(sum,stat['confusion_true_by_pred_B_S_M']))==stat['n']
for v in load('verdicts.json'):
    if v['condition']=='text_only':assert v['verdict']=='Recall is also a problem'
save('quality_checks.json',{'status':'PASS','rows':len(rr),'prediction_rows':len(pred),'groups':{m+'/'+c:n for (m,c),n in groups.items()},'frozen_data_hash_unchanged':True,'frozen_design_hash_unchanged':True,'MALICIOUS_only_alert_asserted':True,'SPAM_never_alerts':True,'review_rows':len(review),'review_columns_blank':True,'probabilities_sum_to_one':True,'confusion_denominators_checked':True,'all_eight_text_only_verdicts':'Recall is also a problem','candidate_training_fits':0,'GPU_requested':False,'never_read_datasets_v5_or_user_data':True})
print('QA PASS',len(rr),'rows,',len(pred),'predictions;87.1%lead =V3two-stage453/520, notV2')
