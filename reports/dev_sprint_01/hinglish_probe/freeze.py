from probe_lib import *
import collections,datetime
protect()
rr=csvread('draft_probe_set.csv');gen=load('generation_manifest.json');intra=load('intra_probe_audit.json');audit=load('corpus_audit_manifest.json')
assert intra['cap_pass'];assert len(rr)==1320
assert sum(r['language']=='Hinglish' and r['expected']=='MALICIOUS' for r in rr)==480
assert sum(r['language']=='Hinglish' and r['expected']=='BENIGN' for r in rr)==480
assert sum(r['language']=='Hinglish' and r['expected']=='SPAM' for r in rr)==120
assert sum(r['language']=='Hinglish' and r['expected']=='MALICIOUS' and r['has_url']=='false' for r in rr)>=192
for expected in ('MALICIOUS','BENIGN','SPAM'):
    selected=[r for r in rr if r['language']=='Hinglish' and r['expected']==expected];assert sum(r['channel_style']=='SMS' for r in selected)*2==len(selected)
assert all('.invalid' in r['text'] for r in rr if r['has_url']=='true')
assert all(r['sender_header']=='' for r in rr if r['channel_style']=='WhatsApp')
# Exact new-file byte copy; the source is this run's own draft, never an existing corpus.
(OUT/'probe_set.csv').open('xb').write((OUT/'draft_probe_set.csv').read_bytes())
digest=sha(OUT/'probe_set.csv');(OUT/'probe_set.sha256').open('x',encoding='ascii').write(digest+'  probe_set.csv\n')
time=datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest={'frozen_UTC':time,'path':'probe_set.csv','sha256':digest,'rows':len(rr),'counts':gen['counts'],'design_preregistered_sha256':sha(OUT/'DESIGN_PREREGISTERED.md'),'corpus_audit_sha256':sha(OUT/'corpus_audit_manifest.json'),'overlap_tags_sha256':sha(OUT/'overlap_tags.jsonl'),'blind_QA_sha256':sha(OUT/'blind_QA_summary.json'),'blind_disagreements':load('blind_QA_summary.json')['disagreements'],'max_near_duplicate_component':intra['max_component_size'],'models_seen_set':False,'training_fits':0,'GPU_requested':False,'immutable_exam_for_future_training':True,'all_labels':'ASSUMED single-generator intent; unreviewed','proposed_decision_rules_locked':True}
save('freeze_manifest.json',manifest)
design=(OUT/'DESIGN_PREREGISTERED.md').read_text(encoding='utf-8')+'\n\n## OBSERVED freeze commitment — before model inference\n\n'+f'Frozen at {time}. Exact UTF-8/BOM CSV SHA-256: `{digest}` (`probe_set.csv`). Rows: 1,320. All generation/audit constraints above passed. Original author labels remain unchanged. 80 blind-pass disagreements are retained, not automatically relabeled. Cross-corpus flagged rows: {audit["cross_corpus_flagged"]}; training text sources: {audit["training_files"]}; complete text-source count: {len(audit["corpora"])}. Largest intraprobe Jaccard>=.85 component: {intra["max_component_size"]}. REVIEW_SAMPLE.csv has {load("review_sample_manifest.json")["rows_after_union"]} rows, all user fields blank.\n\n'+ 'Generation counts and actual word-length/style/noise counts are in generation_manifest.json. Audit corpus paths/hashes, parsing limitations and row-level overlap tags are immutable sidecars. Freeze manifest SHA-256: `'+sha(OUT/'freeze_manifest.json')+'`. The final design is created once from the preregistration plus this commitment; no existing design or dataset is overwritten. No model has scored this set at this point.\n'
with (OUT/'HINGLISH_PROBE_DESIGN.md').open('x',encoding='utf-8') as f:f.write(design)
print('FROZEN',digest,'rows',len(rr),'design hash',sha(OUT/'HINGLISH_PROBE_DESIGN.md'))
