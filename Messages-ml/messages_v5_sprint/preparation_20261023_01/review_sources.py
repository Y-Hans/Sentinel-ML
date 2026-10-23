from preplib import *
guard()
assert load(OUT/'B_original_manifest_verification.json')['mismatch_count']==0
annpath=ROOT/'assistant_review_20261023/ANNOTATED_REVIEW_SAMPLE_v2.csv';ann=list(rows(annpath));orig=list(rows(PREV/'frozen/REVIEW_SAMPLE_v2.csv'));byid={r['id']:r for r in orig}
changes=[]
for r in ann:
 for k,v in byid[r['id']].items():
  if r.get(k)!=v:changes.append({'id':r['id'],'column':k,'original':v,'annotated':r.get(k)})
duplicates=collections.defaultdict(list)
for r in ann:duplicates[r['text']].append(r['id'])
extra=[k for k in ann[0] if k not in orig[0]]
review={'annotated_sha256':sha(annpath),'original_sha256':sha(PREV/'frozen/REVIEW_SAMPLE_v2.csv'),'n_rows':len(ann),'n_distinct_texts':len(duplicates),'label_counts':dict(collections.Counter(r['expected'] for r in ann)),'duplicated_exact_texts':[{'ids':v,'text_sha256':hashlib.sha256(k.encode()).hexdigest(),'text':k} for k,v in duplicates.items() if len(v)>1],'inherited_field_differences':changes,'annotation_columns':extra,'annotation_counts':{k:dict(collections.Counter(r[k] for r in ann)) for k in extra if len({r[k] for r in ann})<30},'human_marks':sum(bool(r['user_agree'].strip() or r['user_note'].strip()) for r in ann),'not_independent_human_review':True}
save('probe_review_audit.json',review)
tripath=B/'assistant_review_20261023/DATASET_LABEL_TRIAGE.csv';tri=list(rows(tripath));save('triage_reference.json',{'path':str(tripath),'sha256':sha(tripath),'rows':len(tri),'columns':list(tri[0]),'by_source':{k:dict(collections.Counter(r[k] for r in tri)) for k in tri[0] if 'source' in k.lower() and len({r[k] for r in tri})<15},'interpretation':'AI concerns, neither adjudicated errors nor random error-rate estimate'})
# Provenance-preserving copy of review concerns in our own output; no label changes.
csvwrite('DATASET_LABEL_TRIAGE_REFERENCE.csv',tri)
sources={};allrows=[];sourcehashes={};groupstats={}
for sid in ['sidzzz07','ridham','ysangam','karan','financial2025']:
 p=B/'normalized'/f'{sid}.jsonl';sourcehashes[sid]=sha(p);rr=list(rows(p));allrows.extend(rr);original=[r for r in rr if r['conversion']=='none'];gs=collections.defaultdict(list)
 for r in rr:gs[r['group_id']].append(r)
 groupstats[sid]={'rows':len(rr),'original_rows':len(original),'unique_group_ids':len(gs),'groups_without_exactly_one_original':sum(sum(r['conversion']=='none' for r in g)!=1 for g in gs.values()),'groups_with_label_conflict':sum(len({r['mapped_class'] for r in g})>1 for g in gs.values()),'missing_group_id':sum(not r.get('group_id') for r in rr),'variant_meaning_checks':dict(collections.Counter(str(r.get('meaning_check')) for r in rr if r['conversion']!='none'))}
 sources[sid]={'sha256':sourcehashes[sid],'rows':len(rr),'originals':len(original),'original_labels':dict(collections.Counter(r['mapped_class'] for r in original)),'original_language_class':dict(collections.Counter(r['language']+':'+r['mapped_class'] for r in original)),'all_language_class':dict(collections.Counter(r['language']+':'+r['mapped_class'] for r in rr)),'original_label_values':dict(collections.Counter(str(r['original_label']) for r in original)),'notes_examples':[r.get('notes') for r in original[:1]],'license_values':sorted({str(r.get('license')) for r in rr})}
save('B_original_source_inventory.json',{'scope':'OBSERVED archived pre-remediation external sources; no admission/split','sources':sources,'total_originals':sum(v['originals'] for v in sources.values()),'total_with_variants':len(allrows),'training_rows_admitted':0,'untouched_real_Hinglish_holdout_certified':0})
save('variant_group_audit.json',groupstats)
stats=collections.Counter((r['source_id'],r['language'],r['mapped_class'],r['conversion'],str(r.get('meaning_check'))) for r in allrows)
csvwrite('source_counts.csv',[{'source_id':k[0],'language':k[1],'mapped_class':k[2],'conversion':k[3],'meaning_check':k[4],'n':v} for k,v in sorted(stats.items())])
# Plain hardneg-train existence only; no sealed directory enumeration or content read.
hard=ROOT/'sentinel-ml/user_data/hardneg_train.csv';save('hardneg_availability.json',{'path':str(hard),'exists':hard.is_file(),'content_opened':False,'overlap_status':'UNPROVEN: expected hardneg_train.csv absent' if not hard.is_file() else 'PENDING_AUTHORIZED_INTAKE','sealed_exam_opened':False})
print('review',len(ann),'unique texts',len(duplicates),'inherited differences',len(changes),'human marks',review['human_marks'],'columns',extra)
print('triage',len(tri),'columns',list(tri[0]))
for sid,s in sources.items():print(sid,'originals',s['originals'],'lang/class',s['original_language_class'])
