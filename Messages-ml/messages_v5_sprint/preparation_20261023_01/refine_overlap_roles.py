from preplib import *
guard()
def role(p):
 s=str(p).replace('\\','/').lower();name=Path(s).name
 if '/benchmarks/' in s or '/evaluation/' in s or '/holdouts/' in s or name.startswith(('bench_','holdout_','probe_','simulation_messages')) or name in ('test.jsonl','val.jsonl','ood.jsonl','controlled_validation_set.jsonl'):return 'confirmed_evaluation'
 return 'raw_training_lineage_or_unclassified'
allflags=list(rows(OUT/'historical_SPAM_overlap.jsonl'));refined=[];byfile=collections.Counter()
for r in allflags:
 confirmed=[];lineage=[]
 for h in r['hits']:
  for p in h['evaluation_files']:
   item={'path':p,'jaccard':h['jaccard'],'exact':h['exact']}
   (confirmed if role(p)=='confirmed_evaluation' else lineage).append(item)
 for p in {h['path'] for h in confirmed}:byfile[p]+=1
 refined.append({'id':r['id'],'confirmed_eval_overlap':bool(confirmed),'confirmed_hits':confirmed,'lineage_or_unclassified_hits':lineage})
jsonl('historical_SPAM_overlap_v2.jsonl',refined)
metadata=[];sourcecounts=collections.Counter();rows_with_source=0
for r in rows(ROOT/'sentinel-ml/Messages-ml/data/processed/train.jsonl'):
 if r.get('security_label')!='SUSPICIOUS_SPAM':continue
 source=r.get('source_id',r.get('source',r.get('dataset_source',r.get('source_dataset','MISSING'))));sourcecounts[str(source)]+=1
 if len(metadata)<3:metadata.append({k:v for k,v in r.items() if k not in ('raw_text','text','cleaned_text')})
save('historical_SPAM_readiness_v2.json',{'spam_rows':len(allflags),'confirmed_eval_overlap_rows':sum(r['confirmed_eval_overlap'] for r in refined),'not_flagged_against_confirmed_eval':sum(not r['confirmed_eval_overlap'] for r in refined),'flagged_by_confirmed_file':dict(byfile),'source_counts_with_source_id_precedence':dict(sourcecounts),'metadata_examples_no_text':metadata,'correction':'First broad pass mislabeled raw/all_processed/reference corpora as evaluation, flagging all1169. Confirmed-role filter corrects the classification without changing text matches. Unclassified lineage is retained, not asserted to be test leakage. No admission based on no-match alone.'})
bm=[];counts=collections.defaultdict(set)
for r in rows(OUT/'overlap_matches.jsonl'):
 rr={**r,'refined_role':role(r['match_source']) if r['match_role']=='evaluation' else r['match_role']};bm.append(rr);counts[(r['source_id'],rr['refined_role'])].add(r['id'])
jsonl('overlap_matches_v2.jsonl',bm)
save('overlap_role_correction.json',{'source_rows_by_role':{'|'.join(k):len(v) for k,v in counts.items()},'original_raw_evaluation_role_was_overbroad':True,'rule':'explicit benchmark/evaluation/holdout paths or test/val/ood/controlled-validation filenames; other references retained as lineage/unclassified','hardneg_status':'UNPROVEN, absent'})
tri=list(rows(OUT/'DATASET_LABEL_TRIAGE_REFERENCE.csv'));tc=collections.Counter(r['origin'].split('_none')[0].split('_translit')[0] for r in tri);save('triage_counts.json',{'by_origin':dict(collections.Counter(r['origin'] for r in tri)),'provisional_triage':dict(collections.Counter(r['provisional_triage'] for r in tri)),'confirmed_errors':None,'source_error_rate':None,'note':'Nonrandom AI-selected concerns, not a prevalence estimate'})
print('historical SPAM confirmed evaluation flags',sum(r['confirmed_eval_overlap'] for r in refined),'/',len(allflags),'source counts',dict(sourcecounts));print('B refined',{'|'.join(k):len(v) for k,v in counts.items()})
