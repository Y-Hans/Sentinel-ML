from sprintlib import *
guard()
imp=list(rows(OUT/'permutation_importance.csv'));groups=collections.defaultdict(list)
for r in imp:groups[(r['model'],r['feature'],r['scope'])].append(r)
agg=[{'model':k[0],'feature':k[1],'scope':k[2],**{m:sum(float(r[m]) for r in rr)/len(rr) for m in ['recall_drop','false_alert_increase','balanced_accuracy_drop']}} for k,rr in groups.items()]
save('importance_summary.json',agg)
missing=list(rows(OUT/'sender_missing_by_file_label_source.csv'));fileagg=collections.defaultdict(lambda:collections.Counter())
for r in missing:
 for k in ['n','null_or_blank','nonempty','suffix_P','suffix_G']:fileagg[r['file']][k]+=int(r.get(k,0))
save('sender_file_totals.json',{p:{**dict(c),'missing_share':c['null_or_blank']/c['n']} for p,c in fileagg.items()})
act=list(rows(OUT/'paired_feature_activation.csv'));collapse=sorted([r for r in act if r['model']=='V2'],key=lambda r:-int(r['E_active_H_zero']))[:12]
summary=list(rows(OUT/'probe_summary.jsonl'));v43=[r for r in summary if r['model']=='V4.3'];cells=list(rows(OUT/'probe_cells.jsonl'));url=[r for r in cells if r['model']=='V4.3' and r['set']=='v2' and r['axis']=='has_url']
hist=load(OUT/'English_TEST_baselines.json');gate=[]
for n in [50,100,200,300,400,500,600,1551,1556]:
 k=next((k for k in range(n+1) if k/n>=.85 and wilson(k,n)[0]>=.8),None)
 gate.append({'n':n,'min_success_for_point85_and_lower80':k,'wilson_at_min':wilson(k,n) if k is not None else None,'at85pct_ceil':wilson(math.ceil(.85*n),n)})
save('sample_size_arithmetic.json',gate)
dis=list(rows(OLD/'blind_disagreements.csv'));blindcounts=dict(collections.Counter(r['language']+':'+r['expected'] for r in dis))
save('diagnostic_summary.json',{'v43_probe':v43,'v43_url_cells':url,'collapse':collapse,'v1_blind_disagreement_counts':blindcounts,'TEST_v43':[r for r in hist if r['model']=='V4.3'],'top_importance':{m:sorted([r for r in agg if r['model']==m],key=lambda r:-r['balanced_accuracy_drop'])[:6] for m in ['V2','V4.3']}})
for m in ['V2','V4.3']:print(m,sorted([r for r in agg if r['model']==m],key=lambda r:-r['balanced_accuracy_drop'])[:5])
for p,c in fileagg.items():
 if p.endswith(('processed/train.jsonl','train_v4_3.jsonl')):print(p,dict(c))
print('collapse',[(r['feature'],r['H_nonzero'],r['E_nonzero'],r['E_active_H_zero']) for r in collapse[:6]])
print('V43 URL cells',[(r['value'],r['MALICIOUS']) for r in url]);print('blind disagreement counts',blindcounts)
