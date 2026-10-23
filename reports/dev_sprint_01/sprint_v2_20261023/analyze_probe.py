from sprintlib import *
guard()
sets={'v1':list(rows(OLD/'probe_set.csv')),'v1_normalized':list(rows(OUT/'probe_v1_normalized.csv')),'v2':list(rows(OUT/'frozen/probe_v2.csv'))}
idmap=load(OLD/'blind_id_map.json');active={idmap[r['blind_id']] for r in rows(OLD/'blind_classification.csv') if r['blind_label']=='MALICIOUS'}
overlap={r['id'] for r in rows(OUT/'overlap_tags.jsonl') if r['overlap_flag']}
marks=load(OUT/'review_marks.json')['marks'];excluded={r['id'] for r in marks if r.get('user_agree','').strip().lower() in ('no','n','false','0','wrong','disagree')}
pred=collections.defaultdict(dict)
for r in rows(OUT/'probe_predictions.jsonl'):pred[(r['set'],r['model'])][r['id']]=r
summary=[];cells=[];verdict=[];pairs=[];worst=[]
def metric(rr,pp):
 d={};conf=[]
 for label in ['BENIGN','SPAM','MALICIOUS']:
  sub=[r for r in rr if r['expected']==label];k=sum(pp[r['id']]['alert'] for r in sub);n=len(sub)
  d[label]={'k':k,'n':n,'rate':k/n if n else None,'wilson95':wilson(k,n),'interpretation':'recall' if label=='MALICIOUS' else 'false_alert_rate','quality':'indicative only' if n<30 else 'synthetic descriptive'}
  conf.append([sum(pp[r['id']]['predicted']==c for r in sub) for c in ['BENIGN','SPAM','MALICIOUS']])
 benign=[r for r in rr if r['expected']!='MALICIOUS'];k=sum(pp[r['id']]['alert'] for r in benign);n=len(benign)
 d['BENIGN_SPAM']={'k':k,'n':n,'rate':k/n if n else None,'wilson95':wilson(k,n)};d['confusion']=conf;return d
for (setname,model),pp in pred.items():
 base=[r for r in sets[setname] if r['language']=='Hinglish']
 scopes={'all':base,'user_corrected':[r for r in base if r['id'] not in excluded]}
 if setname=='v2':scopes['no_overlap']=[r for r in base if r['id'] not in overlap]
 if setname=='v1':scopes['blind_active_intent']=[r for r in base if r['id'] in active]
 for scope,rr in scopes.items():summary.append({'set':setname,'model':model,'scope':scope,**metric(rr,pp)})
 for axis in ['family','has_url','channel_style','length_bin','noise_level','generator_batch','hinglish_density']:
  for value in sorted({r[axis] for r in base}):cells.append({'set':setname,'model':model,'axis':axis,'value':value,**metric([r for r in base if r[axis]==value],pp)})
 lookup={r['id']:r for r in sets[setname]};paired=[r for r in base if r['expected']=='MALICIOUS' and r['english_twin_id']]
 ph=sum(pp[r['id']]['alert'] for r in paired);pe=sum(pp[r['english_twin_id']]['alert'] for r in paired);gap=(pe-ph)/len(paired)
 pairs.append({'set':setname,'model':model,'n':len(paired),'Hinglish_TP':ph,'English_TP':pe,'gap_English_minus_Hinglish':gap,'English_Wilson':wilson(pe,len(paired)),'Hinglish_Wilson':wilson(ph,len(paired)),'English_only_correct':sum(not pp[r['id']]['alert'] and pp[r['english_twin_id']]['alert'] for r in paired),'Hinglish_only_correct':sum(pp[r['id']]['alert'] and not pp[r['english_twin_id']]['alert'] for r in paired)})
 if setname=='v2':
  mm=metric(base,pp)['MALICIOUS'];fc=[c['MALICIOUS'] for c in cells if c['set']=='v2' and c['model']==model and c['axis']=='family' and c['MALICIOUS']['n']>=30];bad=sum(c['rate']<.80 for c in fc)
  fp_main=mm['wilson95'][0]>=.9 and bad==0 and gap<=.05;recall=mm['rate']<.85 or bad>=3 or gap>.10
  verdict.append({'model':model,'verdict':'False positives are the main problem' if fp_main else 'Recall is also a problem' if recall else 'mixed/inconclusive','recall':mm,'families_below80':bad,'English_gap':gap})
  misses=sorted([r for r in base if r['expected']=='MALICIOUS' and not pp[r['id']]['alert']],key=lambda r:pp[r['id']]['p_malicious'])[:25]
  fas=sorted([r for r in base if r['expected']!='MALICIOUS' and pp[r['id']]['alert']],key=lambda r:-pp[r['id']]['p_malicious'])[:25]
  for kind,rs in [('miss',misses),('false_alert',fas)]:
   for r in rs:worst.append({'model':model,'kind':kind,**r,'predicted':pp[r['id']]['predicted'],'p_malicious':pp[r['id']]['p_malicious']})
jsonl('probe_summary.jsonl',summary);jsonl('probe_cells.jsonl',cells);save('verdicts.json',verdict);save('paired_English.json',pairs);csvwrite('worst_failures.csv',worst)
def fmt(m):
 if not m['n']:return '0/0; unavailable'
 return f"{m['k']}/{m['n']} = {100*m['rate']:.1f}% [{100*m['wilson95'][0]:.1f}, {100*m['wilson95'][1]:.1f}]"
table='| Model | v2 recall, Wilson95 | benign false alerts | spam false alerts | English pair gap | Verdict |\n|---|---|---|---|---|---|\n'
for v in verdict:
 s=next(s for s in summary if s['set']=='v2' and s['model']==v['model'] and s['scope']=='all');table+=f"| {v['model']} | {fmt(s['MALICIOUS'])} | {fmt(s['BENIGN'])} | {fmt(s['SPAM'])} | {100*v['English_gap']:.1f} pp | {v['verdict']} |\n"
diagnostics='| Model | v1 all attacks | v1 normalized | v1 active-pattern subset |\n|---|---|---|---|\n'
for v in verdict:
 vals=[next(s for s in summary if s['model']==v['model'] and s['set']==st and s['scope']==sc)['MALICIOUS'] for st,sc in [('v1','all'),('v1_normalized','all'),('v1','blind_active_intent')]];diagnostics+='| '+v['model']+' | '+' | '.join(map(fmt,vals))+' |\n'
breaks='| Model | Axis | Cell | Recall Wilson95 | B+S false alerts Wilson95 | Interpretation |\n|---|---|---|---|---|---|\n'
for c in cells:
 if c['set']=='v2':breaks+=f"| {c['model']} | {c['axis']} | {c['value']} | {fmt(c['MALICIOUS'])} | {fmt(c['BENIGN_SPAM'])} | {c['MALICIOUS']['quality']} |\n"
write('PROBE_V2_RESULTS.md','# Probe v2 results\n\nOBSERVED frozen-model inference / ASSUMED synthetic labels / PROVISIONAL real-world interpretation. Models and thresholds unchanged. This set is single-author, with reused family contexts and benign contrasts; it is not independent natural traffic. English twins share scenarios. Row-level Wilson intervals do not account for template correlation. No labels came from scores.\n\n'+table+'\n## V1 confound diagnostics\n\nOBSERVED paired text transformation; changing URL/phone tokens simultaneously cannot identify each causal contribution. Active subset is chosen by the previous same-author rule classifier, not verified truth; selection bias favors recognizable attacks. Do not call its complement cue-free.\n\n'+diagnostics+'\n## Integrity and limits\n\nOBSERVED V4.3 reproduction gate: 1510/1556 and 2/520 benign any-nonbenign. All raw probabilities and final MALICIOUS-only alerts are in probe_predictions.jsonl. Full TEST vs English metadata confusion is in English_TEST_baselines.json. No sender headers were fed. The first score-free validator failed on benign channel balance; repair_manifest.json records metadata-only correction, with draft preserved. Frozen dataset and design are under frozen/; freeze_manifest.json commits hashes before scores.\n\nOBSERVED user review marks: '+str(len(marks))+'; excluded explicit wrong marks: '+str(len(excluded))+'. REVIEW_SAMPLE_v2.csv contains a class-stratified random sample 60/40/20 without enrichment. More than 5% wrong requires a new set before trusting this one; exactly 6/120 is 5%, 7/120 exceeds it. Do not tune on either probe. Invented 9000000NNN patterns match the regex but are not proven unallocated. URLs are reserved .invalid, never fetched, neutral and lacking scenario words. Synthetic .invalid URLs still differ from deployment.\n\nOBSERVED all/no-overlap and user-corrected counts: probe_summary.jsonl; cross-corpus evidence: corpus_audit_manifest.json, overlap_tags.jsonl. Excluding overlap is sensitivity analysis, not a guarantee of source independence. Worst25 misses and25 false alerts per model are in worst_failures.csv.\n\n## All requested v2 cells\n\n'+breaks)
verdict_top='; '.join(sorted({v['verdict'] for v in verdict}))
write('stage_0B/PROGRESS.md',f'# Stage 0B — {verdict_top}\n\nOBSERVED: frozen v2 and v1 diagnostics completed, eight models on CPU, fixed thresholds. PROVISIONAL: labels await random user review. Continue Stage 1 regardless of verdict. No dataset intake, fits, exports or Android execution.\n')
print(table);print('Stage 0B completed')
