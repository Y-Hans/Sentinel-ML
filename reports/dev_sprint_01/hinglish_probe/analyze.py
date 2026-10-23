from probe_lib import *
import math,collections
protect()
rows={r['id']:r for r in csvread('probe_set.csv')};tags={r['id']:r for r in readjsonl(OUT/'overlap_tags.jsonl')};pred=readjsonl(OUT/'probe_predictions.jsonl');LABELS=['BENIGN','SPAM','MALICIOUS'];bygroup=collections.defaultdict(list)
for p in pred:bygroup[(p['model'],p['condition'])].append({**rows[p['id']],**p,**tags[p['id']]})
def wilson(k,n):
    if not n:return None
    z=1.959963984540054;p=k/n;den=1+z*z/n;mid=(p+z*z/(2*n))/den;half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [max(0.,mid-half),min(1.,mid+half)]
def rate(k,n):return {'count':k,'N':n,'rate':k/n if n else None,'Wilson95':wilson(k,n),'indicative_only':n<30}
def stats(rr,endpoint='predicted'):
    cm=[[sum(r['expected']==a and r[endpoint]==b for r in rr) for b in LABELS] for a in LABELS];bb=[r for r in rr if r['expected']=='BENIGN'];ss=[r for r in rr if r['expected']=='SPAM'];mm=[r for r in rr if r['expected']=='MALICIOUS'];miss=[r for r in mm if r[endpoint]!='MALICIOUS']
    return {'n':len(rr),'confusion_true_by_pred_B_S_M':cm,'malicious_recall':rate(sum(r[endpoint]=='MALICIOUS' for r in mm),len(mm)),'benign_false_alert':rate(sum(r[endpoint]=='MALICIOUS' for r in bb),len(bb)),'spam_false_alert':rate(sum(r[endpoint]=='MALICIOUS' for r in ss),len(ss)),'malicious_misses':len(miss),'misses_predicted_SPAM':sum(r[endpoint]=='SPAM' for r in miss),'misses_predicted_BENIGN':sum(r[endpoint]=='BENIGN' for r in miss),'miss_share_SPAM':sum(r[endpoint]=='SPAM' for r in miss)/len(miss) if miss else None,'alert_endpoint':'MALICIOUS only; SPAM never alerts'}
def pairs(rr):
    lookup={r['id']:r for r in rr};pairs=[]
    for r in rr:
        if r['language']=='Hinglish' and r['english_twin_id'] in lookup:
            e=lookup[r['english_twin_id']]
            pairs.append({'model':r['model'],'condition':r['condition'],'pair_id':r['pair_id'],'expected':r['expected'],'family':r['family'],'hinglish_id':r['id'],'english_id':e['id'],'hinglish_alert':r['alert'],'english_alert':e['alert'],'hinglish_predicted':r['predicted'],'english_predicted':e['predicted'],'hinglish_pM':r['p_malicious'],'english_pM':e['p_malicious'],'hinglish_text':r['text'],'english_text':e['text']})
    result={}
    for lab in ('MALICIOUS','BENIGN'):
        ll=[p for p in pairs if p['expected']==lab];h=sum(p['hinglish_alert'] for p in ll);e=sum(p['english_alert'] for p in ll)
        result[lab]={'paired_n':len(ll),'Hinglish_alert_rate':rate(h,len(ll)),'English_alert_rate':rate(e,len(ll)),'English_minus_Hinglish_pp':100*(e-h)/len(ll) if ll else None,'English_only_alert':sum(p['english_alert'] and not p['hinglish_alert'] for p in ll),'Hinglish_only_alert':sum(p['hinglish_alert'] and not p['english_alert'] for p in ll),'both_alert':sum(p['hinglish_alert'] and p['english_alert'] for p in ll),'neither_alert':sum(not p['hinglish_alert'] and not p['english_alert'] for p in ll)}
    return result,pairs
summ=[];breakdowns=[];paired=[];verdicts=[];worstmiss=[];worstfalse=[];raw=[]
for (model,condition),rr in bygroup.items():
    scopes={'all':rr,'without_corpus_overlap':[r for r in rr if not r['overlap_flag']],'without_intra_near_duplicates':[r for r in rr if not r['intra_near_flag']],'corrected_user_review':[r for r in rr]}
    for scope,selected in scopes.items():
        for language in ('Hinglish','English'):
            sub=[r for r in selected if r['language']==language];summ.append({'model':model,'condition':condition,'scope':scope,'language':language,'labels':'ASSUMED_SINGLE_AUTHOR_UNREVIEWED','user_wrong_rows_excluded':0 if scope=='corrected_user_review' else None,**stats(sub)})
        pairing,pr=pairs(selected)
        if scope=='all':paired+=pr
        summ.append({'model':model,'condition':condition,'scope':scope,'language':'paired_control','pairing':pairing,'labels':'ASSUMED_SINGLE_AUTHOR_UNREVIEWED'})
    hing=[r for r in rr if r['language']=='Hinglish']
    for axis in ('family','channel_style','has_url','has_phone','hinglish_density','noise_level','length_bin','generator_batch','persona'):
        for value in sorted(set(r[axis] for r in hing)):
            for scope,selected in [('all',[r for r in hing if r[axis]==value]),('without_corpus_overlap',[r for r in hing if r[axis]==value and not r['overlap_flag']])]:breakdowns.append({'model':model,'condition':condition,'axis':axis,'value':value,'scope':scope,**stats(selected)})
    raw.append({'model':model,'condition':condition,'language':'Hinglish','scope':'raw_argmax',**stats(hing,'raw_argmax')})
    # Rules use unfiltered Hinglish and matched English attack pairs, locked before inference.
    st=stats(hing);fam=[b for b in breakdowns if b['model']==model and b['condition']==condition and b['axis']=='family' and b['scope']=='all' and b['malicious_recall']['N']>=30];low=[b['value'] for b in fam if b['malicious_recall']['rate']<.8];pairing,pr=pairs(rr);gap=pairing['MALICIOUS']['English_minus_Hinglish_pp'];rec=st['malicious_recall']['rate'];lower=st['malicious_recall']['Wilson95'][0] if st['malicious_recall']['Wilson95'] else None
    fp_main=lower is not None and lower>=.9 and not low and gap is not None and gap<=5
    recall_problem=rec is not None and (rec<.85 or len(low)>=3 or (gap is not None and gap>10))
    verdict='False positives are the main problem' if fp_main else 'Recall is also a problem' if recall_problem else 'mixed/inconclusive'
    verdicts.append({'model':model,'condition':condition,'verdict':verdict,'overall_Hinglish_recall':st['malicious_recall'],'families_below_80_Nge30':low,'paired_English_minus_Hinglish_pp':gap,'rule_overall_point_below85':rec<.85 if rec is not None else None,'rule_3families_below80':len(low)>=3,'rule_gap_exceeds10':gap>10 if gap is not None else None,'false_positive_main_all_conditions':fp_main,'evidence':'OBSERVED frozen decisions / ASSUMED synthetic labels; single-generator probe'})
    misses=sorted([r for r in hing if r['expected']=='MALICIOUS' and not r['alert']],key=lambda r:r['p_malicious'])[:25];fps=sorted([r for r in hing if r['expected'] in ('BENIGN','SPAM') and r['alert']],key=lambda r:-r['p_malicious'])[:25]
    fields=['model','condition','id','text','expected','predicted','family','channel_style','hinglish_density','noise_level','length_bin','p_benign','p_spam','p_malicious','overlap_flag']
    worstmiss += [{k:r[k] for k in fields} for r in misses];worstfalse += [{k:r[k] for k in fields} for r in fps]
jsonl('probe_metrics.jsonl',summ);jsonl('probe_breakdowns.jsonl',breakdowns);jsonl('paired_English_comparisons.jsonl',paired);jsonl('raw_argmax_metrics.jsonl',raw);save('verdicts.json',verdicts)
csvwrite('worst_25_misses_per_model.csv',worstmiss);csvwrite('worst_25_false_alerts_per_model.csv',worstfalse)
save('review_correction_status.json',{'user_review_received':False,'user_wrong_rows':0,'original_analysis_preserved':True,'corrected_user_review_scope':'identical to original until the user supplies wrong-label decisions; NOT a human-validated correction','blind_disagreements_excluded':False,'blind_disagreements_not_labels':True})
save('analysis_counts.json',{'summary_records':len(summ),'breakdown_cells':len(breakdowns),'paired_records':len(paired),'worst_miss_rows':len(worstmiss),'worst_false_alert_rows':len(worstfalse),'Wilson_z':1.959963984540054,'no_training_or_tuning':True})
print(json.dumps([{'model':v['model'],'condition':v['condition'],'recall':v['overall_Hinglish_recall']['rate'],'Wilson95':v['overall_Hinglish_recall']['Wilson95'],'verdict':v['verdict'],'bad_families':len(v['families_below_80_Nge30']),'English_gap_pp':v['paired_English_minus_Hinglish_pp']} for v in verdicts],indent=2))
