from runlib import *
import collections,math
protect()
import numpy as np
manifest=jload('freeze_manifest_v2.json'); rng=np.random.default_rng(20261022); B=2000; prevalences=[.001,.01,.05]
def ci(v):
    v=np.asarray(v); v=v[np.isfinite(v)]
    return [float(x) for x in np.quantile(v,[.025,.975])] if len(v) else None
def rate(a,n): return a/n if n else None
def metrics(rr,bootstrap=False):
    known=[r for r in rr if r['y'] in (0,1)]; ben=[r for r in known if r['y']==0]; att=[r for r in known if r['y']==1]; nb=len(ben); na=len(att); fp=sum(r['alert'] for r in ben); tp=sum(r['alert'] for r in att); f=rate(fp,nb); rec=rate(tp,na)
    out={'n':len(rr),'labeled_n':len(known),'unlabeled_n':len(rr)-len(known),'benign_n':nb,'attack_n':na,'FP':fp,'TP':tp,'FPR':f,'recall_any_alert':rec,'alerts_per_1000_benign':1000*f if f is not None else None,'alert_rate_all':rate(sum(r['alert'] for r in rr),len(rr)),'benign_clusters':len(set(r['group'] for r in ben)),'attack_clusters':len(set(r['group'] for r in att)),'not_decision_grade':bool(nb<30 or na<30 or len(set(r['group'] for r in ben))<30 or len(set(r['group'] for r in att))<30),'prevalences':[]}
    ff=rrr=None
    if bootstrap and known:
        gs=sorted(set(r['group'] for r in known)); gi={g:i for i,g in enumerate(gs)}; counts=np.zeros((len(gs),4))
        for r in known:
            i=gi[r['group']]; counts[i,0 if r['y']==0 else 2]+=1; counts[i,1 if r['y']==0 else 3]+=r['alert']
        # Weighted row estimand, bootstrap sampling units are clusters, no label shuffling.
        draws=rng.multinomial(len(gs),np.full(len(gs),1/len(gs)),size=B)@counts
        with np.errstate(divide='ignore',invalid='ignore'): ff=draws[:,1]/draws[:,0]; rrr=draws[:,3]/draws[:,2]
        out['bootstrap_95CI_FPR']=ci(ff); out['bootstrap_95CI_recall']=ci(rrr); out['bootstrap_replicates']=B
        out['zero_FP_onesided_95_upper_independent_rows']=float(1-.05**(1/nb)) if nb and fp==0 else None
        out['zero_FP_onesided_95_upper_clusters_if_independent']=float(1-.05**(1/out['benign_clusters'])) if out['benign_clusters'] and fp==0 else None
    for p in prevalences:
        denom=p*rec+(1-p)*f if f is not None and rec is not None else None; ppv=p*rec/denom if denom else None; volume=rr[0]['volume'] if rr else 0
        z={'assumed_prevalence':p,'PPV':ppv,'false_alerts_user_day':volume*(1-p)*f if f is not None else None,'total_alerts_user_day':volume*denom if denom is not None else None,'recall':rec}
        if ff is not None:
            with np.errstate(divide='ignore',invalid='ignore'): bp=p*rrr/(p*rrr+(1-p)*ff)
            z.update(PPV_bootstrap95CI=ci(bp),recall_bootstrap95CI=ci(rrr),false_alerts_day_bootstrap95CI=ci(volume*(1-p)*ff))
        out['prevalences'].append(z)
    return out
summaries=[]; breakdown=[]; worst=[]; logged=[]; reliability=[]; thresholds=[]; policy=[]
for track,pfile in [('messages','message_predictions.jsonl'),('urls','url_predictions.jsonl')]:
    ss={r['uid']:r for r in readrows(OUT/manifest[track]['path'])}; preds=readrows(OUT/pfile); bymodel=collections.defaultdict(list)
    for p in preds: bymodel[p['model']].append(p)
    for model,pp in bymodel.items():
        for mode in ('raw','adjudicated'):
            rr=[]
            for p in pp:
                r=ss[p['uid']]; score=p.get(mode+'_score',p['score']); rr.append({**r,**p,'alert':p[mode+'_alert'],'used_score':score,'volume':300 if track=='messages' else 30})
            subsets={'all':rr,'without_overlap':[r for r in rr if not r['overlap_flag']],'overlap_only':[r for r in rr if r['overlap_flag']], 'natural_provisional':[r for r in rr if not r['synthetic']], 'synthetic_authored':[r for r in rr if r['synthetic']], 'transported_projection':[r for r in rr if (not r['synthetic'] and r['label_status']=='PROVISIONAL_BENIGN_UNREVIEWED') or (r['synthetic'] and r['y']==1)]}
            for val in sorted(set(r['label_status'] for r in rr)): subsets['label_status='+val]=[r for r in rr if r['label_status']==val]
            for scope,selected in subsets.items(): summaries.append({'track':track,'model':model,'mode':mode,'scope':scope,'evidence':'PROVISIONAL metrics conditional on authored/unreviewed labels; transported_projection assumes class-conditional transportability',**metrics(selected,True)})
            axes=['language','script','channel','conversation','attack_family','label_status','overlap_flag','pull_id']+(['url_form','popularity','registrable_domain'] if track=='urls' else [])
            for axis in axes:
                for val in sorted(set(str(r.get(axis,'UNKNOWN')) for r in rr)):
                    sel=[r for r in rr if str(r.get(axis,'UNKNOWN'))==val]; breakdown.append({'track':track,'model':model,'mode':mode,'axis':axis,'value':val,**metrics(sel,True)})
            for scope,sel in [('all_labeled',[r for r in rr if r['y'] in (0,1)]),('natural_provisional',[r for r in rr if not r['synthetic'] and r['y'] in (0,1)]),('authored',[r for r in rr if r['synthetic'] and r['y'] in (0,1)])]:
                for prior in [None]+prevalences:
                    nb=sum(r['y']==0 for r in sel); na=sum(r['y']==1 for r in sel); bins=[]; ece=0.; brier=0.; total=0.
                    weights=[1. if prior is None else ((1-prior)/nb if r['y']==0 and nb else prior/na if na else 0.) for r in sel]
                    total=sum(weights)
                    for lo in np.linspace(0,.9,10):
                        inds=[i for i,r in enumerate(sel) if lo<=r['used_score']<(lo+.10000001 if lo>.89 else lo+.1)]
                        w=sum(weights[i] for i in inds)
                        if not w: continue
                        confidence=sum(weights[i]*sel[i]['used_score'] for i in inds)/w; observed=sum(weights[i]*sel[i]['y'] for i in inds)/w; ece+=w*abs(confidence-observed); bins.append({'lo':float(lo),'hi':float(lo+.1),'n':len(inds),'confidence':confidence,'observed_positive_rate':observed})
                    brier=sum(w*(r['used_score']-r['y'])**2 for r,w in zip(sel,weights))/total if total else None
                    reliability.append({'track':track,'model':model,'mode':mode,'scope':scope,'assumed_prior':prior,'ECE':ece/total if total else None,'Brier':brier,'n':len(sel),'bins':bins,'limitation':'diagnostic decision scores (non-benign includes spam); synthetic/unreviewed labels; no deployment calibration claim'})
            for t in sorted(set([.1,.2,.28,.4,.5,.61,.63,.68,.704,.8,.9,rr[0]['threshold']])):
                sel=[{**r,'alert':int(r['used_score']>=t)} for r in rr]; thresholds.append({'track':track,'model':model,'mode':mode,'diagnostic_threshold':t,**metrics(sel),'selection':'NONE; locked original operating threshold retained'})
            errors=[r for r in rr if r['y'] in (0,1) and r['alert']!=r['y']]
            errors.sort(key=lambda r: -r['used_score'] if r['y']==0 else r['used_score'])
            for r in errors[:30]: worst.append({'track':track,'model':model,'mode':mode,'uid':r['uid'],'example':r.get('text',r.get('url')),'y':r['y'],'label_status':r['label_status'],'score':r['used_score'],'alert':r['alert'],'overlap_flag':r['overlap_flag'],'language':r['language'],'family':r['attack_family'],'synthetic':r['synthetic']})
            for r in rr:
                if r.get('riskLevel') is None: continue
                # This compares binary logged non-green vs current model alert, not historical model identity or truth.
                log_alert=r['riskLevel']!='GREEN'
                logged.append({'track':track,'model':model,'mode':mode,'uid':r['uid'],'pull_id':r.get('pull_id'),'logged_level':r['riskLevel'],'logged_score':r.get('riskScore'),'logged_explanation':r.get('explanation'),'logged_alert':int(log_alert),'new_alert':r['alert'],'new_score':r['used_score'],'disagrees':int(log_alert!=bool(r['alert'])),'label_status':r['label_status']})
        for p in pp:
            if p['raw_alert']!=p['adjudicated_alert']: policy.append({'track':track,**p,'example':ss[p['uid']].get('text',ss[p['uid']].get('url')),'y':ss[p['uid']]['y'],'label_status':ss[p['uid']]['label_status']})
jsonl('metrics_summary.jsonl',summaries); jsonl('segment_metrics.jsonl',breakdown); jsonl('worst_failures.jsonl',worst); jsonl('logged_comparison.jsonl',logged); jsonl('calibration_reliability.jsonl',reliability); jsonl('threshold_sensitivity.jsonl',thresholds); jsonl('policy_changes.jsonl',policy)
jsave('analysis_counts.json',{'summaries':len(summaries),'segment_cells':len(breakdown),'worst_case_rows':len(worst),'logged_comparisons':len(logged),'policy_changed_rows':len(policy),'bootstrap_replicates_per_cell':B,'seed':20261022,'note':'Every prevalence is ASSUMED; all inferred labels PROVISIONAL; NEEDS_REVIEW excluded from accuracy, included in alert rate and logged comparisons'})
print(json.dumps(jload('analysis_counts.json')))
