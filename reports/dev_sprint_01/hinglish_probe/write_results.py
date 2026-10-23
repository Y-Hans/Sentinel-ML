from probe_lib import *
import collections,math
protect()
def table(h,rr):return '| '+' | '.join(h)+' |\n| '+' | '.join('---' for _ in h)+' |\n'+'\n'.join('| '+' | '.join(str(x).replace('|','/').replace('\n',' ') for x in row)+' |' for row in rr)+'\n'
def pct(x):return 'NA' if x is None else f'{100*x:.1f}%'
def rstr(r):return f"{r['count']}/{r['N']} ({pct(r['rate'])}; "+('NA' if not r['Wilson95'] else '['+', '.join(pct(v) for v in r['Wilson95'])+']')+')'+(' — indicative only' if r['indicative_only'] else '')
metrics=readjsonl(OUT/'probe_metrics.jsonl');breakdown=readjsonl(OUT/'probe_breakdowns.jsonl');verdict=load('verdicts.json');qa=load('quality_checks.json');historical=load('historical_87_1_lead.json');audit=load('corpus_audit_manifest.json');gen=load('generation_manifest.json');counts=load('analysis_counts.json');inf=load('inference_manifest.json');models=[v['model'] for v in verdict if v['condition']=='text_only'];summary=[r for r in metrics if r['scope']=='all' and r['language']=='Hinglish' and r['condition']=='text_only'];pairs=[r for r in metrics if r['scope']=='all' and r['language']=='paired_control' and r['condition']=='text_only'];eng=load('English_TEST_comparison.json')
def lookup(model,axis,value):return next(r for r in breakdown if r['model']==model and r['condition']=='text_only' and r['scope']=='all' and r['axis']==axis and r['value']==value)
sm={r['model']:r for r in summary};vmap={v['model']:v for v in verdict if v['condition']=='text_only'}
testmeta={}
for split in ('test','ood'):
    p=ROOT/f'sentinel-ml/Messages-ml/data/processed/{split}.jsonl';rr=readjsonl(p);testmeta[split]={'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'n':len(rr),'language_counts':dict(collections.Counter(str(r.get('language')) for r in rr))}
save('report_input_counts.json',{'TEST_OOD_metadata':testmeta,'report_source_sha256':sha(__file__),'model_order':models})
flat=[]
for r in breakdown:
    f={k:r[k] for k in ('model','condition','axis','value','scope','n','malicious_misses','misses_predicted_SPAM','misses_predicted_BENIGN')}
    for metric in ('malicious_recall','benign_false_alert','spam_false_alert'):
        z=r[metric];f.update({metric+'_count':z['count'],metric+'_N':z['N'],metric+'_rate':z['rate'],metric+'_Wilson_lo':z['Wilson95'][0] if z['Wilson95'] else None,metric+'_Wilson_hi':z['Wilson95'][1] if z['Wilson95'] else None,metric+'_indicative_only':z['indicative_only']})
    flat.append(f)
csvwrite('PROBE_BREAKDOWNS.csv',flat)
s='''# Stage 0 — Hinglish probe results

Date: October 22, 2026 (Asia/Calcutta). **Verdict under the unchanged pre-registered rules: “Recall is also a problem” for all eight text-only frozen models. False positives are not the only observed problem.** This is a single-author synthetic stress probe; it does not measure real-world prevalence or prove real-world attack recall. A synthetic failure is informative; a pass would not certify field performance.

Evidence labels: **OBSERVED** means executed/inspected here; **ASSUMED** means generator intent/label or design choice; **REPORTED** means historical claim; **PROVISIONAL** means an interpretation relying on unreviewed synthetic labels. No training, GPU request, threshold change, calibration fit, export, source/model overwrite, Android/Kotlin/Gradle execution, link fetch or DNS resolution occurred. Neither datasets_v5 nor user_data was opened. The set is frozen as an exam and must not enter later training/tuning.

## 1. Primary answer: MALICIOUS only, SPAM never alerts

**OBSERVED decisions / ASSUMED labels:** 480 malicious, 480 benign, 120 spam Hinglish rows; 120 malicious and 120 benign English twins. Text-only inference uses sender=None and the original frozen p(non-benign) threshold followed by the spam/malicious class decision. Positive=final MALICIOUS, never SPAM. Raw three-class probabilities/argmax and final class are retained separately; this is not a new threshold policy or an Android fused-alert claim.

'''+table(['Model','Attack recall / Wilson 95%','Benign false alerts / Wilson 95%','Spam false alerts / Wilson 95%','Misses → BENIGN / SPAM','Pre-registered verdict'],[[r['model'],rstr(r['malicious_recall']),rstr(r['benign_false_alert']),rstr(r['spam_false_alert']),f"{r['misses_predicted_BENIGN']} / {r['misses_predicted_SPAM']}",vmap[r['model']]['verdict']] for r in summary])+'''
**OBSERVED:** V4.3 detects207/480=43.125%, misses273, all classified BENIGN. V2 detects115/480=23.958%, misses365 (358BENIGN,7SPAM). Best text-only point recall is V4.4 CandidateA314/480=65.417%, while it falsely alerts on203/480 benign and39/120 spam rows. Spam-never-alerts does not rescue these attacks: the misses are overwhelmingly below the benign boundary, not merely assigned to spam. No single model is chosen or promoted from these results.

**PROPOSED rules applied without revision:** FP-main requires lower95% overall recall≥.90, no N≥30family pointrecall<.80 and paired-English gap≤5points. Recall-also if pointrecall<.85 OR≥3families below.80 OR paired-English gap>10points. Otherwise mixed/inconclusive. All eight text-only models satisfy the recall-also condition through overall recall; family and twin gaps also trigger it. Exact Boolean rule inputs are in verdicts.json.

'''+table(['Model','Families below80% (N≥30)','Paired English−Hinglish gap, points','Recall lower95%'],[[v['model'],len(v['families_below_80_Nge30']),f"{v['paired_English_minus_Hinglish_pp']:.2f}",pct(v['overall_Hinglish_recall']['Wilson95'][0])] for v in verdict if v['condition']=='text_only'])+'''
## 2. Family breakdown

**OBSERVED / PROVISIONAL:** each family has40Hinglish attacks. Cells give detected/N,pointrecall andWilson95%; these are row-level synthetic intervals, not independent-population evidence. Near templates are capped, but shared frames/translation ancestry still correlate rows.

'''+table(['Family']+models,[[family]+[rstr(lookup(m,'family',family)['malicious_recall']) for m in models] for family in sorted(set(r['family'] for r in csvread('probe_set.csv') if r['expected']=='MALICIOUS'))])+'''
## 3. Channel, URL-like text, density, noise and length

**OBSERVED:** below are all requested attack-recall slices, text-only, with their denominators/intervals. `PROBE_BREAKDOWNS.csv` and `probe_breakdowns.jsonl` additionally include benign andspam false-alert rates, three-way confusion, everypersona/batch andall/unflagged source-overlap versions. N<30 is explicitly “indicative only.” A cell with N≥30 is still a synthetic, correlated diagnostic, not automatically real-world decision-grade evidence.

'''+table(['Model','Axis','Value','Attack recall / Wilson95%'],[[r['model'],r['axis'],r['value'],rstr(r['malicious_recall'])] for r in breakdown if r['condition']=='text_only' and r['scope']=='all' and r['axis'] in ('channel_style','has_url','hinglish_density','noise_level','length_bin') and r['malicious_recall']['N']])+'''
**OBSERVED failure pattern:** V4.3 URL-less recall75/288=26.042%, URL-like132/192=68.750%; V2 URL-less35/288=12.153%, URL-like80/192=41.667%. Both fail without a link, not just on benign false alarms. **PROVISIONAL caution:** has_url marks defangedhxxps/.invalid tokens; the legacyhttp(s)/www regex need not recognize them as URLs. Do not describe this as a clean true-HTTPS-versus-no-URL experiment or infer an exact deployed-feature mechanism. No post-score rewrite was made to fix this confound. Callback numbers use fictionalNANP55501xx rather than Indian mobile-format numbers, which can affect legacy phone features. Report these safe-syntax/geographic limitations before extrapolation.

## 4. Paired English twins and English TEST

**OBSERVED:** the paired comparison uses only each row's own English twin, not all480Hinglish against120English. 120random scenario pairs were selected before scores (seed202610220), adding both malicious andbenign English translations. Language/translation/noise artifacts remain possible; no pure causal-language claim is made. Each rate hasWilson95%; paired discordant outcomes/texts are in paired_English_comparisons.jsonl.

'''+table(['Model','Matched malicious Hinglish recall','Same-scenario English recall','English−Hinglish gap, points','English-only / Hinglish-only detections'],[[r['model'],rstr(r['pairing']['MALICIOUS']['Hinglish_alert_rate']),rstr(r['pairing']['MALICIOUS']['English_alert_rate']),f"{r['pairing']['MALICIOUS']['English_minus_Hinglish_pp']:.2f}",f"{r['pairing']['MALICIOUS']['English_only_alert']} / {r['pairing']['MALICIOUS']['Hinglish_only_alert']}"] for r in pairs])+'''
**OBSERVED paired benign controls:**

'''+table(['Model','Hinglish false-alert rate','English twin false-alert rate','English−Hinglish false-alert points'],[[r['model'],rstr(r['pairing']['BENIGN']['Hinglish_alert_rate']),rstr(r['pairing']['BENIGN']['English_alert_rate']),f"{r['pairing']['BENIGN']['English_minus_Hinglish_pp']:.2f}"] for r in pairs])+'''
**OBSERVED English TEST comparison:** fullTEST reproduces the requiredV4.3 target1510/1556 and2/520before anyprobe inference. English-only uses metadata language en/English, with actual denominators below; it is not mislabeled as the fullTEST. TEST/OOD language count/hash evidence is report_input_counts.json; both contain3hinglish-tagged records. TEST is an older different scenario/source distribution, not a matched language control.

'''+table(['Model','TEST scope','Attack detections / N','Recall','Benign MALICIOUS alerts / N','Spam MALICIOUS alerts / N'],[[r['model'],r['scope'],f"{r['TP_M_only']}/{r['malicious_n']}",pct(r['TP_M_only']/r['malicious_n'] if r['malicious_n'] else None),f"{r['benign_FP_M_only']}/{r['benign_n']}",f"{r['spam_FP_M_only']}/{r['spam_n']}"] for r in eng])+'''
**PROVISIONAL:** text-only paired English gains span15.833–42.5points, with all eight above the10point recall-also threshold. The English synthetic controls can also be harder than EnglishTEST; therefore this study finds both language sensitivity and scenario/style shift, not solely one causal defect.

## 5. Condition 2: sender-header metadata (V2 only)

**OBSERVED:** onlyV2's feature pipeline accepts sender_header. V4.3andV4.4 extract text-only structural signals, so no fake condition2 is created by prepending metadata. SMS headers are fictionalDLT-shaped labels (e.g.AD-NAVBNK), not verified sender identity. Compare the sameSMS-style Hinglish rows, not alltext rows againsttheSMSsubset:

'''+table(['Model / condition','SMS malicious recall','SMS benign false alerts','SMS spam false alerts'],[[r['model']+'/'+r['condition'],rstr(r['malicious_recall']),rstr(r['benign_false_alert']),rstr(r['spam_false_alert'])] for r in ([lookup('V2','channel_style','SMS')]+[r for r in metrics if r['scope']=='all' and r['language']=='Hinglish' and r['condition']=='SMS_with_sender_header'])])+'''
**OBSERVED:** with sender metadataV2 detects7/240Hinglish SMS attacks(2.917%) while falsely alerting on4/240benign and0/60spam. This supports investigating learned sender-trust sensitivity; it does not prove a real sender-authentication bypass or an Android runtime defect. Headers are invented, and this is frozen Python feature behavior only. Condition2 verdict andEnglish pairing are separately recorded; it also satisfies recall-also. No threshold was changed.

## 6. Three-way confusion, raw output and overlap controls

**OBSERVED:** matrix order true rows/predicted columns=BENIGN,SPAM,MALICIOUS. The MALICIOUS-only endpoint remains constant. Complete per-model raw probabilities/final classes are probe_predictions.jsonl; raw-argmax metrics are raw_argmax_metrics.jsonl, not substituted for the locked operating result.

'''+table(['Model / condition','BENIGN row B/S/M','SPAM row B/S/M','MALICIOUS row B/S/M'],[[r['model']+'/'+r['condition']]+[str(x) for x in r['confusion_true_by_pred_B_S_M']] for r in metrics if r['scope']=='all' and r['language']=='Hinglish'])+'''
**OBSERVED:** source audit covers79text-bearing corpus/report sources,23classifiedtraining sources. Conservative report examples count as past exposure; source paths/hashes, parser errors and normalization are in corpus_audit_manifest.json. No normalized-exact/tokenJaccard≥.85 cross-corpus overlaps were flagged. Eight intraprobe near edges form components ofsize2(max), within the3rowcap. No post-score filtering is used for the primary verdict.

'''+table(['Model','Scope','Hinglish recall','Benign false-alert rate','Spam false-alert rate'],[[r['model'],r['scope'],rstr(r['malicious_recall']),rstr(r['benign_false_alert']),rstr(r['spam_false_alert'])] for r in metrics if r['condition']=='text_only' and r['language']=='Hinglish' and r['scope'] in ('all','without_corpus_overlap','without_intra_near_duplicates')])+'''
**PROVISIONAL audit limits:** a zero lexical-overlap screen does not certify semantic/template independence, true human-label validity or all historical provenance. Excluded config/model/cache/prohibited/sealed paths are enumerated by the audit rules; text-bearing records in supportedformats were audited without opening datasets_v5/user_data oranysealedexam. Design was fixed before generation; setfinalhash was recorded before inference. The original andallunflagged metrics remain immutable.

## 7. Label QA and user review

**OBSERVED:** a separate content-only deterministic blind process read opaque text/channel/header/language fields without expected,family,pair fields. It assigned all1320labels and disagreed with80author labels. This is file-level blindness, not independenthumanreview: the same author knows the grammar and its rule classifier is fallible. Disagreements are retained inblind_disagreements.csv with rationale; no expected label was changed to improve scores.

**OBSERVED:** REVIEW_SAMPLE.csv contains202unique rows: the seeded50malicious,50benign,25spam Hinglish sample plus everyblinddisagreement not already sampled. user_agree/user_note remainblank. Read the benign/spam intent boundaries, legitimate deliveryPIN handoff, verifiedfriend moneycases, loan/recovery threats, noisyshortmessages andall disagreementrationales before deciding label correctness. Mark wrong intended labels explicitly. No user review has arrived, so corrected_user_review scope currentlyexcludeszero rows and equalsoriginal; it is not a verified correction. A futureuser review mustcreate aNEWexclusion/analysisartifact; retainthisoriginal frozen exam unchanged.

## 8. Twenty-five worst misses and false alerts per model

**OBSERVED decisions / ASSUMED labels:** worst_25_misses_per_model.csv ranksHinglishmaliciousfalse negatives byascendingpM; worst_25_false_alerts_per_model.csv ranksbenign/spamalerts bydescendingpM,withtext,expected/finalclass,family,style,density,noise,lengthandprobabilities. They hold25/condition when enough errors exist, otherwiseallavailableerrors,neverfabricatedexamples. Tablesbelowgive representative rows; theCSVfiles containthecomplete requestedper-model lists,includingcondition2.

'''
miss=csvread('worst_25_misses_per_model.csv');false=csvread('worst_25_false_alerts_per_model.csv')
s+=table(['Model','Worst miss example','Predicted','pM'],[[m,next(r['text'] for r in miss if r['model']==m and r['condition']=='text_only'),next(r['predicted'] for r in miss if r['model']==m and r['condition']=='text_only'),next(r['p_malicious'] for r in miss if r['model']==m and r['condition']=='text_only')] for m in models])
s+='\n'+table(['Model','Worst false-alert example','Expected','pM'],[[m,next(r['text'] for r in false if r['model']==m and r['condition']=='text_only'),next(r['expected'] for r in false if r['model']==m and r['condition']=='text_only'),next(r['p_malicious'] for r in false if r['model']==m and r['condition']=='text_only')] for m in models])
s+='''
## 9. The87.1%lead and earlier intentionalHinglish tests

**REPORTED master §6.2:** V2Hinglish smishing recall87.1%,67missesoutof520. **OBSERVED source attribution:** `7sep_messages_v3/reports/HINGLISH_520_ATTACK_AUDIT.json` embeds520attack records in detailed_eval,13categories×40,with p_v2/v2_detected andp_v3_ts/v3_ts_detected. It reportsV2=327/520=62.885% andV3two-stage=453/520=87.115%(67misses). Thus87.1%belongs toV3two-stageinthat source,notV2. These oldresults areREPORTED,not newly reproduced; originalauthoring/tool/environment provenance oftheembedded520 isnotcertified. Hashes,recordschema andcategorycounts are historical_87_1_lead.json.

**REPORTED older report:** HINGLISH_ROBUSTNESS_REPORT.md describesa100rowslice with50maliciousV2recall14%=7/50,anda separate80semanticpair study. Its data sourcebench_hinglish_robustness.jsonl existsandwascounted/hashed. Therefore“neverintentionallytested”isnottrueforV2intheexistingrepository; that doesnotdiminishthevalueofthisnewimmutableprobeorproveallcurrentvariantsweretestedpreviously. MasterV2TEST94.2%alsoconflictswiththecurrenttext-onlyreproduction; neitheris silentlyusedastheother'sbaseline. Do notmixV3deterministicpolicyescalation,oldV2features,fullTEST,andnewHinglishcontrolcohorts.

## 10. Five informative patterns and disposition

1. **OBSERVED / PROVISIONAL:** all eighttext-onlyrecallsare23.96–65.42%,eachbelow85%;thefalse-positive-onlyhypothesisfails undertheregisteredrules. PairedEnglishimprovementis15.83–42.5points,withscenario/styleandtranslationcaveats.
2. **OBSERVED / PROVISIONAL:** URL-lessattacksareparticularlyweak(V4.3=75/288,V2=35/288),includingcallbackandreply-onlyfamilies. DefangedURL/nonnativephone-formatlimitationsmeanthestructuralcomparisonisdiagnostic,notanequivalentdeploymentsimulation.
3. **OBSERVED:** missesmostlybecomeBENIGN,notSPAM(V4.3all273;V2=358of365). Spam-never-alertsdoesnotexplainawaythoselowrecalls.
4. **OBSERVED / PROVISIONAL:** V2SMSsenderheadersdriveattackdetectiondownto7/240;same-rowtext-onlycomparisonisgivenabove. Learnedmetadata/trustfeaturesneedinvestigation; thisisnotproofaboutrealverifiedsendersorAndroidpolicy.
5. **OBSERVED / PROVISIONAL:** falsealertsremainmaterialtoo(V4.3=87/480benign,20/120spam;CandidateA=203/480benign). Candidatechangestradeoffrecallandbenign/spamalerts;thisexamdoesnotauthorizeaselectedmodel,thresholdtweakortraining.

**STOP:** Stage0iscompleteafterthefinalintegrity/evidencechecks. Recallisalsoamaterialproblemforthefrozenreference models,sothecontinuationconditiondoesnotpermitstartingStage1. TheuserhasalsosaidStage1willbeprovidedafterStage0. Waitforuserreview/instruction; donotrequestGPU,train,finetune,tuneagainstthisexam,copyittotrainingdata,orstartasprintimplementation.
'''
with (OUT/'HINGLISH_PROBE_RESULTS.md').open('x',encoding='utf-8') as f:f.write(s)
save('stage0_disposition.json',{'stage0':'COMPLETE_PENDING_FINAL_INTEGRITY','verdict_all_eight_text_only':'Recall is also a problem','proceed_to_Stage1':False,'reason':'pre-registered recall-also rules triggered for both frozen reference models; user said Stage1 will be supplied afterStage0','GPU_requested':False,'user_review_needed':'REVIEW_SAMPLE.csv, all80blinddisagreements andassumedlabels; no labelcorrection ortrainingauthorized'})
print(table(['Model','Hinglish recall','Wilson95','Verdict'],[[r['model'],pct(r['malicious_recall']['rate']),str([round(100*v,1) for v in r['malicious_recall']['Wilson95']]),vmap[r['model']]['verdict']] for r in summary]))
