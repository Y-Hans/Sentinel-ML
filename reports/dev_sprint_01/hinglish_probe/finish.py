from probe_lib import *
import datetime,collections
protect()
old=load('protected_before.json');after={p:{'bytes':(ROOT/p).stat().st_size,'sha256':sha(ROOT/p)} for p in old};changed=[p for p in old if old[p]!=after[p]]
save('protected_after.json',after)
if changed:save('HARD_STOP_HASH_CHANGE.json',{'changed':changed});raise RuntimeError('HARD_STOP_PROTECTED_HASH_CHANGE: '+str(changed))
g=subprocess.run(['git','-C',str(ROOT/'sentinel-ai'),'status','--porcelain'],cwd=ROOT,capture_output=True,text=True,env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'});before=load('git_before.json')
save('git_after.json',{'argv':g.args,'cwd':str(ROOT),'exit_code':g.returncode,'stdout':g.stdout,'stderr':g.stderr})
if before['stdout']!=g.stdout:raise RuntimeError('HARD_STOP_GIT_STATUS_CHANGE')
f=load('freeze_manifest.json');inf=load('inference_manifest.json');assert sha(OUT/'probe_set.csv')==f['sha256'];assert sha(OUT/'HINGLISH_PROBE_DESIGN.md')==inf['design_sha256_before_probe']
assert not any(set(Path(p).parts)&BLOCKED for p in old)
review=csvread('REVIEW_SAMPLE.csv');assert all(not r['user_agree'] and not r['user_note'] for r in review)
qa=load('quality_checks.json');assert qa['status']=='PASS'
paths={line[3:]:line[:2] for line in before['stdout'].splitlines()};apaths={line[3:]:line[:2] for line in g.stdout.splitlines()}
save('integrity_checks.json',{'status':'PASS','protected_existing_files':len(old),'changed':changed,'git_file_by_file_identical':True,'git_paths':[{ 'path':p,'before':paths.get(p),'after':apaths.get(p)} for p in sorted(set(paths)|set(apaths))],'git_exit_codes':[before['exit_code'],g.returncode],'probe_sha256':sha(OUT/'probe_set.csv'),'design_sha256':sha(OUT/'HINGLISH_PROBE_DESIGN.md'),'freeze_hash_unchanged':True,'design_unchanged_since_inference':True,'user_review_columns_blank':True,'CPU_only':True,'GPU_requested':False,'training_fits':0,'threshold_changes':0,'exports':0,'Android_Kotlin_Gradle_runs':0,'excluded_prohibited_inputs':['datasets_v5','user_data']})
save('final_command.json',{'argv':sys.orig_argv,'cwd':str(ROOT),'python':sys.version,'interpreter':sys.executable,'completed_checks_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':0,'note':'external shell exit0 confirms completion; no logging wrapper writes after output manifest'})
commands=[load(p.name) for p in sorted(OUT.glob('*.command.json'))];save('command_ledger.json',commands)
def table(h,rr):return '| '+' | '.join(h)+' |\n| '+' | '.join('---' for _ in h)+' |\n'+'\n'.join('| '+' | '.join(str(x).replace('|','/').replace('\n',' ') for x in row)+' |' for row in rr)+'\n'
core=['HINGLISH_PROBE_DESIGN.md','probe_set.csv','probe_set.sha256','REVIEW_SAMPLE.csv','HINGLISH_PROBE_RESULTS.md','probe_predictions.jsonl','RUN_EVIDENCE.md']
files=sorted(set([p.relative_to(OUT).as_posix() for p in OUT.rglob('*') if p.is_file()]+['RUN_EVIDENCE.md','output_manifest.json','COMPLETION.json']))
cmdtable=table(['Exact command argv','CWD','Exit','Seconds'],[[' '.join('"'+str(a)+'"' for a in c['argv']),c['cwd'],c['exit_code'],round(c['seconds'],3)] for c in commands])
modelpaths=['sentinel-ml/6sep/messages/final/champion_v2_model.pkl','sentinel-ml/Messages-ml/messages_v4_3/models/candidate_d/model.pkl']+[p for p in old if re.fullmatch(r'sentinel-ml/Messages-ml/messages_v4_4/models/[^/]+/model\.pkl',p)]
hashtable=table(['Model artifact','Before SHA-256','After SHA-256'],[[p,old[p]['sha256'],after[p]['sha256']] for p in modelpaths])
evidence=f'''# Stage 0 run evidence — CPU only

Date: October 22, 2026 (Asia/Calcutta). **OBSERVED:** all requested artifacts are written under `{OUT}`. No files outside this new folder were written, no candidate training/calibrator/tokenizer fit was run, no GPU was requested, no model/threshold was changed/exported/promoted, no Android/Kotlin/Gradle was executed, and no Git mutation was performed. Neither `sentinel-ml/datasets_v5/` nor `user_data/` was opened. Stage1 is NOT started; the user will supply it after Stage0, and the recall-also verdict requires stopping here.

## Design, generation and freeze order

**OBSERVED:** DESIGN_PREREGISTERED.md was written before generation. `generate.py` uses author-written family action/benign contrasts and forty author-written framing/English translation patterns, eight personas in forty27-rowHinglish batches, deterministic noise/style variation and seed202610220. No model imports/scores occur during generation. All1,320rows are ASSUMED single-author synthetic intent, not real user reports or independent human adjudication. Counts are480M/480B/120S Hinglish and120M/120B English. SMS/WhatsApp are50/50 per Hinglish class;288/480attacks are URL-less. Actual word bins:190short,539medium,351long among1,080Hinglish rows. Domains end.invalid and are defangedhxxps; phone numbers use fictionalNANP55501xx. No network access, DNS or executable payload is present.

**OBSERVED:** score-free intraprobe audit has8Jaccard≥.85edges,maxcomponent2,cap3passes. Corpus audit covers79text-bearing sources,23training-role sources,normalizedexact andtokenJaccard≥.85;crosscorpusflags0. Full manifests list sourcepaths/hashes,errors andlexical/provenance limitations. Blind process sees onlyopaque text/channel/header/language fields,noexpected/family/pairs;80disagreements preserved,notrelabeled. REVIEW_SAMPLE.csvcontains202rows:base50M/50B/25S plusallremainingdisagreements,emptyuser_agree/user_note. Blindrulepass isfile-level blindbutnotindependenthumanreview; grammar isknownbythesameauthor.

**OBSERVED immutable freeze:** probe_set.csv SHA-256 `{f['sha256']}`; rows1,320; freeze timeUTC `{f['frozen_UTC']}`. Frozen design SHA-256 `{sha(OUT/'HINGLISH_PROBE_DESIGN.md')}`. Final design wascreated once frompreregistereddesign plusfreezecommitment BEFORE infer.py. Datasetanddesign hashesremainunchanged afterscores. No score-ledregeneration,modelselection,thresholdtuningortraining occurred. Thissetremainsexam materialandmustnotenterlatertraining. Draftretainedunderitsownfilename;actualfrozenCSVbytesareidenticalto theauditeddraft,notareplacementforahistoricalartifact.

## Runtime and reproduction

**OBSERVED:** interpreter`{inf['interpreter']}`,Python`{inf['python']}`;numpy`{inf['numpy']}`,sklearn`{inf['sklearn']}`. EnvironmentCUDA_VISIBLE_DEVICES=-1,OMP/OPENBLAS/MKLthreads1,PYTHONDONTWRITEBYTECODE=1;Python-B. OnlyCPU sklearn frozen tree inference wasused;nottorch/tensorflow/GPUinference. All eightfrozenmodel bundles loaded;unpicklewarningsandartifact/scaler/vectorizerhashesarelistedininference_manifest.json. Reusedrun_02paths,featureorderingandthresholds(V2.704,V4.3.61,V4.4configs),withoutimportingoldscriptsthatwritefiles.

**OBSERVED gate:** V4.3 fullTESTmalicious-class1510/1556andbenignanyalert2/520at.61reproducedBEFOREprobescores. TEST/OODmetadata languagecountsandhashesareinreport_input_counts.json;bothcontain3hinglish-taggedrecords. English-onlymetadatasubsetandfullTESTMALICIOUS-onlycountsarekeptseparateinEnglish_TEST_comparison.json. No reproductiontargetwasmadeconvenientbychoosinganotherthreshold.

**OBSERVED:**11,220predictionrows=8×1,320text-only +660V2SMS-header rows. All preserveP(B),P(S),P(M),p(non-benign),rawargmax,finalthresholdedclass,andMALICIOUS-onlyalert. assert(SPAM⇒noalert)passes. V4.3/V4.4arenotgivenafakesendercondition;theirtext-onlyfeaturecontractdoesnotacceptheaders. V2headersareinventedmetadata,notverifiedrealDLTidentity. Allper-modelsourcehashes,conditions,exactτsandwarningsareininference_manifest.json.

## Commands, working directory, exit codes

**OBSERVED exactscientificchildcommands:** workingdirectory`{ROOT}`. Eachcommandhasadjacentstdout/stderr,anindividual.command.jsonrecordwithexitcode/duration/environment/outputhashes,andthisconsolidatedcommand_ledger.json. Allsuccessfulscientificstepsbelowexit0.

{cmdtable}

**OBSERVED directfinalcommand:**

```powershell
python -B reports/dev_sprint_01/hinglish_probe/finish.py
```

Itperformsfinalhash/Git/freezechecks,writesthisevidenceandoutputmanifest,validatesalllistedoutputs,printscompletiondigest,andmustexit0forevidencecompletion.final_command.jsonrecordsoriginalargv,cwd,interpreterandchecktime;thetool'sshellresultconfirmsexitcode. Read-onlyGet-Content,rgandGet-ChildItemdiscoverycommandsprecededscientificscripts;everyreportednumericclaimwasthenrederivedbytheloggedscriptsorREPORTEDfromhash-listedhistoricalsources.Noerrorrecoverychangedthesetorlabels.

## Primary protected model hashes

{hashtable}

**OBSERVED:** all{len(old)}inventoriedexistingML/Androidsource/model/datafileshaveidenticalbefore/afterSHA-256andbytecounts;fullper-filemapsareprotected_before.json/protected_after.json. Companionweights/scalers/vectorizers,data,schemas,APKsandmodelconfigsareincluded. Exclusions:hidden/build/tool/venv/cachefolders,newpermittedexperimentfolders,andexplicitprohibiteddatasets_v5/user_data. Thisisascope-definedaudit,notawhole-disksnapshot. Noneoftheprohibitedinputfolderswastraversedorhashed.Theoldsource/master/reportsremainunchanged;allnewwriteswereguardedtoallowedprobeoutputs.

## Git status, file by file

**OBSERVED before:**

```text
{before['stdout'].rstrip()}
```

**OBSERVED after:**

```text
{g.stdout.rstrip()}
```

**OBSERVED:** exactporcelainstringsandexitcodesmatch;integrity_checks.jsonalsoenumerateseachpath'sbefore/aftertwo-characterstatus.Noadd/commit/reset/revert/checkout/stash/clean/buildwasused.GIT_OPTIONAL_LOCKS=0.

## Metrics, QA and corrected analysis

**OBSERVED decisions / ASSUMED labels:** allratiosuseMALICIOUS-onlyalerts. 95%Wilsonintervalsusez1.959963984540054;N<30flaggedindicativeonly. Wilsonintervalsdescribeeventrows,notindependentscenario/populationuncertainty. Family/channel/URL-like/density/noise/actual-lengthandpersona/batchcellsareprobe_breakdowns.jsonlandPROBE_BREAKDOWNS.csv. All/unflaggedsource-overlap/intraprobe-near-neighborversionsarepreserved,withoutalteringtheprimaryverdict.PairedEnglishusesmatchedtwinsforbothlabels,retainingdiscordantcasesandtexts.No50/50sampleshareisreportedasanaturaldeploymentprevalence.

**OBSERVED:** originalandcorrected_user_reviewscopescoincidewithzerouserexclusionsbecauseuser_agree/user_notearestillblank.Thatdoesnotmeanlabelsarevalidated;80blinddisagreementsareNOTusedasautomaticcorrections.Whenuserreviewarrives,createnewimmutableexclusion/metricfilesandreportwronglabelsseparately,retainingthisoriginalset/report.WorstmissandfalsealertCSVscontain25permodel/conditionwhereavailable;fewererrorsarereportedhonestly.

**OBSERVED attribution / REPORTED oldoutcomes:** master§6.2's87.1%leadmisattributesV3two-stage453/520toV2;embedded520auditreportsV2327/520(62.885%). Older100rowHinglishslicealreadyexists,withreportedV27/50(14%). Sourcehashes,embeddedrecordschemaandcountsarehistorical_87_1_lead.json.Nooldreportedscoreisrepresentedasanewreproductionorusedtotunethisprobe.

**PROVISIONAL limitations:**singleauthor/grammarandstylecorrelation;file-levelruleblindnessnotindependentreview;unreviewedlabel/benign-versus-spam/legit-secret-handoffboundaries;translatedEnglish/noiseconfounds;nonfunctionalhxxpsURLsnotlegacyhttp(s)featureinputs;fictionalnon-Indianphoneformat;fictitioussenderheadersnotauthenticatedsenders;lexicalzerooverlapnotsemanticindependence.NoAndroidfusedpolicyorreal-worldrateisclaimed.Afailisinformative,apasswouldnotprovereal-worldrecall.

## Files created and completion

**OBSERVED:** allnewfilesareunderreports/dev_sprint_01/hinglish_probe/. Nofilenamethatexistedbeforethispasswasoverwritten.output_manifest.jsonlistsper-fileSHA-256andbytecountsforalloutputsbesidesitselfandthecompletionanchor.COMPLETION.jsoncommitstheoutputmanifestdigest;itsownhashisprintedinthefinalcommandoutputtoavoidacircularself-hash.

'''+ '\n'.join('- `'+p+'`' for p in files)+'''

**STOP/disposition:** Stage0complete,all8text-onlymodels“Recallisalsoaproblem”undertheunchangedproposedrules;Stage1notstarted.NoGPUrequestedandnotrainingqueued.UsermustreviewREVIEW_SAMPLE.csv(especiallyall80blinddisagreements),confirm/correctsyntheticintentlabels,thenprovidethenextinstruction.Thisexamanditsresultsarefrozenandmustnotbeusedfortrainingortuning.
'''
with (OUT/'RUN_EVIDENCE.md').open('x',encoding='utf-8') as h:h.write(evidence)
for n in core:assert (OUT/n).exists()
manifest={p.relative_to(OUT).as_posix():{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(OUT.rglob('*')) if p.is_file() and p.name not in ('output_manifest.json','COMPLETION.json')}
save('output_manifest.json',manifest)
assert all(sha(OUT/p)==v['sha256'] for p,v in manifest.items())
save('COMPLETION.json',{'status':'STAGE0_COMPLETE_STOP_WAIT_USER','verdict':'Recall is also a problem for all eight text-only models','core_files':{n:sha(OUT/n) for n in core},'protected_files_unchanged':len(old),'git_status_identical':True,'probe_hash_unchanged':True,'CPU_only':True,'GPU_requested':False,'training_fits':0,'Stage1_started':False,'output_manifest_sha256':sha(OUT/'output_manifest.json'),'user_review_needed':True})
print(json.dumps({'exit_code':0,'protected_files_unchanged':len(old),'git_status_identical':True,'probe_sha256':f['sha256'],'core_files':len(core),'new_files':len(manifest)+2,'COMPLETION_sha256':sha(OUT/'COMPLETION.json'),'verdict':'Recall is also a problem — all eight','Stage1_started':False,'GPU_requested':False},indent=2))
