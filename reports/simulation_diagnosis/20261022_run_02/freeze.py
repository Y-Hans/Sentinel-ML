from runlib import *
from data_utils import *
import collections,random,secrets,unicodedata
protect()
rows=readrows(OUT/'merged_recovered_v2.jsonl')
adjudication=[]
for base in ('sentinel-ml','sentinel-ai/docs'):
    for d,dirs,names in os.walk(ROOT/base):
        dirs[:]=[x for x in dirs if x not in ('venv','tools','__pycache__','simulation_run_02') and not x.startswith('.')]
        for n in names:
            if n.endswith(('.md','.json')):
                p=Path(d)/n
                if p.stat().st_size>2000000: continue
                s=p.read_text(encoding='utf-8',errors='replace')
                for lineno,line in enumerate(s.splitlines(),1):
                    if re.search(r'29 natural|31 non.green|human review|all 29|threat_records\.json',line,re.I): adjudication.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'line':lineno,'excerpt':line[:2000]})
jsave('adjudication_search.json',{'hits':adjudication,'record_level_human_label_map_found':False,'reason':'aggregate narrative claims found, no hash-linked 31-row human annotation file in searched sources; docs inspected do not provide per-record review IDs','not_found':'threat_records.json'})
def annotate(r,origin):
    s=text(r); sc=script(s)
    nonlatin=any(c.isalpha() and 'LATIN' not in unicodedata.name(c,'') for c in s)
    risky=bool(urls(s) or re.search(r'\d{6,}|\b(otp|pin|pay|payment|bank|upi|account|bill|password|kyc)\b',s,re.I) or nonlatin)
    status='PROVISIONAL_BENIGN_UNREVIEWED' if r.get('riskLevel')=='GREEN' and not risky else 'NEEDS_REVIEW'
    return {**r,'uid':origin+':'+str(r.get('id',r.get('message_id')))+':'+hashlib.sha256((s+str(r.get('timestamp'))).encode()).hexdigest()[:12], 'text':s,'origin':origin,'label_status':status,'y':0 if status=='PROVISIONAL_BENIGN_UNREVIEWED' else None,'channel':str(r.get('source','UNKNOWN')),'conversation':groupguess(r),'language':language(s),'script':sc,'attack_family':'UNKNOWN','synthetic':False,'group':str(r.get('source','UNKNOWN'))+'|'+str(r.get('senderIdentifier') or r.get('senderDisplayName') or r.get('sender_header') or 'UNKNOWN')}
natural=[annotate(r,'recovered') for r in rows]
# Preserve the 294 labeled replay as an explicitly REPORTED-label auxiliary source, never human-adjudicated.
for r in readrows(ROOT/'sentinel-ml/7sep_messages_v3/data/bench_sentinel_replay.jsonl'):
    rr=annotate({**r,'content':r['raw_text'],'riskLevel':r['db_risk_level'],'riskScore':r['db_risk_score'],'pull_id':'reported_replay_294'},'reported_replay')
    rr['reported_security_label']=r['security_label']; rr['auxiliary_y']=1 if r['security_label']=='MALICIOUS' else 0
    natural.append(rr)
with (OUT/'REVIEW_SHEET.csv').open('x',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['id','pull_id','channel','text','logged_prediction','label_status','reviewer_label','reviewer_note']); w.writeheader()
    for r in natural:
        for pull in r.get('pull_ids',[r.get('pull_id')]): w.writerow({'id':r.get('id'),'pull_id':pull,'channel':r['channel'],'text':r['text'],'logged_prediction':json.dumps(r.get('logged_predictions',{'level':r.get('riskLevel'),'score':r.get('riskScore')}),ensure_ascii=False),'label_status':r['label_status'],'reviewer_label':'','reviewer_note':''})
# Reserve unseen-by-inference entire sender/channel groups before synthesis, overlap or model execution.
groups=sorted(set(r['group'] for r in natural)); rng=random.Random(20261022); rng.shuffle(groups); reserved=set(groups[:max(1,len(groups)//5)])
exam_real=[r for r in natural if r['group'] in reserved]; sim=[r for r in natural if r['group'] not in reserved]
# Authored diagnostic templates; values are assumptions, not native independently reviewed ground truth.
templates={
'English':['Lunch after class tomorrow?','Your OTP is 482913. Do not share it with anyone.','Exam timetable is posted on the college notice board.','Your power will be cut tonight. Call 9876543210 and pay the agent now.','Send me the OTP you just received to keep your account active.'],
'Hinglish':['Bhai kal class ke baad lunch kare?','Aapka OTP 482913 hai. Kisi ko mat batana.','College ka exam timetable notice board par hai.','Aaj raat bijli kat jayegi. Abhi 9876543210 par call karke agent ko paise bhejo.','Account chalu rakhne ke liye abhi aaya OTP mujhe bhejo.'],
'Hindi':['कल कक्षा के बाद खाना खाएँ?','आपका OTP 482913 है। इसे किसी के साथ साझा न करें।','परीक्षा की समय सारणी कॉलेज के सूचना पट पर है।','आज रात बिजली काट दी जाएगी। अभी 9876543210 पर फोन करके एजेंट को पैसे भेजें।','खाता चालू रखने के लिए अभी आया OTP मुझे भेजें।'],
'Gujarati':['કાલે વર્ગ પછી જમવા જઈએ?','તમારો OTP 482913 છે. કોઈને આપશો નહીં.','પરીક્ષાનું સમયપત્રક કોલેજના સૂચના બોર્ડ પર છે.','આજે રાત્રે વીજળી કપાશે. હવે 9876543210 પર ફોન કરીને એજન્ટને પૈસા મોકલો.','ખાતું ચાલુ રાખવા હમણાં આવેલો OTP મને મોકલો.'],
'Tamil':['நாளை வகுப்புக்குப் பிறகு சாப்பிடலாமா?','உங்கள் OTP 482913. யாரிடமும் பகிர வேண்டாம்.','தேர்வு அட்டவணை கல்லூரி அறிவிப்பு பலகையில் உள்ளது.','இன்று இரவு மின்சாரம் துண்டிக்கப்படும். இப்போது 9876543210 அழைத்து முகவருக்கு பணம் அனுப்புங்கள்.','கணக்கை செயல்பாட்டில் வைத்திருக்க வந்த OTP எண்ணை எனக்கு அனுப்புங்கள்.'],
'Telugu':['రేపు తరగతి తర్వాత భోజనం చేద్దామా?','మీ OTP 482913. ఎవరితోనూ పంచుకోవద్దు.','పరీక్షల సమయ పట్టిక కళాశాల నోటీసు బోర్డులో ఉంది.','ఈ రాత్రి విద్యుత్ నిలిపివేస్తాం. ఇప్పుడు 9876543210 కి కాల్ చేసి ఏజెంట్ కు డబ్బు పంపండి.','ఖాతా కొనసాగడానికి ఇప్పుడే వచ్చిన OTP నాకు పంపండి.'],
'Bengali':['কাল ক্লাসের পরে খাবার খাব?','আপনার OTP 482913। কাউকে জানাবেন না।','পরীক্ষার সময়সূচি কলেজের নোটিশ বোর্ডে আছে।','আজ রাতে বিদ্যুৎ কেটে দেওয়া হবে। এখনই 9876543210 নম্বরে ফোন করে এজেন্টকে টাকা পাঠান।','অ্যাকাউন্ট চালু রাখতে সদ্য আসা OTP আমাকে পাঠান।'],
'Marathi':['उद्या वर्गानंतर जेवायला जाऊ या?','तुमचा OTP 482913 आहे. कोणालाही सांगू नका.','परीक्षेचे वेळापत्रक कॉलेजच्या सूचना फलकावर आहे.','आज रात्री वीज कापली जाईल. आता 9876543210 वर फोन करून एजंटला पैसे पाठवा.','खाते चालू ठेवण्यासाठी आत्ताच आलेला OTP मला पाठवा.'],
'Punjabi':['ਕੱਲ੍ਹ ਕਲਾਸ ਤੋਂ ਬਾਅਦ ਖਾਣਾ ਖਾਈਏ?','ਤੁਹਾਡਾ OTP 482913 ਹੈ। ਕਿਸੇ ਨਾਲ ਸਾਂਝਾ ਨਾ ਕਰੋ।','ਪ੍ਰੀਖਿਆ ਦਾ ਸਮਾਂ ਕਾਲਜ ਦੇ ਨੋਟਿਸ ਬੋਰਡ ਉੱਤੇ ਹੈ।','ਅੱਜ ਰਾਤ ਬਿਜਲੀ ਕੱਟੀ ਜਾਵੇਗੀ। ਹੁਣੇ 9876543210 ਉੱਤੇ ਫੋਨ ਕਰਕੇ ਏਜੰਟ ਨੂੰ ਪੈਸੇ ਭੇਜੋ।','ਖਾਤਾ ਚਾਲੂ ਰੱਖਣ ਲਈ ਹੁਣੇ ਆਇਆ OTP ਮੈਨੂੰ ਭੇਜੋ।']}
channels=[('SMS','1:1'),('WhatsApp','1:1'),('WhatsApp','group'),('other_app','UNKNOWN')]
for lang,tt in templates.items():
    for family,s in enumerate(tt):
        for ch,conv in channels:
            sim.append({'uid':f'synth:{lang}:{family}:{ch}:{conv}','text':s,'origin':'synthetic_diagnostic','label_status':'SYNTHETIC_AUTHORED','y':int(family>=3),'channel':ch,'conversation':conv,'language':lang,'script':script(s),'attack_family':['chat','legit_OTP','campus_exam','callback_scam','OTP_coercion'][family],'synthetic':True,'group':'authored_family_'+str(family),'pull_id':'synthetic','riskLevel':None})
# Corpus-wide normalized and Jaccard>=.85 tagging, never dropping.
train={}; corpus=[]
for d,dirs,names in os.walk(ROOT/'sentinel-ml/Messages-ml'):
    dirs[:]=[x for x in dirs if x not in ('__pycache__','simulation_run_02')]
    for n in names:
        if n.startswith('train') and n.endswith('.jsonl'):
            p=Path(d)/n; rr=readrows(p); corpus.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'rows':len(rr)})
            for r in rr: train.setdefault(norm(text(r)),set()).add(p.relative_to(ROOT).as_posix())
tok=[frozenset(k.split()) for k in train]; keys=list(train); inv=collections.defaultdict(set)
for i,t in enumerate(tok):
    for w in t: inv[w].add(i)
for r in sim:
    n=norm(r['text']); ts=frozenset(n.split()); exact=n in train; best=0.; hit=None
    if exact: best=1.; hit=n
    else:
        counts=collections.Counter(i for w in ts for i in inv.get(w,()))
        for i,inter in counts.items():
            if not tok[i] or min(len(ts),len(tok[i]))<.85*max(len(ts),len(tok[i])): continue
            score=inter/len(ts|tok[i])
            if score>best: best=score; hit=keys[i]
    r['overlap_exact']=exact; r['jaccard_max']=best; r['overlap_flag']=bool(exact or best>=.85); r['overlap_evidence']={'normalized_sha256':hashlib.sha256((hit or '').encode()).hexdigest(),'corpora':sorted(train.get(hit,set())) if r['overlap_flag'] else []}
jsonl('simulation_messages.jsonl',sim)
# URL training reference union: all candidate-training CSV sources, conservative superset when historical split unproven.
utr=set(); ud=set(); urlcorpus=[]
for name in ('cleaned_dataset.csv','data.csv','final_dataset.csv','v7_structural_benign.csv','v6_synthetic_benign.csv','remediation_hard_negatives_v1.csv','remediation_hard_negatives_v2.csv','remediation_hard_negatives_v3.csv'):
    p=ROOT/'sentinel-ml/URL-ml/data'/name; ct=0
    with p.open(encoding='utf-8-sig',newline='') as f:
        for rr in csv.DictReader(f):
            u=rr.get('url',rr.get('URL',''))
            if u: utr.add(norm(u)); ud.add(domain(u)); ct+=1
    urlcorpus.append({'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'rows':ct,'scope':'conservative training-source superset; includes holdouts where historical fit lineage not separable'})
urlsim=[]
for r in sim:
    if r['synthetic']: continue
    for i,u in enumerate(urls(r['text'])): urlsim.append({'uid':r['uid']+':url'+str(i),'url':u,'origin':r['origin'],'label_status':'NEEDS_REVIEW','y':None,'channel':r['channel'],'conversation':r['conversation'],'language':r['language'],'script':r['script'],'attack_family':'UNKNOWN','synthetic':False,'group':domain(u),'pull_id':r.get('pull_id'),'parent_uid':r['uid'],'riskLevel':r.get('riskLevel')})
safe=['https://www.instagram.com','www.instagram.com','//www.instagram.com','instagram.com','http://www.instagram.com','https://github.com/example/project/blob/main/README.md','https://www.google.com/search?q=college+exam','https://irctc.co.in','https://paytm.com','https://tatapower-ddl.com/billpay','https://ahmedabadcity.gov.in/portal/index.jsp','https://bit.ly/unknown','https://192.0.2.10/status']
attacks=[('https://github.com/example/release/drop.apk','hosted_payload'),('https://www.google.com/url?q=https://credential-check.example/login','open_redirect_lure'),('https://sbi-kyc-update.xyz/login','credential_theft'),('http://198.51.100.9/login','IP_phishing_lure'),('www.bank-update.top/otp','credential_theft')]
for i,u in enumerate(safe):
    unknown=('bit.ly' in u or '192.0.2.' in u)
    urlsim.append({'uid':'url_synth_safe_'+str(i),'url':u,'origin':'synthetic_diagnostic','label_status':'SYNTHETIC_UNRESOLVED' if unknown else 'SYNTHETIC_AUTHORED','y':None if unknown else 0,'channel':'authored','conversation':'UNKNOWN','language':'NA','script':'NA','attack_family':'shortener_unresolved' if unknown else 'ordinary_url','synthetic':True,'group':domain(u),'pull_id':'synthetic','popularity':'CURATED_FAMILIAR_ASSUMED' if domain(u) in ('instagram.com','github.com','google.com') else 'UNKNOWN'})
for i,(u,fam) in enumerate(attacks): urlsim.append({'uid':'url_synth_attack_'+str(i),'url':u,'origin':'synthetic_diagnostic','label_status':'SYNTHETIC_AUTHORED','y':1,'channel':'authored','conversation':'UNKNOWN','language':'NA','script':'NA','attack_family':fam,'synthetic':True,'group':domain(u),'pull_id':'synthetic','popularity':'CURATED_FAMILIAR_ASSUMED' if domain(u) in ('github.com','google.com') else 'UNKNOWN'})
for r in urlsim:
    u=r['url']; r['url_form']=form(u); r.setdefault('popularity','UNKNOWN'); r['registrable_domain']=domain(u); r['overlap_exact']=norm(u) in utr; r['overlap_domain']=domain(u) in ud; r['overlap_jaccard']=None
    # URL token Jaccard exact computation against length-compatible training source rows is done in a separate index below.
utokens=[frozenset(x.split()) for x in utr]; ukeys=list(utr); ui=collections.defaultdict(set)
for i,ts in enumerate(utokens):
    for w in ts: ui[w].add(i)
for r in urlsim:
    ts=frozenset(norm(r['url']).split()); best=0.
    counts=collections.Counter(i for w in ts for i in ui.get(w,()))
    for i,c in counts.items():
        if min(len(ts),len(utokens[i]))>=.85*max(len(ts),len(utokens[i])): best=max(best,c/len(ts|utokens[i]))
    r['overlap_jaccard']=best; r['overlap_flag']=bool(r['overlap_exact'] or r['overlap_domain'] or best>=.85)
jsonl('simulation_urls.jsonl',urlsim)
# Separate exam grammar and reserved groups; contents are written, never scored or summarized by label.
# Distinct independently sourced future exam remains required: this seal prevents reuse this pass, not author knowledge.
secret=secrets.token_hex(16); ex=exam_real.copy()
for i in range(24):
    token=hashlib.sha256((secret+str(i)).encode()).hexdigest()[:10]
    ex.append({'uid':'sealed_authored_'+token,'text':('The registrar moved room '+str(100+i)+'; read the signed campus circular.' if i%2==0 else 'To reverse a transfer, send the verification code to caller '+str(7000000000+i)+'.'),'group':'sealed_family_'+str(i%4),'synthetic':True,'label_status':'SYNTHETIC_AUTHORED_UNREVIEWED','y':i%2,'exam_only':True})
jsonl('SEALED_EXAM_DO_NOT_SCORE.jsonl',ex)
jsave('freeze_manifest.json',{'evidence':'OBSERVED file counts/hashes; labels/provenance conditional','messages':{'path':'simulation_messages.jsonl','rows':len(sim),'sha256':sha(OUT/'simulation_messages.jsonl'),'label_status':dict(collections.Counter(r['label_status'] for r in sim)),'overlap_rows':sum(r['overlap_flag'] for r in sim)},'urls':{'path':'simulation_urls.jsonl','rows':len(urlsim),'sha256':sha(OUT/'simulation_urls.jsonl'),'label_status':dict(collections.Counter(r['label_status'] for r in urlsim)),'overlap_rows':sum(r['overlap_flag'] for r in urlsim)},'sealed_exam':{'path':'SEALED_EXAM_DO_NOT_SCORE.jsonl','sha256':sha(OUT/'SEALED_EXAM_DO_NOT_SCORE.jsonl'),'rows':len(ex),'heldout_real_groups':len(reserved),'authored_cases':24,'limitation':'PROVISIONAL seal, authors know grammar; no independent custodian; no scores/labels used in decisions this pass'},'message_training_corpora':corpus,'url_training_sources':urlcorpus,'PSL':{'path':PSL.relative_to(ROOT).as_posix(),'sha256':sha(PSL)},'grouping':'sender/channel, translations share scenario-family cluster, URLs PSL registrable domain','assumptions':{'prevalences':[.001,.01,.05],'message_daily_volume':300,'url_daily_volume':30,'bootstrap_seed':20261022,'bootstrap_replicates':2000,'CI':.95}})
print(json.dumps({'message_rows':len(sim),'URL_rows':len(urlsim),'sealed_rows':len(ex),'message_overlap':sum(r['overlap_flag'] for r in sim),'url_overlap':sum(r['overlap_flag'] for r in urlsim),'training_files':len(corpus)},indent=2))
