from sprintlib import *
import ast,random
guard()
# Read author phrases as literals; do not execute the old generator or import a model.
tree=ast.parse(small(OLD/'generate.py'))
F=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='F' for t in n.targets))
ATTACKS=[
 [('KYC band hone wali hai, bank OTP mujhe bhejo','KYC will be blocked; send me your banking OTP'),('account kholne ko apna netbanking password yahan likho','write your netbanking password here to unlock the account'),('bank jaanch ke liye ATM PIN agent ko batao','tell the agent your ATM PIN for the bank check'),('aaj account freeze hoga, card CVV reply karo','your account freezes today; reply with your card CVV'),('KYC bachane ko mere personal wallet mein fee daalo','pay a fee into my personal wallet to keep KYC active')],
 [('bank ka OTP mujhe forward karo, main transaction rokunga','forward your bank OTP to me so I can stop the transaction'),('login code isi chat mein bhejo, account theek karunga','send the login code in this chat so I can fix the account'),('jo chhe ank aaye hain mujhe suna do, bank verification hai','read me the six digits you received for bank verification'),('refund approve karna hai, apna OTP agent ko batao','tell the agent your OTP to approve the refund'),('bank password reset ka code reply karo, main support se hoon','reply with the bank password reset code; I am from support')],
 [('refund lena hai toh meri collect request PIN daalke approve karo','enter your PIN and approve my collect request to receive a refund'),('paisa receive karne ko UPI PIN mujhe batao','tell me your UPI PIN to receive money'),('galat transfer wapas milega, pehle mere wallet mein advance bhejo','first send an advance to my wallet to recover the wrong transfer'),('cashback ke liye apna bank OTP isi chat mein do','give your banking OTP in this chat for cashback'),('refund unlock karne ko private account mein security fee jama karo','deposit a security fee into a private account to unlock the refund')],
 [('parcel release karna hai, customs fee mere personal wallet mein bhejo','send customs fees to my personal wallet to release the parcel'),('courier verification ke naam par bank OTP mujhe batao','tell me your banking OTP for courier verification'),('delivery address theek karne ko card CVV yahan likho','write your card CVV here to correct the delivery address'),('parcel mein illegal samaan mila, case dabane ko mujhe paisa bhejo','illegal goods were found in your parcel; send me money to suppress the case'),('package rok diya hai, private account mein turant jurmana bhejo','your package is held; send a fine to a private account immediately')],
 [('raat ko bijli kategi, officer ke private wallet mein fee bhejo','power will be cut tonight; send fees to the officer private wallet'),('gas supply band hogi, reconnection ke liye bank OTP batao','gas supply will stop; tell me your banking OTP for reconnection'),('meter band hone se bachao, apna ATM PIN operator ko do','give the operator your ATM PIN to prevent meter shutdown'),('bijli notice cancel karne ko netbanking password reply karo','reply with your netbanking password to cancel the electricity notice'),('bill jama hai phir bhi line kategi, mere account mein emergency fee bhejo','power will be cut despite your paid bill; send an emergency fee to my account')],
 [('SIM aaj band hogi, porting OTP mujhe forward karo','your SIM stops today; forward your porting OTP to me'),('number chalu rakhna hai toh SIM code agent ko batao','tell the agent your SIM code to keep the number active'),('telecom KYC ke liye bank password yahan likho','write your bank password here for telecom KYC'),('network unblock karunga, bank OTP reply mein do','reply with your banking OTP so I can unblock the network'),('SIM verification abhi karo, private wallet mein service fee bhejo','verify your SIM now; send service fees to a private wallet')],
 [('lottery jeet gaye, inaam se pehle mere wallet mein tax bhejo','you won the lottery; send tax to my wallet before receiving the prize'),('car prize lene ke liye bank OTP mujhe do','give me your bank OTP to receive the car prize'),('reward release hoga, card CVV isi reply mein bhejo','send your card CVV in this reply to release the reward'),('lucky draw ka paisa chahiye toh private account mein fee daalo','pay fees into a private account to receive lucky draw money'),('cash inaam ka registration karo, ATM PIN agent ko batao','tell the agent your ATM PIN to register for the cash prize')],
 [('loan ke paise abhi mere wallet mein bhejo warna photos sabko bhejunga','send loan money to my wallet now or I will send your photos to everyone'),('contacts ko badnaam kar dunga, settlement private account mein karo','settle in a private account or I will shame you before your contacts'),('karza na diya toh gharwalon ko photo bhejunga, bank OTP do','give your banking OTP or I will send your photos to relatives over the debt'),('loan recovery hoon, apna bank password batao warna police bhejunga','I handle loan recovery; tell me your bank password or I will send police'),('tumhari edited photo group mein jayegi, abhi mere account mein paisa daalo','pay my account now or your edited photo goes to the group')],
 [('job pakki hai, joining se pehle recruiter ke wallet mein deposit bhejo','the job is confirmed; send a deposit to the recruiter wallet before joining'),('task ki salary nikalni hai toh pehle private account recharge karo','recharge a private account first to withdraw task earnings'),('interview seat bachane ko agent ko bank OTP batao','tell the agent your banking OTP to reserve the interview seat'),('ghar baithe naukri milegi, security fee personal UPI pe bhejo','send a security fee to personal UPI for a job from home'),('salary verification hai, apna netbanking password recruiter ko bhejo','send your netbanking password to the recruiter for salary verification')],
 [('giraftari rokni hai toh officer ke personal wallet mein settlement bhejo','send settlement money to the officer personal wallet to avoid arrest'),('challan cancel hoga, bank OTP isi reply mein do','reply with your banking OTP to cancel the traffic fine'),('tax refund ke liye apna card PIN agent ko batao','tell the agent your card PIN for the tax refund'),('police case dabane ko private account mein abhi paisa jama karo','deposit money in a private account now to suppress the police case'),('sarkari notice hata dunga, netbanking password mujhe bhejo','send me your netbanking password and I will remove the government notice')],
 [('bank update ka APK install karo aur SMS access mujhe do','install the bank update APK and give me SMS access'),('unknown app ki warning ignore karo, remote screen control chalu karo','ignore the unknown app warning and enable remote screen control'),('refund ke liye private APK chalao aur accessibility allow karo','run the private APK and allow accessibility for a refund'),('security check hai, meri app ko bank SMS padhne do','let my app read bank SMS for a security check'),('store chhodo, bheja hua package install karke phone access do','skip the app store; install the supplied package and give phone access')],
 [('main tera dost naye number pe hoon, bina verify kiye naye UPI par paisa bhej','I am your friend on a new number; send money to new UPI without verifying'),('hospital emergency hai, call mat karna bas mere naye account mein transfer kar','hospital emergency; do not call, just transfer to my new account'),('naam pe bharosa kar, family ko bataye bina mujhe turant paisa bhej','trust my name; send me money now without telling the family'),('purana number band hai, video call nahi hoga, private wallet mein fee bhej','my old number is off; no video call; send fees to a private wallet'),('main boss hoon, awaaz verify mat kar aur secret payment naye account mein kar','I am your boss; do not verify my voice; secretly pay the new account')]
]
VOICE=[('',''),('Kripya, ','Please, '),('Bhai, ','Friend, '),('Yaar sun, ','Listen, '),('Jaldi: ','Quickly: '),('Beta, ','Dear, '),('Ji, ','Hello, '),('Arre, ','Hey, ')]
PERSONA=['terse_service','formal_desk','friend','student','hurried_texter','household','merchant','colloquial_adviser']
LEVEL=['clean','texting_abbrev','missing_vowels','mixed_case','typos']
def noise(s,lev):
 maps={'texting_abbrev':{'nahi':'nhi','hai':'h','mujhe':'mjhe','karna':'krna','bhejo':'bhejdo'},'missing_vowels':{'account':'accnt','payment':'pymnt','private':'prvt','security':'secrty'},'typos':{'bank':'bnak','password':'passwrod','verification':'verificaton'}}
 for a,b in maps.get(lev,{}).items():s=re.sub(r'\b'+a+r'\b',b,s,flags=re.I)
 if lev=='mixed_case':s=' '.join(w.upper() if i%4==0 and '://' not in w else w for i,w in enumerate(s.split()))
 return s
rng=random.Random(202610230);accepted=[];tok=[];parent=[];sizes=[];rejects=collections.Counter()
def root(i):
 while parent[i]!=i:i=parent[i]
 return i
def admit(text):
 t=frozenset(norm(text).split());matches=[i for i,u in enumerate(tok) if min(len(t),len(u))>=.85*max(len(t),len(u)) and len(t&u)/len(t|u)>=.85]
 roots={root(i) for i in matches}
 if 1+sum(sizes[x] for x in roots)>3:return False
 i=len(tok);tok.append(t);parent.append(i);sizes.append(1)
 for x in roots:parent[x]=i;sizes[i]+=sizes[x]
 return True
def add(text,en,label,family,index,persona,hasurl,hasphone,pair):
 if not admit(text):rejects[label]+=1;return False
 r={'id':'','text':text,'expected':label,'family':family,'channel_style':'SMS' if index%2==0 else 'WhatsApp','sender_header':'AD-NOTICE' if index%2==0 else '', 'hinglish_density':'medium' if persona%3 else 'heavy','noise_level':LEVEL[index%5],'length_bin':'6_15' if len(text.split())<=15 else '16_30' if len(text.split())<=30 else '31_plus','has_url':str(hasurl).lower(),'has_phone':str(hasphone).lower(),'pair_id':pair,'english_twin_id':'','generator_batch':PERSONA[persona],'language':'Hinglish','word_count':len(text.split()),'label_status':'ASSUMED_SINGLE_AUTHOR_SYNTHETIC','english_text':en}
 accepted.append(r);return True
for fi,f in enumerate(F):
 fam,entities,ctx,oldatt,ben,enctx,oldena,enben=f
 for label,n in [('MALICIOUS',50),('BENIGN',33)]:
  for i in range(n):
   url=i%5<3;phone=i%5==3;pair=f'V2PAIR_{fi:02}_{i:02}';resource=f'https://q{rng.randrange(10000,99999)}.invalid/{rng.randrange(100000,999999):x}' if url else f'9000000{(fi*50+i)%1000:03}' if phone else ''
   for attempt in range(300):
    j=(i+attempt)%5;persona=(i+fi+attempt)%8;entity=entities[(i//5+attempt)%4]
    if label=='MALICIOUS':body,enbody=ATTACKS[fi][j]
    else:body,enbody=ben[(i+attempt)%4],enben[(i+attempt)%4]
    # Short context frames contribute scenario content, never filler to hit a length quota.
    style=(i//5+attempt)%4
    if style==0:body=f'{entity}: {body}';enbody=f'{entity}: {enbody}'
    elif style==1:body=f'{ctx[(i+attempt)%4]}; {body}';enbody=f'{enctx[(i+attempt)%4]}; {enbody}'
    elif style==2:body=f'{body}. {entity}';enbody=f'{enbody}. {entity}'
    body=VOICE[persona][0]+body;enbody=VOICE[persona][1]+enbody
    if phone:
     body+=f'. {"Is number par call karo" if label=="MALICIOUS" else "Saved helpline se confirm kiya"}: {resource}'
     enbody+=f'. {"Call this number" if label=="MALICIOUS" else "Confirmed with saved helpline"}: {resource}'
    elif url:body+=' '+resource;enbody+=' '+resource
    elif label=='MALICIOUS' and fi!=10:body+='. Reply karo';enbody+='. Reply here'
    body=noise(body,LEVEL[i%5]);enbody=noise(enbody,LEVEL[i%5])
    if i%13==0:body+=' 🙏';enbody+=' 🙏'
    if len(body.split())>36:rejects['length']+=1;continue
    if add(body,enbody,label,fam,i,persona,url,phone,pair):break
   else:raise RuntimeError('score-free generation exhausted '+fam+label+str(i))
EXTRA=[('Login OTP 420583 hai, sirf apne app mein daalna','Your login OTP is 420583; enter it only in your own app'),('Bank login code 680214 hai, teen minute valid hai','Your bank login code is 680214 and valid for three minutes'),('Rs 450 jama ho gaye, receipt app mein mil jayegi','Rs 450 was credited; the receipt is available in the app'),('Gas bill bhar diya hai, supply chalu rahegi','The gas bill is paid and supply will continue')]
for i,(s,en) in enumerate(EXTRA):assert add(s,en,'BENIGN','safe_OTP_transaction',i,i,False,False,'EXTRA'+str(i))
PRODUCTS=[('jooton','shoes'),('kitabon','books'),('kursiyon','chairs'),('pizza','pizza'),('headphones','headphones'),('chai','tea'),('bags','bags'),('shirts','shirts'),('sabun','soap'),('plants','plants')]
PROMOS=[('par weekend discount hai, dukaan pe dekh lena','have a weekend discount; see them in the shop'),('ki nayi range aa gayi, catalogue padh lo','have a new range; read the catalogue'),('ka combo offer hai, pasand ho toh order karna','have a combo offer; order if you like'),('ki sale lagi hai, rates brochure mein hain','are on sale; prices are in the brochure'),('par coupon milega, khareedna zaroori nahi','have a coupon; no purchase is required'),('ki clearance hai, sizes counter pe milenge','are on clearance; find sizes at the counter'),('ka festive ad hai, details store mein hain','have a festive advertisement; details are in the store'),('par membership chhoot hai, terms padho','have a membership discount; read the terms'),('ki exhibition lagegi, family ke saath aana','will be exhibited; visit with your family'),('ka monthly offer aaya, price list dekh lo','have a monthly offer; check the price list')]
for i in range(100):
 p,ep=PRODUCTS[i%10];s,es=PROMOS[i//10];pers=i%8;url=i%5<3;res=f'https://q{rng.randrange(10000,99999)}.invalid/{rng.randrange(100000,999999):x}' if url else ''
 text=noise(f'{VOICE[pers][0]}{p} {s} {res}'.strip(),LEVEL[i%5]);en=f'{VOICE[pers][1]}{ep} {es} {res}'.strip()
 assert add(text,en,'SPAM','promotion_no_secret',i,pers,url,False,'PROMO'+str(i))
controls=[]
for label,n in [('MALICIOUS',150),('BENIGN',100),('SPAM',25)]:
 selected=rng.sample([r for r in accepted if r['expected']==label],n)
 for r in selected:
  en={**r,'text':r['english_text'],'language':'English','hinglish_density':'not_applicable'};en['word_count']=len(en['text'].split());en['length_bin']='6_15' if en['word_count']<=15 else '16_30' if en['word_count']<=30 else '31_plus';controls.append(en)
allrows=accepted+controls;rng.shuffle(allrows)
for i,r in enumerate(allrows):r['id']=f'HP2_{i+1:05}';r.pop('english_text')
lookup={(r['pair_id'],r['expected'],r['language']):r for r in allrows}
for r in allrows:
 twin=lookup.get((r['pair_id'],r['expected'],'English' if r['language']=='Hinglish' else 'Hinglish'));r['english_twin_id']=twin['id'] if twin else ''
csvwrite('probe_v2.csv',allrows)
sample=[];reviewrng=random.Random(202610231)
for label,n in [('MALICIOUS',60),('BENIGN',40),('SPAM',20)]:sample.extend(reviewrng.sample([r for r in accepted if r['expected']==label],n))
reviewrng.shuffle(sample);csvwrite('REVIEW_SAMPLE_v2.csv',[{**r,'user_agree':'','user_note':''} for r in sample])
v1=list(rows(OLD/'probe_set.csv'));v1norm=[]
for i,r in enumerate(v1):
 text=re.sub(r'hxxps?://\S+|https?://\S+|www\.\S+',f'https://x-{i%100:02}.invalid/p',r['text'])
 text=re.sub(r'\+1-202-555-01\d{2}',f'9000000{i%1000:03}',text)
 v1norm.append({**r,'text':text})
csvwrite('probe_v1_normalized.csv',v1norm)
save('generation_manifest.json',{'seed':202610230,'review_seed':202610231,'counts':dict(collections.Counter(r['language']+':'+r['expected'] for r in allrows)),'hinglish_word_bins':dict(collections.Counter(r['length_bin'] for r in accepted)),'personas':dict(collections.Counter(r['generator_batch'] for r in accepted)),'rejected_before_scores':dict(rejects),'source_phrases':{'new_attack_literal_pairs':60,'reused_v1_family_contexts_and_benign_contrasts':True,'source_sha256':sha(OLD/'generate.py')},'model_imports':False,'human_reviewed':False,'phone_note':'invented diagnostic pattern; assignment status not verified; no call or resolution','design_sha256':sha(OUT/'PROBE_V2_DESIGN.md')})
print('generated',len(allrows),'counts',collections.Counter(r['language']+':'+r['expected'] for r in allrows),'rejections',dict(rejects))
