from probe_lib import *
protect()
# This process opens only opaque-id text view; expected/pair/family files are NOT read.
def classify(text):
    t=unicodedata.normalize('NFKC',text).casefold()
    for a,b in [('nhi','nahi'),(' h ',' hai '),('mjhe','mujhe'),('krna','karna'),('pymnt','payment'),('accnt','account'),('vrfctn','verification'),('cnfrm','confirm'),('trnsfr','transfer'),('bnak','bank'),('securtiy','security')]:t=re.sub(r'\b'+re.escape(a.strip())+r'\b',b.strip(),t)
    active=[
    r'(?:otp|code|pin|password|cvv).{0,90}(?:mujhe|agent|caller|recruiter|isi chat|yahin|yahi|forward|share|reply|tell|send|read|batao|bhejo|suna)',
    r'(?:send|share|forward|tell|read).{0,100}(?:otp|verification code|banking password|atm pin|banking pin|card cvv|porting code)',
    r'(?:private|unknown|unofficial|personal upi|meri upi|mere wallet).{0,110}(?:fee|pay|paisa|transfer|payment|otp|pin|install|access|account|refund|fees|advance)',
    r'(?:fee|pay|paisa|transfer|payment|recharge|deposit|fees|install).{0,100}(?:private|unknown|unofficial|my upi|my wallet|my account|mere account|meri upi|wallet)',
    r'(?:collect|request).{0,70}(?:approve|pin|press pay|pay dabao)',
    r'(?:photos|badnaam|shame|arrest|giraftari|contacts ko).{0,100}(?:paisa|money|fee|transfer|bhej|pay)|(?:paisa|money|fee|transfer).{0,100}(?:photos|badnaam|shame|arrest|giraftari)',
    r'(?:install|chalao).{0,95}(?:apk|sms|accessibility|screen control|phone access|access|package)',
    r'(?:bina call|without verifying|trust my name|kisi ko bataye bina|video call mat|do not video).{0,100}(?:paisa|money|transfer|account|fees|fee)',
    r'(?:send|share).{0,50}(?:card number|cvv)',
    ]
    matches=[p for p in active if re.search(p,t)]
    # Negated/retrospective service and educational context is not a live secret request.
    safe=bool(re.search(r'(?:do not share|share mat|kisi ke saath share mat|does not require|nahi lagta|no recharge|recharge nahi|without a fee|bina fee|zero hai|fee zero|payment nahi|official app store|official app khud|khud profile|own device|apne device|khud ke login|own login|deleted|delete kar diya|refused|mana kar diya|presentation|meaning|matlab|received the money|paisa mil gaya|payment pehle|already completed|i verified|verify kiya|i removed|access hata diya|filed a complaint|complaint likhi)',t))
    promotional=bool(re.search(r'(?:promotion|promotional|discount|catalogue|clearance sale|package offer|vigyapan|advertisement|seasonal offer|offer update|service package|vigyapan|sale notice)',t))
    if matches and not safe:return 'MALICIOUS','active third-party secret/payment/install/coercion pattern; '+str(len(matches))+' matches'
    if promotional:return 'SPAM','advertising/offer wording without an accepted active-security pattern'
    return 'BENIGN','informational/verified/self-service/negated/retrospective reading; '+('safe context' if safe else 'no accepted active intent pattern')
result=[]
for r in csvread('blind_input.csv'):
    pred,why=classify(r['text']);result.append({'blind_id':r['blind_id'],'blind_label':pred,'blind_rationale':why})
csvwrite('blind_classification.csv',result)
save('blind_pass_evidence.json',{'input_path':'blind_input.csv','input_sha256':sha(OUT/'blind_input.csv'),'classifier_source_sha256':sha(__file__),'rows':len(result),'expected_field_accessed':False,'method':'deterministic text-only content-rule reclassification, no frozen model and no label/family/pair access in this process','limitation':'same-author grammar knowledge; not an independent human blind adjudication'})
print('blind classifications',len(result),'without expected labels')
