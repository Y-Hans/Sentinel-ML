from probe_lib import *
import random,collections
protect()
# Author-written scenario clauses, legitimate contrasts and English translations. No model imports/scores.
F=[
('bank_KYC_block',['SBI','HDFC Bank','ICICI Bank','Axis Bank'],
 ['bank KYC pending hai','savings khata hold par hai','customer profile dobara jaanchni hai','aaj account verification ki baari hai'],
 ['agent ko KYC wala OTP bhejo, tabhi account khulega','private wallet mein verification fee jama karo warna khata band','link par banking password dalo aur security code mujhe batao','block hatane ke liye apna ATM PIN yahin reply karo'],
 ['branch mein KYC appointment kal hai, documents saath lana','verification poori hui; savings account chalu hai','official banking app mein khud profile update kar sakte ho','yeh tumhare login ka OTP hai, sirf apne device par dalo'],
 ['bank KYC is pending','the savings account is on hold','the customer profile needs review','account verification is due today'],
 ['send the KYC OTP to the agent to unlock the account','pay a verification fee into this private wallet or lose access','enter the banking password on the link and tell me the security code','reply here with your ATM PIN to remove the block'],
 ['your branch KYC appointment is tomorrow; bring your documents','verification is complete and the savings account is active','you can update your own profile in the official banking app','this is the OTP for your login; enter it on your own device']),
('OTP_coercion',['Login team','Account support','Verification desk','Security helper'],
 ['tumhare mobile par naya code aaya hai','login atka hua dikh raha hai','purana session phir verify karna hai','security check abhi chal raha hai'],
 ['jo OTP aaya use mujhe forward kar do','code ka screenshot bhejo taaki main login kar sakun','apna six digit OTP isi chat mein share karna padega','account bachana hai toh received verification code mujhe batao'],
 ['OTP 482913 hai; isko kisi ke saath share mat karna','OTP 731826 tumhare khud ke login ke liye hai','bhai OTP ka matlab one time password hota hai','code expire ho gaya, apne app mein naya OTP mangao'],
 ['a new code has arrived on your phone','your login appears stuck','the previous session needs verification','a security check is in progress'],
 ['forward the OTP you received to me','send a screenshot of the code so I can log in','share your six digit OTP in this chat','tell me the received verification code to save the account'],
 ['your OTP is 482913; do not share it with anyone','OTP 731826 is for your own login','OTP means one time password, friend','the code expired; request a new OTP in your own app']),
('UPI_collect_refund',['UPI helpdesk','Refund desk','Payment support','Merchant settlement'],
 ['refund process chal raha hai','failed payment ka paisa lautna hai','cashback settlement pending hai','UPI collect request aayi hogi'],
 ['refund lene ke liye collect approve karo aur UPI PIN dalo','credit release karne ko pehle mere wallet mein paisa bhejo','UPI PIN mujhe batao, main refund manually daal dunga','paisa receive karne ke liye meri request par pay dabao'],
 ['refund tumhare account mein credit ho chuka hai','paisa receive karne ke liye UPI PIN nahi lagta','apni bheji hui payment ka status official app mein dekh lo','bhai kal ke lunch ka paisa mil gaya, thanks'],
 ['a refund is being processed','the failed payment should be returned','cashback settlement is pending','a UPI collect request may have arrived'],
 ['approve the collect request and enter your UPI PIN to receive the refund','first send money to my wallet to release your credit','tell me your UPI PIN and I will add the refund manually','press pay on my request to receive money'],
 ['the refund has been credited to your account','receiving money does not require a UPI PIN','check your own outgoing payment status in the official app','I received the money for yesterday lunch, thank you']),
('courier_customs_fee',['India Post','Blue Dart','Delhivery','DTDC'],
 ['parcel customs mein ruka hai','delivery address verify hona hai','packet return queue mein pada hai','courier ka clearance pending hai'],
 ['parcel chhudane ke liye agent ko private clearance fee bhejo','delivery cancel hogi; abhi personal UPI par customs payment karo','release ke naam par card number aur CVV isi chat mein bhejo','address unlock karne ko link par banking OTP dalo'],
 ['parcel kal aayega; delivery ka time official tracking mein hai','address sahi hai, courier dispatch ho chuka hai','parcel milne ke baad delivery PIN courier ko dena','bhai tracking link bheja tha, packet ghar pahunch gaya'],
 ['the parcel is held at customs','the delivery address needs verification','the package is queued for return','courier clearance is pending'],
 ['send a private clearance fee to the agent to release the parcel','pay customs to this personal UPI account now or delivery is cancelled','send your card number and CVV in this chat for release','enter the banking OTP on the link to unlock the address'],
 ['the parcel arrives tomorrow; the time is in official tracking','the address is correct and the courier has been dispatched','give the delivery PIN to the courier after receiving the parcel','the package reached home after you sent the tracking link']),
('electricity_gas_callback',['MSEDCL','BESCOM','Tata Power','Indraprastha Gas'],
 ['aaj raat supply katne wali hai','meter ka bill update nahi hua','gas connection rokne ka notice hai','bijli ka payment mismatch dikh raha hai'],
 ['turant is agent ko call karke private wallet mein reconnection fee bhejo','line bachani hai toh unknown technician ko advance transfer karo','disconnection rokne ke liye phone par banking OTP batao','agent ki private request pay karo warna aaj hi supply band'],
 ['bill receipt mil gayi, payment official portal mein update hai','maintenance ki wajah se kal supply do ghante band rahegi','meter reading ka schedule hai; staff card dekh lena','gas booking confirm hai, delivery ke waqt receipt lena'],
 ['the supply is due to be cut tonight','the meter bill has not been updated','there is a gas connection suspension notice','the electricity payment appears mismatched'],
 ['call this agent immediately and send a reconnection fee to a private wallet','transfer an advance to this unknown technician to save the connection','tell the caller your banking OTP to stop disconnection','pay the private request from the agent or supply stops today'],
 ['the bill receipt arrived and payment is updated in the official portal','maintenance will interrupt supply for two hours tomorrow','the meter reading is scheduled; check the staff identity card','gas booking is confirmed; collect the receipt on delivery']),
('SIM_telecom_KYC',['Airtel','Jio','Vi','BSNL'],
 ['SIM KYC ki date aa gayi hai','number verification pending hai','mobile service expiry ka message hai','subscriber details update honi hain'],
 ['SIM bachane ko abhi aaya OTP caller ko suna do','telecom agent ko recharge verification ke liye banking PIN batao','number band hone se pehle is private link par card details bharo','porting code mujhe forward karo, main KYC khud complete karunga'],
 ['SIM KYC ke liye official store mein appointment book hai','recharge 28 din ke liye successful hai','apna number verify karna ho toh official app khud kholna','service renewal kal hai; plan details app mein dekh sakte ho'],
 ['the SIM KYC date has arrived','number verification is pending','there is a mobile service expiry message','subscriber details need updating'],
 ['read the new OTP to the caller to save the SIM','tell the telecom agent your banking PIN for recharge verification','enter card details on this private link before your number is blocked','forward the porting code to me and I will complete KYC'],
 ['an appointment is booked at the official store for SIM KYC','the recharge succeeded for twenty eight days','open the official app yourself to verify your number','service renewal is tomorrow; check plan details in the app']),
('prize_lottery',['Reward desk','Lucky draw team','Festival winner cell','Prize coordinator'],
 ['tumhara naam lucky draw mein nikla hai','festival prize reserve hua hai','winner certificate ready hai','cash reward ka claim aaya hai'],
 ['inaam release karane ko pehle processing fee mere account mein bhejo','prize lene ke liye bank password aur OTP yahin share karo','lottery tax abhi private UPI par bhar do phir paisa milega','winning amount ke liye card CVV agent ko batao'],
 ['college draw ka prize office se bina fee le lena','winner list notice board par hai, apna naam dekh lena','school quiz ka certificate mil gaya, koi payment nahi hai','bhai lottery scam wali news padha, free prize pe bharosa mat kar'],
 ['your name was selected in a lucky draw','a festival prize has been reserved','the winner certificate is ready','there is a cash reward claim'],
 ['first send a processing fee to my account to release the prize','share your bank password and OTP here to claim the prize','pay lottery tax to this private UPI account before receiving money','tell the agent your card CVV for the winnings'],
 ['collect the college draw prize from the office without a fee','the winner list is on the notice board; check your name','the school quiz certificate is available without payment','I read about a lottery scam; do not trust a free prize']),
('loan_app_threat',['Loan recovery desk','Credit agent','Dues department','Finance collector'],
 ['loan app ki due date paas hai','installment ka record dikh raha hai','credit account par reminder aaya hai','repayment ka notice bheja gaya hai'],
 ['abhi private UPI par paisa bhejo warna tumhari photos contacts ko bhejunga','meri fee transfer karo nahi toh gharwalon ko badnaam karunga','loan close karane ko agent ko card PIN batao','collection rokni hai toh private APK install karke contacts access do'],
 ['installment receipt aa gayi, official statement mein balance dekh lo','due date agle hafte hai, approved bank channel se khud pay karna','loan app contacts permission maang raha tha, maine mana kar diya','bhai meri EMI budget sheet dekh, personal details chhupa di hain'],
 ['the loan app due date is near','the installment record is available','there is a credit account reminder','a repayment notice was sent'],
 ['send money to this private UPI now or I will send your photos to your contacts','transfer my fee or I will shame you before your family','tell the agent your card PIN to close the loan','install the private APK and grant contact access to stop collection'],
 ['the installment receipt arrived; check the official statement balance','the due date is next week; pay yourself through an approved bank channel','the loan app requested contacts permission and I refused','look at my EMI budget sheet; I removed personal details']),
('job_task_fee',['Hiring coordinator','Task income desk','Part time recruiter','Work from home team'],
 ['part time ka offer mila hai','online task payout pending hai','job interview slot reserve hai','salary account registration hona hai'],
 ['job confirm karne ko security deposit meri UPI par bhejo','task earning nikalni hai toh pehle recharge fee pay karo','salary verify karne ko banking OTP recruiter ko forward karo','joining ke liye private APK install karke SMS access allow karo'],
 ['interview college placement cell mein hai, joining fee zero hai','task ka payment credit hua, koi recharge nahi chahiye','recruiter ne resume manga, maine sensitive number hata diya','training free hai, schedule apne email mein dekh lena'],
 ['a part time offer arrived','an online task payout is pending','a job interview slot is reserved','a salary account needs registration'],
 ['send a security deposit to my UPI account to confirm the job','pay a recharge fee first to withdraw task earnings','forward the banking OTP to the recruiter to verify salary','install the private APK and allow SMS access to join'],
 ['the interview is at the college placement cell and the joining fee is zero','the task payment was credited and no recharge is required','the recruiter requested a resume and I removed sensitive numbers','training is free; check the schedule in your email']),
('challan_tax_government',['RTO notice desk','GST help cell','Income tax officer','Municipal tax section'],
 ['challan ka notice aaya hai','tax return ki jaanch pending hai','government dues ka reminder hai','fine settlement ka case dikh raha hai'],
 ['giraftari rokne ko abhi private settlement account mein paisa bhejo','tax refund release ke liye agent ko netbanking password batao','case close karne ko caller ko bank OTP suna do','fine bachana hai toh is unofficial app ko SMS permission do'],
 ['challan details official portal par khud check kar lena','tax return acknowledgement receipt mil gayi hai','office helpdesk ka appointment kal hai, documents lana','bhai fake police payment call aaya tha, maine complaint likhi'],
 ['a traffic fine notice arrived','a tax return review is pending','there is a government dues reminder','a fine settlement case is showing'],
 ['send money to a private settlement account now to avoid arrest','tell the agent your netbanking password to release the tax refund','read the banking OTP to the caller to close the case','grant SMS permission to this unofficial app to avoid the fine'],
 ['check the traffic fine details yourself on the official portal','the tax return acknowledgement receipt has arrived','the office helpdesk appointment is tomorrow; bring documents','I received a fake police payment call and filed a complaint']),
('APK_install_lure',['Security patch team','Bank app support','Utility app updater','Device safety desk'],
 ['app update ka notification aaya hai','security patch ki baat ho rahi hai','phone safety check pending hai','banking application verify karni hai'],
 ['private APK install karo aur SMS reading accessibility sab allow karo','app store chhodo, meri update file chalao aur screen control do','refund ke liye unknown package install karke phone ka access mujhe do','security warning ignore karke attachment wala APK install kar lo'],
 ['update chahiye toh official app store khud khol lo','unknown APK attachment delete kar diya, phone theek hai','bhai APK malware par class presentation bana raha hoon','app permission settings check ki, unnecessary SMS access hata diya'],
 ['an app update notification arrived','there is discussion of a security patch','a phone safety check is pending','the banking application needs verification'],
 ['install the private APK and allow SMS reading and accessibility','skip the app store; run my update file and give screen control','install the unknown package and give me phone access for the refund','ignore the security warning and install the attached APK'],
 ['open the official app store yourself if you need an update','I deleted the unknown APK attachment and the phone is fine','I am making a class presentation about APK malware','I checked app permissions and removed unnecessary SMS access']),
('friend_impersonation_money',['Rohit','Neha','Aman','Pooja'],
 ['main naye number se bol raha hoon','emergency hospital bill aaya hai','friend ko urgent paise chahiye','purana WhatsApp abhi nahi chal raha'],
 ['bina call verify kiye mere naye UPI par turant paisa bhej','naam pe bharosa kar aur kisi ko bataye bina transfer kar de','tera OTP mere rescue account mein lagna hai, mujhe forward kar','video call mat kar; naya account diya hai usmein abhi fees bhej'],
 ['purane saved number par call karke identity confirm kar lena','hospital bill ki receipt mil gayi, payment pehle hi ho gayi','bhai college fee ka paisa mil gaya, thanks','naye UPI par paisa bhejne se pehle voice call mein verify kiya'],
 ['I am contacting you from a new number','an emergency hospital bill arrived','a friend urgently needs money','the old WhatsApp account is not working'],
 ['send money to my new UPI immediately without verifying by a call','trust my name and transfer without telling anyone','your OTP is needed for my rescue account; forward it to me','do not video call; send the fee to the new account now'],
 ['call the old saved number to confirm my identity','the hospital receipt arrived and payment was already completed','I received the money for the college fee, thank you','I verified by voice call before transferring to the new UPI'])]

# Forty independently phrased presentation patterns, grouped into eight distinct author voices.
FRAMES=[
('{entity}: {act}. {resource}','{entity}: {act}. {resource}'),
('{ctx}. Abhi dhyan do: {act}. {resource}','{ctx}. Please pay attention now: {act}. {resource}'),
('Suchna {entity} se: {ctx}; aage ka kaam, {act}. {resource}','Notice from {entity}: {ctx}; next action, {act}. {resource}'),
('Aaj ka update: {ctx}. Is mamle mein {act}. {resource}','Today update: {ctx}. For this matter, {act}. {resource}'),
('Dhyan se padhein. {ctx}; is sandesh mein batayi baat yeh hai: {act}. Reference sirf isi case ka hai. {resource}','Read carefully. {ctx}; this message says: {act}. This reference concerns only this case. {resource}'),
('{act}, kripya. {resource}','Please {act}. {resource}'),
('Adarniya grahak, {ctx}. Aapke liye nirdesh: {act}. {resource}','Dear customer, {ctx}. Your instruction: {act}. {resource}'),
('Seva kendra ka update hai: {ctx}. Sandarbh ke mutabik {act}. Yeh aapke account se juda vishay hai. {resource}','Service desk update: {ctx}. For this reference, {act}. This concerns your account. {resource}'),
('Mahoday, {entity} ke naam se yeh sandesh hai. {ctx}; kripya poora padhein aur {act}. {resource}','This message is in the name of {entity}. {ctx}; please read it in full and {act}. {resource}'),
('Grahak se sambandhit suchna: {ctx}. Humne neeche agla kadam likha hai, {act}. Sandesh padhne ke baad mamle ki sthiti samajh lein. {resource}','Customer notice: {ctx}. We have written the next step below: {act}. Read the message to understand the case status. {resource}'),
('Bhai, {act}. {resource}','Friend, {act}. {resource}'),
('Yaar ek baat thi, {ctx}. Tu bas {act}. {resource}','I needed to tell you something: {ctx}. Just {act}. {resource}'),
('Sun na, {entity} wala scene hai. {ctx}. Meri baat poori sun: {act}. {resource}','Listen, this concerns {entity}. {ctx}. Hear the whole request: {act}. {resource}'),
('Arre dost, mujhe abhi yeh mila: {ctx}. Main isi liye message kar raha hoon; {act}. {resource}','My friend, I just got this: {ctx}. That is why I am messaging you; {act}. {resource}'),
('Bhai main class se bahar hoon isliye lamba call nahi kar paunga. {ctx}. Message dhyan se padh, {act}. Baaki baat baad mein karte hain. {resource}','I am outside class and cannot make a long call. {ctx}. Read the message carefully: {act}. We can talk about the rest later. {resource}'),
('Dost, {act}. {resource}','Friend, {act}. {resource}'),
('Class group mein {ctx}. College se aate waqt {act}. {resource}','In the class group, {ctx}. On your way from college, {act}. {resource}'),
('Semester ke beech yeh {entity} ka update mila. {ctx}. Notice mein likha hai ki {act}. {resource}','This {entity} update arrived during the semester. {ctx}. The notice says to {act}. {resource}'),
('Campus se ghar pahunch kar dekhna: {ctx}. Deadline wali baat alag hai, filhal {act}. {resource}','Check this after reaching home from campus: {ctx}. The deadline is a separate matter; for now, {act}. {resource}'),
('Kal lab aur assignment dono the, ab yeh sandesh aaya. {ctx}. Maine poori baat neeche likh di hai taaki context clear rahe: {act}. {resource}','Yesterday there was a lab and an assignment, and now this message arrived. {ctx}. I wrote the whole point below so the context stays clear: {act}. {resource}'),
('Jaldi, {act}. {resource}','Quickly, {act}. {resource}'),
('Abhi busy hoon. {ctx}; fatafat {act}. {resource}','I am busy right now. {ctx}; quickly {act}. {resource}'),
('Thoda time kam hai, {ctx}. Main chhota sa likh raha: {act}. {resource}','There is little time: {ctx}. I will keep it short: {act}. {resource}'),
('Phone ki battery low hai aur ghar pahunchne mein der hogi. {ctx}. Isliye seedha point par aa raha: {act}. {resource}','My phone battery is low and I will reach home late. {ctx}. So I will get straight to the point: {act}. {resource}'),
('Aaj bahut kaam tha, poora din messages dekhne ka mauka nahi mila. Ab dekha ki {ctx}. Baar baar poochhne ki jagah yahin bata raha hoon: {act}. {resource}','There was a lot of work today and no chance to check messages. Now I see that {ctx}. Rather than ask repeatedly, I will explain here: {act}. {resource}'),
('Beta, {act}. {resource}','Dear, {act}. {resource}'),
('Ghar mein baat hui, {ctx}. Tum dekh lena aur {act}. {resource}','We discussed this at home: {ctx}. Please check and {act}. {resource}'),
('Mujhe {entity} ke naam ka sandesh samajhna tha. {ctx}. Jo baat likhi hai woh yeh: {act}. {resource}','I wanted to understand the message in the name of {entity}. {ctx}. It says: {act}. {resource}'),
('Beta jab kaam se fursat mile tab yeh padhna. {ctx}. Maine jitna samjha uske hisab se {act}. {resource}','Read this when you have a break from work. {ctx}. As far as I understand, {act}. {resource}'),
('Subah se ghar ke kaam mein laga tha isliye ab message bhej raha hoon. {ctx}. Tumhare liye poora sandarbh bata diya; baat ko dhyan se samajhkar {act}. {resource}','I was busy with housework all morning, so I am messaging now. {ctx}. I have explained the context; understand it carefully and {act}. {resource}'),
('Seedhi baat: {act}. {resource}','The main point: {act}. {resource}'),
('Pehle hua yeh ki {ctx}. Uske baad bataya gaya: {act}. {resource}','First this happened: {ctx}. Then the instruction was: {act}. {resource}'),
('Mamla thoda samjho: {ctx}. Yahan jis action ki baat hai woh hai, {act}. {resource}','Here is the situation: {ctx}. The action being discussed here is to {act}. {resource}'),
('Do alag baatein ek saath aayi hain. Ek taraf {ctx}; doosri taraf sandesh keh raha hai ki {act}. {resource}','Two things arrived together. On one hand, {ctx}; on the other, the message asks you to {act}. {resource}'),
('Poora context dena zaroori hai kyunki sirf ek shabd padhne se galat samajh aa sakti hai. {ctx}. Ab jo baat karni hai woh saaf likh raha hoon: {act}. {resource}','The full context matters because reading one word can cause a misunderstanding. {ctx}. I will clearly write the action being discussed: {act}. {resource}'),
('Ek kaam: {act}. {resource}','One thing: {act}. {resource}'),
('Practical update, {ctx}. Process simple hai: {act}. {resource}','Practical update: {ctx}. The process is simple: {act}. {resource}'),
('Quick context de raha hoon. {ctx}. Next step ke naam par yeh likha mila: {act}. {resource}','Here is some quick context. {ctx}. This was written as the next step: {act}. {resource}'),
('Important context missing na rahe isliye note kar lo: {ctx}. Main jo exact baat batana chahta hoon, {act}. {resource}','Please note the context so nothing important is missing: {ctx}. The exact point I want to convey is to {act}. {resource}'),
('Message thoda detailed hai par scenario wahi rozmarra wala hai. {ctx}. Jis action par dhyan dena hai usko alag likh raha hoon taaki baaki chat se confuse na ho: {act}. {resource}','This message is detailed but concerns an everyday scenario. {ctx}. I am writing the relevant action separately so it is not confused with the rest of the chat: {act}. {resource}')]
PERSONAS=['terse_SMS','formal_service','casual_friend','campus_student','hurried_texter','older_household','explanatory_narrator','mixed_code_adviser']
NOISE=['clean','texting_abbrev','missing_vowels','mixed_case','typos']
def noise(s,level):
    maps={'texting_abbrev':{'nahi':'nhi','hai':'h','karna':'krna','mujhe':'mjhe','please':'pls','your':'ur'},'missing_vowels':{'payment':'pymnt','account':'accnt','verification':'vrfctn','confirm':'cnfrm','transfer':'trnsfr'},'typos':{'bank':'bnak','message':'mesage','security':'securtiy','aaj':'ajj','received':'recieved'}}
    if level=='mixed_case': return ' '.join(w.upper() if i%4==1 and not ('.invalid' in w or re.search(r'\d',w)) else w for i,w in enumerate(s.split()))
    for a,b in maps.get(level,{}).items():s=re.sub(r'\b'+a+r'\b',b,s,flags=re.I)
    return s
rows=[];english={};pair_ids=[]
for fi,(fam,entities,ctxs,ats,bts,ectxs,eats,ebts) in enumerate(F):
    for i in range(40):
        pair=f'PAIR_{fi:02}_{i:02}';pair_ids.append(pair);entity=entities[(i+fi)%4];j=(i//5+i+fi)%4;density=['light','medium','heavy'][(i+fi)%3];level=NOISE[(i+2*fi)%5];hasurl=i%5 in (0,1);hasphone=i%5 in (2,3)
        resource=f'hxxps://{fam.replace("_", "-")}-{i%7:02}.invalid/case/{100+i}' if hasurl else f'+1-202-555-01{(fi*7+i)%100:02}' if hasphone else ''
        if fam=='APK_install_lure' and hasurl:resource=resource+'/update[.]apk'
        context=ectxs[j]+' hai' if density=='light' else ctxs[j];context=context.replace(' hai hai',' hai')
        for expected,acts,eacts in [('MALICIOUS',ats,eats),('BENIGN',bts,ebts)]:
            action=acts[(i+fi)%4];frame=FRAMES[i][0];raw=frame.format(entity=entity,ctx=context,act=action,resource=resource)
            raw=' '.join(raw.split()).strip();raw=noise(raw,level)
            if i%8==3:raw+=[' 🙂',' ⚠️',' 📌',' 🙏'][(fi+i)%4]
            en=noise(FRAMES[i][1].format(entity=entity,ctx=ectxs[j],act=eacts[(i+fi)%4],resource=resource),level);en=' '.join(en.split())
            r={'id':'','text':raw,'expected':expected,'family':fam,'channel_style':'SMS' if i%2==0 else 'WhatsApp','sender_header':('AD-'+['NAVBNK','SEVAKR','PARCEL','SURKSH','BILPAY','HELPDS'][(fi+i)%6]) if i%2==0 else '', 'hinglish_density':density,'noise_level':level,'length_bin':'','has_url':str(hasurl).lower(),'has_phone':str(hasphone).lower(),'pair_id':pair,'english_twin_id':'','generator_batch':'','language':'Hinglish','persona':PERSONAS[i//5],'word_count':len(raw.split()),'source_status':'ASSUMED_SINGLE_AUTHOR_SYNTHETIC'}
            r['length_bin']='short_5_15' if 5<=r['word_count']<=15 else 'medium_16_30' if r['word_count']<=30 else 'long_31_plus';rows.append(r);english[(pair,expected)]=en
SPAM=[
'Festival sale mein naye headphones par discount hai, chaaho toh catalogue dekh lo',
'Gym membership ka naya offer aaya hai, fees aur timing brochure mein hain',
'Weekend pizza combo sasta hai, bas dukaan par aakar order kar sakte ho',
'Coaching ka demo lecture free hai, interest ho toh course details padho',
'Travel agency ka holiday package promotion hai, booking ki abhi zaroorat nahi',
'Mobile covers ki clearance sale lagi hai, colours aur price list bheji hai',
'Cafe mein birthday special menu hai, pasand aaye toh family ke saath aana',
'Furniture showroom mein exchange offer hai, terms counter par padh sakte ho',
'Subscription plan par annual discount mil raha hai, comparison chart dekh lena',
'Beauty salon ka festive coupon hai, appointment lena ho toh service list padho',
'Sports store mein shoes par seasonal offer hai, size chart saath diya hai',
'Bookshop mein exam guides ki sale hai, naye editions ki list share kar rahe hain',
'Language course ka promotional batch announce hua hai, class schedule enclosed hai',
'Home cleaning service ka package offer hai, kaam aur charges ka brochure hai',
'Online concert ka advertisement hai, ticket categories ki information dekh lo']
SPAMPREFIX=['Offer update','Dukaan se promotional sandesh','Yaar yeh ad mila','College market promotion','Quick sale notice','Ghar ke liye catalogue','Product ki jaankari','Service package ka vigyapan']
for i in range(120):
    persona=i%8;frame=i//15;body=SPAM[i%15];suffix=['Ye sirf promotion hai, lena zaroori nahi.','Chaaho toh baad mein dekh lena.','Details ka printed brochure bhi mil jayega.','Offer ki validity weekend tak likhi hai.','Naye customers ke liye rate alag diya hai.','Purana plan lena ho toh woh bhi available hai.','Delivery charge ki conditions neeche likhi hain.','Koi code ya personal account details nahi chahiye.'][frame];s=f'{SPAMPREFIX[persona]}: {body}. {suffix}'
    url=i%5 in(0,1)
    if url:s+=f' hxxps://bazaar-catalogue-{i%9}.invalid/offers/{i+100}'
    s=noise(s,NOISE[i%5]);rows.append({'id':'','text':s,'expected':'SPAM','family':'promotion_no_secret','channel_style':'SMS' if i%2==0 else 'WhatsApp','sender_header':'VM-BAZAAR' if i%2==0 else '', 'hinglish_density':['light','medium','heavy'][i%3],'noise_level':NOISE[i%5],'length_bin':'medium_16_30' if len(s.split())<=30 else 'long_31_plus','has_url':str(url).lower(),'has_phone':'false','pair_id':f'SPAM_{i:03}','english_twin_id':'','generator_batch':'','language':'Hinglish','persona':PERSONAS[persona],'word_count':len(s.split()),'source_status':'ASSUMED_SINGLE_AUTHOR_SYNTHETIC'})
for persona in PERSONAS:
    rr=[r for r in rows if r['persona']==persona];assert len(rr)==135
    for j,r in enumerate(rr):r['generator_batch']=persona+f'_batch_{j//27+1:02}'
rng=random.Random(202610220);selected=set(rng.sample(pair_ids,120));controls=[]
for r in rows:
    if r['expected']!='SPAM' and r['pair_id'] in selected:
        en={**r,'text':english[(r['pair_id'],r['expected'])],'language':'English','hinglish_density':'not_applicable','generator_batch':r['generator_batch']+'_EN_CONTROL'};en['word_count']=len(en['text'].split());en['length_bin']='short_5_15' if 5<=en['word_count']<=15 else 'medium_16_30' if en['word_count']<=30 else 'long_31_plus';controls.append(en)
allrows=rows+controls;rng.shuffle(allrows)
for i,r in enumerate(allrows):r['id']=f'HP_{i+1:05}'
lookup={(r['pair_id'],r['expected'],r['language']):r for r in allrows}
for r in allrows:
    if r['expected']!='SPAM' and r['pair_id'] in selected:r['english_twin_id']=lookup[(r['pair_id'],r['expected'],'English' if r['language']=='Hinglish' else 'Hinglish')]['id']
assert len(allrows)==1320
csvwrite('draft_probe_set.csv',allrows)
blind=[{'blind_id':f'BLIND_{i:05}','text':r['text'],'language':r['language'],'channel_style':r['channel_style'],'sender_header':r['sender_header']} for i,r in enumerate(allrows,1)]
rng.shuffle(blind);csvwrite('blind_input.csv',blind);save('blind_id_map.json',{f'BLIND_{i:05}':r['id'] for i,r in enumerate(allrows,1)})
save('generation_manifest.json',{'generator_sha256':sha(__file__),'design_sha256':sha(OUT/'DESIGN_PREREGISTERED.md'),'seed':202610220,'draft_sha256':sha(OUT/'draft_probe_set.csv'),'counts':dict(collections.Counter((r['language']+':'+r['expected']) for r in allrows)),'generator_batches':dict(collections.Counter(r['generator_batch'] for r in rows)),'styles':dict(collections.Counter(r['persona'] for r in rows)),'length_bins':dict(collections.Counter(r['length_bin'] for r in rows)),'density':dict(collections.Counter(r['hinglish_density'] for r in rows)),'noise':dict(collections.Counter(r['noise_level'] for r in rows)),'malicious_URLless':sum(r['expected']=='MALICIOUS' and r['has_url']=='false' for r in rows),'CPU_only':True,'models_imported':False})
print(json.dumps(load('generation_manifest.json')['counts']), 'batches',40)
