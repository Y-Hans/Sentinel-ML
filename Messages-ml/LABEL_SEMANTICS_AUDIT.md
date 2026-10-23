# Label Semantics Audit — V4.3 Training Corpus

**VERIFIED** counts are literal regex/metadata intersections over all 19,672 V4.3 training rows. These are descriptive screens, not adjudications or relabeling. Duplicate records remain counted because training rows are what the model saw.

## Security label definitions

**VERIFIED:** data/schemas/taxonomy.json defines BENIGN as safe/legitimate communications (including OTPs, bank alerts and delivery notices); SUSPICIOUS_SPAM as unsolicited commercial messages, telemarketing and nuisance/unverified offers without credential theft or severe threat payloads; MALICIOUS as severe threats including phishing, credential theft, reverse OTP, fake KYC/PAN suspension, electricity scams, UPI collect fraud, APK droppers and extortion. The distinction between a nuisance offer and malicious prize/credential lure therefore depends on action and threat intent, not promotional vocabulary alone.

## Label composition and source association

| Label | N | Percent |
|---|---|---|
| BENIGN | 5891 | 29.95% |
| MALICIOUS | 12612 | 64.11% |
| SUSPICIOUS_SPAM | 1169 | 5.94% |

Label-conditioned source/language/category/intent/threat-vector/URL/phone/length distributions are in the TRAIN by_label object in DATASET_COMPOSITION_AUDIT.json. Category and intent both map to primary_type by taxonomy; source-supplied scam_type is distinct.

## Keyword association counts

Counts below overlap across terms and are not a bag-of-words feature attribution.

| Term family | Rows | BENIGN | SPAM | MALICIOUS | P(M) among hits |
|---|---|---|---|---|---|
| hello | 332 | 34 | 35 | 263 | 79.22% |
| hi | 566 | 80 | 78 | 408 | 72.08% |
| electricity | 422 | 82 | 1 | 339 | 80.33% |
| meter | 18 | 8 | 0 | 10 | 55.56% |
| bill | 770 | 215 | 12 | 543 | 70.52% |
| otp | 1142 | 450 | 0 | 692 | 60.60% |
| apk | 150 | 0 | 0 | 150 | 100.00% |
| phone_or_call | 3538 | 503 | 258 | 2777 | 78.49% |
| institutional | 682 | 333 | 9 | 340 | 49.85% |
| promotional | 1817 | 103 | 482 | 1232 | 67.80% |
| account_security | 4931 | 417 | 54 | 4460 | 90.45% |

**VERIFIED:** 'hello' occurs in 332 rows (263 MALICIOUS; 79.2% of hits); 'hi' in 566 (408 M; 72.1%); electricity 422 (339 M; 80.3%); bill 770 (543 M; 70.5%); OTP 1,142 (692 M; 60.6%); literal `.apk` 150 (all M); institutional vocabulary 682 (340 M /333 B); promotional vocabulary 1,817 (1,232 M /482 S /103 B); account/security vocabulary 4,931 (4,460 M /417 B /54 S). 'Phone/call/contact' matches are 2,777 M /503 B /258 S.

**Caveat:** these regexes are intentionally broad and count benign text such as “Do not share OTP” as security wording; an occurrence is not a threat intent. Category mix and label associations vary by source, so these numbers demonstrate skew/overlap, not causality.

## Label-semantic ambiguity screens

### MALICIOUS promotional wording with no raw URL/phone

| Label | N | Example text |
|---|---|---|
| BENIGN | 103 | Are you free now?can i call now?; I probably won't eat at all today. I think I'm gonna pop. How was your weekend? Did u miss me?; Lol yes. Our friendship is hanging on a thread cause u won't buy stuff. |
| SUSPICIOUS_SPAM | 482 | Buy Space Invade<AMOUNT> a chance <NUM> win orig Arcade Game console. Press <NUM> for Games Arcade (std WAP charge) See o2.co.uk/games <NUM>; REMINDER FROM O2: To get <NUM>.<NUM> pounds free call credit and details of great offers pls reply <NUM> this text with your valid name, hou; You won $100000USD in MASTERCARD promo! Send Name & Mobile Number to email for claim: |
| MALICIOUS | 1189 | URGENT! We are trying to contact U. Todays draw shows that you have won a £<NUM_CODE> prize GUARANTEED. Call <PHONE> from land line. Claim <; You have been in close contact with someone who has the Omicron Variant. You must order a free PCR testing kit here: <URL>; FNB Pension Fund Reserves: Select LOG IN, select FNB Reserve to check & submit your claim on link below. Regards Momentum. |

### Security/account terms by label

| Label | N | Example text |
|---|---|---|
| BENIGN | 714 | Save yourself the stress. If the person has a dorm account, just send your account details and the money will be sent to you.; OTP for Axis Bank Debit Card ending in <NUM_CODE> for <AMOUNT> is <NUM_CODE>. Do not share OTP with anyone to prevent fraud.; OTP for Axis Bank Debit Card ending in <NUM_CODE> for <AMOUNT> is <NUM_CODE>. Do not share OTP with anyone to prevent fraud. |
| SUSPICIOUS_SPAM | 54 | Push alert: You are one step away from validating your account. Please follow the link.; SMSSERVICES. for yourinclusive text credits, pls goto <URL> login= 3qxj9 unsubscribe with STOP, no extra charge. help <PHONE>.COMUK. <NUM>-C; Congratulation your winning price your first winning price your Swift dzire car second option your marketing value <US_DRIVER_LICENSE> your  |
| MALICIOUS | 5027 | BNZ: Due to numerous failed card payments we are placing a hold on your account, to continue using BNZ services please verify your identity ; LLOYDS: A new device has logged into your online banking. If this was NOT you, please login to remove this device now:; Dear SBI customer your account has been blocked due to KYC kindly contact customer care <PHONE_NUMBER> to continue your account Thank you. |

### URL/phone-less messages of at most 8 words by label

| Label | N | Example text |
|---|---|---|
| BENIGN | 1997 | Horrible bf... I now v hungry...; Send me your resume:-); Networking technical support associate. |
| SUSPICIOUS_SPAM | 91 | Your Wife will Love Your Boner; Biggest Giveaway Oprah Has Ever Done; <NUM>/<NUM> 146tf150p |
| MALICIOUS | 1124 | http://
<URL>als; [BBT BANK] Security Information Urgnet Dial <DATE_TIME>; <NUM> debited from your wallet. |


**REPRODUCED:** 1,189 MALICIOUS rows match promotional words without raw URL or phone; examples include prizes, data boosters, free testing kits, plus contextually diverse messages. This is meaningful surface overlap, but some still contain URLs as `<URL>` or coercive/action context; it does not prove mislabeled marketing.

**REPRODUCED:** 714 BENIGN rows match broad account/security/OTP terms. Many are legitimate safety warnings or transactional alerts, e.g. “Do not share OTP … to prevent fraud.” These show that security vocabulary is not sufficient to call MALICIOUS.

**REPRODUCED:** 1,124 MALICIOUS rows are <=8 whitespace tokens and lack raw URL/phone; this heuristic includes promotional or clipped texts as well as conversational items. Source examples include greetings and ordinary-looking acknowledgements in held-out error files. It cannot distinguish social engineering from source label/taxonomy noise.

## Finding

**VERIFIED:** the training dataset's primary_type annotation does not conform to the schema/taxonomy enumerations: 20 distinct values (3,817 controlled-addition rows) are outside both allowed sets. source_type also has 4,154 out-of-enum rows; controlled additions omit threat_vectors.

**INFERENCE:** topic words alone cannot define the three security labels. Metadata has overlapping promotional/security topics; primary_type provides a coarse intent category but not full action intent/channel trust. This establishes annotation-schema inconsistency and ambiguity, but **does not establish that the security labels themselves are incorrect** without provenance-aware human review. Actual SPAM→MALICIOUS prediction evidence is in CLASS_CONFUSION_ANALYSIS.md.
