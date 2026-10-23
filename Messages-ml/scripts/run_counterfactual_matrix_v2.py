"""Twenty authored one-clause counterfactual pairs; mechanism analysis only."""
import json,pickle,sys
from pathlib import Path
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"messages_v4_3"/"models"))
from candidate_d_v4_3 import extract_structural_signals
ART=ROOT/"messages_v4_3"/"models"/"candidate_d"
OUT=ROOT/"COUNTERFACTUAL_METHOD_AUDIT.json"
PAIRS=[
 {"id":"CF01","domain":"bank OTP","benign":"Your account was accessed. Do not share your OTP.","malicious":"Your account was accessed. Share your OTP with our agent.","changed_property":"OTP disclosure request","rationale":"A security warning that prohibits disclosure is benign; an unsolicited agent asks for the authentication secret."},
 {"id":"CF02","domain":"bank password","benign":"To check your account alert, sign in through the official bank app.","malicious":"To check your account alert, send your password to the agent by text.","changed_property":"credential handling channel","rationale":"The only changed action routes authentication from the official app to disclosure by text."},
 {"id":"CF03","domain":"account recovery","benign":"To restore access, enter the recovery code in the official account settings.","malicious":"To restore access, send the recovery code to the support agent.","changed_property":"recovery-code recipient","rationale":"A recovery code is used locally in official settings versus disclosed to a third party."},
 {"id":"CF04","domain":"electricity bill","benign":"Your electricity bill is ready. Pay it only in the official provider app.","malicious":"Your electricity bill is ready. Pay it only to this personal UPI ID: powerhelp@upi.","changed_property":"payment destination","rationale":"Same bill and payment intent; only the destination changes from the provider channel to a personal UPI handle."},
 {"id":"CF05","domain":"electricity disconnection","benign":"Your electricity account needs attention. Check the notice in the official provider app.","malicious":"Your electricity account needs attention. Call 9876543210 to stop disconnection tonight.","changed_property":"response channel and coercive callback","rationale":"This probes an unsolicited callback instruction; the explicit disconnection pressure is part of the malicious action clause."},
 {"id":"CF06","domain":"parcel delivery code","benign":"Your parcel is arriving today. Give the delivery OTP to the courier at your door.","malicious":"Your parcel is arriving today. Send the delivery OTP to this number before arrival.","changed_property":"OTP delivery timing and recipient","rationale":"The code is released at handoff versus remotely before the package arrives."},
 {"id":"CF07","domain":"parcel fee","benign":"Your parcel needs a delivery fee. Pay it in the carrier's official app.","malicious":"Your parcel needs a delivery fee. Pay it at this shortened link: https://bit.ly/parcel-fee.","changed_property":"payment channel","rationale":"Same fee request; only the route changes from the official carrier app to an unsolicited short URL."},
 {"id":"CF08","domain":"campus account","benign":"The campus account notice is ready. Review it through the university portal.","malicious":"The campus account notice is ready. Send your password to the university helpdesk by SMS.","changed_property":"credential action","rationale":"Same institutional pretext; one version uses the official portal, the other solicits a password by SMS."},
 {"id":"CF09","domain":"university tuition","benign":"Your tuition balance is due. Pay through the university's official portal.","malicious":"Your tuition balance is due. Pay to this personal UPI ID: campusfees@upi.","changed_property":"payment destination","rationale":"Same tuition payment request; the payment destination changes to a personal handle."},
 {"id":"CF10","domain":"Microsoft sign-in","benign":"Your Microsoft sign-in needs review. Change your password in account settings.","malicious":"Your Microsoft sign-in needs review. Reply to this message with your password.","changed_property":"credential submission route","rationale":"A password change in account settings versus password disclosure in a reply."},
 {"id":"CF11","domain":"SIM replacement","benign":"A SIM replacement was requested. Review the request in your carrier app.","malicious":"A SIM replacement was requested. Reply with your SIM PIN to cancel it.","changed_property":"secret disclosure request","rationale":"Same account event; malicious version asks the recipient to disclose a SIM security secret."},
 {"id":"CF12","domain":"toll payment","benign":"Your toll balance is due. Pay it in the official highway toll app.","malicious":"Your toll balance is due. Pay it to this personal UPI ID: fasttoll@upi.","changed_property":"payment destination","rationale":"Same debt notice; only the payee changes from official app to personal UPI."},
 {"id":"CF13","domain":"tax refund","benign":"Your tax refund status is available. Check it on the official tax portal.","malicious":"Your tax refund status is available. Send your OTP to the refund agent.","changed_property":"verification action","rationale":"Same refund status; malicious version solicits an OTP rather than directing the user to the official portal."},
 {"id":"CF14","domain":"card security","benign":"A card transaction needs review. Lock the card in your bank app.","malicious":"A card transaction needs review. Send your card PIN to the security agent.","changed_property":"security response","rationale":"Same alert; protective self-service action versus disclosure of a banking secret."},
 {"id":"CF15","domain":"medical portal","benign":"Your patient portal code arrived. Enter it in the official health app.","malicious":"Your patient portal code arrived. Read it to the caller who contacted you.","changed_property":"code recipient","rationale":"Same one-time code; local use in official app versus disclosure to an unsolicited caller."},
 {"id":"CF16","domain":"job application","benign":"Your job application is open. Apply through the company's official careers page.","malicious":"Your job application is open. Pay a registration fee to this personal UPI ID: hiring@upi.","changed_property":"application action/payment route","rationale":"Same job opportunity; malicious version requires an advance payment to a personal handle."},
 {"id":"CF17","domain":"software update","benign":"The software update is ready. Install it from the official app store.","malicious":"The software update is ready. Install this file from an external APK link.","changed_property":"software distribution source","rationale":"Same update; trusted app-store distribution versus direct sideloaded executable source."},
 {"id":"CF18","domain":"shopping reward","benign":"Your shopping reward is ready. View it in the retailer's official app.","malicious":"Your shopping reward is ready. Send your card CVV to claim it.","changed_property":"claim action","rationale":"Same reward pretext; benign in-app viewing versus disclosure of a payment-card secret."},
 {"id":"CF19","domain":"WhatsApp device linking","benign":"A device-linking code was generated. Enter it only in the WhatsApp app you opened.","malicious":"A device-linking code was generated. Send it to the support agent who contacted you.","changed_property":"linking-code recipient","rationale":"Same code; user-initiated in-app use versus remote disclosure to an unsolicited contact."},
 {"id":"CF20","domain":"government benefit","benign":"Your benefit application status is ready. Check it on the official government portal.","malicious":"Your benefit application status is ready. Send your bank OTP to the benefits agent.","changed_property":"verification action","rationale":"Same benefit status; official portal lookup versus credential/OTP solicitation."},
]
def main():
 with open(ART/"model.pkl","rb") as f:m=pickle.load(f)
 with open(ART/"scaler.pkl","rb") as f:s=pickle.load(f)
 with open(ART/"word_vec.pkl","rb") as f:w=pickle.load(f)
 with open(ART/"char_vec.pkl","rb") as f:c=pickle.load(f)
 texts=[t for pair in PAIRS for t in (pair['benign'],pair['malicious'])]
 st=np.asarray([extract_structural_signals(t) for t in texts],dtype=np.float32)
 X=np.hstack([st,w.transform(texts).toarray(),c.transform(texts).toarray()]).astype(np.float32)
 probs=m.predict_proba(s.transform(X)); out=[]
 for i,pair in enumerate(PAIRS):
  scores=[]
  for j,expected in ((2*i,"BENIGN"),(2*i+1,"MALICIOUS")):
   p=probs[j]; pnb=float(p[1]+p[2]); pred="BENIGN" if pnb<.61 else ("MALICIOUS" if p[2]>=p[1] else "SUSPICIOUS_SPAM")
   scores.append({"intended_label":expected,"predicted_label":pred,"probabilities":{"BENIGN":float(p[0]),"SUSPICIOUS_SPAM":float(p[1]),"MALICIOUS":float(p[2])},"p_nonbenign":pnb})
  row=dict(pair); row["scores"]=scores; row["intended_order_correct"]=(scores[0]["p_nonbenign"]<scores[1]["p_nonbenign"])
  out.append(row)
 obj={"status":"ANALYSIS_ONLY_NOT_BENCHMARK","threshold_unchanged":.61,"label_policy":"BENIGN=use a verifiable official channel or protect secrets; MALICIOUS=unsolicited solicitation of secrets, personal payment routing, unsafe executable source, or remote interception of delivery/authentication codes. These intended labels describe this constructed scenario, not generic lexical rules.","construction_rule":"Each pair keeps the surrounding scenario fixed and substitutes one action clause/property. Rationales state that property and intended security semantics.","pairs":out}
 OUT.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding="utf-8")
 print("pairs",len(out),"intended score order",sum(x['intended_order_correct'] for x in out))
 for x in out: print(x['id'],x['scores'][0]['predicted_label'],round(x['scores'][0]['p_nonbenign'],3),"=>",x['scores'][1]['predicted_label'],round(x['scores'][1]['p_nonbenign'],3),x['intended_order_correct'])
if __name__=="__main__":main()
