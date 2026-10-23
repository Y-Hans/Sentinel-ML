import sys
from pathlib import Path
import json
import joblib
import numpy as np
import re
from tqdm import tqdm

ROOT = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel-ml")
sys.path.insert(0, str(ROOT / "Messages-ml" / "scripts"))

from feature_extraction import extract_message_features, get_feature_names

MODELS = ROOT / "Messages-ml" 
clf = joblib.load(MODELS / "champion_v2_model.pkl")
scaler = joblib.load(MODELS / "champion_v2_scaler.pkl")
tfidf_word = joblib.load(MODELS / "champion_v2_tfidf_word.pkl")
tfidf_char = joblib.load(MODELS / "champion_v2_tfidf_char.pkl")

class DualTfidf:
    def __init__(self, w, c):
        self.w = w
        self.c = c
    def transform(self, texts):
        if not texts:
            return np.zeros((0, self.w.n_features_in_ + self.c.n_features_in_))
        w_mat = self.w.transform(texts).toarray()
        c_mat = self.c.transform(texts).toarray()
        return np.hstack((w_mat, c_mat))

tfidf = DualTfidf(tfidf_word, tfidf_char)

# V3 Logic Implementation
def adjudicate_v3(txt, p1, is_after=False):
    lowerText = txt.lower()
    hasLink = "http://" in lowerText or "https://" in lowerText or "www." in lowerText or bool(re.search(r'(?:\.xyz|\.top|\.cc|\.tk|\.ga|\.ml|\.cf|\.club|\.online)\b', txt, re.I))
    
    reOtpSolicit = re.compile(r'\b(?:otp|code|pin|password|verification\s*code|one\s*time\s*password)\b.*\b(?:bhej|bhejo|bhejoo|send\s+k(?:a)?r|forward\s+k(?:a)?r|fwd\s+k(?:a)?r|bata|btao|share\s+k(?:a)?r|de\s+do|de\s+de|de|tell|provide|forward|send|share|text\s+k(?:a)?r|sms\s+k(?:a)?r|need|want|chahiye)\b|\b(?:bhej|bhejo|send\s+k(?:a)?r|forward\s+k(?:a)?r|fwd\s+k(?:a)?r|bata|btao|share\s+k(?:a)?r|de|tell|provide|forward|send|share|need|want|chahiye|mang\s+raha)\b.*\b(?:otp|code|pin|password|verification\s*code|one\s*time\s*password)\b|\b(?:otp|code)\s+aaya\s+(?:hoga|hai|h|hei)\b.*(?:forward|send|bhej|bata|share|mujhe|fwd|text)', re.I)
    reKycPhish = re.compile(r'\b(?:sbi|yono|hdfc|icici|axis|pnb|kotak|bob|bank|a/c|account|pan|kyc|aadhar)\b.*\b(?:expire|expired|band|block|blocked|suspend|suspended|deactivate|update|verify|pending)\b|\b(?:pan\s*card|kyc|aadhar)\s+(?:update|verify|link)\b', re.I)
    reElectricityExtort = re.compile(r'\b(?:electricity|power|bijli|light|line)\b.*\b(?:disconnected\s+tonight|power\s+cut\s+tonight|light\s+cut\s+tonight|kat\s+jayegi\s+aaj\s+raat|cut\s+tonight|will\s+be\s+disconnected|line\s+cut|cut\s+jayegi|kat\s+jayegi)\b|\b(?:aaj\s+raat|tonight)\b.*\b(?:bijli|power|light|line)\b.*\b(?:cut|kat\s+jayegi|cut\s+jayegi|disconnect)\b|\b(?:disconnected|cut|suspended|kat\s+jayegi)\b.*(?:\+91|0)?[6-9]\d{9}|(?:\+91|0)?[6-9]\d{9}.*\b(?:disconnected|cut|suspended|kat\s+jayegi)\b|\b(?:bijli\s+vibhag\s+officer|electricity\s+officer\s+call)\b', re.I)
    reLegitWarning = re.compile(r'\b(?:bank\s+never\s+asks|never\s+share\s+(?:your\s+)?(?:otp|password|pin|cvv)|do\s+not\s+share\s+(?:your\s+)?(?:otp|password|pin|cvv)|beware\s+of\s+fraud)\b|\b(?:never|do\s+not|don\'t|mat|nahi|nhi)\s+(?:share|send|tell|give|bata|bhejo|bhej|forward|enter)\b|\b(?:share|send|tell|give|bata|bhejo|bhej|forward|enter)\s+(?:mat|nahi|nhi)\b|\b(?:kisi\s+(?:ko\s+)?bhi\s+mat|kisi\s+se\s+share\s+na)\b|\b(?:nahi\s+karna\s+padta|not\s+required\s+to\s+receive)\b', re.I)
    reDeliveryOtp = re.compile(r'\b(?:delivery\s+(?:agent|associate|partner|boy|executive|person)|courier|package|order|arriving)\b.*\b(?:share|give|provide)\s+(?:delivery\s+)?(?:otp|code|pin|verification\s*code)\b|\b(?:delivery\s+otp)\b|\bshare\s+(?:delivery\s+)?(?:otp|code|pin|verification\s*code)\b.*?(?:delivery|order)', re.I)
    reUpiFraud = re.compile(r'\b(?:enter\s+(?:upi\s+)?pin|approve\s+collect|accept\s+request|send\s+pin)\b|\b(?:upi\s+pin|pin)\b.*(?:enter|daal|daalo|dalo|type|batao|share|lagao)\b|\b(?:collect\s+request|gpay|google\s*pay|phonepe|paytm|upi)\b.*(?:approve|accept|approve\s+k(?:a)?r|accept\s+k(?:a)?r)\b|\b(?:approve|accept)\b.*(?:collect\s*request|gpay|google\s*pay|phonepe|paytm|upi)\b|\b(?:cashback|reward|lottery|prize)\b.*(?:claim|receive|jeet)\b.*(?:pin|collect|upi)', re.I)
    reCredentialTheft = re.compile(r'\b(?:password|cvv|credentials|passcode|secret\s*key|login\s*details)\b.*(?:share|send|bata|btao|enter|verify|provide|reset)|\b(?:enter|share|send|bata|btao|verify|reset)\b.*(?:password|cvv|credentials|passcode|secret\s*key|login\s*details)', re.I)
    reMalwareApk = re.compile(r'\.apk\b|\b(?:install|download)\s+(?:support|bank|customercare|live|quicksupport|cleaner|app|patch)\b|\b(?:anydesk|teamviewer|quicksupport|screen\s*shar(?:e|ing))\b', re.I)
    reBenignQuestion = re.compile(r'\b(?:kya\s+hota\s+hai|kaise\s+(?:karte|kare|hota)\s+hai|kyu|kyun|kab\s+(?:aayega|aaye|hoga)|kitna\s+aaya)\b|\?', re.I)
    rePaidConfirmation = re.compile(r'\b(?:pay\s+kar\s+diya|jama\s+kar\s+diya|paid|bill\s+paid|recharge\s+done|successful|credited)\b', re.I)
    reSystemProgress = re.compile(r'\b(?:uploading:\s*\d+(?:\.\d+)?\s*(?:kb|mb)|backup\s+in\s+progress|backing\s+up\s+chats|doing\s+work\s+in\s+the\s+background|syncing\s+google\s+drive)\b', re.I)
    reStandaloneGreeting = re.compile(r'^(?:hello|hi|hey|good\s+morning|good\s+evening|how\s+are\s+you|kya\s+haal\s+hai|kaise\s+ho|thanks|thank\s+you|okay|haan|nahi|theek\s+hai)[.!?]?$', re.I)

    hasOtpSolicit = bool(reOtpSolicit.search(txt))
    hasKycPhish = bool(reKycPhish.search(txt))
    hasElecExtort = bool(reElectricityExtort.search(txt))
    hasUpiFraud = bool(reUpiFraud.search(txt))
    hasCredTheft = bool(reCredentialTheft.search(txt))
    hasMalware = bool(reMalwareApk.search(txt))

    isQuestion = not hasLink and bool(reBenignQuestion.search(txt))
    if isQuestion and not any(w in lowerText for w in ["bhej", "forward", "link", "pin", "need"]):
        hasOtpSolicit = False
        hasUpiFraud = False
    
    if rePaidConfirmation.search(txt):
        hasElecExtort = False
    
    if reLegitWarning.search(txt) and not any(w in lowerText for w in ["bhej", "click", "http", "call"]):
        hasCredTheft = False
        hasOtpSolicit = False
        hasUpiFraud = False
        
    if reDeliveryOtp.search(txt) and not any(w in lowerText for w in ["click", "http", "call"]):
        hasOtpSolicit = False
        
    hasStrongThreatIntent = hasOtpSolicit or hasKycPhish or hasElecExtort or hasUpiFraud or hasCredTheft or hasMalware
    
    if hasStrongThreatIntent:
        return max(p1, 0.92)
        
    if is_after:
        instKeywords = ["hi everyone", "dear students", "dear team", "announcement", "partnered with", "partnership", "our institution", "campus", "university", "college", "faculty", "students", "procure", "provided", "available", "next week", "regards"]
        instMatchCount = sum(1 for k in instKeywords if k in lowerText)
        if instMatchCount >= 2:
            reUrgentThreatOverride = re.compile(r'\b(?:immediately|urgent|expires|suspended|blocked|deactivated|last chance|action required|verify your account|verification fee)\b', re.I)
            reFinancialFraudOverride = re.compile(r'\b(?:pay|payment|transfer|upi|collect request|bank|refund|fee|account blocked|kyc)\b', re.I)
            reCredTheftOverride = re.compile(r'\b(?:password|otp|pin|cvv|verification code|login|credentials|passcode|account verification)\b', re.I)
            reMaliciousDownloadsOverride = re.compile(r'(?:\.apk|\.exe|\.bat|\.scr|\.vbs|download this file|install this application)', re.I)
            
            hasOverride = hasLink or hasStrongThreatIntent or bool(reUrgentThreatOverride.search(txt)) or bool(reFinancialFraudOverride.search(txt)) or bool(reCredTheftOverride.search(txt)) or bool(reMaliciousDownloadsOverride.search(txt))
            
            if not hasOverride:
                return min(p1, 0.15)
        
    if p1 <= 0.75:
        if not hasLink and reSystemProgress.search(txt):
            return min(p1, 0.05)
        if not hasLink and reStandaloneGreeting.match(txt):
            return min(p1, 0.05)
        if not hasLink and (isQuestion or rePaidConfirmation.search(txt)):
            return min(p1, 0.10)
            
        peerKeywords = ["github.com", "repo", "simulink", "ppt", "dataset", "dr severity", "quality check + lesion", "diabetic-retinopathy"]
        isPeerCollab = any(w in lowerText for w in peerKeywords)
        threatKeywords = ["otp", "password", "pin", "verify here", "account block"]
        if isPeerCollab and not any(w in lowerText for w in threatKeywords):
            return min(p1, 0.15)
            

    return p1

def run_benchmark():
    metrics = {}
    cfg = None
    det_names = get_feature_names(cfg)
    
    splits = {
        "val": ROOT / "Messages-ml" / "data" / "processed" / "val.jsonl",
        "institutional": ROOT / "Messages-ml" / "data" / "benchmarks" / "slice_institutional_partnerships.jsonl"
    }
    
    for split_name, path in splits.items():
        if not path.exists():
            continue
        with open(path, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f]
            
        if len(records) > 5000:
            np.random.seed(42)
            records = np.random.choice(records, 5000, replace=False).tolist()
            
        texts = [r["raw_text"] for r in records]
        labels = [r["security_label"] for r in records]
        
        det_features = []
        for t in texts:
            d = extract_message_features(t, None, cfg)
            det_features.append([d[k] for k in det_names])
        det_features = np.array(det_features)
        
        tfidf_features = tfidf.transform(texts)
        X_concat = np.hstack((det_features, tfidf_features))
        X_scaled = scaler.transform(X_concat)
        
        probs = clf.predict_proba(X_scaled)
        p_non_benigns = probs[:, 1] + probs[:, 2]
        
        metrics[split_name] = {"before": [], "after": [], "labels": labels, "records": records}
        for i, (txt, p1) in enumerate(zip(texts, p_non_benigns)):
            final_p_before = adjudicate_v3(txt, p1, is_after=False)
            final_p_after = adjudicate_v3(txt, p1, is_after=True)
            metrics[split_name]["before"].append(final_p_before)
            metrics[split_name]["after"].append(final_p_after)
            
    # Calculate metrics
    res = {}
    for sn, m in metrics.items():
        y_true = np.array([1 if l in ["MALICIOUS", "SUSPICIOUS_SPAM", "SUSPICIOUS"] else 0 for l in m["labels"]])
        y_pred_before = np.array([1 if p >= 0.704 else 0 for p in m["before"]])
        y_pred_after = np.array([1 if p >= 0.704 else 0 for p in m["after"]])
        
        # Threat vectors
        tvs = [r.get("threat_vectors", []) for r in m["records"]]
        
        def calc(pred):
            fp = np.sum((y_true == 0) & (pred == 1))
            tn = np.sum(y_true == 0)
            tp = np.sum((y_true == 1) & (pred == 1))
            fn = np.sum(y_true == 1)
            fpr = fp / tn if tn > 0 else 0
            rec = tp / fn if fn > 0 else 0
            
            # Sub-recalls
            otp_tp = sum(1 for i, v in enumerate(tvs) if "OTP_THEFT" in v and pred[i] == 1)
            otp_fn = sum(1 for i, v in enumerate(tvs) if "OTP_THEFT" in v)
            otp_rec = otp_tp / otp_fn if otp_fn > 0 else 0
            
            kyc_tp = sum(1 for i, v in enumerate(tvs) if "KYC_PHISHING" in v and pred[i] == 1)
            kyc_fn = sum(1 for i, v in enumerate(tvs) if "KYC_PHISHING" in v)
            kyc_rec = kyc_tp / kyc_fn if kyc_fn > 0 else 0

            return {"fpr": fpr, "rec": rec, "otp_rec": otp_rec, "kyc_rec": kyc_rec}

        res[sn] = {"before": calc(y_pred_before), "after": calc(y_pred_after)}
        
        if sn == "institutional":
            legit = np.where(y_true == 0)[0]
            mal = np.where(y_true == 1)[0]
            print("\nInstitutional Suite Results:")
            print(f"  Legit N={len(legit)}")
            print(f"  Legit FPR Before: {np.sum(y_pred_before[legit]) / len(legit):.4f}")
            print(f"  Legit FPR After:  {np.sum(y_pred_after[legit]) / len(legit):.4f}")
            
            print(f"  Malicious N={len(mal)}")
            print(f"  Mal Recall Before: {np.sum(y_pred_before[mal]) / len(mal):.4f}")
            print(f"  Mal Recall After:  {np.sum(y_pred_after[mal]) / len(mal):.4f}")
            
            for i in legit:
                if "hp" in m["records"][i]["raw_text"].lower():
                    print(f"\nOriginal Message Test:")
                    print(f"  Before P: {m['before'][i]:.4f}")
                    print(f"  After P:  {m['after'][i]:.4f}")
                    print(f"  Before Risk: {min(100, int((m['before'][i]/0.704)*100))}")
                    print(f"  After Risk:  {min(100, int((m['after'][i]/0.704)*100))}")
                        
    print("\nOverall Validation Results:")
    print(f"  FPR Before: {res['val']['before']['fpr']:.4f}")
    print(f"  FPR After:  {res['val']['after']['fpr']:.4f}")
    print(f"  Recall Before: {res['val']['before']['rec']:.4f}")
    print(f"  Recall After:  {res['val']['after']['rec']:.4f}")

run_benchmark()
