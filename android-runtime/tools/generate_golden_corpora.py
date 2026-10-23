import json
import pickle
import sys
from pathlib import Path
import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "URL-ml" / "scripts"))
sys.path.insert(0, str(ROOT / "Messages-ml" / "scripts"))

from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector, get_feature_names
import v7_features
from v7_classifier import V7GatedURLClassifier

OUTPUT_DIR = ROOT / "android-runtime" / "golden_test_data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================================
# 1. URL GOLDEN CORPUS
# ============================================================================
def generate_url_golden():
    print("Generating URL golden test suite...")
    sys_model = joblib.load(ROOT / "URL-ml" / "models" / "v7_champion.joblib")
    
    url_test_cases = [
        # Benign clean roots
        {"id": "URL_B01", "url": "https://www.google.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B02", "url": "https://github.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B03", "url": "https://www.apple.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B04", "url": "https://www.microsoft.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B05", "url": "https://en.wikipedia.org", "category": "BENIGN_ROOT"},
        {"id": "URL_B06", "url": "https://www.amazon.in", "category": "BENIGN_ROOT"},
        {"id": "URL_B07", "url": "https://www.hdfcbank.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B08", "url": "https://uidai.gov.in", "category": "BENIGN_ROOT"},
        {"id": "URL_B09", "url": "https://stackoverflow.com", "category": "BENIGN_ROOT"},
        {"id": "URL_B10", "url": "https://www.netflix.com", "category": "BENIGN_ROOT"},
        
        # Benign deep paths
        {"id": "URL_B11", "url": "https://github.com/torvalds/linux/blob/master/Makefile", "category": "BENIGN_DEEP_PATH"},
        {"id": "URL_B12", "url": "https://en.wikipedia.org/wiki/Machine_learning", "category": "BENIGN_DEEP_PATH"},
        {"id": "URL_B13", "url": "https://medium.com/@username/how-to-deploy-ml-models-on-android-12345", "category": "BENIGN_DEEP_PATH"},
        {"id": "URL_B14", "url": "https://developer.android.com/guide/topics/ui/layout", "category": "BENIGN_DEEP_PATH"},
        {"id": "URL_B15", "url": "https://aws.amazon.com/ec2/pricing/on-demand/", "category": "BENIGN_DEEP_PATH"},
        
        # Benign query params & search
        {"id": "URL_B16", "url": "https://www.google.com/search?q=machine+learning+security&hl=en", "category": "BENIGN_QUERY"},
        {"id": "URL_B17", "url": "https://www.amazon.com/dp/B08N5WRWNW?ref_=ast_sto_dp&th=1", "category": "BENIGN_QUERY"},
        {"id": "URL_B18", "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ&feature=share", "category": "BENIGN_QUERY"},
        
        # Benign auth & login on known safe brands
        {"id": "URL_B19", "url": "https://trello.com/login", "category": "BENIGN_AUTH_PORTAL"},
        {"id": "URL_B20", "url": "https://accounts.google.com/signin/v2/identifier", "category": "BENIGN_AUTH_PORTAL"},
        {"id": "URL_B21", "url": "https://github.com/login", "category": "BENIGN_AUTH_PORTAL"},
        {"id": "URL_B22", "url": "https://www.paypal.com/signin", "category": "BENIGN_AUTH_PORTAL"},
        {"id": "URL_B23", "url": "https://login.microsoftonline.com/common/oauth2/authorize", "category": "BENIGN_AUTH_PORTAL"},
        
        # Malicious IP Host
        {"id": "URL_M01", "url": "http://192.168.1.1/admin/login.php", "category": "MALICIOUS_IP_HOST"},
        {"id": "URL_M02", "url": "http://45.33.32.156:8080/payload.exe", "category": "MALICIOUS_IP_HOST"},
        {"id": "URL_M03", "url": "http://103.21.244.0/banking/verification", "category": "MALICIOUS_IP_HOST"},
        
        # Malicious Brand Impersonation on Subdomain
        {"id": "URL_M04", "url": "http://paypal.account-security-update.com/login", "category": "MALICIOUS_BRAND_SUBDOMAIN"},
        {"id": "URL_M05", "url": "http://amazon.orders-verification-desk.xyz/signin", "category": "MALICIOUS_BRAND_SUBDOMAIN"},
        {"id": "URL_M06", "url": "http://netflix.payment-recovery.top/update", "category": "MALICIOUS_BRAND_SUBDOMAIN"},
        {"id": "URL_M07", "url": "http://sbi.kyc-verification-portal.online/pan", "category": "MALICIOUS_BRAND_SUBDOMAIN"},
        
        # Malicious Suspicious TLD
        {"id": "URL_M08", "url": "http://account-verify-online.top", "category": "MALICIOUS_SUSP_TLD"},
        {"id": "URL_M09", "url": "http://secure-banking-login.xyz/auth", "category": "MALICIOUS_SUSP_TLD"},
        {"id": "URL_M10", "url": "http://claim-reward-now.buzz/wallet", "category": "MALICIOUS_SUSP_TLD"},
        {"id": "URL_M11", "url": "http://electricity-bill-update.click/pay", "category": "MALICIOUS_SUSP_TLD"},
        
        # Malicious Punycode & Typosquatting
        {"id": "URL_M12", "url": "http://xn--gogle-qta.com/signin", "category": "MALICIOUS_PUNYCODE"},
        {"id": "URL_M13", "url": "http://p-a-y-p-a-l.com/webscr/login", "category": "MALICIOUS_TYPOSQUAT"},
        {"id": "URL_M14", "url": "http://app1e-support-id.com/recover", "category": "MALICIOUS_TYPOSQUAT"},
        
        # Malicious Open Redirect & Nested URLs
        {"id": "URL_M15", "url": "http://evil-site.com/redirect?url=https://phishing.com/login", "category": "MALICIOUS_REDIRECT"},
        {"id": "URL_M16", "url": "http://attacker.com/r?link=https%3A%2F%2Fbank.com%2Fverify", "category": "MALICIOUS_REDIRECT"},
        {"id": "URL_M17", "url": "http://phish-hub.com/https://legit-service.com/checkout", "category": "MALICIOUS_NESTED_URL"},
        
        # Malicious Suspicious Extensions & APK Links
        {"id": "URL_M18", "url": "http://update-system.org/security_patch.apk", "category": "MALICIOUS_SUSP_EXT"},
        {"id": "URL_M19", "url": "http://download-document.net/invoice_scan.exe", "category": "MALICIOUS_SUSP_EXT"},
        {"id": "URL_M20", "url": "http://verify-portal.biz/script.vbs", "category": "MALICIOUS_SUSP_EXT"},
        
        # Evasion / Double Encoding / Port manipulation / Case manipulation
        {"id": "URL_M21", "url": "http://login-service.com/verify%2520account", "category": "MALICIOUS_DOUBLE_ENC"},
        {"id": "URL_M22", "url": "http://banking-portal.com:8443/auth/session", "category": "MALICIOUS_UNUSUAL_PORT"},
        {"id": "URL_M23", "url": "HTTP://SECURITY-UPDATE-PORTAL.XYZ/LOGIN/INDEX.PHP", "category": "MALICIOUS_UPPERCASE_EVASION"},
        {"id": "URL_M24", "url": "http://site.com/../../etc/passwd", "category": "MALICIOUS_TRAVERSAL"},
        {"id": "URL_M25", "url": "http://user@target-account.com/login", "category": "MALICIOUS_AT_SYMBOL"},
        
        # Edge cases
        {"id": "URL_E01", "url": "http://a.co", "category": "EDGE_SHORT_URL"},
        {"id": "URL_E02", "url": "https://example.com/" + "a" * 500, "category": "EDGE_LONG_URL"},
        {"id": "URL_E03", "url": "www.google.com", "category": "EDGE_NO_SCHEME"},
    ]
    
    golden_results = []
    for item in url_test_cases:
        u = item["url"]
        feat_dict = v7_features.extract_v7_features(u)
        feat_vec = [feat_dict[n] for n in v7_features.V7_FEATURE_NAMES]
        
        mat = np.array([feat_vec], dtype=np.float32)
        raw_p = float(sys_model.base_model.predict_proba(mat)[0, 1])
        final_probs = sys_model.predict_proba(mat)[0]
        final_p = float(final_probs[1])
        final_pred = int(sys_model.predict(mat)[0])
        final_label = "MALICIOUS" if final_pred == 1 else "BENIGN"
        
        golden_results.append({
            "id": item["id"],
            "url": u,
            "category": item["category"],
            "feature_names": v7_features.V7_FEATURE_NAMES,
            "features": feat_vec,
            "raw_probability": raw_p,
            "final_probability": final_p,
            "prediction": final_pred,
            "label": final_label,
            "threshold": float(sys_model.threshold),
            "conf_bound": float(sys_model.conf_bound)
        })
        
    out_file = OUTPUT_DIR / "golden_urls.json"
    out_file.write_text(json.dumps(golden_results, indent=2), encoding="utf-8")
    print(f"Exported {len(golden_results)} URL golden test records to {out_file}")

# ============================================================================
# 2. MESSAGES GOLDEN CORPUS
# ============================================================================
def generate_messages_golden():
    print("Generating Messages golden test suite...")
    tw = pickle.load(open(ROOT / "Messages-ml" / "champion_v2_tfidf_word.pkl", "rb"))
    tc = pickle.load(open(ROOT / "Messages-ml" / "champion_v2_tfidf_char.pkl", "rb"))
    sc = pickle.load(open(ROOT / "Messages-ml" / "champion_v2_scaler.pkl", "rb"))
    clf = pickle.load(open(ROOT / "Messages-ml" / "champion_v2_model.pkl", "rb"))
    cfg = FeatureConfig()
    det_names = get_feature_names(cfg)
    
    msg_test_cases = [
        # Benign transactions
        {
            "id": "MSG_B01",
            "sender": "VK-HDFCBK",
            "text": "Your HDFC Bank account XX1234 has been debited by Rs. 2,500.00 on 24-AUG-26. Avl bal: Rs. 45,210.50. Txn: UPI/482910.",
            "category": "BENIGN_TRANSACTION"
        },
        {
            "id": "MSG_B02",
            "sender": "AD-SBIINB",
            "text": "Dear Customer, INR 10,000.00 credited to your A/C **5678 on 20-08-2026 by NEFT. Available balance is INR 1,25,000.00.",
            "category": "BENIGN_TRANSACTION"
        },
        # Benign OTP warnings & Delivery
        {
            "id": "MSG_B03",
            "sender": "AX-AXISBK",
            "text": "482910 is your OTP for Axis Bank NetBanking login. OTP is confidential. Bank never asks to share OTP or password with anyone.",
            "category": "BENIGN_OTP_WARNING"
        },
        {
            "id": "MSG_B04",
            "sender": "VK-SWIGGY",
            "text": "Your Swiggy order is arriving soon. Share delivery OTP 5928 with your delivery partner at your door.",
            "category": "BENIGN_DELIVERY_OTP"
        },
        {
            "id": "MSG_B05",
            "sender": "BW-AMAZON",
            "text": "Your Amazon package containing 1 item is out for delivery. Delivery associate will reach your address today.",
            "category": "BENIGN_DELIVERY"
        },
        # Benign Casual
        {
            "id": "MSG_B06",
            "sender": "+919876543210",
            "text": "Hey are we still meeting for lunch today at 1:30 PM near the office?",
            "category": "BENIGN_CASUAL"
        },
        # Suspicious Lottery / Reward Spam
        {
            "id": "MSG_S01",
            "sender": "+919820012345",
            "text": "Congratulations! Your mobile number won Rs 25,00,000 in KBC Lucky Draw. Call customer manager Mr. Sharma immediately at 9876501234.",
            "category": "SUSPICIOUS_LOTTERY"
        },
        {
            "id": "MSG_S02",
            "sender": "LM-REWARD",
            "text": "Dear user, you earned 5000 bonus reward points worth Rs. 5000. Claim your free cashback gift before tonight 12 AM: http://bit.ly/3x8Gift",
            "category": "SUSPICIOUS_SPAM"
        },
        # Malicious Power Disconnection Phishing
        {
            "id": "MSG_M01",
            "sender": "+918877665544",
            "text": "Dear customer, your electricity power will be disconnected tonight at 9:30 PM from electricity office because your previous month bill was not update. Please immediately contact our electricity officer at 9876543210. Mahavitaran MSEDCL.",
            "category": "MALICIOUS_POWER_DISCONNECT"
        },
        # Malicious KYC / PAN Phishing
        {
            "id": "MSG_M02",
            "sender": "+919123456789",
            "text": "Dear SBI User, your YONO account has been blocked today due to incomplete KYC document verification. Click immediately to update PAN card: https://bit.ly/sbi-pan-update",
            "category": "MALICIOUS_KYC_PHISHING"
        },
        # Malicious OTP Disclosure Request
        {
            "id": "MSG_M03",
            "sender": "+919988776655",
            "text": "URGENT: Unauthorized transaction of Rs. 49,999 initiated on your credit card. Forward or share OTP code to customer care officer at 9876512340 to cancel transaction immediately.",
            "category": "MALICIOUS_OTP_THEFT"
        },
        # Malicious APK Installation
        {
            "id": "MSG_M04",
            "sender": "+917788990011",
            "text": "Your bank account has been suspended. Download and install official bank support security update app immediately: http://192.168.1.10/support.apk",
            "category": "MALICIOUS_APK"
        },
        # Homoglyphs and Zero-Width Evasion
        {
            "id": "MSG_M05",
            "sender": "+919876509876",
            "text": "De\u200bar cust\u043eme\u200dr, y\u043eur ac\u0441ount is bl\u043ecked. Upd\u0430te PAN \u0441ard immed\u0456ately: http://bit.ly/update-pan",
            "category": "MALICIOUS_HOMOGLYPH_ZW"
        },
        # Edge cases
        {
            "id": "MSG_E01",
            "sender": None,
            "text": "",
            "category": "EDGE_EMPTY_TEXT"
        },
        {
            "id": "MSG_E02",
            "sender": None,
            "text": "   \\n\\t  ",
            "category": "EDGE_WHITESPACE"
        },
        {
            "id": "MSG_E03",
            "sender": "12345",
            "text": "Urgent alert: " + "password expired " * 50,
            "category": "EDGE_LONG_REPETITIVE"
        }
    ]
    
    golden_results = []
    for item in msg_test_cases:
        txt = item["text"]
        hdr = item["sender"]
        
        # Feature extraction
        xd = np.array(extract_feature_vector(txt, hdr, cfg), dtype=np.float64)
        xw = tw.transform([txt]).toarray()[0]
        xc = tc.transform([txt]).toarray()[0]
        x_raw = np.hstack([xd, xw, xc])
        x_scaled = sc.transform(x_raw.reshape(1, -1))[0]
        
        raw_margins = clf._raw_predict(x_scaled.reshape(1, -1))[0]
        probs = clf.predict_proba(x_scaled.reshape(1, -1))[0]
        
        p_benign = float(probs[0])
        p_susp = float(probs[1])
        p_mal = float(probs[2])
        p_non_benign = p_susp + p_mal
        
        if p_non_benign >= 0.704:
            pred_class = 1 if p_susp > p_mal else 2
            label = "SUSPICIOUS_SPAM" if p_susp > p_mal else "MALICIOUS"
        else:
            pred_class = 0
            label = "BENIGN"
            
        golden_results.append({
            "id": item["id"],
            "text": txt,
            "sender": hdr,
            "category": item["category"],
            "deterministic_features": xd.tolist(),
            "word_tfidf_nonzero": int(np.count_nonzero(xw)),
            "char_tfidf_nonzero": int(np.count_nonzero(xc)),
            "raw_margins": raw_margins.tolist(),
            "probabilities": [p_benign, p_susp, p_mal],
            "p_non_benign": p_non_benign,
            "predicted_class": pred_class,
            "label": label,
            "threshold": 0.704
        })
        
    out_file = OUTPUT_DIR / "golden_messages.json"
    out_file.write_text(json.dumps(golden_results, indent=2), encoding="utf-8")
    print(f"Exported {len(golden_results)} Messages golden test records to {out_file}")

if __name__ == "__main__":
    generate_url_golden()
    generate_messages_golden()
    print("Golden corpora generation complete.")

