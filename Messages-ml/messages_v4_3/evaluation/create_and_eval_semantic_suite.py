"""
Independent Semantic Generalization Suite for Sentinel Messages ML.
Authored from scratch to test:
1. Company/Entity Substitution
2. Paraphrasing
3. English <-> Hinglish
4. Word-Order Variation
5. Harmless Wording Changes (Contrastive Pairs)
6. Action-Intent Changes
7. Informational vs Coercive OTP Changes
"""
import json
from pathlib import Path
import pickle
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
import sys
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "messages_v4_3/models"))
from feature_config import FeatureConfig
from feature_extraction import extract_feature_vector
from candidate_d_v4_3 import extract_structural_signals

LABELS = {"BENIGN": 0, "SUSPICIOUS_SPAM": 1, "MALICIOUS": 2}
REV_LABELS = {0: "BENIGN", 1: "SUSPICIOUS_SPAM", 2: "MALICIOUS"}

SEMANTIC_TEST_CASES = [
    # 1. Company / Entity Substitutions
    {"id": "SEM_01", "category": "company_substitution", "security_label": "MALICIOUS", "raw_text": "Your Bandhan Bank account will be terminated today. Download APK to update KYC: https://bandhan-kyc.top"},
    {"id": "SEM_02", "category": "company_substitution", "security_label": "BENIGN", "raw_text": "Your Bandhan Bank account balance for A/C XX4412 is Rs 4,500 on 14-Sep."},
    {"id": "SEM_03", "category": "company_substitution", "security_label": "MALICIOUS", "raw_text": "Dhanlaxmi Bank security notice: Suspicious activity found. Re-activate debit card at https://dhanlaxmi-login.xyz"},
    {"id": "SEM_04", "category": "company_substitution", "security_label": "BENIGN", "raw_text": "Dhanlaxmi Bank: OTP for transaction of Rs 1,200 at Amazon is 584910. Do not share."},
    {"id": "SEM_05", "category": "company_substitution", "security_label": "MALICIOUS", "raw_text": "Porter delivery delayed due to unpaid surcharge of Rs 25. Clear dues immediately at https://porter-pay.live"},
    {"id": "SEM_06", "category": "company_substitution", "security_label": "BENIGN", "raw_text": "Your Porter mini-truck is arriving in 5 mins. Share start OTP 4491 with driver at pickup location."},
    {"id": "SEM_07", "category": "company_substitution", "security_label": "MALICIOUS", "raw_text": "Tata Neu luxury gift card worth Rs 10000 waiting for you! Click to claim: http://tataneu-rewards.club"},
    {"id": "SEM_08", "category": "company_substitution", "security_label": "BENIGN", "raw_text": "Tata Neu: You earned 45 NeuCoins on your BigBasket purchase of Rs 920."},

    # 2. Paraphrasing
    {"id": "SEM_09", "category": "paraphrasing", "security_label": "MALICIOUS", "raw_text": "Attention subscriber, power grid shutdown scheduled at 9pm due to pending invoice. Avoid blackout by calling 9123456780."},
    {"id": "SEM_10", "category": "paraphrasing", "security_label": "BENIGN", "raw_text": "Dear citizen, scheduled power maintenance in Sector 4 from 2 PM to 5 PM today. Inconvenience regretted."},
    {"id": "SEM_11", "category": "paraphrasing", "security_label": "MALICIOUS", "raw_text": "Notice of impending legal proceedings: A formal complaint has been filed with cyber cell. Contact inspector at 9988776655 to settle."},
    {"id": "SEM_12", "category": "paraphrasing", "security_label": "BENIGN", "raw_text": "Notice: Annual General Meeting of residential society will be held on Sunday at 10 AM in clubhouse."},
    {"id": "SEM_13", "category": "paraphrasing", "security_label": "MALICIOUS", "raw_text": "Tax refund of Rs 18,400 has been sanctioned by department. Fill refund form: http://incometax-refund.top"},
    {"id": "SEM_14", "category": "paraphrasing", "security_label": "BENIGN", "raw_text": "Income Tax Department: Your e-filing for AY 2026-27 has been successfully processed. Check status on official portal incometax.gov.in"},

    # 3. English <-> Hinglish
    {"id": "SEM_15", "category": "english_hinglish", "security_label": "MALICIOUS", "raw_text": "Urgent: Transfer money immediately to cancel your arrest warrant issued by CBI."},
    {"id": "SEM_16", "category": "english_hinglish", "security_label": "MALICIOUS", "raw_text": "Turant paise transfer karo varna CBI arrest warrant nikal degi aur police ghar aayegi."},
    {"id": "SEM_17", "category": "english_hinglish", "security_label": "BENIGN", "raw_text": "Can you transfer Rs 200 for lunch? I forgot my wallet at home today."},
    {"id": "SEM_18", "category": "english_hinglish", "security_label": "BENIGN", "raw_text": "Bhai lunch ke liye 200 rupaye bhej de na, wallet ghar par bhool gaya tha."},
    {"id": "SEM_19", "category": "english_hinglish", "security_label": "MALICIOUS", "raw_text": "Your SIM card will be deactivated in 24 hours. Submit Aadhaar documents now: http://airtel-verify.cc"},
    {"id": "SEM_20", "category": "english_hinglish", "security_label": "MALICIOUS", "raw_text": "Aapki SIM 24 ghante me band ho jayegi. Turant Aadhaar update karein: http://airtel-verify.cc"},
    {"id": "SEM_21", "category": "english_hinglish", "security_label": "BENIGN", "raw_text": "Recharge of Rs 299 successful for your airtel prepaid number. Data balance: 1.5 GB/day."},
    {"id": "SEM_22", "category": "english_hinglish", "security_label": "BENIGN", "raw_text": "Recharge ho gaya hai 299 wala, ab internet chalne lagega."},

    # 4. Word-Order Variation
    {"id": "SEM_23", "category": "word_order", "security_label": "MALICIOUS", "raw_text": "Urgent: Click http://secure-debit.xyz now to unlock your debit card before midnight."},
    {"id": "SEM_24", "category": "word_order", "security_label": "MALICIOUS", "raw_text": "Your debit card is locked; before midnight arrives, click http://secure-debit.xyz to unlock it right now."},
    {"id": "SEM_25", "category": "word_order", "security_label": "MALICIOUS", "raw_text": "Before midnight, unlocking your debit card requires you to click http://secure-debit.xyz urgently."},
    {"id": "SEM_26", "category": "word_order", "security_label": "BENIGN", "raw_text": "Your debit card ending in 8892 was used for Rs 450 at Metro Station. Available balance Rs 12,300."},
    {"id": "SEM_27", "category": "word_order", "security_label": "BENIGN", "raw_text": "At Metro Station, Rs 450 was spent using your debit card ending in 8892. Available balance Rs 12,300."},

    # 5. Harmless Wording Changes (Contrastive Pairs)
    {"id": "SEM_28", "category": "harmless_contrastive", "security_label": "MALICIOUS", "raw_text": "Electricity bill unpaid. Your line will be disconnected tonight. Call office 9811223344 immediately."},
    {"id": "SEM_29", "category": "harmless_contrastive", "security_label": "BENIGN", "raw_text": "Electricity bill paid successfully for Consumer No 558192. Amount Rs 1,420. Thank you for using online portal."},
    {"id": "SEM_30", "category": "harmless_contrastive", "security_label": "BENIGN", "raw_text": "Bhai light chali gayi hai colony me, tumhare ghar pe inverter chal raha hai kya?"},
    {"id": "SEM_31", "category": "harmless_contrastive", "security_label": "MALICIOUS", "raw_text": "Colony bijli cut ho jayegi agar bill submit nahi kiya. Call 9811223344"},
    {"id": "SEM_32", "category": "harmless_contrastive", "security_label": "MALICIOUS", "raw_text": "Your courier parcel could not be delivered. Update address and pay Rs 15: http://indiapost-track.top"},
    {"id": "SEM_33", "category": "harmless_contrastive", "security_label": "BENIGN", "raw_text": "Your courier parcel has been dispatched from Mumbai hub. Expected delivery date is 16-Sep."},
    {"id": "SEM_34", "category": "harmless_contrastive", "security_label": "BENIGN", "raw_text": "Delivery boy is waiting outside downstairs, please collect your Swiggy order."},

    # 6. Action-Intent Changes (Informational vs Coercive)
    {"id": "SEM_35", "category": "action_intent", "security_label": "BENIGN", "raw_text": "Your daily UPI transfer limit has been set to Rs 50,000 for account XX9102. Contact branch if not requested."},
    {"id": "SEM_36", "category": "action_intent", "security_label": "MALICIOUS", "raw_text": "Enter UPI PIN on this collect prompt to receive Rs 25,000 cashback directly in your bank account."},
    {"id": "SEM_37", "category": "action_intent", "security_label": "BENIGN", "raw_text": "You have received a UPI payment of Rs 1,500 from Rohit Sharma via Google Pay."},
    {"id": "SEM_38", "category": "action_intent", "security_label": "MALICIOUS", "raw_text": "Rohit Sharma sent you Rs 5,000 lottery bonus. Click link to approve transaction: http://gpay-collect.live"},
    {"id": "SEM_39", "category": "action_intent", "security_label": "BENIGN", "raw_text": "Dear customer, your credit card statement for August is ready. Total due Rs 4,520 by 20-Sep."},
    {"id": "SEM_40", "category": "action_intent", "security_label": "MALICIOUS", "raw_text": "Credit card rewards expiring today! Redeem points for Rs 8,000 cash voucher: http://creditcard-point.xyz"},

    # 7. Informational vs Coercive OTP Changes
    {"id": "SEM_41", "category": "otp_intent", "security_label": "BENIGN", "raw_text": "739201 is your secret OTP for login. Bank never calls to ask for OTP. Keep it strictly confidential."},
    {"id": "SEM_42", "category": "otp_intent", "security_label": "MALICIOUS", "raw_text": "Bank manager: To prevent debit card block, reply back with the 6-digit OTP you just received."},
    {"id": "SEM_43", "category": "otp_intent", "security_label": "BENIGN", "raw_text": "Do not share this OTP: 449120. Valid for 5 mins for netbanking login."},
    {"id": "SEM_44", "category": "otp_intent", "security_label": "MALICIOUS", "raw_text": "Your OTP 449120 is required by our customer executive to approve loan disbursal. Tell officer now."},
    {"id": "SEM_45", "category": "otp_intent", "security_label": "BENIGN", "raw_text": "Delivery OTP for your package from Flipkart is 8391. Give this code to delivery agent only upon arrival."},
    {"id": "SEM_46", "category": "otp_intent", "security_label": "MALICIOUS", "raw_text": "Delivery agent calling: Delivery failed, share OTP over call to reschedule delivery for tomorrow."},

    # 8. Work from home / Task Frauds vs Real Job Alerts
    {"id": "SEM_47", "category": "job_task", "security_label": "MALICIOUS", "raw_text": "YouTube video like task: Earn Rs 500 per video from mobile. Start today on Telegram: t.me/yt_task_daily"},
    {"id": "SEM_48", "category": "job_task", "security_label": "BENIGN", "raw_text": "Your interview with Infosys is scheduled for tomorrow at 11:00 AM via Microsoft Teams. Link sent to email."},
    {"id": "SEM_49", "category": "job_task", "security_label": "MALICIOUS", "raw_text": "Hotels rating job: Earn Rs 4000 daily part time. No experience needed. Contact WhatsApp 9876543210"},
    {"id": "SEM_50", "category": "job_task", "security_label": "BENIGN", "raw_text": "Hi team, please review the PR on GitHub before tomorrow's release build."},
]

def evaluate_semantic_suite():
    out_jsonl = ROOT / "messages_v4_3/evaluation/independent_semantic_generalization.jsonl"
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for r in SEMANTIC_TEST_CASES:
            f.write(json.dumps(r) + "\n")
    print(f"Authored and saved {len(SEMANTIC_TEST_CASES)} independent test cases to {out_jsonl}")

    # Load V2
    with open(ROOT / "champion_v2_model.pkl", "rb") as f: v2_model = pickle.load(f)
    with open(ROOT / "champion_v2_scaler.pkl", "rb") as f: v2_scaler = pickle.load(f)
    with open(ROOT / "champion_v2_tfidf_word.pkl", "rb") as f: v2_word = pickle.load(f)
    with open(ROOT / "champion_v2_tfidf_char.pkl", "rb") as f: v2_char = pickle.load(f)

    # Load V4.3
    with open(ROOT / "messages_v4_3/models/candidate_d/model.pkl", "rb") as f: v43_model = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/scaler.pkl", "rb") as f: v43_scaler = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/word_vec.pkl", "rb") as f: v43_word = pickle.load(f)
    with open(ROOT / "messages_v4_3/models/candidate_d/char_vec.pkl", "rb") as f: v43_char = pickle.load(f)

    texts = [r["raw_text"] for r in SEMANTIC_TEST_CASES]
    y_true = np.array([LABELS[r["security_label"]] for r in SEMANTIC_TEST_CASES], dtype=np.int32)
    mal_mask = (y_true == 2)
    ben_mask = (y_true == 0)
    n_mal = int(mal_mask.sum())
    n_ben = int(ben_mask.sum())

    # V2 eval
    det_v2 = np.asarray([extract_feature_vector(t, None, FeatureConfig()) for t in texts], dtype=np.float32)
    w_v2 = v2_word.transform(texts).toarray()
    c_v2 = v2_char.transform(texts).toarray()
    X_v2 = np.hstack([det_v2, w_v2, c_v2])
    probs_v2 = v2_model.predict_proba(v2_scaler.transform(X_v2))
    p_nb_v2 = probs_v2[:, 1] + probs_v2[:, 2]
    pred_v2 = np.where(p_nb_v2 >= 0.704, np.where(probs_v2[:, 2] >= probs_v2[:, 1], 2, 1), 0)

    # V4.3 eval
    st_v43 = np.asarray([extract_structural_signals(t) for t in texts], dtype=np.float32)
    w_v43 = v43_word.transform(texts).toarray()
    c_v43 = v43_char.transform(texts).toarray()
    X_v43 = np.hstack([st_v43, w_v43, c_v43]).astype(np.float32)
    probs_v43 = v43_model.predict_proba(v43_scaler.transform(X_v43))
    p_nb_v43 = probs_v43[:, 1] + probs_v43[:, 2]
    pred_v43 = np.where(p_nb_v43 >= 0.61, np.where(probs_v43[:, 2] >= probs_v43[:, 1], 2, 1), 0)

    v2_mal_rec = float((pred_v2[mal_mask] == 2).sum()) / n_mal
    v2_ben_fp = int((pred_v2[ben_mask] != 0).sum())
    v2_ben_fpr = float(v2_ben_fp) / n_ben

    v43_mal_rec = float((pred_v43[mal_mask] == 2).sum()) / n_mal
    v43_ben_fp = int((pred_v43[ben_mask] != 0).sum())
    v43_ben_fpr = float(v43_ben_fp) / n_ben

    print("\n" + "="*80)
    print(f"INDEPENDENT SEMANTIC GENERALIZATION BENCHMARK (N={len(SEMANTIC_TEST_CASES)}: {n_mal} Malicious, {n_ben} Benign)")
    print("="*80)
    print(f"Champion V2 Baseline: Malicious Recall = {(pred_v2[mal_mask] == 2).sum()}/{n_mal} ({v2_mal_rec*100:.1f}%), Benign FP = {v2_ben_fp}/{n_ben} ({v2_ben_fpr*100:.1f}%)")
    print(f"Sentinel V4.3 Model:  Malicious Recall = {(pred_v43[mal_mask] == 2).sum()}/{n_mal} ({v43_mal_rec*100:.1f}%), Benign FP = {v43_ben_fp}/{n_ben} ({v43_ben_fpr*100:.1f}%)")
    print(f"Delta:                Malicious Recall = {(v43_mal_rec - v2_mal_rec)*100:+.1f}%, Benign FPR = {(v43_ben_fpr - v2_ben_fpr)*100:+.1f}%")

    # Category breakdown
    print("\n--- Breakdown by Semantic Transformation Category ---")
    cats = sorted(list(set(r["category"] for r in SEMANTIC_TEST_CASES)))
    for cat in cats:
        cat_indices = [i for i, r in enumerate(SEMANTIC_TEST_CASES) if r["category"] == cat]
        cat_y = y_true[cat_indices]
        c_mal = (cat_y == 2)
        c_ben = (cat_y == 0)
        n_c_mal = int(c_mal.sum())
        n_c_ben = int(c_ben.sum())

        v2_c_rec = f"{(pred_v2[cat_indices][c_mal] == 2).sum()}/{n_c_mal}" if n_c_mal > 0 else "N/A"
        v43_c_rec = f"{(pred_v43[cat_indices][c_mal] == 2).sum()}/{n_c_mal}" if n_c_mal > 0 else "N/A"

        v2_c_fp = f"{(pred_v2[cat_indices][c_ben] != 0).sum()}/{n_c_ben}" if n_c_ben > 0 else "N/A"
        v43_c_fp = f"{(pred_v43[cat_indices][c_ben] != 0).sum()}/{n_c_ben}" if n_c_ben > 0 else "N/A"

        print(f"{cat:<24s} | Mal Rec: V2={v2_c_rec:>5s}, V4.3={v43_c_rec:>5s} | Ben FP: V2={v2_c_fp:>5s}, V4.3={v43_c_fp:>5s}")

if __name__ == "__main__":
    evaluate_semantic_suite()
