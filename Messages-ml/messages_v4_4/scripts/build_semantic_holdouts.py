"""
Create protected counterfactual semantic holdout suite (55 benign, 55 malicious pairs).
Disjoint from all existing suites and training data.
"""
import json
from pathlib import Path

HOLDOUT_DIR = Path(r"c:\Users\user\Programing files\Yajat\Projects\sentinel\sentinel-ml\Messages-ml\messages_v4_4\evaluation\holdouts")

counterfactual_pairs = [
    # Pair 1: Electricity bill payment vs threat
    ("Electricity bill of Rs 850 paid successfully for consumer 902183 via netbanking.", "BENIGN", "electricity_pair"),
    ("Electricity bill of Rs 850 unpaid. Supply will be cut tonight at 9 PM. Call 9811223344.", "MALICIOUS", "electricity_pair"),
    
    # Pair 2: Credit card reward points
    ("You have 450 reward points on your credit card. Redeem for gift vouchers on official bank app.", "BENIGN", "rewards_pair"),
    ("Credit card reward points Rs 8,500 expiring in 1 hour! Redeem for cash at: http://hdfc-cash.top", "MALICIOUS", "rewards_pair"),

    # Pair 3: Bank account status
    ("Your SBI savings account balance is Rs 14,250 as on 18-Sep. Mini statement available on Yono app.", "BENIGN", "banking_pair"),
    ("Your SBI savings account has been suspended due to pending KYC. Re-activate at: http://sbi-kyc.top", "MALICIOUS", "banking_pair"),

    # Pair 4: Delivery package
    ("Your Amazon package with tracking ID 402910 has been delivered to your doorstep.", "BENIGN", "delivery_pair"),
    ("Your Amazon package could not be delivered due to wrong address. Pay Rs 20 redelivery: http://pkg-del.top", "MALICIOUS", "delivery_pair"),

    # Pair 5: WhatsApp verification
    ("WhatsApp security code changed for chat with Rahul. Tap to verify security keys.", "BENIGN", "chat_pair"),
    ("WhatsApp security code: Send the 6-digit code received on your phone to keep account active.", "MALICIOUS", "chat_pair"),

    # Pair 6: Mobile recharge
    ("Recharge of Rs 299 successful for Jio mobile 9876543210. 1.5 GB/day valid for 28 days.", "BENIGN", "telecom_pair"),
    ("Jio recharge failed. Outgoing calls suspended. Dial *401*9876543210# to resume outgoing services.", "MALICIOUS", "telecom_pair"),

    # Pair 7: Tax refund
    ("Income Tax Department: E-filing acknowledgment for AY 2026-27 processed. Check status on incometax.gov.in", "BENIGN", "tax_pair"),
    ("Income Tax refund of Rs 18,500 approved. Enter bank account and OTP to claim: http://it-refund.site", "MALICIOUS", "tax_pair"),

    # Pair 8: Hospital/Doctor appointment
    ("Apollo Clinic: Your appointment with Dr. Sharma is confirmed for tomorrow 11:30 AM.", "BENIGN", "healthcare_pair"),
    ("Hospital emergency: Your friend met with severe accident. Transfer Rs 10,000 to ICU desk on 9811223344.", "MALICIOUS", "healthcare_pair"),

    # Pair 9: UPI payment
    ("Received Rs 500 from Amit Kumar via PhonePe UPI. UPI Ref 99281029.", "BENIGN", "upi_pair"),
    ("Amit Kumar sent you Rs 5,000 lottery cash. Enter UPI PIN on collect request to accept funds.", "MALICIOUS", "upi_pair"),

    # Pair 10: KYC verification
    ("Aadhaar authentication successful for netbanking login on 18-Sep at 14:32 IST.", "BENIGN", "kyc_pair"),
    ("Aadhaar card not linked with SIM card. Number will be blocked today. Update here: http://sim-link.cc", "MALICIOUS", "kyc_pair"),

    # Pair 11: Flight ticket
    ("IndiGo flight 6E-402 from Bangalore to Delhi is on schedule. Boarding gate 14 opens at 16:15.", "BENIGN", "travel_pair"),
    ("Flight 6E-402 cancelled by airline. Click link to receive instant refund to Google Pay: http://indigo-pay.top", "MALICIOUS", "travel_pair"),

    # Pair 12: Gas utility
    ("Indraprastha Gas: Piped natural gas bill for Consumer 449102 is Rs 620 due on 25-Sep. Pay on iglonline.net", "BENIGN", "utility_pair"),
    ("Gas connection notice: Supply cutoff in 2 hours due to pending inspection fee. Call supervisor 9822334455.", "MALICIOUS", "utility_pair"),

    # Pair 13: Job interview
    ("Tata Consultancy Services: Your interview is scheduled on Monday at 10 AM via MS Teams.", "BENIGN", "employment_pair"),
    ("TCS selected you for part-time data entry job. Pay registration fee Rs 1,000 on GPay to HR 9833445566.", "MALICIOUS", "employment_pair"),

    # Pair 14: Netflix billing
    ("Netflix: Your monthly subscription of Rs 649 was renewed successfully using Mastercard ending in 4921.", "BENIGN", "streaming_pair"),
    ("Netflix: Membership payment failed. Update card details within 24 hours to avoid cancellation: http://netf-bill.cc", "MALICIOUS", "streaming_pair"),

    # Pair 15: Speed post / India Post
    ("India Post: Consignment EK99281029IN delivered at New Delhi GPO. Signature recorded.", "BENIGN", "postal_pair"),
    ("India Post: Address missing on package EK99281029IN. Update street name and pay Rs 15: http://post-help.top", "MALICIOUS", "postal_pair"),

    # Pair 16: Traffic violation
    ("Delhi Traffic Police: Notice for overspeeding generated for DL1CAB1234. View notice at echallan.parivahan.gov.in", "BENIGN", "challan_pair"),
    ("Delhi Traffic Police: Vehicle impound order issued. Pay settlement fine of Rs 1,500 immediately: http://dl-fine.top", "MALICIOUS", "challan_pair"),

    # Pair 17: Banking OTP
    ("594812 is your secret OTP for Axis Bank netbanking. Bank never calls asking for OTP.", "BENIGN", "otp_pair"),
    ("Axis Bank manager: To reverse accidental debit of Rs 25,000, reply with OTP 594812 immediately.", "MALICIOUS", "otp_pair"),

    # Pair 18: Hotel reservation
    ("Marriott Hotels: Reservation confirmed for 2 nights starting 24-Sep. Confirmation number MAR992810.", "BENIGN", "hotel_pair"),
    ("Hotel booking cancelled by resort manager. Call 9844556677 immediately to claim full refund.", "MALICIOUS", "hotel_pair"),

    # Pair 19: Hinglish food delivery
    ("Bhai khana deliver ho gaya hai gate pe, security guard ke paas rakha hai.", "BENIGN", "hinglish_delivery"),
    ("Bhai Zomato refund aane ke liye jo OTP tere SMS me aaya hai turant bhej de.", "MALICIOUS", "hinglish_delivery"),

    # Pair 20: Hinglish friend loan
    ("Bhai kal sham ko milte hain coffee shop pe, 100 rupaye le aana.", "BENIGN", "hinglish_social"),
    ("Bhai accident ho gaya hai mera, 5000 Google Pay kar de turant emergency hai.", "MALICIOUS", "hinglish_social"),

    # Pair 21: Water bill
    ("Delhi Jal Board: Water bill for K No 992810 is Rs 340. Due date 28-Sep. Pay on djb.gov.in", "BENIGN", "water_pair"),
    ("Jal Board alert: Water meter disconnected today due to non-payment. Call officer 9855667788 now.", "MALICIOUS", "water_pair"),

    # Pair 22: College admission
    ("University notice: Semester exam admit card is available for download on college student portal.", "BENIGN", "education_pair"),
    ("College admission cancelled: Transfer Rs 5,000 seat retention fee on PhonePe 9866778899 within 30 mins.", "MALICIOUS", "education_pair"),

    # Pair 23: Debit card expiry
    ("Your HDFC debit card ending in 8812 will expire next month. New card has been dispatched to your address.", "BENIGN", "card_pair"),
    ("Your debit card is blocked permanently. Re-activate online: http://hdfc-activate.top", "MALICIOUS", "card_pair"),

    # Pair 24: Mutual funds
    ("Zerodha Coin: Monthly SIP of Rs 5,000 for Nifty 50 Index Fund executed on 18-Sep.", "BENIGN", "investment_pair"),
    ("Crypto guarantee: Invest Rs 1,000 and earn Rs 15,000 daily with zero risk. Contact manager on WhatsApp 9877889900.", "MALICIOUS", "investment_pair"),

    # Pair 25: Society maintenance
    ("RWA Notice: Monthly maintenance charges of Rs 2,500 due by 25-Sep. Pay via society MyGate app.", "BENIGN", "society_pair"),
    ("RWA Warning: Water and electricity to your flat will be severed today. Call president on 9888990011.", "MALICIOUS", "society_pair"),

    # Pair 26: Mobile banking app
    ("HDFC Bank MobileBanking app updated with enhanced biometric security on Google Play Store.", "BENIGN", "app_pair"),
    ("HDFC Bank: Download HDFC_Security.apk to unblock your netbanking account: http://hdfc-shield.top", "MALICIOUS", "app_pair"),

    # Pair 27: Food cashback
    ("Swiggy Money: Cashback of Rs 35 credited to your Swiggy wallet on order 992810.", "BENIGN", "cashback_pair"),
    ("Swiggy VIP: You won Rs 2,500 festive cash gift. Click to accept money on UPI: http://swiggy-cash.live", "MALICIOUS", "cashback_pair"),

    # Pair 28: Telecom 5G
    ("Airtel 5G Plus is now available in your locality. Enjoy 5G speeds on your 5G handset without extra cost.", "BENIGN", "5g_pair"),
    ("Airtel 5G VIP activation: Dial *21*9811223344# to enable unlimited free high-speed 5G data.", "MALICIOUS", "5g_pair"),

    # Pair 29: Broadband bill
    ("ACT Fibernet: Account 109283 bill of Rs 825 due on 22-Sep. Pay on actcorp.in", "BENIGN", "broadband_pair"),
    ("ACT Fibernet alert: Internet connection disconnected due to arrears. Call technician 9899001122 to restore.", "MALICIOUS", "broadband_pair"),

    # Pair 30: Insurance renewal
    ("Bajaj Allianz: Car insurance policy 882910 expires on 30-Sep. Renew on bajajallianz.com", "BENIGN", "insurance_pair"),
    ("Traffic insurance expired: Fine of Rs 4,000 ordered. Avoid penalty by renewing at 80% discount: http://insure-deal.top", "MALICIOUS", "insurance_pair"),

    # Pair 31: Fastag toll
    ("FASTag: Toll of Rs 85 deducted at Kherki Daula toll plaza. Available balance Rs 450.", "BENIGN", "fastag_pair"),
    ("FASTag blacklisted due to negative balance. Re-activate by paying Rs 100 on: http://fastag-topup.site", "MALICIOUS", "fastag_pair"),

    # Pair 32: EPFO passbook
    ("EPFO: Monthly contribution of Rs 4,200 deposited by employer for July 2026.", "BENIGN", "epfo_pair"),
    ("EPFO alert: PF account frozen due to Aadhaar non-linkage. Update here: http://epfo-link.top", "MALICIOUS", "epfo_pair"),

    # Pair 33: Airline web check-in
    ("Air India: Web check-in completed for passenger Rahul Sharma. Boarding pass sent to email.", "BENIGN", "checkin_pair"),
    ("Air India notice: Flight delayed 12 hours. Click to claim Rs 4,000 refreshment compensation: http://airindia-comp.top", "MALICIOUS", "checkin_pair"),

    # Pair 34: Laptop repair
    ("Lenovo Service: Your laptop motherboard repair is completed. Collect device from Nehru Place service center.", "BENIGN", "repair_pair"),
    ("Lenovo Customer Care: Software virus detected on your PC. Download Lenovo_Cleaner.apk: http://lenovo-clean.top", "MALICIOUS", "repair_pair"),

    # Pair 35: Bank locker
    ("ICICI Bank: Annual locker rent of Rs 3,500 debited from A/C XX8812 on 18-Sep.", "BENIGN", "locker_pair"),
    ("ICICI Bank notice: Locker break-open notice issued. Call bank manager at 9900112233 to prevent seizure.", "MALICIOUS", "locker_pair"),

    # Pair 36: Courier dispatch
    ("BlueDart: AWB 992810294 dispatched from Mumbai hub. Expected delivery on 20-Sep.", "BENIGN", "courier_pair"),
    ("BlueDart alert: Parcel withheld by police. Call narcotics officer 9911223344 immediately.", "MALICIOUS", "courier_pair"),

    # Pair 37: Book return
    ("British Council Library: Book 'Machine Learning' is due for return on 22-Sep. Renew on online portal.", "BENIGN", "library_pair"),
    ("Library legal notice: Unreturned books penalty Rs 5,000. Pay online to avoid police complaint: http://library-fine.top", "MALICIOUS", "library_pair"),

    # Pair 38: Electricity tariff
    ("BESCOM: Tariff revision notice effective from next month available on bescom.org", "BENIGN", "tariff_pair"),
    ("BESCOM alert: Meter disconnect in 1 hour due to tariff discrepancy. Call lineman 9922334455.", "MALICIOUS", "tariff_pair"),

    # Pair 39: Google account security
    ("Google: Security checkup completed. No recommendations found for your account.", "BENIGN", "google_pair"),
    ("Google alert: Password leaked online. Enter your current password to secure account: http://google-sec.top", "MALICIOUS", "google_pair"),

    # Pair 40: Credit score check
    ("CIBIL: Your monthly credit score for September is 782. Full report available on cibil.com", "BENIGN", "cibil_pair"),
    ("CIBIL emergency: Negative remarks added to your credit profile. Settle now to clear score: http://cibil-fix.site", "MALICIOUS", "cibil_pair"),

    # Pair 41: OTT renewal
    ("Disney+ Hotstar: Annual subscription renewed for Rs 899 via UPI auto-pay.", "BENIGN", "hotstar_pair"),
    ("Disney+ Hotstar: Account suspended for password sharing. Click to re-activate: http://hotstar-login.top", "MALICIOUS", "hotstar_pair"),

    # Pair 42: Bank loan statement
    ("HDFC Bank: Home loan statement for account 992810 sent to registered email address.", "BENIGN", "homeloan_pair"),
    ("HDFC Bank: Loan foreclosure notice. Call loan recovery officer 9933445566 to settle dues.", "MALICIOUS", "homeloan_pair"),

    # Pair 43: Hinglish movie plan
    ("Bhai sham ko PVR chal rahe hain kya movie dekhne? Maine tickets check ki hain.", "BENIGN", "hinglish_movie"),
    ("Bhai movie tickets free me book karne ke liye ye app download kar: http://free-movies.top/app.apk", "MALICIOUS", "hinglish_movie"),

    # Pair 44: Hinglish ride sharing
    ("Bhai main car le ke nikal raha hoon metro station se, 5 min me pickup kar lunga.", "BENIGN", "hinglish_ride"),
    ("Bhai cab driver ne mana kar diya, tere PhonePe pe request bheji hai pay kar de jaldi.", "MALICIOUS", "hinglish_ride"),

    # Pair 45: Gym subscription
    ("Gold's Gym: Your annual gym membership is active until 31-December-2026. Keep working out!", "BENIGN", "gym_pair"),
    ("Gold's Gym: VIP pass won in raffle! Pay registration fee of Rs 499 at: http://golds-vip.top", "MALICIOUS", "gym_pair"),

    # Pair 46: School fee receipt
    ("DPS School: Term 2 tuition fee receipt for student Aarav Sharma downloaded successfully.", "BENIGN", "school_pair"),
    ("DPS School: Student expelled due to pending fee. Call principal assistant at 9944556677 immediately.", "MALICIOUS", "school_pair"),

    # Pair 47: Telecom DND
    ("TRAI: Do Not Disturb preference updated successfully on your mobile number.", "BENIGN", "dnd_pair"),
    ("TRAI alert: Mobile number disconnected for spam calls. Call verification desk 9955667788.", "MALICIOUS", "dnd_pair"),

    # Pair 48: Electricity meter change
    ("MSEDCL: Smart meter installation scheduled for your locality next week. No charges applicable.", "BENIGN", "smartmeter_pair"),
    ("MSEDCL notice: Old meter rejected. Pay Rs 2,500 smart meter charge immediately: http://msedcl-meter.top", "MALICIOUS", "smartmeter_pair"),

    # Pair 49: Domestic gas cylinder
    ("Indane Gas: Refill cylinder booked. Order No 992810. Cash on delivery amount Rs 820.", "BENIGN", "lpg_pair"),
    ("Indane Gas: Gas subsidy of Rs 450 cancelled. Re-link Aadhaar on: http://indane-subsidy.site", "MALICIOUS", "lpg_pair"),

    # Pair 50: Pharmacy order
    ("Tata 1mg: Your prescription medicines have been packed and handed to delivery partner.", "BENIGN", "pharmacy_pair"),
    ("Tata 1mg alert: Medicine dispatch stopped due to pending government tax Rs 35. Pay at: http://1mg-pay.top", "MALICIOUS", "pharmacy_pair"),

    # Pair 51: Hinglish office tea
    ("Bhai chai peene aaja niche tapri pe, mast garam samosa bhi mil raha hai.", "BENIGN", "hinglish_tea"),
    ("Bhai emergency hai, account me paise khatam ho gaye, 1000 GPay kar de sham ko de dunga.", "MALICIOUS", "hinglish_tea"),

    # Pair 52: Hinglish room rent
    ("Bhai landlord ko rent de diya tha maine cheque se, receipt le li hai.", "BENIGN", "hinglish_rent"),
    ("Bhai rent transfer karne ke liye landlord ke account pe jo OTP aaya hai bata de.", "MALICIOUS", "hinglish_rent"),

    # Pair 53: E-commerce return
    ("Flipkart: Return request for shoes approved. Pickup executive will visit on Friday.", "BENIGN", "flipkart_pair"),
    ("Flipkart alert: Refund of Rs 2,499 failed. Enter netbanking details at: http://fk-refund.live", "MALICIOUS", "flipkart_pair"),

    # Pair 54: Banking debit alert
    ("SBI: Rs 1,200 withdrawn from ATM at Connaught Place, New Delhi. Available balance Rs 28,400.", "BENIGN", "atm_pair"),
    ("SBI: Unauthorized ATM withdrawal of Rs 40,000 detected. Reply with OTP immediately to block card.", "MALICIOUS", "atm_pair"),

    # Pair 55: Passport dispatch
    ("Passport Seva: Passport dispatched via Speed Post tracking number PP99281029IN.", "BENIGN", "passport_pair"),
    ("Passport Seva: Passport application rejected by police verification. Call officer 9966778899 to clear file.", "MALICIOUS", "passport_pair"),
]

out_p = HOLDOUT_DIR / "holdout_counterfactual_semantic.jsonl"
with open(out_p, "w", encoding="utf-8") as f:
    for idx, (txt, label, cat) in enumerate(counterfactual_pairs):
        record = {
            "message_id": f"sem_cf_{idx+1:04d}",
            "raw_text": txt,
            "security_label": label,
            "category": cat,
            "source_id": "V4_4_HOLDOUT_COUNTERFACTUAL_SEMANTIC",
            "source_type": "PROTECTED_HOLDOUT"
        }
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

print(f"Saved {len(counterfactual_pairs)} counterfactual semantic holdout records to {out_p}")
