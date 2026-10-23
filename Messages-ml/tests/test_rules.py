"""
Unit tests for deterministic rule signals and context-aware OTP heuristics.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from rules_engine import evaluate_rules


class TestRulesEngine(unittest.TestCase):

    def test_legitimate_otp_warning_rule(self):
        text = "483921 is your secret OTP. Never share this OTP with anyone, including bank staff."
        signals = evaluate_rules(text, sender_header="VK-HDFCBK")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("LEGIT_OTP_WARNING", signal_types)
        self.assertNotIn("OTP_DISCLOSURE_REQUEST", signal_types)

    def test_legitimate_delivery_otp_rule(self):
        text = "Your delivery OTP is 4920. Share it with the delivery associate when your package arrives."
        signals = evaluate_rules(text, sender_header="VK-AMAZON")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("LEGIT_DELIVERY_OTP", signal_types)
        self.assertNotIn("OTP_DISCLOSURE_REQUEST", signal_types)

    def test_malicious_otp_disclosure_rule(self):
        text = "Your account is suspended. Send OTP 483921 to customer care at 9800000001 immediately."
        signals = evaluate_rules(text, sender_header="+919800000001")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("OTP_DISCLOSURE_REQUEST", signal_types)
        otp_sig = next(s for s in signals if s.signal_type == "OTP_DISCLOSURE_REQUEST")
        self.assertEqual(otp_sig.severity, "HIGH")

    def test_electricity_disconnection_scam_rule(self):
        text = "Dear consumer, electricity will be disconnected at 9:30 PM tonight due to unpaid bill. Call officer at 9800000030."
        signals = evaluate_rules(text, sender_header="+919800000030")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("ELECTRICITY_SCAM_THREAT", signal_types)
        elec_sig = next(s for s in signals if s.signal_type == "ELECTRICITY_SCAM_THREAT")
        self.assertEqual(elec_sig.severity, "CRITICAL")

    def test_bank_kyc_phishing_link_rule(self):
        text = "SBI YONO user: Account suspended due to pending PAN card. Click http://bit.ly/sbi-pan-update to restore."
        signals = evaluate_rules(text, sender_header="+919800000010")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("BANK_KYC_PHISHING", signal_types)

    def test_upi_collect_fraud_rule(self):
        # Malicious positive: reward lure requesting UPI PIN entry to receive money
        scam_text = "Congratulations! You have won Rs 5000 reward cashback. Enter UPI PIN to receive money in your account."
        signals = evaluate_rules(scam_text, sender_header="+919800000060")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("UPI_COLLECT_FRAUD", signal_types)
        upi_sig = next(s for s in signals if s.signal_type == "UPI_COLLECT_FRAUD")
        self.assertEqual(upi_sig.rule_id, "RULE-UPI-COLLECT")
        self.assertEqual(upi_sig.severity, "CRITICAL")

        # Benign negative: legitimate UPI transaction confirmation
        legit_text = "Your UPI payment of INR 500.00 to Grocery Store was successful on 24-AUG-26. Ref: 987654321098."
        signals_legit = evaluate_rules(legit_text, sender_header="AX-SBIPAY")
        self.assertEqual(len(signals_legit), 0)

    def test_task_job_scam_rule(self):
        # Malicious positive: part-time review job lure redirecting to WhatsApp
        job_scam_text = "Work from home part-time job! Earn Rs 2500 daily by Google Maps review task. Contact HR on WhatsApp: https://wa.me/919800000042"
        signals = evaluate_rules(job_scam_text, sender_header="+919800000042")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("JOB_TASK_SCAM", signal_types)
        job_sig = next(s for s in signals if s.signal_type == "JOB_TASK_SCAM")
        self.assertEqual(job_sig.rule_id, "RULE-TASK-JOB-SCAM")
        self.assertEqual(job_sig.severity, "HIGH")

        # Benign negative: legitimate corporate work-from-home or employment advisory
        legit_work_text = "Notice: Work from home policy updated for all employees. Please review HR guidelines on internal portal."
        signals_legit = evaluate_rules(legit_work_text, sender_header="VM-CORP-INFO")
        self.assertEqual(len(signals_legit), 0)

    def test_apk_malware_dropper_rule(self):
        # Malicious positive: delivery update directing to download APK app
        apk_scam_text = "Delivery on hold. Download support app http://delivery.xyz/app.apk to reschedule."
        signals = evaluate_rules(apk_scam_text, sender_header="+919800000070")
        signal_types = [s.signal_type for s in signals]
        self.assertIn("APK_MALWARE_DROPPER", signal_types)
        apk_sig = next(s for s in signals if s.signal_type == "APK_MALWARE_DROPPER")
        self.assertEqual(apk_sig.rule_id, "RULE-APK-DROPPER")
        self.assertEqual(apk_sig.severity, "HIGH")

        # Benign negative: official shipping notice without APK download
        legit_shipping_text = "Your order has been shipped via IndiaPost tracking #123456. Track online at indiapost.gov.in."
        signals_legit = evaluate_rules(legit_shipping_text, sender_header="AD-INDPOST")
        self.assertEqual(len(signals_legit), 0)

    def test_sender_suffix_alone_produces_no_rule_verdict(self):
        # A neutral message from a promotional or government header should NOT trigger critical rules
        neutral_text = "Good morning! Wishing you a wonderful week ahead."
        signals_p = evaluate_rules(neutral_text, sender_header="VM-BRAND-P")
        signals_g = evaluate_rules(neutral_text, sender_header="AD-GOVT-G")
        self.assertEqual(len(signals_p), 0)
        self.assertEqual(len(signals_g), 0)


if __name__ == "__main__":
    unittest.main()

