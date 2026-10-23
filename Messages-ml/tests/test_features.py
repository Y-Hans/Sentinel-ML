"""
Unit tests for deterministic feature extraction and feature group selection.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from feature_config import FeatureConfig
from feature_extraction import (
    extract_feature_vector,
    extract_message_features,
    get_feature_names,
)


class TestFeatureExtraction(unittest.TestCase):

    def test_empty_message_features(self):
        feats = extract_message_features("", sender_header=None)
        self.assertIsInstance(feats, dict)
        self.assertEqual(feats["message_length"], 0.0)
        self.assertEqual(feats["word_count"], 0.0)
        self.assertEqual(feats["otp_disclosure_request"], 0.0)

    def test_feature_group_selection(self):
        cfg_structural = FeatureConfig(active_groups=["STRUCTURAL"])
        feats_struct = extract_message_features("Hello world", config=cfg_structural)
        self.assertIn("message_length", feats_struct)
        self.assertNotIn("urgency_word_count", feats_struct)
        self.assertNotIn("otp_disclosure_request", feats_struct)

        cfg_otp = FeatureConfig(active_groups=["OTP_INTENT"])
        feats_otp = extract_message_features("Hello world", config=cfg_otp)
        self.assertIn("otp_disclosure_request", feats_otp)
        self.assertNotIn("message_length", feats_otp)

    def test_otp_intent_legitimate_warning(self):
        text = "483921 is your OTP for HDFC Bank. Valid for 10 mins. Do not share with anyone."
        feats = extract_message_features(text, sender_header="VK-HDFCBK")
        self.assertEqual(feats["otp_present"], 1.0)
        self.assertEqual(feats["otp_negation_warning"], 1.0)
        self.assertEqual(feats["otp_disclosure_request"], 0.0)
        self.assertLess(feats["otp_intent_risk_score"], 0.0)

    def test_otp_intent_disclosure_theft(self):
        text = "Your card has unauthorized charge. Forward the OTP to 9800000001 immediately to cancel."
        feats = extract_message_features(text, sender_header="+919800000001")
        self.assertEqual(feats["otp_present"], 1.0)
        self.assertEqual(feats["otp_negation_warning"], 0.0)
        self.assertEqual(feats["otp_disclosure_request"], 1.0)
        self.assertGreater(feats["otp_intent_risk_score"], 0.0)

    def test_delivery_otp_context(self):
        text = "Swiggy order arriving! Share delivery OTP 4920 with delivery agent at your door."
        feats = extract_message_features(text, sender_header="AD-SWIGGY")
        self.assertEqual(feats["delivery_otp_context"], 1.0)

    def test_cta_url_shorteners_and_phones(self):
        text = "Update KYC now at http://bit.ly/kyc-update or call +919876543210. UPI: user@paytm"
        feats = extract_message_features(text, sender_header=None)
        self.assertEqual(feats["url_count"], 1.0)
        self.assertEqual(feats["has_shortener_url"], 1.0)
        self.assertGreaterEqual(feats["phone_number_count"], 1.0)
        self.assertEqual(feats["upi_vpa_count"], 1.0)

    def test_feature_names_order_deterministic(self):
        names1 = get_feature_names()
        names2 = get_feature_names()
        self.assertEqual(names1, names2)

        vec = extract_feature_vector("Test message", sender_header="AX-TEST")
        self.assertEqual(len(vec), len(names1))


if __name__ == "__main__":
    unittest.main()
