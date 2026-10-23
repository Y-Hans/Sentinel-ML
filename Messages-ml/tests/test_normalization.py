"""
Unit tests for text normalization, script analysis, and homoglyph detection.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from text_normalization import analyze_and_normalize, mask_sensitive_patterns


class TestTextNormalization(unittest.TestCase):

    def test_empty_string(self):
        res = analyze_and_normalize("")
        self.assertEqual(res.total_chars, 0)
        self.assertEqual(res.cleaned_text, "")
        self.assertEqual(res.detected_script, "UNKNOWN")
        self.assertFalse(res.is_mixed_script)

    def test_none_handling(self):
        res = analyze_and_normalize(None)
        self.assertEqual(res.total_chars, 0)

    def test_zero_width_characters(self):
        # Text with zero-width spaces (\u200B) and zero-width joiners (\u200D)
        obfuscated = "S\u200bB\u200bI\u200d Y\u200bONO"
        res = analyze_and_normalize(obfuscated)
        self.assertEqual(res.zero_width_count, 4)
        self.assertEqual(res.cleaned_text, "SBI YONO")

    def test_homoglyph_detection_and_normalization(self):
        # Cyrillic 'а' (\u0430) and 'о' (\u043e) inserted into 'Bank'
        homoglyph_text = "B\u0430nk \u043eTP"
        res = analyze_and_normalize(homoglyph_text)
        self.assertTrue(res.has_homoglyphs)
        self.assertEqual(res.homoglyph_count, 2)
        self.assertEqual(res.normalized_lowercase, "bank otp")

    def test_script_detection_latin(self):
        text = "Your OTP is 483921 for HDFC NetBanking."
        res = analyze_and_normalize(text)
        self.assertEqual(res.detected_script, "LATIN")
        self.assertFalse(res.is_mixed_script)

    def test_script_detection_devanagari(self):
        text = "आपका ओटीपी 483921 है।"
        res = analyze_and_normalize(text)
        self.assertEqual(res.detected_script, "DEVANAGARI")

    def test_script_detection_mixed(self):
        text = "SBI बैंक अकाउंट ब्लॉक हो गया है"
        res = analyze_and_normalize(text)
        self.assertEqual(res.detected_script, "MIXED")
        self.assertTrue(res.is_mixed_script)

    def test_mask_sensitive_patterns(self):
        text = "Your OTP is 483921 for A/C XX9182 debit of INR 1,500.00. Call +919876543210 or visit https://bank.com."
        masked = mask_sensitive_patterns(text)
        self.assertIn("<NUM_CODE>", masked)
        self.assertIn("<ACCOUNT>", masked)
        self.assertIn("<AMOUNT>", masked)
        self.assertIn("<PHONE>", masked)
        self.assertIn("<URL>", masked)
        self.assertNotIn("483921", masked)
        self.assertNotIn("9876543210", masked)


if __name__ == "__main__":
    unittest.main()
