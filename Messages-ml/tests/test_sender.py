"""
Unit tests for sender intelligence and DLT header parsing.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from sender_parser import parse_sender_header


class TestSenderParser(unittest.TestCase):

    def test_dlt_compliant_header(self):
        res = parse_sender_header("VK-HDFCBK")
        self.assertEqual(res.sender_type, "ALPHANUMERIC_HEADER")
        self.assertTrue(res.has_dlt_structural_shape)
        self.assertEqual(res.dlt_prefix, "VK")
        self.assertEqual(res.dlt_entity_code, "HDFCBK")
        self.assertIsNone(res.dlt_suffix_category)
        self.assertEqual(res.known_entity_category, "BANK")

    def test_dlt_header_with_suffix(self):
        res = parse_sender_header("AX-SBIINB-S")
        self.assertEqual(res.sender_type, "ALPHANUMERIC_HEADER")
        self.assertTrue(res.has_dlt_structural_shape)
        self.assertEqual(res.dlt_prefix, "AX")
        self.assertEqual(res.dlt_entity_code, "SBIINB")
        self.assertEqual(res.dlt_suffix_category, "S")
        self.assertEqual(res.known_entity_category, "BANK")

    def test_dlt_promotional_suffix(self):
        res = parse_sender_header("VM-MYNTRA-P")
        self.assertEqual(res.sender_type, "ALPHANUMERIC_HEADER")
        self.assertTrue(res.has_dlt_structural_shape)
        self.assertEqual(res.dlt_suffix_category, "P")

    def test_standalone_alphanumeric_header(self):
        res = parse_sender_header("HDFCBK")
        self.assertEqual(res.sender_type, "ALPHANUMERIC_HEADER")
        self.assertFalse(res.has_dlt_structural_shape)
        self.assertEqual(res.known_entity_category, "BANK")

    def test_domestic_indian_phone_number(self):
        for phone in ["+919876543210", "09876543210", "9876543210"]:
            res = parse_sender_header(phone)
            self.assertEqual(res.sender_type, "PHONE_NUMBER", f"Failed for {phone}")
            self.assertTrue(res.is_domestic_phone, f"Failed for {phone}")
            self.assertFalse(res.has_dlt_structural_shape)

    def test_international_phone_number(self):
        res = parse_sender_header("+12025550199")
        self.assertEqual(res.sender_type, "PHONE_NUMBER")
        self.assertTrue(res.is_international_phone)
        self.assertFalse(res.is_domestic_phone)

    def test_shortcode(self):
        res = parse_sender_header("567676")
        self.assertEqual(res.sender_type, "SHORTCODE")
        self.assertTrue(res.is_shortcode)

    def test_empty_or_none_sender(self):
        res_none = parse_sender_header(None)
        self.assertEqual(res_none.sender_type, "UNKNOWN")
        res_empty = parse_sender_header("")
        self.assertEqual(res_empty.sender_type, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
