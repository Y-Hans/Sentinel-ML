"""
Unit tests for canonical dataset schema validation and integrity verification.
"""

import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from dataset_validator import (
    validate_dataset_file,
    validate_message_record,
)


class TestDatasetSchema(unittest.TestCase):

    def test_valid_record_passes(self):
        valid_rec = {
            "message_id": "TEST_001",
            "raw_text": "483921 is your OTP for HDFC Bank. Do not share.",
            "security_label": "BENIGN",
            "source_id": "TEST_SUITE_V1",
            "primary_type": "OTP_AUTH",
            "threat_vectors": ["NONE"],
            "sender_header": "VK-HDFCBK",
            "sender_type": "ALPHANUMERIC_HEADER",
        }
        is_valid, issues = validate_message_record(valid_rec)
        self.assertTrue(is_valid, f"Issues found: {issues}")
        self.assertEqual(len(issues), 0)

    def test_missing_required_fields_fails(self):
        # Missing raw_text and security_label
        invalid_rec = {
            "message_id": "TEST_002",
            "source_id": "TEST_SUITE_V1",
        }
        is_valid, issues = validate_message_record(invalid_rec)
        self.assertFalse(is_valid)
        self.assertGreaterEqual(len(issues), 2)

    def test_invalid_security_label_fails(self):
        invalid_label_rec = {
            "message_id": "TEST_003",
            "raw_text": "Hello world",
            "security_label": "DANGEROUS",  # Invalid enum (should be MALICIOUS)
            "source_id": "TEST_SUITE_V1",
        }
        is_valid, issues = validate_message_record(invalid_label_rec)
        self.assertFalse(is_valid)
        self.assertTrue(any(iss.issue_type == "INVALID_SECURITY_LABEL" for iss in issues))

    def test_benchmark_slice_files_are_all_valid(self):
        benchmark_dir = ROOT / "data" / "benchmarks"
        jsonl_files = list(benchmark_dir.glob("*.jsonl"))
        self.assertGreater(len(jsonl_files), 0, "Benchmark files must exist")

        for jf in jsonl_files:
            report = validate_dataset_file(jf)
            self.assertTrue(
                report.is_valid,
                f"File {jf.name} failed validation. Invalid: {report.invalid_records}, Issues: {report.issues}",
            )


if __name__ == "__main__":
    unittest.main()
