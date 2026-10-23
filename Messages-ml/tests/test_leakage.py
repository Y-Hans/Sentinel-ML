"""
Unit tests for template clustering, group-aware partitioning, and leakage auditing.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from leakage_analysis import (
    audit_splits_for_leakage,
    compute_template_cluster_id,
    partition_dataset_group_aware,
)


class TestLeakageAnalysis(unittest.TestCase):

    def test_template_clustering_parameter_invariance(self):
        msg1 = "Your A/C ending 1234 was debited by INR 500.00 on 24-AUG-26. Avl Bal: INR 12,000.00."
        msg2 = "Your A/C ending 5678 was debited by INR 800.00 on 25-AUG-26. Avl Bal: INR 34,500.00."

        cid1 = compute_template_cluster_id(msg1)
        cid2 = compute_template_cluster_id(msg2)

        self.assertEqual(cid1, cid2, "Parameter variations of the same template must produce identical cluster IDs")

    def test_group_aware_partitioning_zero_leakage(self):
        # Create dataset with 4 distinct template clusters, multiple variations each
        records = [
            # Template 1 variations
            {"message_id": "T1_1", "raw_text": "Your A/C ending 1111 debited INR 100", "security_label": "BENIGN"},
            {"message_id": "T1_2", "raw_text": "Your A/C ending 2222 debited INR 200", "security_label": "BENIGN"},
            {"message_id": "T1_3", "raw_text": "Your A/C ending 3333 debited INR 300", "security_label": "BENIGN"},
            # Template 2 variations
            {"message_id": "T2_1", "raw_text": "OTP 100001 is secret code. Do not share.", "security_label": "BENIGN"},
            {"message_id": "T2_2", "raw_text": "OTP 200002 is secret code. Do not share.", "security_label": "BENIGN"},
            # Template 3 variations
            {"message_id": "T3_1", "raw_text": "SBI account blocked. Call 9800000001.", "security_label": "MALICIOUS"},
            {"message_id": "T3_2", "raw_text": "SBI account blocked. Call 9800000002.", "security_label": "MALICIOUS"},
            # Template 4 variations
            {"message_id": "T4_1", "raw_text": "Electricity cut at 9 PM. Call 9800000010.", "security_label": "MALICIOUS"},
            {"message_id": "T4_2", "raw_text": "Electricity cut at 10 PM. Call 9800000020.", "security_label": "MALICIOUS"},
        ]

        splits = partition_dataset_group_aware(
            records, train_ratio=0.50, val_ratio=0.25, test_ratio=0.25, seed=42
        )

        report = audit_splits_for_leakage(splits)
        self.assertTrue(report.is_leakage_free)
        self.assertEqual(report.exact_text_cross_split_overlaps, 0)
        self.assertEqual(report.template_cluster_cross_split_overlaps, 0)

    def test_leakage_detector_catches_overlap(self):
        # Intentionally place same template in train and test
        splits_leaky = {
            "TRAIN": [{"message_id": "L1", "raw_text": "Your A/C ending 1234 debited INR 500"}],
            "TEST": [{"message_id": "L2", "raw_text": "Your A/C ending 5678 debited INR 800"}],
        }
        report = audit_splits_for_leakage(splits_leaky)
        self.assertFalse(report.is_leakage_free)
        self.assertEqual(report.template_cluster_cross_split_overlaps, 1)


if __name__ == "__main__":
    unittest.main()
