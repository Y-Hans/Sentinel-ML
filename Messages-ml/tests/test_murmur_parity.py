"""
Unit tests and golden vectors for 32-bit MurmurHash3 (x86 variant) parity with Kotlin/JVM.
"""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from feature_extraction import murmur3_32


class TestMurmurParity(unittest.TestCase):

    def test_golden_vectors(self):
        """
        Known standard 32-bit Murmur3 test vectors (seed=0 and seed=42).
        Guarantees that pure Python and Kotlin implementations produce identical hashes.
        """
        test_cases = [
            (b"", 0, 0),
            (b"", 42, 142593372),
            (b"hello", 0, 613153351),
            (b"hello", 42, 3806057185),
            (b"otp", 42, 52657099),
            (b"hdfc", 42, 4025721876),
            (b"Your OTP is 123456", 42, 1433093512),
            ("आपका ओटीपी 483921 है".encode("utf-8"), 42, 3253639173),
            ("aaj raat account band ho jayega".encode("utf-8"), 42, 643876909),
            ("A/C XX4821 debited by INR 1,250.00".encode("utf-8"), 42, 1055292128),
            ("!@#$%^&*()_+=-{}[]:;\"'<>,.?/".encode("utf-8"), 42, 988808431),
        ]

        for text_bytes, seed, expected_hash in test_cases:
            actual_hash = murmur3_32(text_bytes, seed=seed)
            self.assertEqual(
                actual_hash,
                expected_hash,
                f"Mismatch for input {text_bytes!r} with seed {seed}. Expected {expected_hash}, got {actual_hash}",
            )


if __name__ == "__main__":
    unittest.main()
