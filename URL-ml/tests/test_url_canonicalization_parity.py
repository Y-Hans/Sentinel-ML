"""Phase 1A Python/Kotlin Parity & Canonicalization Regression Test Suite.

Verifies:
1. Canonicalization contract alignment with Android runtime (UrlFeatureExtractor.kt).
2. Schemeless, bare apex, www, protocol-relative, and explicit scheme handling.
3. Feature invariant: 67 features, strict alphabetical ordering, identical dimensions.
4. Feature parity: Schemeless URLs extract 100% identical vectors to explicit HTTPS URLs.
5. Insecure HTTP penalty preservation: Explicit HTTP retains IsHTTPS = 0.0 and Risk_HTTP penalties.
6. Threat detection invariance: Attacks without schemes (payload extensions, IPs, phishing paths)
   remain evaluated as MALICIOUS with identical verdicts.
7. Golden corpus parity: All 174 reference records in golden_urls_v8.json match to < 1e-4 tolerance.
"""
from __future__ import annotations

import json
import math
import sys
import unittest
from pathlib import Path

# Add URL-ml scripts directory to sys.path
TEST_DIR = Path(__file__).resolve().parent
URL_ML_DIR = TEST_DIR.parent
SCRIPTS_DIR = URL_ML_DIR / "scripts"
MODELS_DIR = URL_ML_DIR / "models"
GOLDEN_CORPUS_PATH = URL_ML_DIR.parent / "android-runtime" / "golden_test_data" / "golden_urls_v8.json"

sys.path.insert(0, str(SCRIPTS_DIR))

import joblib
import numpy as np
from v7_features import (
    canonicalize_url,
    extract_v7_features,
    vectorize_v7,
    V7_FEATURE_NAMES,
)
from v8_normalization import (
    canonicalize_url as v8_norm_canonicalize_url,
    parse_v8_url,
    ParsedV8URL,
)
from v8_classifier import V8RelationalURLClassifier


class TestUrlCanonicalizationContract(unittest.TestCase):
    """Test URL canonicalization contract against Android reference specification."""

    def test_canonicalize_schemeless_and_bare_domains(self):
        cases = [
            ("www.instagram.com", "https://www.instagram.com"),
            ("instagram.com", "https://instagram.com"),
            ("google.com", "https://google.com"),
            ("www.google.com", "https://www.google.com"),
            ("sub.domain.example.co.uk", "https://sub.domain.example.co.uk"),
        ]
        for inp, expected in cases:
            with self.subTest(url=inp):
                self.assertEqual(canonicalize_url(inp), expected)
                self.assertEqual(v8_norm_canonicalize_url(inp), expected)

    def test_canonicalize_protocol_relative(self):
        cases = [
            ("//instagram.com", "https://instagram.com"),
            ("//www.google.com/search", "https://www.google.com/search"),
            ("//example.com:8080/path?q=1", "https://example.com:8080/path?q=1"),
        ]
        for inp, expected in cases:
            with self.subTest(url=inp):
                self.assertEqual(canonicalize_url(inp), expected)
                self.assertEqual(v8_norm_canonicalize_url(inp), expected)

    def test_canonicalize_explicit_schemes(self):
        cases = [
            ("https://instagram.com", "https://instagram.com"),
            ("http://instagram.com", "http://instagram.com"),
            ("HTTP://INSTAGRAM.COM", "http://INSTAGRAM.COM"),
            ("HTTPS://INSTAGRAM.COM", "https://INSTAGRAM.COM"),
            ("ftp://files.example.com", "ftp://files.example.com"),
        ]
        for inp, expected in cases:
            with self.subTest(url=inp):
                self.assertEqual(canonicalize_url(inp), expected)
                self.assertEqual(v8_norm_canonicalize_url(inp), expected)

    def test_canonicalize_trailing_delimiters(self):
        cases = [
            ("   www.instagram.com.   ", "https://www.instagram.com"),
            ("example.com/test,", "https://example.com/test"),
            ("example.com/test;:", "https://example.com/test"),
            ("example.com/test!?", "https://example.com/test"),
            ("example.com/test)]}>", "https://example.com/test"),
            ("example.com/test\"'", "https://example.com/test"),
            ("https://example.com/path...", "https://example.com/path"),
            ("http://example.com/path.", "http://example.com/path"),
        ]
        for inp, expected in cases:
            with self.subTest(url=inp):
                self.assertEqual(canonicalize_url(inp), expected)
                self.assertEqual(v8_norm_canonicalize_url(inp), expected)

    def test_canonicalize_empty_and_whitespace(self):
        cases = ["", "   ", "\t\n", None]
        for inp in cases:
            with self.subTest(inp=inp):
                self.assertEqual(canonicalize_url(inp), "")
                self.assertEqual(v8_norm_canonicalize_url(inp), "")

    def test_canonicalize_preserves_paths_and_queries(self):
        url = "example.com/redirect?url=https://test.com&token=abc#frag"
        expected = "https://example.com/redirect?url=https://test.com&token=abc#frag"
        self.assertEqual(canonicalize_url(url), expected)


class TestFeatureVectorParity(unittest.TestCase):
    """Test feature vector dimensionality, ordering, and schemeless-to-https invariance."""

    def test_feature_vector_dimension_and_order(self):
        self.assertEqual(len(V7_FEATURE_NAMES), 67)
        self.assertEqual(V7_FEATURE_NAMES, sorted(V7_FEATURE_NAMES))
        # Ensure critical features are present at expected alphabetized locations
        self.assertEqual(V7_FEATURE_NAMES[0], "BrandImpersonationScore")
        self.assertEqual(V7_FEATURE_NAMES[15], "IsHTTPS")
        self.assertEqual(V7_FEATURE_NAMES[65], "URLLength")
        self.assertEqual(V7_FEATURE_NAMES[66], "URLUppercaseRatio")

    def test_schemeless_to_https_feature_invariance(self):
        pairs = [
            ("www.instagram.com", "https://www.instagram.com"),
            ("instagram.com", "https://instagram.com"),
            ("google.com", "https://google.com"),
            ("www.google.com", "https://www.google.com"),
            ("//instagram.com", "https://instagram.com"),
            ("   www.instagram.com.   ", "https://www.instagram.com"),
            ("example.com/test,", "https://example.com/test"),
            ("example.com/redirect?url=https://test.com", "https://example.com/redirect?url=https://test.com"),
            ("sbi-kyc-update.xyz/login", "https://sbi-kyc-update.xyz/login"),
            ("evil-download.com/update.apk", "https://evil-download.com/update.apk"),
            ("192.168.1.1/login", "https://192.168.1.1/login"),
            ("irs-helpdesk.win/reset-password", "https://irs-helpdesk.win/reset-password"),
        ]
        for schemeless, https_url in pairs:
            with self.subTest(schemeless=schemeless):
                f_schemeless = extract_v7_features(schemeless)
                f_https = extract_v7_features(https_url)
                self.assertEqual(len(f_schemeless), 67)
                self.assertEqual(len(f_https), 67)
                for feat_name in V7_FEATURE_NAMES:
                    val_s = f_schemeless[feat_name]
                    val_h = f_https[feat_name]
                    self.assertAlmostEqual(
                        val_s,
                        val_h,
                        places=4,
                        msg=f"Feature {feat_name} mismatch for {schemeless} ({val_s}) vs {https_url} ({val_h})"
                    )

    def test_is_https_feature_contract(self):
        self.assertEqual(extract_v7_features("https://instagram.com")["IsHTTPS"], 1.0)
        self.assertEqual(extract_v7_features("HTTPS://INSTAGRAM.COM")["IsHTTPS"], 1.0)
        self.assertEqual(extract_v7_features("www.instagram.com")["IsHTTPS"], 1.0)
        self.assertEqual(extract_v7_features("instagram.com")["IsHTTPS"], 1.0)
        self.assertEqual(extract_v7_features("//instagram.com")["IsHTTPS"], 1.0)

        # Explicit HTTP must remain 0.0
        self.assertEqual(extract_v7_features("http://instagram.com")["IsHTTPS"], 0.0)
        self.assertEqual(extract_v7_features("HTTP://INSTAGRAM.COM")["IsHTTPS"], 0.0)
        self.assertEqual(extract_v7_features("http://www.instagram.com")["IsHTTPS"], 0.0)


class TestModelPredictionAndAdjudicationParity(unittest.TestCase):
    """Test model classification and security invariant adjudication on schemeless and edge inputs."""

    @classmethod
    def setUpClass(cls):
        model_path = MODELS_DIR / "v8_champion.joblib"
        cls.classifier: V8RelationalURLClassifier = joblib.load(model_path)
        cls.names = V7_FEATURE_NAMES

    def _eval(self, url: str):
        feat = extract_v7_features(url)
        vec = np.array([[feat[k] for k in self.names]], dtype=np.float32)
        raw_p = float(self.classifier.base_model.predict_proba(vec)[0, 1])
        final_p, pred, label = self.classifier.adjudicate_single(url, vec[0], raw_p)
        return {
            "raw_p": raw_p,
            "final_p": final_p,
            "pred": pred,
            "label": label,
            "feat": feat
        }

    def test_safe_brand_schemeless_benign_parity(self):
        res_schemeless = self._eval("www.instagram.com")
        res_https = self._eval("https://www.instagram.com")

        self.assertEqual(res_schemeless["label"], "BENIGN")
        self.assertEqual(res_https["label"], "BENIGN")
        self.assertEqual(res_schemeless["pred"], 0)
        self.assertEqual(res_https["pred"], 0)
        self.assertAlmostEqual(res_schemeless["raw_p"], res_https["raw_p"], places=4)
        self.assertAlmostEqual(res_schemeless["final_p"], res_https["final_p"], places=4)

    def test_explicit_http_penalized_as_malicious(self):
        res_http = self._eval("http://www.instagram.com")
        self.assertEqual(res_http["label"], "MALICIOUS")
        self.assertEqual(res_http["pred"], 1)
        self.assertGreater(res_http["raw_p"], 0.80)
        self.assertEqual(res_http["feat"]["IsHTTPS"], 0.0)

    def test_bare_apex_locked_policy_evaluation(self):
        res_bare = self._eval("google.com")
        res_https = self._eval("https://google.com")

        self.assertEqual(res_bare["label"], res_https["label"])
        self.assertAlmostEqual(res_bare["raw_p"], res_https["raw_p"], places=4)
        self.assertAlmostEqual(res_bare["final_p"], res_https["final_p"], places=4)
        # Google bare apex raw probability is ~0.4676 (>= 0.28)
        self.assertEqual(res_bare["label"], "MALICIOUS")

        # www.google.com has distinct features and evaluates as BENIGN
        res_www = self._eval("www.google.com")
        res_www_https = self._eval("https://www.google.com")
        self.assertEqual(res_www["label"], "BENIGN")
        self.assertEqual(res_www_https["label"], "BENIGN")
        self.assertAlmostEqual(res_www["raw_p"], res_www_https["raw_p"], places=4)

    def test_schemeless_malicious_attacks_detected(self):
        targets = [
            "sbi-kyc-update.xyz/login",
            "bankofamerica-security-portal.cfd/signin/account-verify",
            "netflix-billing-update.top/verification/session",
            "paypal-secure-token.work/checkout/confirm",
            "chase-online-verify.buzz/login/auth",
            "wellsfargo-account-alert.xyz/verify",
            "amazon-security-center.cam/signin",
            "apple-id-verify.country/account/unlock",
        ]
        for target in targets:
            with self.subTest(target=target):
                res = self._eval(target)
                self.assertEqual(res["label"], "MALICIOUS")
                self.assertEqual(res["pred"], 1)
                self.assertGreaterEqual(res["final_p"], 0.28)

    def test_schemeless_suspicious_extensions_detected(self):
        targets = [
            "evil-download.com/update.apk",
            "invoice-details.online/statement.exe",
            "secure-docs-verify.ru/attachment.scr",
            "drive-storage-shares.xyz/installer.zip",
        ]
        for target in targets:
            with self.subTest(target=target):
                res = self._eval(target)
                self.assertEqual(res["label"], "MALICIOUS")
                self.assertEqual(res["pred"], 1)
                self.assertGreaterEqual(res["final_p"], 0.28)

    def test_schemeless_ip_based_urls_detected(self):
        targets = [
            "192.168.1.1/login",
            "185.220.101.5/banking/signin",
            "45.33.32.156:8080/admin",
        ]
        for target in targets:
            with self.subTest(target=target):
                res = self._eval(target)
                self.assertEqual(res["label"], "MALICIOUS")
                self.assertEqual(res["pred"], 1)
                self.assertGreaterEqual(res["final_p"], 0.28)

    def test_irs_helpdesk_adjudication_parity(self):
        res_http = self._eval("http://irs-helpdesk.win/reset-password")
        self.assertEqual(res_http["label"], "MALICIOUS")
        self.assertAlmostEqual(res_http["raw_p"], 0.4817, places=3)
        self.assertAlmostEqual(res_http["final_p"], 0.9500, places=3)

        res_schemeless = self._eval("irs-helpdesk.win/reset-password")
        self.assertEqual(res_schemeless["label"], "MALICIOUS")
        self.assertAlmostEqual(res_schemeless["raw_p"], 0.2160, places=3)
        self.assertAlmostEqual(res_schemeless["final_p"], 0.9500, places=3)

    def test_malformed_and_corner_cases_do_not_crash(self):
        corners = [
            "/relative/path/only",
            "//example.com/foo",
            "example.com:8080/path",
            "example.com/redirect?url=https://phish.xyz",
            "not-a-domain",
            "",
            "   ",
        ]
        for c in corners:
            with self.subTest(corner=c):
                res = self._eval(c)
                self.assertTrue(math.isfinite(res["raw_p"]))
                self.assertTrue(math.isfinite(res["final_p"]))
                self.assertIn(res["label"], ("BENIGN", "MALICIOUS"))


class TestGoldenCorpus174Parity(unittest.TestCase):
    """Test complete cross-language parity against the 174-record golden corpus."""

    @classmethod
    def setUpClass(cls):
        self_dir = Path(__file__).resolve().parent
        golden_file = GOLDEN_CORPUS_PATH
        if not golden_file.exists():
            raise FileNotFoundError(f"Golden corpus not found: {golden_file}")
        cls.records = json.loads(golden_file.read_text(encoding="utf-8"))
        cls.classifier = joblib.load(MODELS_DIR / "v8_champion.joblib")
        cls.names = V7_FEATURE_NAMES

    def test_all_174_golden_records(self):
        self.assertEqual(len(self.records), 174)
        max_feat_diff = 0.0
        max_raw_diff = 0.0
        max_final_diff = 0.0
        label_matches = 0

        for rec in self.records:
            u = rec["url"]
            expected_feats = rec["features"]
            expected_raw = rec["rawProbability"]
            expected_final = rec["finalProbability"]
            expected_label = rec["label"]

            actual_feats_dict = extract_v7_features(u)
            actual_vec = [actual_feats_dict[n] for n in self.names]
            actual_arr = np.array([actual_vec], dtype=np.float32)

            for i in range(67):
                diff = abs(actual_vec[i] - expected_feats[i])
                if diff > max_feat_diff:
                    max_feat_diff = diff

            actual_raw = float(self.classifier.base_model.predict_proba(actual_arr)[0, 1])
            actual_final, pred, actual_label = self.classifier.adjudicate_single(u, actual_arr[0], actual_raw)

            raw_diff = abs(actual_raw - expected_raw)
            if raw_diff > max_raw_diff:
                max_raw_diff = raw_diff

            final_diff = abs(actual_final - expected_final)
            if final_diff > max_final_diff:
                max_final_diff = final_diff

            if actual_label == expected_label:
                label_matches += 1

        self.assertLess(max_feat_diff, 1e-4, f"Max feature diff exceeded: {max_feat_diff}")
        self.assertLess(max_raw_diff, 1e-4, f"Max raw prob diff exceeded: {max_raw_diff}")
        self.assertLess(max_final_diff, 1e-4, f"Max final prob diff exceeded: {max_final_diff}")
        self.assertEqual(label_matches, 174, f"Label matches {label_matches} != 174")


if __name__ == "__main__":
    unittest.main()
