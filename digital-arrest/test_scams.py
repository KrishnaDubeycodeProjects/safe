import unittest
import numpy as np
import cv2
from unittest.mock import patch, MagicMock
from utils.image_cascade import ImageCascade
from utils.link_cascade import LinkCascade
from utils.scoring_engine import ScoringEngine
from utils.suggestion_engine import SuggestionEngine


class TestLinkCascadeLayers(unittest.TestCase):
    """Tests for utils/link_cascade.py"""

    def setUp(self):
        self.cascade = LinkCascade()

    # --- Layer 0: Parsing & Normalization ---
    def test_parse_and_normalize_http(self):
        result = self.cascade.parse_and_normalize("example.com/login")
        self.assertEqual(result["parsed_domain"], "example.com")
        self.assertTrue(result["original_url"].startswith("http://"))

    def test_parse_and_normalize_punycode(self):
        # Simulates an IDN domain
        result = self.cascade.parse_and_normalize("https://xn--80ak6aa92e.com")
        self.assertIn("decoded_domain", result)

    # --- Layer 1: Blocklists & Whitelists ---
    def test_whitelist_match(self):
        prob, verdict = self.cascade.check_blocklists_and_whitelist("sbi.co.in")
        self.assertEqual(verdict, "whitelisted")
        self.assertEqual(prob, 0.0)

    def test_blocklist_match(self):
        prob, verdict = self.cascade.check_blocklists_and_whitelist("secure-bank-login.com")
        self.assertEqual(verdict, "blocked_list")
        self.assertEqual(prob, 1.0)

    # --- Layer 2: Typosquatting Detection ---
    def test_typosquatting_exact_match(self):
        is_typo, brand = self.cascade.detect_typosquatting("paytm-secure-login.com")
        self.assertTrue(is_typo)
        self.assertEqual(brand, "paytm")

    def test_no_typosquatting(self):
        is_typo, brand = self.cascade.detect_typosquatting("legitimate-business.org")
        self.assertFalse(is_typo)

    # --- Layer 3: Heuristics ---
    def test_suspicious_tld(self):
        data = {"decoded_domain": "free-money.xyz", "path": "/", "original_url": ""}
        score, reasons = self.cascade.calculate_heuristics(data)
        self.assertGreater(score, 0)
        self.assertTrue(any(".xyz" in r for r in reasons))

    def test_ip_address_detection(self):
        data = {"decoded_domain": "192.168.1.1", "path": "/login", "original_url": ""}
        score, reasons = self.cascade.calculate_heuristics(data)
        self.assertGreaterEqual(score, 3.0)

    # --- Layer 4: Landing Page Analysis (Mocked) ---
    @patch('utils.link_cascade.requests.get')
    def test_password_field_detection(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.raw.read.return_value = b'<html><input type="password" name="pwd"></html>'
        mock_get.return_value = mock_resp
        
        data = {
            "final_url": "http://fake-scam.com", 
            "decoded_domain": "fake-scam.com",
            "is_https": False
        }
        prob, reasons = self.cascade.analyze_landing_page(data)
        self.assertGreater(prob, 0)
        self.assertTrue(any("password" in r.lower() for r in reasons))

    @patch('utils.link_cascade.requests.get')
    def test_brand_impersonation_on_page(self, mock_get):
        """Test that brand impersonation is detected even when brand name IS in the phishing domain."""
        mock_resp = MagicMock()
        mock_resp.raw.read.return_value = b'<html>welcome to sbi banking portal</html>'
        mock_get.return_value = mock_resp

        data = {
            "final_url": "http://not-sbi.com",
            "decoded_domain": "not-sbi.com",
            "is_https": False
        }

        # This calls YOUR FIXED analyze_landing_page method
        prob, reasons = self.cascade.analyze_landing_page(data)

        self.assertGreater(prob, 0, f"Expected scam_prob > 0, got {prob}. Reasons: {reasons}")
        self.assertTrue(
            any("sbi" in r.lower() for r in reasons),
            f"Expected 'sbi' in reasons, got: {reasons}"
        )


class TestImageCascadeLayers(unittest.TestCase):
    """Tests for utils/image_cascade.py"""

    def setUp(self):
        # Mock dependencies since we don't have real models/text_cascade in tests
        mock_text = MagicMock()
        mock_link = MagicMock()
        self.cascade = ImageCascade(mock_text, mock_link)
        
        # Create a dummy black image for CV tests
        self.dummy_img = np.zeros((100, 100, 3), dtype=np.uint8)

    # --- Layer 0: OCR & Extraction ---
    def test_extract_urls_from_text(self):
        text = "Visit http://scam-site.xyz or www.phishing.com for money"
        urls = self.cascade.extract_urls_from_text(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://scam-site.xyz", urls)

    def test_extract_phone_numbers_indian(self):
        text = "Call +91-9876543210 or 09876543210 immediately"
        phones = self.cascade.extract_phone_numbers(text)
        self.assertGreater(len(phones), 0)

    def test_extract_emails(self):
        text = "Contact support@fake-bank.com or admin@test.org"
        emails = self.cascade.extract_emails(text)
        self.assertEqual(len(emails), 2)

    # --- Layer 1: Hashing ---
    def test_sha256_calculation(self):
        # Create temp file
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as f:
            cv2.imwrite(f.name, self.dummy_img)
            temp_path = f.name
        
        sha = self.cascade.calculate_sha256(temp_path)
        self.assertEqual(len(sha), 64)  # SHA256 hex length
        os.unlink(temp_path)

    def test_dhash_consistency(self):
        h1 = self.cascade.calculate_dhash(self.dummy_img)
        h2 = self.cascade.calculate_dhash(self.dummy_img.copy())
        self.assertEqual(h1, h2)

    # --- Layer 2: CV Manipulations ---
    def test_clean_image_low_tamper_score(self):
        score, reasons = self.cascade.analyze_cv_manipulations(self.dummy_img)
        # A solid black image should have very few contours/blocks
        self.assertLess(score, 0.1)

    # --- Layer 3: Deepfake (Mocked) ---
    def test_deepfake_model_not_loaded(self):
        prob = self.cascade.run_deepfake_inference(self.dummy_img)
        self.assertEqual(prob, 0.0)


class TestScoringAndSuggestions(unittest.TestCase):
    """Tests for Phase 3 & 4 Engines"""

    def setUp(self):
        self.scoring = ScoringEngine()
        self.suggestions = SuggestionEngine()

    def test_score_normalization(self):
        self.assertEqual(self.scoring._normalize_to_10_scale(0.0), 0.0)
        self.assertEqual(self.scoring._normalize_to_10_scale(1.0), 10.0)
        self.assertEqual(self.scoring._normalize_to_10_scale(0.5), 5.0)

    def test_risk_level_classification(self):
        self.assertEqual(self.scoring._calculate_risk_level(9.0), "CRITICAL")
        self.assertEqual(self.scoring._calculate_risk_level(7.0), "HIGH")
        self.assertEqual(self.scoring._calculate_risk_level(5.0), "MEDIUM")
        self.assertEqual(self.scoring._calculate_risk_level(3.0), "LOW")
        self.assertEqual(self.scoring._calculate_risk_level(1.0), "SAFE")

    def test_weighted_scoring_combination(self):
        # Text=8/10, Link=9/10, Image=2/10
        # Expected: (8*0.4) + (9*0.4) + (2*0.2) = 3.2 + 3.6 + 0.4 = 7.2
        breakdown = self.scoring.calculate_score(
            ocr_text_result={"combined_prob": 0.8},
            link_analysis_result={"combined_prob": 0.9},
            image_manipulation_result={"combined_prob": 0.2}
        )
        self.assertAlmostEqual(breakdown.overall_score, 7.2, places=1)

    def test_suggestion_generation_critical(self):
        report = {
            "risk_level": "CRITICAL",
            "breakdown": {
                "text_analysis": {"flags": ["Urgency language detected"]},
                "link_analysis": {"flags": ["Credential harvesting page detected"]},
                "image_analysis": {"flags": []}
            }
        }
        suggestions = self.suggestions.generate_suggestions(report)
        
        self.assertIn("immediate_actions", suggestions)
        self.assertIn("reporting_info", suggestions)
        self.assertIsNotNone(suggestions["reporting_info"])  # Should have 1930 info
        self.assertTrue(any("STOP" in action for action in suggestions["immediate_actions"]))

    def test_suggestion_generation_safe(self):
        report = {
            "risk_level": "SAFE",
            "breakdown": {"text_analysis": {}, "link_analysis": {}, "image_analysis": {}}
        }
        suggestions = self.suggestions.generate_suggestions(report)
        self.assertIsNone(suggestions["reporting_info"])  # No reporting info for safe


if __name__ == '__main__':
    unittest.main()