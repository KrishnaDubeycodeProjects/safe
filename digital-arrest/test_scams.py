import unittest
from unittest.mock import patch, MagicMock
from utils.link_cascade import LinkCascade


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

        prob, reasons = self.cascade.analyze_landing_page(data)

        self.assertGreater(prob, 0, f"Expected scam_prob > 0, got {prob}. Reasons: {reasons}")
        self.assertTrue(
            any("sbi" in r.lower() for r in reasons),
            f"Expected 'sbi' in reasons, got: {reasons}"
        )

    # --- Layer 5: LLM reasoning (mocked Ollama) ---
    @patch('utils.link_cascade.query_ollama')
    @patch('utils.link_cascade.is_ollama_available', return_value=True)
    def test_llm_reasoning_parses_json(self, mock_available, mock_query):
        mock_query.return_value = {
            "text": '{"verdict": "Likely Scam", "risk_percent": 90, "explanation": "Typosquatted domain.", "advice": ["Do not enter credentials."]}'
        }
        result = self.cascade.ask_llm_reasoning(
            {
                "original_url": "http://fake-sbi.tk",
                "decoded_domain": "fake-sbi.tk",
                "final_url": "http://fake-sbi.tk",
                "redirected": False,
            },
            heuristics=["Suspicious TLD"], dom_reasons=[],
        )
        self.assertEqual(result.get("verdict"), "Likely Scam")

    @patch('utils.link_cascade.is_ollama_available', return_value=False)
    def test_llm_reasoning_skipped_when_unavailable(self, mock_available):
        result = self.cascade.ask_llm_reasoning({"original_url": "http://x.com"}, [], [])
        self.assertEqual(result, {})


class TestMessageClassifier(unittest.TestCase):
    """Tests for utils/rag_utils.py classify_message() / _parse_verdict()."""

    def test_parse_verdict_safe(self):
        from utils.rag_utils import _parse_verdict
        result = _parse_verdict("SAFE|This looks like a normal message between friends.")
        self.assertEqual(result, {"tag": "Safe", "message": "This looks like a normal message between friends."})

    def test_parse_verdict_scam_confirmed(self):
        from utils.rag_utils import _parse_verdict
        result = _parse_verdict("SCAM_CONFIRMED|Demands OTP and threatens arrest.")
        self.assertEqual(result["tag"], "Scam Confirmed")

    def test_parse_verdict_malformed_falls_back(self):
        from utils.rag_utils import _parse_verdict
        result = _parse_verdict("not in the expected format")
        self.assertEqual(result["tag"], "Likely Scam")

    @patch('utils.rag_utils.is_ollama_available', return_value=False)
    def test_classify_message_raises_when_ollama_unavailable(self, mock_available):
        from utils.rag_utils import classify_message
        with self.assertRaises(RuntimeError):
            classify_message("Some message")

    @patch('utils.rag_utils.query_ollama')
    @patch('utils.rag_utils.is_ollama_available', return_value=True)
    def test_classify_message_parses_ollama_output(self, mock_available, mock_query):
        from utils.rag_utils import classify_message
        mock_query.return_value = {"text": "LIKELY_SCAM|Pressures urgent action via an unfamiliar link."}
        result = classify_message("Click this link now or your account will be suspended!")
        self.assertEqual(result["tag"], "Likely Scam")


if __name__ == '__main__':
    unittest.main()
