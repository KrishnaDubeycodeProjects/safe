"""
tests/test_merged_backend.py
────────────────────────────
Test suite for the security-safe-chat-backend.

Tests are structured in three groups:
  1. LinkCascade      — link/URL analysis (heuristics + optional LLM enrichment)
  2. Bedrock verdict   — the "TAG|one-line perspective" parser
  3. HTTP endpoints    — FastAPI TestClient, all routes

Run: python -m pytest tests/test_merged_backend.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# ── Make root importable (backend root = project root) ────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ══════════════════════════════════════════════════════════════════════════════
# 1. LinkCascade
# ══════════════════════════════════════════════════════════════════════════════

class TestLinkCascade:
    def test_safe_url(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("https://www.google.com")
        assert "combined_prob" in result
        assert result["combined_prob"] < 0.6

    def test_known_legitimate_domain(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("https://www.sbi.co.in/login")
        assert "label" in result

    def test_empty_url_handled(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("not-a-url")
        assert "label" in result
        assert "combined_prob" in result

    def test_suspicious_url(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("https://sb1-kyc-update.xyz/verify")
        assert "combined_prob" in result

    def test_result_structure(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("https://example.com")
        required_keys = {"label", "combined_prob", "explanation"}
        assert required_keys.issubset(result.keys())

    def test_llm_enrichment_uses_classify_message(self):
        """When a bedrock_client is passed, ask_llm_reasoning() should call
        classify_message() and return its {tag, message} verdict verbatim."""
        from utils.link_cascade import LinkCascade

        mock_bedrock = AsyncMock()
        mock_bedrock.classify_message = AsyncMock(
            return_value={"tag": "Scam Confirmed", "message": "This domain impersonates a bank login page."}
        )
        lc = LinkCascade(bedrock_client=mock_bedrock)
        result = lc.ask_llm_reasoning(
            {"original_url": "http://fake-sbi.tk", "decoded_domain": "fake-sbi.tk"},
            heuristics=["Suspicious TLD"], dom_reasons=[],
        )
        assert result.get("tag") == "Scam Confirmed"
        assert "impersonates" in result.get("message", "")

    def test_no_bedrock_client_skips_enrichment(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()  # no bedrock_client
        result = lc.ask_llm_reasoning({"original_url": "http://x.com"}, [], [])
        assert result == {}


# ══════════════════════════════════════════════════════════════════════════════
# 2. Bedrock verdict parser
# ══════════════════════════════════════════════════════════════════════════════

class TestVerdictParser:
    def test_parses_safe(self):
        from app.bedrock import _parse_verdict
        result = _parse_verdict("SAFE|This looks like a normal message between friends.")
        assert result["tag"] == "Safe"
        assert result["message"] == "This looks like a normal message between friends."

    def test_parses_likely_scam(self):
        from app.bedrock import _parse_verdict
        result = _parse_verdict("LIKELY_SCAM|This pressures you to act urgently.")
        assert result["tag"] == "Likely Scam"
        assert "pressures" in result["message"]

    def test_parses_scam_confirmed(self):
        from app.bedrock import _parse_verdict
        result = _parse_verdict("SCAM_CONFIRMED|This demands your OTP and threatens arrest.")
        assert result["tag"] == "Scam Confirmed"
        assert "OTP" in result["message"]

    def test_handles_malformed_output(self):
        """Model didn't follow the format — should fall back gracefully, not crash."""
        from app.bedrock import _parse_verdict
        result = _parse_verdict("I think this might be suspicious.")
        assert result["tag"] in ("Likely Scam", "Indeterminate")
        assert result["message"]

    def test_handles_empty_output(self):
        from app.bedrock import _parse_verdict
        result = _parse_verdict("")
        assert result["tag"] in ("Likely Scam", "Indeterminate")


# ══════════════════════════════════════════════════════════════════════════════
# 3. HTTP Endpoints (FastAPI TestClient)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def client():
    """Create FastAPI test client with all external deps mocked."""
    import os
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-key-id")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret")
    os.environ.setdefault("AWS_REGION", "us-east-1")
    os.environ.setdefault("API_SECRET_KEY", "")         # auth disabled

    from fastapi.testclient import TestClient
    from main import app
    return TestClient(app)


class TestHTTPEndpoints:
    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "version" in data

    def test_root_redirects_to_docs(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code in (301, 302, 307, 308)
        assert "/docs" in r.headers.get("location", "")

    @patch("app.bedrock.classify_message", new_callable=AsyncMock)
    def test_scan_text_scam(self, mock_classify, client):
        mock_classify.return_value = {"tag": "Scam Confirmed", "message": "Demands OTP and threatens arrest."}
        r = client.post("/api/scan/text", json={"text": "CBI here, share your OTP or be arrested."})
        assert r.status_code == 200
        data = r.json()
        assert data["tag"] == "Scam Confirmed"
        assert "OTP" in data["message"] or data["message"]

    @patch("app.bedrock.classify_message", new_callable=AsyncMock)
    def test_scan_text_safe(self, mock_classify, client):
        mock_classify.return_value = {"tag": "Safe", "message": "Just a lunch plan between friends."}
        r = client.post("/api/scan/text", json={"text": "Lunch tomorrow at 1pm?"})
        assert r.status_code == 200
        data = r.json()
        assert data["tag"] == "Safe"

    def test_scan_text_empty_rejected(self, client):
        r = client.post("/api/scan/text", json={"text": "   "})
        assert r.status_code == 400

    @patch("app.bedrock.classify_message", new_callable=AsyncMock)
    def test_scan_text_llm_unavailable_returns_503(self, mock_classify, client):
        mock_classify.side_effect = RuntimeError("Bedrock error")
        r = client.post("/api/scan/text", json={"text": "Some message"})
        assert r.status_code == 503

    def test_scan_link(self, client):
        r = client.post("/api/scan/link", json={"url": "https://google.com"})
        assert r.status_code == 200
        data = r.json()
        assert "label" in data
        assert "combined_prob" in data

    def test_scan_link_empty_rejected(self, client):
        r = client.post("/api/scan/link", json={"url": ""})
        assert r.status_code == 400

    def test_scan_image_requires_file_or_base64(self, client):
        """The image-scan endpoint validates presence of image."""
        r = client.post("/api/scan/image")
        assert r.status_code == 400

    def test_no_analyze_endpoints(self, client):
        """The old taxonomy /analyze/* endpoints must be gone entirely."""
        assert client.post("/analyze/text", json={"message": "hi"}).status_code == 404
        assert client.post("/analyze/image").status_code == 404
        assert client.post("/analyze/base64", json={"image": "x"}).status_code == 404

    @patch("main.chat_with_llm", new_callable=AsyncMock)
    def test_api_chat_general_safe(self, mock_chat, client):
        mock_chat.return_value = "Hello, how can I assist you with your digital safety?"
        r = client.post(
            "/api/v1/chat",
            data={"message": "Hello!", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "bot_message" in data
        assert data["intent_detected"] == "general"
        assert data["custom_payload"] is None

    @patch("app.bedrock.classify_message", new_callable=AsyncMock)
    def test_api_chat_scan_scam(self, mock_classify, client):
        mock_classify.return_value = {"tag": "Scam Confirmed", "message": "Classic lottery scam pattern."}
        r = client.post(
            "/api/v1/chat",
            data={"message": "Please scan this kbc lottery message", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["intent_detected"] == "scan"
        assert data["custom_payload"]["tag"] == "Scam Confirmed"

    def test_api_chat_redirect_learn(self, client):
        r = client.post(
            "/api/v1/chat",
            data={"message": "how to learn about safety tips?", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["intent_detected"] == "learn"
        assert data["redirect_url"] == "/learn"

    def test_lambda_handler_export(self):
        """Verify that Mangum handler is exported and callable for AWS Lambda."""
        from main import handler
        assert callable(handler)
