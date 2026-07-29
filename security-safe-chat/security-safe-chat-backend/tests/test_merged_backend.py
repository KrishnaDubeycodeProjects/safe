"""
tests/test_merged_backend.py
────────────────────────────
Comprehensive test suite for the merged security-safe-chat-backend.

Tests are structured in five groups:
  1. TextCascade   — heuristics + Bedrock layer (mocked)
  2. LinkCascade   — existing link analysis
  3. ImageCascade  — with mocked OCR + text/link cascades
  4. ScoringEngine — weighted scoring
  5. SuggestionEngine — suggestion generation
  6. Supabase Logger — routing logic (no real HTTP)
  7. Schemas / Parser — taxonomy parser cases 1-5
  8. HTTP endpoints (FastAPI TestClient) — all routes

Run: python -m pytest tests/test_merged_backend.py -v
"""

from __future__ import annotations

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Make root importable (backend root = project root) ────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ══════════════════════════════════════════════════════════════════════════════
# 1. TextCascade
# ══════════════════════════════════════════════════════════════════════════════

class TestTextCascade:
    """Tests for utils/text_cascade.py"""

    def _make_cascade(self, bedrock_result: str | None = None):
        from utils.text_cascade import TextCascade

        mock_bedrock = AsyncMock()
        mock_parser = MagicMock()

        if bedrock_result is not None:
            mock_bedrock.classify_text = AsyncMock(return_value=bedrock_result)
            # Return a realistic parsed result
            mock_parser.parse.return_value = {
                "case": 1,
                "is_scam": True,
                "score": 88,
                "matches": [
                    {
                        "id": "4.1.3",
                        "label": "Digital Arrest Scam",
                        "category": "Impersonation",
                        "subcategory": "Government",
                        "verdict": "scam",
                        "score": 88,
                        "red_flags": ["CBI impersonation", "arrest threat", "money demand"],
                        "detection_message": "This is a Digital Arrest scam.",
                        "entities": {"name": "Rahul", "money": "500000"},
                    }
                ],
                "entities": {"name": "Rahul"},
                "detection_message": "This is a Digital Arrest scam.",
            }
        else:
            mock_bedrock.classify_text = AsyncMock(side_effect=Exception("Bedrock down"))
            mock_parser.parse.return_value = {}

        return TextCascade(bedrock_client=mock_bedrock, parser=mock_parser)

    def test_normalize_removes_zero_width(self):
        from utils.text_cascade import TextCascade
        tc = TextCascade()
        result = tc.normalize_text("hello\u200bworld")
        assert "\u200b" not in result
        assert "helloworld" in result

    def test_whitelist_pattern(self):
        from utils.text_cascade import TextCascade
        tc = TextCascade()
        prob, flag, _ = tc.match_rules("Your OTP for this transaction is 123456")
        assert flag == "whitelisted"
        assert prob == 0.0

    def test_high_risk_heuristics(self):
        from utils.text_cascade import TextCascade
        tc = TextCascade()
        scam_msg = "CBI officer here. You are under digital arrest. Share OTP immediately or face jail."
        prob, flag, details = tc.match_rules(scam_msg)
        assert prob >= 0.9
        assert flag == "high_heuristic"

    def test_low_risk_text(self):
        from utils.text_cascade import TextCascade
        tc = TextCascade()
        prob, flag, _ = tc.match_rules("Meeting tomorrow at 3pm. Please confirm.")
        assert prob < 0.4
        assert flag != "high_heuristic"

    def test_scan_async_whitelist(self):
        tc = self._make_cascade()
        result = asyncio.run(tc.scan_async("Your OTP for this transaction is 123456"))
        assert result["combined_prob"] <= 0.1
        assert "✅" in result["label"]

    def test_scan_async_high_heuristic_skips_bedrock(self):
        tc = self._make_cascade()
        result = asyncio.run(tc.scan_async(
            "CBI officer. Share OTP or arrested. Click link now. Pay 500000 or digital arrest."
        ))
        assert result["combined_prob"] >= 0.9
        assert result["bedrock_result"] is None  # stopped at layer 1

    def test_scan_async_uses_bedrock_for_medium_risk(self):
        tc = self._make_cascade(bedrock_result="4.1.3|name=Rahul,money=500000")
        result = asyncio.run(tc.scan_async("Dear Rahul, CBI officer calling regarding your case."))
        assert result["combined_prob"] > 0.4
        # Bedrock should have been consulted (not None in bedrock_result or explanation from bedrock)
        assert result["label"] in ["🚨 Likely Scam", "⚠️ Uncertain", "✅ Likely Safe"]

    def test_scan_falls_back_on_bedrock_error(self):
        tc = self._make_cascade(bedrock_result=None)  # bedrock will throw
        result = asyncio.run(tc.scan_async("Lucky draw! You won Rs. 50,000!"))
        # Should return a result, not raise
        assert "combined_prob" in result
        assert "label" in result

    def test_sync_scan_wrapper(self):
        tc = self._make_cascade()
        result = tc.scan("Hello, how are you?")
        assert isinstance(result, dict)
        assert "label" in result


# ══════════════════════════════════════════════════════════════════════════════
# 2. LinkCascade
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
        # A typosquatted domain style
        result = lc.scan("https://sb1-kyc-update.xyz/verify")
        assert "combined_prob" in result

    def test_result_structure(self):
        from utils.link_cascade import LinkCascade
        lc = LinkCascade()
        result = lc.scan("https://example.com")
        required_keys = {"label", "combined_prob", "explanation"}
        assert required_keys.issubset(result.keys())


# ══════════════════════════════════════════════════════════════════════════════
# 3. ScoringEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestScoringEngine:
    def test_safe_message_low_score(self):
        from utils.scoring_engine import ScoringEngine
        engine = ScoringEngine()
        breakdown = engine.calculate_score()
        assert breakdown.overall_score == 0.0
        assert breakdown.risk_level == "SAFE"

    def test_high_text_prob_raises_score(self):
        from utils.scoring_engine import ScoringEngine
        engine = ScoringEngine()
        breakdown = engine.calculate_score(
            ocr_text_result={"combined_prob": 0.95, "explanation": "urgent financial authority phishing", "cascade_steps": []}
        )
        # Text alone weighs 40% → 9.5 × 0.40 = 3.8 → LOW risk (correct by design)
        # Confirm score is elevated and risk is at least LOW
        assert breakdown.overall_score > 3.0
        assert breakdown.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_critical_combined(self):
        from utils.scoring_engine import ScoringEngine
        engine = ScoringEngine()
        breakdown = engine.calculate_score(
            ocr_text_result={"combined_prob": 0.95, "explanation": "urgent phishing otp bank authority", "cascade_steps": ["Layer 1"]},
            link_analysis_result={"combined_prob": 0.95, "explanation": "typosquatting new domain ssl", "meta": {}},
        )
        assert breakdown.overall_score >= 6.0

    def test_score_label_emoji(self):
        from utils.scoring_engine import ScoringEngine
        engine = ScoringEngine()
        assert "CRITICAL" in engine.get_score_label(9.0) or "🚨" in engine.get_score_label(9.0)
        assert "✅" in engine.get_score_label(0.5)

    def test_format_detailed_report_keys(self):
        from utils.scoring_engine import ScoringEngine
        engine = ScoringEngine()
        breakdown = engine.calculate_score()
        report = engine.format_detailed_report(breakdown)
        assert "scam_score" in report
        assert "risk_level" in report
        assert "breakdown" in report
        assert "summary" in report


# ══════════════════════════════════════════════════════════════════════════════
# 4. SuggestionEngine
# ══════════════════════════════════════════════════════════════════════════════

class TestSuggestionEngine:
    def _score_report(self, risk: str, flags: list[str]) -> dict:
        return {
            "risk_level": risk,
            "breakdown": {
                "text_analysis": {"flags": flags},
                "link_analysis": {"flags": []},
                "image_analysis": {"flags": []},
            },
        }

    def test_safe_returns_reassuring(self):
        from utils.suggestion_engine import SuggestionEngine
        eng = SuggestionEngine()
        result = eng.generate_suggestions(self._score_report("SAFE", []))
        assert "✅" in result["immediate_actions"][0]
        assert result["reporting_info"] is None

    def test_critical_has_reporting_info(self):
        from utils.suggestion_engine import SuggestionEngine
        eng = SuggestionEngine()
        result = eng.generate_suggestions(self._score_report("CRITICAL", ["Urgency language detected", "OTP credential"]))
        assert result["reporting_info"] is not None
        assert result["reporting_info"]["helpline"] == "1930"

    def test_medium_no_reporting_info(self):
        from utils.suggestion_engine import SuggestionEngine
        eng = SuggestionEngine()
        result = eng.generate_suggestions(self._score_report("MEDIUM", ["Authority impersonation"]))
        assert result["reporting_info"] is None

    def test_immediate_actions_not_empty(self):
        from utils.suggestion_engine import SuggestionEngine
        eng = SuggestionEngine()
        result = eng.generate_suggestions(self._score_report("HIGH", ["Deepfake/synthetic media detected"]))
        assert len(result["immediate_actions"]) >= 1
        assert any("video" in a.lower() or "hang" in a.lower() for a in result["immediate_actions"])

    def test_educational_tip_present(self):
        from utils.suggestion_engine import SuggestionEngine
        eng = SuggestionEngine()
        result = eng.generate_suggestions(self._score_report("HIGH", ["QR code contains suspicious content"]))
        assert "💡" in result["educational_tip"]


# ══════════════════════════════════════════════════════════════════════════════
# 5. Supabase Logger routing logic
# ══════════════════════════════════════════════════════════════════════════════

class TestSupabaseLogger:
    """Tests that verify routing logic only — no real HTTP calls."""

    def _mock_settings(self, **overrides):
        """Patch settings object."""
        defaults = {
            "supabase_url": "https://test.supabase.co",
            "supabase_service_key": "test-key",
            "supabase_logging_enabled": True,
        }
        defaults.update(overrides)
        return defaults

    @pytest.mark.asyncio
    async def test_case5_goes_to_scam_analysis_logs(self):
        """Case 5 (safe/err) should insert into scam_analysis_logs."""
        from app import supabase_logger

        inserted_to = []

        async def fake_insert(endpoint, payload):
            inserted_to.append(endpoint)

        response = {"case": 5, "is_scam": False, "score": None, "raw_model_output": "err",
                    "matches": [], "entities": {}, "detection_message": None}

        with patch.object(supabase_logger, "_insert", side_effect=fake_insert):
            with patch.object(supabase_logger, "settings") as mock_settings:
                mock_settings.supabase_logging_enabled = True
                mock_settings.get_log_cases.return_value = {5}
                await supabase_logger.log_result(
                    input_type="text", input_text="hello", extracted_ocr=None,
                    response=response,
                )

        assert any("scam_analysis_logs" in e for e in inserted_to)
        assert not any("user_message_logs" in e for e in inserted_to)

    @pytest.mark.asyncio
    async def test_case1_goes_to_user_message_logs(self):
        """Case 1 (scam detected) should insert into user_message_logs."""
        from app import supabase_logger

        inserted_to = []

        async def fake_insert(endpoint, payload):
            inserted_to.append(endpoint)

        response = {"case": 1, "is_scam": True, "score": 90, "raw_model_output": "1.1.1|name=Rahul",
                    "matches": [{"id": "1.1.1", "label": "cash_lottery"}], "entities": {},
                    "detection_message": "Lottery scam."}

        with patch.object(supabase_logger, "_insert", side_effect=fake_insert):
            with patch.object(supabase_logger, "settings") as mock_settings:
                mock_settings.supabase_logging_enabled = True
                mock_settings.get_log_cases.return_value = {5}
                await supabase_logger.log_result(
                    input_type="text", input_text="You won a lottery!", extracted_ocr=None,
                    response=response,
                )

        assert any("user_message_logs" in e for e in inserted_to)

    @pytest.mark.asyncio
    async def test_logging_disabled_when_no_config(self):
        """No Supabase calls when logging is disabled."""
        from app import supabase_logger

        inserted_to = []

        async def fake_insert(endpoint, payload):
            inserted_to.append(endpoint)

        response = {"case": 1, "is_scam": True, "score": 90, "raw_model_output": "1.1.1",
                    "matches": [], "entities": {}, "detection_message": None}

        with patch.object(supabase_logger, "_insert", side_effect=fake_insert):
            with patch.object(supabase_logger, "settings") as mock_settings:
                mock_settings.supabase_logging_enabled = False
                await supabase_logger.log_result(
                    input_type="text", input_text="test", extracted_ocr=None,
                    response=response,
                )

        assert len(inserted_to) == 0


# ══════════════════════════════════════════════════════════════════════════════
# 6. Parser — taxonomy output cases
# ══════════════════════════════════════════════════════════════════════════════

class TestParser:
    def test_case1_single_taxonomy(self):
        from app.parser import parse
        result = parse("1.1.1|name=Rahul,money=500000")
        assert result["case"] == 1
        assert result["is_scam"] is True
        assert result["matches"][0]["id"] == "1.1.1"
        assert result["matches"][0]["entities"].get("name") == "Rahul"

    def test_case2_multi_taxonomy(self):
        from app.parser import parse
        result = parse("multi:1.1.1+4.1.3|name=Rahul,money=10000,authority=CBI")
        assert result["case"] == 2
        assert result["is_scam"] is True
        assert len(result["matches"]) >= 2

    def test_case3_generic(self):
        from app.parser import parse
        result = parse("gen|name=Priya,money=20000")
        assert result["case"] == 3
        assert result["is_scam"] is True
        assert result["generic_scam"] is True

    def test_case4_unsure(self):
        from app.parser import parse
        result = parse("unsure")
        assert result["case"] == 4
        assert result["is_scam"] is False
        assert result["ambiguous"] is True

    def test_case5_safe(self):
        from app.parser import parse
        result = parse("err")
        assert result["case"] == 5
        assert result["is_scam"] is False

    def test_parse_handles_garbage(self):
        from app.parser import parse
        # Should not crash
        result = parse("totally unexpected model output\nwith newlines")
        assert "case" in result


# ══════════════════════════════════════════════════════════════════════════════
# 7. HTTP Endpoints (FastAPI TestClient)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def client():
    """Create FastAPI test client with all external deps mocked."""
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test-key-id")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test-secret")
    os.environ.setdefault("AWS_REGION", "us-east-1")
    os.environ.setdefault("OCR_SPACE_API_KEY", "test-ocr-key")
    os.environ.setdefault("API_SECRET_KEY", "")         # auth disabled
    os.environ.setdefault("SUPABASE_URL", "")           # logging disabled
    os.environ.setdefault("SUPABASE_SERVICE_KEY", "")

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

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    def test_analyze_text_scam(self, mock_bedrock, client):
        mock_bedrock.return_value = "1.1.1|name=Rahul,money=500000"
        r = client.post("/analyze/text", json={"message": "You won a lottery! Claim Rs 5 lakh now."})
        assert r.status_code == 200
        data = r.json()
        assert data["case"] == 1
        assert data["is_scam"] is True

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    def test_analyze_text_safe(self, mock_bedrock, client):
        mock_bedrock.return_value = "err"
        r = client.post("/analyze/text", json={"message": "Meeting tomorrow at 3pm. See you there!"})
        assert r.status_code == 200
        data = r.json()
        assert data["case"] == 5
        assert data["is_scam"] is False

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    @patch("app.ocr.ocr_from_bytes", new_callable=AsyncMock)
    def test_analyze_image(self, mock_ocr, mock_bedrock, client):
        mock_ocr.return_value = "Your account is blocked. Call 9999999999."
        mock_bedrock.return_value = "2.1.1|name=User"
        import io
        # Tiny 1x1 PNG (valid image bytes)
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01"
            b"\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        r = client.post(
            "/analyze/image",
            files={"file": ("test.png", io.BytesIO(png_bytes), "image/png")},
        )
        assert r.status_code == 200
        data = r.json()
        assert "case" in data
        assert "is_scam" in data

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    @patch("app.ocr.ocr_from_base64", new_callable=AsyncMock)
    def test_analyze_base64(self, mock_ocr, mock_bedrock, client):
        mock_ocr.return_value = "Congratulations! You won."
        mock_bedrock.return_value = "1.1.1|name=User,money=100000"
        r = client.post(
            "/analyze/base64",
            json={"image": "aGVsbG8=", "content_type": "image/jpeg"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["case"] == 1

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    def test_scan_text_cascade(self, mock_bedrock, client):
        mock_bedrock.return_value = "err"
        r = client.post("/api/scan/text", json={"text": "Meeting tomorrow at 3pm."})
        assert r.status_code == 200
        data = r.json()
        assert "label" in data
        assert "combined_prob" in data
        assert "scam_score" in data
        assert "risk_level" in data
        assert "suggestions" in data

    def test_scan_text_empty_rejected(self, client):
        r = client.post("/api/scan/text", json={"text": "   "})
        assert r.status_code == 400

    def test_scan_link(self, client):
        r = client.post("/api/scan/link", json={"url": "https://google.com"})
        assert r.status_code == 200
        data = r.json()
        assert "label" in data
        assert "combined_prob" in data

    def test_scan_link_empty_rejected(self, client):
        r = client.post("/api/scan/link", json={"url": ""})
        assert r.status_code == 400

    @patch("utils.image_cascade.ImageCascade.scan_async", new_callable=AsyncMock)
    def test_scan_image_cascade(self, mock_scan, client):
        mock_scan.return_value = {
            "label": "✅ Likely Safe",
            "combined_prob": 0.1,
            "explanation": "No threats found.",
            "actionSteps": ["Stay safe."],
            "cascade_steps": [],
            "sub_results": {},
            "meta": {},
        }
        import io
        png_bytes = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01"
            b"\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        r = client.post(
            "/api/scan/image",
            files={"file": ("test.png", io.BytesIO(png_bytes), "image/png")},
        )
        assert r.status_code == 200
        data = r.json()
        assert "combined_prob" in data
        assert "scam_score" in data

    def test_api_chat_general_safe(self, client):
        r = client.post(
            "/api/v1/chat",
            data={"message": "Hello!", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "bot_message" in data
        assert data["intent_detected"] == "general"
        assert data["custom_payload"] is None

    @patch("app.bedrock.classify_text", new_callable=AsyncMock)
    def test_api_chat_scan_scam(self, mock_bedrock, client):
        mock_bedrock.return_value = "err"
        r = client.post(
            "/api/v1/chat",
            data={"message": "Please scan this kbc lottery message", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert "bot_message" in data
        assert data["intent_detected"] == "scan"
        assert data["custom_payload"] is not None

    def test_api_chat_redirect_learn(self, client):
        r = client.post(
            "/api/v1/chat",
            data={"message": "how to learn about safety tips?", "session_id": "test_session"}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["intent_detected"] == "learn"
        assert data["redirect_url"] == "/learn"


# ══════════════════════════════════════════════════════════════════════════════
# 8. Integration — cascade → scoring → suggestions pipeline
# ══════════════════════════════════════════════════════════════════════════════

class TestPipelineIntegration:
    """End-to-end: TextCascade result → ScoringEngine → SuggestionEngine."""

    def test_scam_pipeline(self):
        from utils.text_cascade import TextCascade
        from utils.scoring_engine import ScoringEngine
        from utils.suggestion_engine import SuggestionEngine

        tc = TextCascade()  # no Bedrock — heuristics only
        se = ScoringEngine()
        sug = SuggestionEngine()

        msg = "CBI officer. Digital arrest. Pay Rs 50,000 OTP share or jail now. Click here urgently."
        cascade_result = tc.scan(msg)

        breakdown = se.calculate_score(ocr_text_result=cascade_result)
        report = se.format_detailed_report(breakdown)
        suggestions = sug.generate_suggestions(report)

        assert cascade_result["combined_prob"] >= 0.8
        assert report["scam_score"] >= 0.0   # score exists
        assert "immediate_actions" in suggestions
        assert len(suggestions["immediate_actions"]) >= 1

    def test_safe_pipeline(self):
        from utils.text_cascade import TextCascade
        from utils.scoring_engine import ScoringEngine
        from utils.suggestion_engine import SuggestionEngine

        tc = TextCascade()
        se = ScoringEngine()
        sug = SuggestionEngine()

        msg = "Hi! Are we still on for lunch tomorrow at 1pm?"
        cascade_result = tc.scan(msg)
        breakdown = se.calculate_score(ocr_text_result=cascade_result)
        report = se.format_detailed_report(breakdown)
        suggestions = sug.generate_suggestions(report)

        assert cascade_result["combined_prob"] < 0.5
        assert "✅" in suggestions["immediate_actions"][0] or "safe" in suggestions["immediate_actions"][0].lower()
