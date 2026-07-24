"""
supabase_logger.py — Async logger that writes LLM results to two Supabase tables.

┌──────────────────────────┬───────────────────────────────────────────────────┐
│  Table                   │  When logged                                      │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  scam_analysis_logs      │  Case 5 (err / safe message).                     │
│                          │  Use for false-positive review and accuracy audit. │
├──────────────────────────┼───────────────────────────────────────────────────┤
│  user_message_logs       │  Cases 1–4 (scam / generic / unsure detected).    │
│                          │  Use for platform usage analytics and to measure  │
│                          │  what users are actually sending vs what is flagged│
└──────────────────────────┴───────────────────────────────────────────────────┘

Both functions are fire-and-forget: they NEVER raise exceptions to the caller.
If Supabase is unavailable the error is logged locally and the API response
continues normally.

Configuration (.env):
    SUPABASE_URL=https://<ref>.supabase.co
    SUPABASE_SERVICE_KEY=<service_role_secret_key>
    SUPABASE_LOG_CASES=5          # which cases go to scam_analysis_logs
                                  # user_message_logs always gets cases 1-4
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# ── REST endpoints ─────────────────────────────────────────────────────────────
_BASE = settings.supabase_url.rstrip("/")
_SAFE_LOG_ENDPOINT    = f"{_BASE}/rest/v1/scam_analysis_logs"   # case 5 only
_USER_MSG_ENDPOINT    = f"{_BASE}/rest/v1/user_message_logs"    # cases 1–4

_HEADERS = {
    "apikey":        settings.supabase_service_key,
    "Authorization": f"Bearer {settings.supabase_service_key}",
    "Content-Type":  "application/json",
    "Prefer":        "return=minimal",   # saves bandwidth; don't echo the row
}


# ── Public API ─────────────────────────────────────────────────────────────────

async def log_result(
    *,
    input_type: str,                   # "text" | "image" | "base64"
    input_text: Optional[str],         # original user message (text endpoint)
    extracted_ocr: Optional[str],      # OCR output (image / base64 endpoints)
    response: dict[str, Any],          # AnalyzeResponse as dict
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
    session_id: Optional[str] = None,  # optional client-supplied X-Session-Id
) -> None:
    """
    Route the result to the correct Supabase table based on case number:

    • case 5 (err / safe)   →  scam_analysis_logs     (controlled by SUPABASE_LOG_CASES)
    • cases 1–4 (detected)  →  user_message_logs       (always, if Supabase is configured)

    Fire-and-forget: never raises, never blocks the HTTP response.
    """
    if not settings.supabase_logging_enabled:
        return

    case = response.get("case", 0)

    if case in settings.get_log_cases():
        # Safe messages — go to the false-positive review table
        await _insert(_SAFE_LOG_ENDPOINT, _build_safe_payload(
            input_type=input_type,
            input_text=input_text,
            extracted_ocr=extracted_ocr,
            response=response,
            user_agent=user_agent,
            ip_address=ip_address,
        ))

    if case in {1, 2, 3, 4}:
        # Flagged / detected messages — go to the platform usage analytics table
        await _insert(_USER_MSG_ENDPOINT, _build_user_msg_payload(
            input_type=input_type,
            input_text=input_text,
            extracted_ocr=extracted_ocr,
            response=response,
            user_agent=user_agent,
            ip_address=ip_address,
            session_id=session_id,
        ))


# ── Internal helpers ───────────────────────────────────────────────────────────

async def _insert(endpoint: str, payload: dict[str, Any]) -> None:
    """Low-level POST to a PostgREST endpoint. Never raises."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(endpoint, headers=_HEADERS, json=payload)
            if resp.status_code not in (200, 201, 204):
                logger.warning(
                    "Supabase insert to %s returned %s: %s",
                    endpoint.split("/")[-1],
                    resp.status_code,
                    resp.text[:300],
                )
            else:
                logger.debug(
                    "Logged case=%s → %s",
                    payload.get("case_number"),
                    endpoint.split("/")[-1],
                )
    except Exception as exc:
        logger.exception("Supabase log failed (non-fatal): %s", exc)


def _build_safe_payload(
    *,
    input_type: str,
    input_text: Optional[str],
    extracted_ocr: Optional[str],
    response: dict[str, Any],
    user_agent: Optional[str],
    ip_address: Optional[str],
) -> dict[str, Any]:
    """Payload for scam_analysis_logs (case 5 — safe/err responses)."""
    return {
        "input_type":        input_type,
        "input_text":        _truncate(input_text, 8000),
        "extracted_ocr":     _truncate(extracted_ocr, 8000),
        "case_number":       response.get("case"),
        "is_scam":           response.get("is_scam", False),
        "score":             response.get("score"),
        "raw_model_output":  _truncate(response.get("raw_model_output", ""), 512),
        "parse_error":       response.get("parse_error"),
        "matches":           response.get("matches") or None,
        "entities":          response.get("entities") or None,
        "detection_message": response.get("detection_message"),
        "generic_scam":      response.get("generic_scam"),
        "ambiguous":         response.get("ambiguous"),
        "user_agent":        _truncate(user_agent, 256),
        "ip_address":        _truncate(ip_address, 64),
    }


def _build_user_msg_payload(
    *,
    input_type: str,
    input_text: Optional[str],
    extracted_ocr: Optional[str],
    response: dict[str, Any],
    user_agent: Optional[str],
    ip_address: Optional[str],
    session_id: Optional[str],
) -> dict[str, Any]:
    """Payload for user_message_logs (cases 1–4 — flagged detections)."""
    # Extract the primary (first) match for easy querying without JSONB ops
    matches: list[dict] = response.get("matches") or []
    primary = matches[0] if matches else {}

    return {
        "input_type":        input_type,
        "input_text":        _truncate(input_text, 8000),
        "extracted_ocr":     _truncate(extracted_ocr, 8000),
        "case_number":       response.get("case"),
        "is_scam":           response.get("is_scam", False),
        "score":             response.get("score"),
        "raw_model_output":  _truncate(response.get("raw_model_output", ""), 512),
        "parse_error":       response.get("parse_error"),
        # Flattened primary match — enables fast SQL GROUP BY without JSONB
        "primary_scam_id":   primary.get("id"),
        "primary_label":     primary.get("label"),
        "category":          primary.get("category"),
        "verdict":           primary.get("verdict"),
        # Full detail still available in JSONB columns
        "matches":           matches or None,
        "entities":          response.get("entities") or None,
        "detection_message": response.get("detection_message"),
        "generic_scam":      response.get("generic_scam"),
        "ambiguous":         response.get("ambiguous"),
        "user_agent":        _truncate(user_agent, 256),
        "ip_address":        _truncate(ip_address, 64),
        "session_id":        _truncate(session_id, 128),
    }


def _truncate(value: Optional[str], max_len: int) -> Optional[str]:
    if value is None:
        return None
    return value[:max_len] if len(value) > max_len else value
