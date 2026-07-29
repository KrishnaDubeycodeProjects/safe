"""
app/main.py — Unified Security Safe Chat Backend

Merges:
  • Digital-arrest-detector cascade engines (text, link, image, scoring, suggestions)
  • security-safe-chat-backend LLM pipeline (AWS Bedrock + OCR.space + taxonomy parser)
  • Supabase two-table logging

Endpoints
─────────
  GET  /                      redirect to /docs
  GET  /health                liveness probe

  POST /analyze/text          Bedrock + taxonomy parser (structured JSON verdict)
  POST /analyze/image         OCR.space → Bedrock + taxonomy parser
  POST /analyze/base64        base64 image → OCR.space → Bedrock + taxonomy parser

  POST /api/scan/text         Full cascade (keyword + Bedrock) + scoring + suggestions
  POST /api/scan/link         Link cascade (typosquatting, blocklists, heuristics)
  POST /api/scan/image        Image cascade (OCR.space + link scan + CV) + scoring + suggestions
  POST /api/feedback          Gmail OAuth feedback (optional — configure credentials.json)
"""
import asyncio
import base64 as b64lib
import logging
import os
import re
from email.mime.text import MIMEText
from pathlib import Path
from typing import Annotated, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Internal modules ──────────────────────────────────────────────────────────
from app import bedrock, ocr, parser, supabase_logger
from app.config import settings
from app.middleware import APIKeyMiddleware
from app.schemas import (
    AnalyzeBase64Request,
    AnalyzeResponse,
    AnalyzeTextRequest,
    HealthResponse,
    ScamMatch,
)

# ── Cascade engines ───────────────────────────────────────────────────────────
from utils.link_cascade import LinkCascade
from utils.image_cascade import ImageCascade
from utils.scoring_engine import ScoringEngine
from utils.suggestion_engine import SuggestionEngine
from utils.text_cascade import TextCascade

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=settings.app_log_level.upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("safe_backend")

# ── Cascade engine instances ──────────────────────────────────────────────────
text_cascade_engine   = TextCascade(bedrock_client=bedrock, parser=parser)
link_cascade_engine   = LinkCascade(bedrock_client=bedrock, parser=parser)
image_cascade_engine  = ImageCascade(text_cascade_engine, link_cascade_engine, ocr_module=ocr)
scoring_engine        = ScoringEngine()
suggestion_engine     = SuggestionEngine()

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

APP_VERSION = "2.0.0"

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Safe Chat — Unified Scam Detection API",
    description=(
        "Production backend combining cascade engines (keyword, link, image) "
        "with AWS Bedrock (Claude 3 Haiku) + OCR.space + Supabase logging.\n\n"
        "**Analyze endpoints** — structured taxonomy verdict (is_scam, score, entities)\n"
        "**Scan endpoints** — cascade verdict (label, combined_prob, scoring, suggestions)"
    ),
    version=APP_VERSION,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# TrustedHost middleware — prevents Host-header injection attacks
if settings.trusted_hosts != "*":
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts_list)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Key", "X-Request-ID"],
)
app.add_middleware(APIKeyMiddleware)


# ── Pydantic request models ───────────────────────────────────────────────────
class TextScanRequest(BaseModel):
    text: str

class LinkScanRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    email: Optional[str] = None
    message: str


# ─────────────────────────────────────────────────────────────────────────────
# BLOG MODELS
# ─────────────────────────────────────────────────────────────────────────────

class BlogSubmitRequest(BaseModel):
    title: str
    author_name: str
    author_email: Optional[str] = None
    category: str                   # e.g. "Banking Scam", "UPI Fraud", etc.
    content_html: str               # Quill Delta HTML output
    content_text: str               # Plain-text version for email body
    legal_disclaimer_accepted: bool = False

class BlogApproveRequest(BaseModel):
    blog_id: str
    admin_notes: Optional[str] = None

class BlogRejectRequest(BaseModel):
    blog_id: str
    reason: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# BLOG STORAGE HELPERS  (flat JSON file, no Supabase needed)
# ─────────────────────────────────────────────────────────────────────────────

import json
import uuid
from datetime import datetime, timezone


def _load_blogs() -> dict:
    """Load blogs store. Returns {approved: [...], pending: [...]}."""
    path = settings.blog_storage_path
    if not os.path.exists(path):
        return {"approved": [], "pending": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"approved": [], "pending": []}


def _save_blogs(data: dict) -> None:
    """Persist blogs store to disk."""
    with open(settings.blog_storage_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _require_admin(request: Request) -> None:
    """Raise 403 if X-Admin-Key header doesn't match settings.admin_blog_key."""
    key = request.headers.get("X-Admin-Key", "")
    if not settings.admin_blog_key or key != settings.admin_blog_key:
        raise HTTPException(status_code=403, detail="Invalid or missing admin key.")


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _build_analyze_response(parsed: dict, extracted_text: str | None = None) -> AnalyzeResponse:
    matches = [
        ScamMatch(
            id=m["id"], label=m.get("label", ""), category=m.get("category", ""),
            subcategory=m.get("subcategory", ""), verdict=m.get("verdict", ""),
            score=m.get("score", 0), red_flags=m.get("red_flags", []),
            detection_message=m.get("detection_message", ""), entities=m.get("entities", {}),
        )
        for m in parsed.get("matches", [])
    ]
    score = parsed.get("score")
    if parsed["case"] == 3 and score is None:
        score = 90
    return AnalyzeResponse(
        case=parsed["case"], is_scam=parsed["is_scam"], score=score,
        matches=matches, entities=parsed.get("entities", {}),
        detection_message=parsed.get("detection_message"),
        ambiguous=parsed.get("ambiguous"), generic_scam=parsed.get("generic_scam"),
        raw_model_output=parsed.get("raw", ""),
        extracted_text=extracted_text, parse_error=parsed.get("parse_error"),
    )


async def _classify_text(message: str) -> AnalyzeResponse:
    try:
        raw = await bedrock.classify_text(message)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY,
                            detail=f"LLM service error: {exc}") from exc
    return _build_analyze_response(parser.parse(raw))


def _fire_log(*, input_type: str, input_text: str | None, extracted_ocr: str | None,
               response: AnalyzeResponse, request: Request) -> None:
    user_agent = request.headers.get("user-agent")
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (request.client.host if request.client else None))
    session_id = request.headers.get("x-session-id")
    asyncio.ensure_future(supabase_logger.log_result(
        input_type=input_type, input_text=input_text, extracted_ocr=extracted_ocr,
        response=response.model_dump(), user_agent=user_agent, ip_address=ip,
        session_id=session_id,
    ))


def _build_cascade_scan_response(cascade_result: dict) -> dict:
    """Add scoring + suggestions to any cascade result (text, image, link)."""
    sub = cascade_result.get("sub_results", {})
    meta = cascade_result.get("meta", {})
    url_results = sub.get("url_results", [])
    extracted_urls = meta.get("extracted_urls", [])

    worst_link = None
    if url_results:
        worst_link = max(url_results, key=lambda x: x.get("result", {}).get("combined_prob", 0.0)).get("result")

    score_report = scoring_engine.format_detailed_report(
        scoring_engine.calculate_score(
            ocr_text_result=sub.get("ocr_text_result"),
            link_analysis_result=worst_link,
            image_manipulation_result=cascade_result,
            extracted_urls_count=len(extracted_urls),
        )
    )
    suggestions = suggestion_engine.generate_suggestions(score_report)

    return {
        **cascade_result,
        "scam_score": score_report["scam_score"],
        "max_score": score_report["max_score"],
        "risk_level": score_report["risk_level"],
        "score_label": score_report["label"],
        "breakdown": score_report["breakdown"],
        "summary": score_report["summary"],
        "suggestions": suggestions,
        "extracted_data": {
            "ocr_text": meta.get("ocr_text", ""),
            "urls": meta.get("extracted_urls", []),
            "phones": meta.get("extracted_phones", []),
            "emails": meta.get("extracted_emails", []),
            "qr_content": meta.get("qr_content", ""),
            "urls_analyzed": meta.get("url_analysis_count", 0),
        },
        "url_analysis": [
            {"url": r.get("url", ""), "label": r.get("result", {}).get("label", ""),
             "combined_prob": r.get("result", {}).get("combined_prob", 0.0),
             "explanation": r.get("result", {}).get("explanation", "")}
            for r in url_results
        ],
        "rag": {"explanation": cascade_result.get("explanation"), "advice": cascade_result.get("actionSteps", [])},
    }


# ═════════════════════════════════════════════════════════════════════════════
# SYSTEM ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, summary="Liveness probe", tags=["System"])
async def health():
    return HealthResponse(status="ok", version=APP_VERSION, environment=settings.app_env)


# ═════════════════════════════════════════════════════════════════════════════
# ANALYZE ENDPOINTS — structured Bedrock taxonomy verdict
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/analyze/text", response_model=AnalyzeResponse, tags=["Analyze"], summary="Classify plain-text (Bedrock)")
async def analyze_text(body: AnalyzeTextRequest, request: Request):
    """
    Classify a raw SMS / email / chat message via AWS Bedrock + taxonomy parser.
    Returns a structured verdict: case number, is_scam, score, matched entities.
    """
    response = await _classify_text(body.message)
    _fire_log(input_type="text", input_text=body.message, extracted_ocr=None,
              response=response, request=request)
    return response


@app.post("/analyze/image", response_model=AnalyzeResponse, tags=["Analyze"], summary="Upload image → OCR → Bedrock")
async def analyze_image_endpoint(request: Request, file: UploadFile = File(...)):
    """Upload a screenshot → OCR.space → Bedrock taxonomy classification."""
    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(400, "Uploaded file is empty.")
    try:
        extracted = await ocr.ocr_from_bytes(
            image_bytes, filename=file.filename or "upload.jpg",
            content_type=file.content_type or "image/jpeg",
        )
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(422, f"OCR error: {exc}") from exc
    response = await _classify_text(extracted)
    response.extracted_text = extracted
    _fire_log(input_type="image", input_text=None, extracted_ocr=extracted,
              response=response, request=request)
    return response


@app.post("/analyze/base64", response_model=AnalyzeResponse, tags=["Analyze"], summary="Base64 image → OCR → Bedrock")
async def analyze_base64_endpoint(body: AnalyzeBase64Request, request: Request):
    """Send a base64-encoded image → OCR.space → Bedrock taxonomy classification."""
    try:
        extracted = await ocr.ocr_from_base64(body.image, content_type=body.content_type)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(422, f"OCR error: {exc}") from exc
    response = await _classify_text(extracted)
    response.extracted_text = extracted
    _fire_log(input_type="base64", input_text=None, extracted_ocr=extracted,
              response=response, request=request)
    return response


# ═════════════════════════════════════════════════════════════════════════════
# SCAN ENDPOINTS — cascade verdict with scoring + suggestions
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/scan/text", tags=["Scan"], summary="Full cascade text scan")
async def api_scan_text(req: TextScanRequest):
    """
    Tiered text scam detection:
    Layer 1 → keyword heuristics
    Layer 2 → AWS Bedrock (Claude 3 Haiku) taxonomy classification

    Returns cascade label, combined_prob, scam_score/10, and actionable suggestions.
    """
    if not req.text.strip():
        raise HTTPException(400, "Text content cannot be empty.")
    result = await text_cascade_engine.scan_async(req.text)
    result["ml_prob"] = result.get("combined_prob", 0.0)
    result["keywords"] = []
    result["rag"] = {"explanation": result.get("explanation"), "advice": result.get("actionSteps", [])}

    # Enrich with scoring
    score_report = scoring_engine.format_detailed_report(
        scoring_engine.calculate_score(ocr_text_result=result)
    )
    suggestions = suggestion_engine.generate_suggestions(score_report)
    result["scam_score"] = score_report["scam_score"]
    result["risk_level"] = score_report["risk_level"]
    result["suggestions"] = suggestions
    return result


@app.post("/api/scan/link", tags=["Scan"], summary="Link/URL cascade scan")
def api_scan_link(req: LinkScanRequest):
    """
    Multi-layer URL analysis:
    • Whitelist / blocklist check
    • Typosquatting detection against 100+ Indian brands
    • Domain heuristics (age, TLD, IP address, path patterns)
    • Landing page analysis (password fields, brand impersonation)
    """
    if not req.url.strip():
        raise HTTPException(400, "URL cannot be empty.")
    res = link_cascade_engine.scan(req.url)
    res["rag"] = {"explanation": res.get("explanation"), "advice": res.get("actionSteps", [])}
    return res


@app.post("/api/scan/image", tags=["Scan"], summary="Full cascade image scan")
async def api_scan_image(file: UploadFile = File(...)):
    """
    Multi-layer image scam analysis:
    Layer 0 → SHA-256 hash blocklist
    Layer 1 → QR code extraction + link cascade
    Layer 2 → OCR.space text extraction + text cascade (Bedrock)
    Layer 3 → CV manipulation detection (optional)

    Returns combined_prob, scam_score/10, breakdown, and contextual suggestions.
    """
    suffix = Path(file.filename or "upload.png").suffix or ".png"
    temp_path = f"temp_scan_{id(file)}{suffix}"
    try:
        with open(temp_path, "wb") as f:
            f.write(await file.read())
        cascade_result = await image_cascade_engine.scan_async(temp_path)
        return _build_cascade_scan_response(cascade_result)
    except Exception as exc:
        logger.exception("Image scan error: %s", exc)
        raise HTTPException(500, str(exc))
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


# ═════════════════════════════════════════════════════════════════════════════
# BLOG ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/blogs", tags=["Blogs"], summary="List all approved blog posts")
def list_approved_blogs():
    """Returns all published (admin-approved) blog posts sorted newest-first."""
    data = _load_blogs()
    return {"blogs": data.get("approved", []), "total": len(data.get("approved", []))}


@app.post("/api/blogs/submit", tags=["Blogs"], summary="User submits a blog post for review")
def submit_blog(body: BlogSubmitRequest):
    """
    Accepts a user blog submission, saves it as PENDING, and emails the admin
    via the same Gmail OAuth pipeline used by feedback.
    """
    if not body.legal_disclaimer_accepted:
        raise HTTPException(400, "You must accept the legal disclaimer before submitting.")

    blog_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()

    entry = {
        "id": blog_id,
        "title": body.title,
        "author_name": body.author_name,
        "author_email": body.author_email or "",
        "category": body.category,
        "content_html": body.content_html,
        "content_text": body.content_text,
        "submitted_at": ts,
        "status": "pending",
    }

    data = _load_blogs()
    data.setdefault("pending", []).insert(0, entry)
    _save_blogs(data)

    # Email admin (best-effort via Gmail OAuth)
    try:
        service = _get_gmail_service()
        profile = service.users().getProfile(userId="me").execute()
        user_email = profile["emailAddress"]

        email_body = (
            f"New Blog Submission — SAFE Platform\n"
            f"{'=' * 50}\n"
            f"Blog ID : {blog_id}\n"
            f"Title   : {body.title}\n"
            f"Author  : {body.author_name} <{body.author_email or 'no email'}>\n"
            f"Category: {body.category}\n"
            f"Submitted: {ts}\n\n"
            f"--- Content (plain text) ---\n{body.content_text}\n\n"
            f"--- To approve, call: POST /api/blogs/approve with blog_id={blog_id} and X-Admin-Key header ---"
        )
        msg = MIMEText(email_body)
        msg["to"] = user_email
        msg["from"] = user_email
        msg["subject"] = f"[Blog Submission] {body.title} | SAFE Platform"
        raw = b64lib.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": raw}).execute()
        logger.info("Blog submission email sent for blog_id=%s", blog_id)
    except Exception as exc:
        logger.warning("Blog email notification failed (non-fatal): %s", exc)

    return {"success": True, "blog_id": blog_id, "message": "Blog submitted for review. You'll hear back soon!"}


@app.get("/api/blogs/pending", tags=["Blogs"], summary="[Admin] List pending blog submissions")
def list_pending_blogs(request: Request):
    """Admin-only: returns all blog submissions awaiting review. Requires X-Admin-Key header."""
    _require_admin(request)
    data = _load_blogs()
    return {"pending": data.get("pending", []), "total": len(data.get("pending", []))}


@app.post("/api/blogs/approve", tags=["Blogs"], summary="[Admin] Approve a pending blog")
def approve_blog(body: BlogApproveRequest, request: Request):
    """Admin-only: moves a pending blog to approved. Requires X-Admin-Key header."""
    _require_admin(request)
    data = _load_blogs()
    pending = data.get("pending", [])
    matched = next((b for b in pending if b["id"] == body.blog_id), None)
    if not matched:
        raise HTTPException(404, f"Blog ID '{body.blog_id}' not found in pending queue.")

    matched["status"] = "approved"
    matched["approved_at"] = datetime.now(timezone.utc).isoformat()
    matched["admin_notes"] = body.admin_notes or ""

    data["pending"] = [b for b in pending if b["id"] != body.blog_id]
    data.setdefault("approved", []).insert(0, matched)
    _save_blogs(data)
    return {"success": True, "blog_id": body.blog_id, "message": "Blog approved and published."}


@app.post("/api/blogs/reject", tags=["Blogs"], summary="[Admin] Reject a pending blog")
def reject_blog(body: BlogRejectRequest, request: Request):
    """Admin-only: removes a pending blog. Requires X-Admin-Key header."""
    _require_admin(request)
    data = _load_blogs()
    pending = data.get("pending", [])
    if not any(b["id"] == body.blog_id for b in pending):
        raise HTTPException(404, f"Blog ID '{body.blog_id}' not found in pending queue.")

    data["pending"] = [b for b in pending if b["id"] != body.blog_id]
    _save_blogs(data)
    return {"success": True, "blog_id": body.blog_id, "message": f"Blog rejected. Reason: {body.reason or 'N/A'}"}


# ═════════════════════════════════════════════════════════════════════════════
# FEEDBACK (Gmail OAuth — optional)
# ═════════════════════════════════════════════════════════════════════════════

def _get_gmail_service():
    """Lazy Gmail service loader. Raises ImportError if google libs missing."""
    from google.auth.transport.requests import Request as GRequest
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=8001, access_type="offline", prompt="consent")
        with open("token.json", "w") as t:
            t.write(creds.to_json())
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


@app.post("/api/feedback", tags=["Feedback"], summary="Submit user feedback via Gmail")
def receive_feedback(data: FeedbackRequest):
    """Archive user feedback as a Gmail label 'feedback'. Requires credentials.json."""
    try:
        from googleapiclient.errors import HttpError
        service = _get_gmail_service()
        profile = service.users().getProfile(userId="me").execute()
        user_email = profile["emailAddress"]

        # Get or create label
        labels = service.users().labels().list(userId="me").execute().get("labels", [])
        label_id = next((l["id"] for l in labels if l["name"].lower() == "feedback"), None)
        if not label_id:
            label_id = service.users().labels().create(
                userId="me",
                body={"name": "feedback", "labelListVisibility": "labelShow", "messageListVisibility": "show"},
            ).execute()["id"]

        msg = MIMEText(f"From: {data.email}\n\n{data.message}")
        msg["to"] = user_email
        msg["from"] = user_email
        msg["subject"] = "Feedback | Security Safe Chat"
        raw = b64lib.urlsafe_b64encode(msg.as_bytes()).decode()

        sent = service.users().messages().send(userId="me", body={"raw": raw, "labelIds": [label_id]}).execute()
        service.users().messages().modify(
            userId="me", id=sent["id"],
            body={"removeLabelIds": ["INBOX", "SENT", "UNREAD"]},
        ).execute()
        return {"success": True, "messageId": sent["id"]}

    except ImportError:
        raise HTTPException(501, "Gmail integration not installed. Run: pip install google-api-python-client google-auth-oauthlib")
    except Exception as exc:
        logger.exception("Feedback error")
        raise HTTPException(500, str(exc))

# ═════════════════════════════════════════════════════════════════════════════
# CHAT ENDPOINT — SAFE Saathi conversational + scan integration
# Rate limit: 50 requests / IP / day
# General responses: real Bedrock LLM (CHAT_SYSTEM_PROMPT, max 100 tokens)
# Scan responses: cascade engines + LLM summary
# ═════════════════════════════════════════════════════════════════════════════

from app.bedrock import chat_with_llm

# Patterns that signal the user wants to scan something (not just chat)
_URL_RE       = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.I)
_SCAN_STRONG  = re.compile(
    r"\b(scan|check this|verify|is this (safe|scam|real|legit)|scam|phishing|"
    r"otp|upi|arrest|kyc|lottery|prize|won|click here|suspicious|fraud|"
    r"suspicious link|malware|ransomware)\b", re.I
)
_LEARN_RE     = re.compile(r"\b(learn|safety tips|tips|guide|how to protect)\b", re.I)

@app.post("/api/v1/chat", tags=["Chat"], summary="Conversational safety assistant (Bedrock LLM, 50 req/IP/day)")
@limiter.limit("50/day")
async def api_chat(
    request: Request,
    message: Annotated[str, Form()] = "",
    session_id: Annotated[str, Form()] = "",
    image: Annotated[Optional[UploadFile], File()] = None,
):
    """
    Unified chat endpoint consumed by SecuritySafe frontend.

    Routing:
      - Image uploaded    → image cascade engine, LLM contextualises result
      - URL or scan text  → text/link cascade engine, LLM contextualises result
      - General chat      → real Bedrock LLM (SAFE Saathi strict safety assistant)

    Rate limit: 50 requests per IP per day.
    LLM token cap: 100 tokens per response.
    """
    text = (message.strip() if message else "")[:1000]   # hard cap input at 1000 chars
    has_image = image is not None and image.filename

    response = {
        "bot_message": "",
        "custom_payload": None,
        "redirect_url": None,
        "intent_detected": "general",
        "is_hallucination": False,
    }

    # ── Image scan path ─────────────────────────────────────────────────────────────
    if has_image:
        response["intent_detected"] = "scan"
        suffix = Path(image.filename or "upload.png").suffix or ".png"
        temp_path = f"temp_chat_{id(image)}{suffix}"
        try:
            contents = await image.read()
            if len(contents) > 10 * 1024 * 1024:  # 10 MB hard limit
                response["bot_message"] = "Image is too large (max 10 MB). Please compress and retry."
                return response
            with open(temp_path, "wb") as f:
                f.write(contents)

            cascade_result = await image_cascade_engine.scan_async(temp_path)
            scan_payload   = _build_cascade_scan_response(cascade_result)

            # LLM contextualises the scan result in plain language
            try:
                explanation = cascade_result.get("explanation") or ""
                llm_summary = await chat_with_llm(
                    f"An image was scanned for scams. Analysis result: {explanation[:400]}. "
                    f"Summarize the safety verdict in 2 sentences max."
                )
                response["bot_message"] = llm_summary
            except Exception:
                response["bot_message"] = f"Image analysed. {scan_payload.get('explanation', 'Analysis complete.')}"

            response["custom_payload"] = scan_payload
        except Exception as exc:
            logger.exception("Chat image scan error: %s", exc)
            response["bot_message"] = "I had trouble analysing that image. Please try a clearer screenshot."
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass
        return response

    # ── Empty message ──────────────────────────────────────────────────────────────────
    if not text:
        response["bot_message"] = (
            "Namaste! I'm SAFE Saathi, your digital safety assistant. "
            "Share a suspicious message, link, or screenshot and I'll check it for you."
        )
        return response

    # ── Learn / Tips redirect ──────────────────────────────────────────────────────────
    if _LEARN_RE.search(text):
        response["intent_detected"] = "learn"
        response["redirect_url"] = "/learn"
        response["bot_message"] = "You can learn more about digital safety and protection tips on our Learn page."
        return response

    # ── URL detected → link cascade directly ───────────────────────────────────────────
    url_match = _URL_RE.search(text)
    if url_match and len(text.split()) <= 6:
        response["intent_detected"] = "scan"
        link_result = link_cascade_engine.scan(url_match.group(0))
        link_result["rag"] = {
            "explanation": link_result.get("explanation"),
            "advice":      link_result.get("actionSteps", []),
        }
        try:
            llm_summary = await chat_with_llm(
                f"A URL was scanned. Result: {link_result.get('explanation','')[:400]}. "
                f"Give a 1-sentence verdict and one safety tip."
            )
            response["bot_message"] = llm_summary
        except Exception:
            response["bot_message"] = f"Link analysed. {link_result.get('explanation', '')}"
        response["custom_payload"] = link_result
        return response

    # ── Strong scan signal → text cascade ────────────────────────────────────────────
    if _SCAN_STRONG.search(text) or len(text) > 80:
        response["intent_detected"] = "scan"
        cascade_result = await text_cascade_engine.scan_async(text)
        prob = cascade_result.get("combined_prob", 0.0)

        score_report = scoring_engine.format_detailed_report(
            scoring_engine.calculate_score(ocr_text_result=cascade_result)
        )
        suggestions = suggestion_engine.generate_suggestions(score_report)
        cascade_result.update({
            "scam_score":  score_report["scam_score"],
            "risk_level":  score_report["risk_level"],
            "suggestions": suggestions,
            "keywords":    [],
            "rag": {
                "explanation": cascade_result.get("explanation"),
                "advice":      cascade_result.get("actionSteps", []),
            },
        })

        if prob > 0.25 or _SCAN_STRONG.search(text):
            try:
                llm_summary = await chat_with_llm(
                    f"Scam scan result: {cascade_result.get('explanation','')[:400]}. "
                    f"Risk score: {score_report['scam_score']}. "
                    f"Give a 2-sentence verdict with one protective action."
                )
                response["bot_message"] = llm_summary
            except Exception:
                response["bot_message"] = f"I found some red flags. {cascade_result.get('explanation', '')}"
            response["custom_payload"] = cascade_result
            return response

    # ── General conversation → real LLM (SAFE Saathi strict mode) ────────────────
    response["intent_detected"] = "general"
    try:
        llm_reply = await chat_with_llm(text)
        response["bot_message"] = llm_reply
    except RuntimeError as exc:
        logger.warning("LLM unavailable for general chat: %s", exc)
        response["bot_message"] = (
            "I'm here to help with scam detection and digital safety. "
            "Share a suspicious message or link and I'll analyse it for you."
        )

    return response


# ── Dev runner ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.app_host, port=settings.app_port,
                reload=not settings.is_production, log_level=settings.app_log_level)