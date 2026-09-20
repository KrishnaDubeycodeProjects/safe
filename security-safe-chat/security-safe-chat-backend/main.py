"""
app/main.py — Unified Security Safe Chat Backend

Endpoints
─────────
  GET  /                      redirect to /docs
  GET  /health                liveness probe

  POST /api/scan/text         One-line scam verdict via LLM system prompt (tag + perspective)
  POST /api/scan/link         Link cascade (typosquatting, blocklists, heuristics)
  POST /api/feedback          Gmail OAuth feedback (optional — configure credentials.json)
"""
import base64 as b64lib
import json
import logging
import os
import re
from email.mime.text import MIMEText
from typing import Annotated, List, Optional
from dotenv import load_dotenv

# Ensure .env is loaded into environment
load_dotenv()

from fastapi import FastAPI, Form, File, UploadFile, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ── Internal modules ──────────────────────────────────────────────────────────
from app import bedrock, ocr
from app.config import settings
from app.middleware import APIKeyMiddleware
from app.schemas import HealthResponse, MessageVerdict, ImageVerdict
from app.token_limiter import get_token_status

# ── Cascade engines ───────────────────────────────────────────────────────────
from utils.link_cascade import LinkCascade

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=settings.app_log_level.upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("safe_backend")

# ── Cascade engine instances ──────────────────────────────────────────────────
link_cascade_engine = LinkCascade(bedrock_client=bedrock)

# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

APP_VERSION = "2.0.0"

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Security Safe Chat — Scam Detection API",
    description=(
        "Message scam detection via a single LLM system prompt (one-line "
        "verdict + tag), plus link-cascade analysis for URLs."
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
    allow_origin_regex=settings.cors_origin_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)
app.add_middleware(APIKeyMiddleware)

# ── AWS Lambda Handler (ASGI Adapter) ─────────────────────────────────────────
# ── Mount Community Scam Registry & Digital Arrest Router ────────────────────
try:
    from routes.community_routes import router as community_router
    app.include_router(community_router)
    logger.info("Community scam registry routes mounted at /api/community")
except Exception as exc:
    logger.warning("Community routes not mounted: %s", exc)

from mangum import Mangum
handler = Mangum(app, lifespan="off")

@app.middleware("http")
async def sanitize_json_control_chars_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH") and "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.body()
            if body:
                try:
                    json.loads(body)
                except json.JSONDecodeError as exc:
                    if "control character" in str(exc).lower() or "line break" in str(exc).lower():
                        try:
                            decoded = body.decode("utf-8", errors="replace")
                            parsed = json.loads(decoded, strict=False)
                            sanitized_body = json.dumps(parsed).encode("utf-8")

                            request._body = sanitized_body
                            async def receive():
                                return {"type": "http.request", "body": sanitized_body, "more_body": False}
                            request._receive = receive
                        except Exception:
                            pass
        except Exception:
            pass
    return await call_next(request)


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
# Blogs are admin-authored only — there is no public submission flow. An admin
# writes a title, a list of captioned images, and a body of plain text that
# references images inline via markers like [1], [2] matching each image's
# position in `images`.

class BlogImage(BaseModel):
    title: str = ""                 # caption shown under the image
    url: str                        # image URL or data: URI

class BlogRequest(BaseModel):
    title: str
    tags: List[str] = []
    images: List[BlogImage] = []
    content_text: str               # plain text body; reference images as [1], [2], ...


# ─────────────────────────────────────────────────────────────────────────────
# BLOG STORAGE HELPERS  (flat JSON file, no Supabase needed)
# ─────────────────────────────────────────────────────────────────────────────

import json
import uuid
from datetime import datetime, timezone


def _load_blogs() -> dict:
    """Load blogs store. Returns {"blogs": [...]}."""
    path = settings.blog_storage_path
    if not os.path.exists(path):
        # Fallback to packaged seed files if running in /tmp
        for candidate in ["blogs_store.json", "/app/blogs_store.json", "data/blogs_store.json"]:
            if os.path.exists(candidate):
                try:
                    with open(candidate, "r", encoding="utf-8-sig") as cf:
                        data = json.load(cf)
                        data.setdefault("blogs", [])
                        return data
                except Exception:
                    pass
        return {"blogs": []}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
            data.setdefault("blogs", [])
            return data
    except Exception as e:
        logger.warning(f"Error reading blogs store from {path}: {e}")
        return {"blogs": []}


def _save_blogs(data: dict) -> None:
    """Persist blogs store to disk."""
    path = settings.blog_storage_path
    parent_dir = os.path.dirname(path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _require_admin(request: Request) -> None:
    """Raise 403 if X-Admin-Key header doesn't match settings.admin_blog_key."""
    key = request.headers.get("X-Admin-Key", "")
    if not settings.admin_blog_key or key != settings.admin_blog_key:
        raise HTTPException(status_code=403, detail="Invalid or missing admin key.")


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
# SCAN ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    is_json_invalid = any(err.get("type") == "json_invalid" for err in errors)
    if is_json_invalid:
        try:
            raw_body = await request.body()
            decoded_text = raw_body.decode("utf-8", errors="replace")
            parsed_data = json.loads(decoded_text, strict=False)
            path = request.url.path
            if path == "/api/scan/text":
                req_obj = TextScanRequest(**parsed_data)
                return await api_scan_text(req_obj)
            elif path == "/api/scan/link":
                req_obj = LinkScanRequest(**parsed_data)
                return api_scan_link(req_obj)
        except Exception as fallback_exc:
            logger.error(f"Fallback parse failed: {fallback_exc}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )


@app.post("/api/scan/text", response_model=MessageVerdict, tags=["Scan"], summary="Message scam-likelihood check")
async def api_scan_text(req: TextScanRequest):
    """
    Sends the message to the LLM with a single system prompt and returns a
    one-line perspective plus a verdict tag: Safe, Likely Scam, or Scam Confirmed.
    """
    if not req.text.strip():
        raise HTTPException(400, "Text content cannot be empty.")
    try:
        return await bedrock.classify_message(req.text)
    except HTTPException:
        raise
    except RuntimeError as exc:
        logger.warning("Message classification unavailable: %s", exc)
        raise HTTPException(503, "Message analysis is temporarily unavailable. Please try again shortly.")


@app.get("/api/usage", tags=["System"], summary="Get daily AI token usage status")
def api_get_token_usage():
    """Returns today's token consumption, 10,000 limit, and block status."""
    return get_token_status()


@app.post("/api/scan/image", response_model=ImageVerdict, tags=["Scan"], summary="Image scam & deepfake check with OCR")
async def api_scan_image(
    request: Request,
    file: Optional[UploadFile] = File(None),
):
    """
    Evaluates photos, screenshots, payment receipts, IDs, ads, profile pictures, and documents.
    1. Extracts visible text via OCR model (OCR.space).
    2. Runs multimodal analysis (Gemma-3-27b-it via Mantle) on Scam Usage (Axis A) and AI/Deepfake Likelihood (Axis B).
    """
    content_type = request.headers.get("content-type", "")
    image_bytes = None
    mime_type = "image/jpeg"

    if "multipart/form-data" in content_type and file is not None:
        image_bytes = await file.read()
        mime_type = file.content_type or "image/jpeg"
    else:
        # Support JSON payload with base64 image
        try:
            body = await request.json()
            b64_str = body.get("image_base64") or body.get("image") or ""
            if b64_str:
                if "base64," in b64_str:
                    header, b64_str = b64_str.split("base64,", 1)
                    mime_type = header.replace("data:", "").replace(";", "").strip() or "image/jpeg"
                image_bytes = b64lib.b64decode(b64_str)
        except Exception:
            pass

    if not image_bytes:
        raise HTTPException(400, "No image provided. Please upload an image file or provide image_base64.")

    # 1. OCR text extraction
    ocr_text = ""
    try:
        ocr_text = await ocr.ocr_from_bytes(image_bytes, filename="uploaded_image.jpg", content_type=mime_type)
        if ocr_text:
            logger.info("OCR extracted %d characters from image", len(ocr_text))
    except Exception as e:
        logger.warning("OCR extraction failed gracefully: %s", e)

    # 2. Multimodal analysis
    try:
        return await bedrock.classify_image(image_bytes=image_bytes, mime_type=mime_type, ocr_text=ocr_text)
    except Exception as exc:
        logger.error("Image classification error: %s", exc)
        raise HTTPException(503, "Image analysis is temporarily unavailable. Please try again shortly.")


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


# ═════════════════════════════════════════════════════════════════════════════
# INVESTIGATE ENDPOINTS — YouTube Video & Comment Scam Analysis
# ═════════════════════════════════════════════════════════════════════════════
from app import investigate

class InvestigateRequest(BaseModel):
    query: Optional[str] = None
    input: Optional[str] = None
    url: Optional[str] = None
    target: Optional[str] = None

@app.post("/api/investigate", tags=["Investigate"], summary="YouTube & Threat Intelligence Investigation")
async def api_investigate(req: InvestigateRequest):
    """
    Accepts YouTube link or target query, calls n8n investigation webhook
    (or synthesized heuristic pipeline), and returns an abstracted threat intelligence report.
    """
    raw_target = (req.input or req.url or req.query or req.target or "").strip()
    if not raw_target:
        raise HTTPException(400, "YouTube link or target query cannot be empty.")
    
    report_data = investigate.run_n8n_investigation(raw_target)
    return report_data


# ═════════════════════════════════════════════════════════════════════════════
# BLOG ENDPOINTS — admin-authored only, published immediately (no review queue)
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/blogs", tags=["Blogs"], summary="List all blog posts")
def list_blogs():
    """Returns all blog posts, newest first. Public — no auth required."""
    data = _load_blogs()
    return {"blogs": data.get("blogs", []), "total": len(data.get("blogs", []))}


@app.get("/api/blogs/{blog_id}", tags=["Blogs"], summary="Get a single blog post")
def get_blog(blog_id: str):
    """Returns one blog post by ID. Public — no auth required."""
    data = _load_blogs()
    blog = next((b for b in data.get("blogs", []) if b["id"] == blog_id), None)
    if not blog:
        raise HTTPException(404, f"Blog ID '{blog_id}' not found.")
    return blog


@app.post("/api/blogs", tags=["Blogs"], summary="[Admin] Create a new blog post")
def create_blog(body: BlogRequest, request: Request):
    """Admin-only: creates and immediately publishes a blog post. Requires X-Admin-Key header."""
    _require_admin(request)
    if not body.title.strip():
        raise HTTPException(400, "Title cannot be empty.")
    if not body.content_text.strip():
        raise HTTPException(400, "Content cannot be empty.")

    blog_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": blog_id,
        "title": body.title.strip(),
        "tags": [t.strip() for t in body.tags if t.strip()],
        "images": [img.model_dump() for img in body.images],
        "content_text": body.content_text,
        "created_at": ts,
        "updated_at": ts,
    }

    data = _load_blogs()
    data.setdefault("blogs", []).insert(0, entry)
    _save_blogs(data)
    return {"success": True, "blog_id": blog_id, "message": "Blog published."}


@app.put("/api/blogs/{blog_id}", tags=["Blogs"], summary="[Admin] Update an existing blog post")
def update_blog(blog_id: str, body: BlogRequest, request: Request):
    """Admin-only: overwrites an existing blog post's fields. Requires X-Admin-Key header."""
    _require_admin(request)
    if not body.title.strip():
        raise HTTPException(400, "Title cannot be empty.")
    if not body.content_text.strip():
        raise HTTPException(400, "Content cannot be empty.")

    data = _load_blogs()
    blogs = data.get("blogs", [])
    matched = next((b for b in blogs if b["id"] == blog_id), None)
    if not matched:
        raise HTTPException(404, f"Blog ID '{blog_id}' not found.")

    matched["title"] = body.title.strip()
    matched["tags"] = [t.strip() for t in body.tags if t.strip()]
    matched["images"] = [img.model_dump() for img in body.images]
    matched["content_text"] = body.content_text
    matched["updated_at"] = datetime.now(timezone.utc).isoformat()
    _save_blogs(data)
    return {"success": True, "blog_id": blog_id, "message": "Blog updated."}


@app.delete("/api/blogs/{blog_id}", tags=["Blogs"], summary="[Admin] Delete a blog post")
def delete_blog(blog_id: str, request: Request):
    """Admin-only: permanently deletes a blog post. Requires X-Admin-Key header."""
    _require_admin(request)
    data = _load_blogs()
    blogs = data.get("blogs", [])
    if not any(b["id"] == blog_id for b in blogs):
        raise HTTPException(404, f"Blog ID '{blog_id}' not found.")

    data["blogs"] = [b for b in blogs if b["id"] != blog_id]
    _save_blogs(data)
    return {"success": True, "blog_id": blog_id, "message": "Blog deleted."}


# ═════════════════════════════════════════════════════════════════════════════
# FEEDBACK (Active Multi-Tier Email Dispatch: SMTP + AWS SES + Local + Mailto)
# ═════════════════════════════════════════════════════════════════════════════

def _send_feedback_email(contact_info: Optional[str], message_text: str) -> dict:
    """
    Delivers citizen feedback to safe.princete@gmail.com via:
    1. SMTP (using Gmail App Password if configured in .env)
    2. AWS SES (using verified email identity with existing AWS credentials)
    3. Graceful status feedback for client-side mailto fallback
    """
    load_dotenv(override=True)
    recipient = os.getenv("FEEDBACK_RECIPIENT_EMAIL", "safe.princete@gmail.com")
    subject = f"[SAFE Feedback] New Citizen Report ({contact_info or 'Anonymous'})"
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    body_text = (
        f"A new feedback or scam report was submitted on the SAFE Platform:\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Sender Contact : {contact_info or 'Not provided (Anonymous)'}\n"
        f"Timestamp      : {now_str}\n"
        f"Recipient      : {recipient}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"Message / Report:\n{message_text}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"Automated Notification from SAFE Cyber Defense Intelligence Engine\n"
    )

    # --- Tier 1: SMTP Dispatch (Gmail / Custom) ---
    smtp_pass = os.getenv("SMTP_PASSWORD") or os.getenv("GMAIL_APP_PASSWORD")
    if smtp_pass:
        smtp_user = os.getenv("SMTP_USER", recipient)
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "465"))
        try:
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import smtplib

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = smtp_user
            msg["To"] = recipient
            if contact_info and "@" in contact_info:
                msg["Reply-To"] = contact_info

            msg.attach(MIMEText(body_text, "plain", "utf-8"))

            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                    server.login(smtp_user, smtp_pass)
                    server.sendmail(smtp_user, [recipient], msg.as_string())
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.sendmail(smtp_user, [recipient], msg.as_string())

            logger.info("Feedback email delivered via SMTP to %s", recipient)
            return {"sent": True, "method": "smtp"}
        except Exception as exc:
            logger.warning("SMTP feedback dispatch error: %s", exc)

    # --- Tier 2: AWS SES Dispatch (Using existing AWS Credentials) ---
    try:
        import boto3
        aws_key = os.getenv("AWS_ACCESS_KEY_ID") or getattr(settings, "aws_access_key_id", "")
        aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY") or getattr(settings, "aws_secret_access_key", "")
        aws_reg = os.getenv("AWS_REGION", "us-east-1") or getattr(settings, "aws_region", "us-east-1")

        if aws_key and aws_secret:
            ses_client = boto3.client(
                "ses",
                region_name=aws_reg,
                aws_access_key_id=aws_key,
                aws_secret_access_key=aws_secret,
            )
            # Check verification status of recipient
            attrs_resp = ses_client.get_identity_verification_attributes(Identities=[recipient])
        status = attrs_resp.get("VerificationAttributes", {}).get(recipient, {}).get("VerificationStatus")

        if status == "Success":
            send_resp = ses_client.send_email(
                Source=recipient,
                Destination={"ToAddresses": [recipient]},
                ReplyToAddresses=[contact_info] if (contact_info and "@" in contact_info) else [],
                Message={
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
                },
            )
            logger.info("Feedback email delivered via AWS SES to %s: %s", recipient, send_resp.get("MessageId"))
            return {"sent": True, "method": "ses", "message_id": send_resp.get("MessageId")}
        elif status == "Pending":
            logger.info("AWS SES identity %s is pending verification", recipient)
            return {"sent": False, "method": "ses", "status": "pending_verification"}
        else:
            # Trigger verification request email from AWS SES to recipient
            ses_client.verify_email_identity(EmailAddress=recipient)
            logger.info("Triggered AWS SES verification request to %s", recipient)
            return {"sent": False, "method": "ses", "status": "verification_sent"}
    except Exception as exc:
        logger.warning("AWS SES feedback dispatch error: %s", exc)

    return {"sent": False, "method": "none", "status": "no_credentials"}


@app.post("/api/feedback", tags=["Feedback"], summary="Submit user feedback or scam report")
def receive_feedback(data: FeedbackRequest):
    """Archive user feedback locally and deliver to safe.princete@gmail.com via SMTP / SES."""
    import json, urllib.parse

    recipient = os.getenv("FEEDBACK_RECIPIENT_EMAIL", "safe.princete@gmail.com")
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email": data.email or "",
        "message": data.message or "",
        "recipient": recipient,
    }

    # 1. Always append to local persistence log
    try:
        log_path = "/tmp/feedback_submissions.jsonl" if (os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT")) else "feedback_submissions.jsonl"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        logger.info("Feedback recorded locally for %s: %s", recipient, entry)
    except Exception as exc:
        logger.warning("Failed to record feedback locally: %s", exc)

    # 2. Attempt active email delivery
    delivery = _send_feedback_email(data.email, data.message)

    # 3. Construct direct mailto fallback URL
    subj_enc = urllib.parse.quote(f"SAFE Feedback from {data.email or 'Citizen'}")
    body_enc = urllib.parse.quote(f"From: {data.email or 'Anonymous'}\n\nFeedback:\n{data.message}\n")
    mailto_url = f"mailto:{recipient}?subject={subj_enc}&body={body_enc}"

    if delivery.get("sent"):
        return {
            "success": True,
            "email_sent": True,
            "method": delivery.get("method"),
            "message": f"Feedback successfully delivered to {recipient}",
        }
    else:
        status_code = delivery.get("status", "pending")
        return {
            "success": True,
            "email_sent": False,
            "status": status_code,
            "mailto_url": mailto_url,
            "message": (
                f"Feedback recorded! Note: {recipient} has an AWS verification email pending. "
                f"Once approved, emails will deliver automatically."
            ),
        }

# ═════════════════════════════════════════════════════════════════════════════
# CHAT ENDPOINT — SAFE Saathi conversational + scan integration
# Rate limit: 50 requests / IP / day
# General responses: real Bedrock LLM (CHAT_SYSTEM_PROMPT, max 100 tokens)
# Scan responses: LLM system-prompt verdict / link cascade
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
):
    """
    Unified chat endpoint consumed by SecuritySafe frontend.

    Routing:
      - URL or scan text  → link cascade / LLM verdict
      - General chat      → real Bedrock LLM (SAFE Saathi strict safety assistant)

    Rate limit: 50 requests per IP per day.
    LLM token cap: 100 tokens per response.
    """
    text = (message.strip() if message else "")[:1000]   # hard cap input at 1000 chars

    response = {
        "bot_message": "",
        "custom_payload": None,
        "redirect_url": None,
        "intent_detected": "general",
        "is_hallucination": False,
    }

    # ── Empty message ──────────────────────────────────────────────────────────────────
    if not text:
        response["bot_message"] = (
            "Namaste! I'm SAFE Saathi, your digital safety assistant. "
            "Share a suspicious message or link and I'll check it for you."
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

    # ── Strong scan signal → LLM message verdict ─────────────────────────────────────
    if _SCAN_STRONG.search(text) or len(text) > 80:
        response["intent_detected"] = "scan"
        try:
            verdict = await bedrock.classify_message(text)
            response["bot_message"] = f"{verdict['message']} — {verdict['tag']}."
            response["custom_payload"] = verdict
        except RuntimeError:
            response["bot_message"] = "I'm having trouble analysing that right now — please try again in a moment."
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