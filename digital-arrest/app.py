# Digital Arrest Detector - Multi-Channel Fraud Prevention API
# app.py — Community reporting + one-line LLM scam verdict for messages/links.

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional locally; in Docker, env vars come from env_file

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
import json
import os
import base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import logging
from typing import Optional

from utils.rag_utils import classify_message
from utils.link_cascade import LinkCascade

class TextScanRequest(BaseModel):
    text: str

class LinkScanRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    email: Optional[str] = None
    message: str


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("safe_backend")

# ============================
# Cascade Engine Setup
# ============================
link_cascade_engine = LinkCascade()

# ============================
# FastAPI App initialization
# ============================

# Read config from env
_CORS_ORIGINS  = os.environ.get("CORS_ORIGINS", "*")
_TRUSTED_HOSTS = os.environ.get("TRUSTED_HOSTS", "*")
_APP_ENV       = os.environ.get("APP_ENV", "development")
_IS_PROD       = _APP_ENV.lower() == "production"

# Rate limiter — uses client IP
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SAFE AI Backend — Digital Arrest Detector",
    description="Community scam registry, one-line LLM message verdicts, and link analysis.",
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# TrustedHost middleware (production only)
if _IS_PROD and _TRUSTED_HOSTS != "*":
    _hosts = [h.strip() for h in _TRUSTED_HOSTS.split(",") if h.strip()]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)

# CORS — enforce explicit origins in production
_cors_list = ["*"] if _CORS_ORIGINS == "*" else [o.strip() for o in _CORS_ORIGINS.split(",") if o.strip()]
if _IS_PROD and _CORS_ORIGINS == "*":
    logger.warning("CORS_ORIGINS=* in production is insecure. Set CORS_ORIGINS to your domain.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

@app.middleware("http")
async def sanitize_json_control_chars_middleware(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH") and "application/json" in request.headers.get("content-type", ""):
        try:
            body = await request.body()
            if body:
                try:
                    json.loads(body)
                except json.JSONDecodeError as exc:
                    logger.warning(f"Caught JSONDecodeError: {exc}")
                    try:
                        decoded = body.decode("utf-8", errors="replace")
                        parsed = json.loads(decoded, strict=False)
                        sanitized_body = json.dumps(parsed).encode("utf-8")
                        logger.info(f"Sanitized body from {len(body)} to {len(sanitized_body)} bytes")

                        request._body = sanitized_body
                        async def receive():
                            return {"type": "http.request", "body": sanitized_body, "more_body": False}
                        request._receive = receive
                    except Exception as e:
                        logger.error(f"Failed sanitizing: {e}")
        except Exception as e:
            logger.error(f"Middleware body read error: {e}")
    return await call_next(request)

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
                return api_scan_text(request, req_obj)
            elif path == "/api/scan/link":
                req_obj = LinkScanRequest(**parsed_data)
                return api_scan_link(req_obj)
        except Exception as fallback_exc:
            logger.error(f"Fallback parse failed: {fallback_exc}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()}
    )

@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok", "service": "safe-ai-backend"}

@app.get("/")
def read_root():
    return {"status": "ok", "app": "Safe AI Backend"}


# ========================================================
# Message scam verdict — single system prompt, one line + tag
# ========================================================
@app.post("/api/scan/text", tags=["Scan"], summary="Message scam-likelihood check")
@limiter.limit("30/minute")
def api_scan_text(request: Request, req: TextScanRequest):
    """
    Sends the message to the local LLM (Ollama) with a single system prompt
    and returns a one-line perspective plus a verdict tag:
    Safe, Likely Scam, or Scam Confirmed.
    """
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text content cannot be empty.")
    try:
        return classify_message(req.text)
    except RuntimeError as exc:
        logger.warning(f"Message classification unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Message analysis is temporarily unavailable. Please try again shortly.")


@app.post("/api/scan/link", tags=["Scan"], summary="Link/URL cascade scan")
def api_scan_link(req: LinkScanRequest):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL content cannot be empty.")
    res = link_cascade_engine.scan(req.url)
    res["rag"] = {
        "explanation": res.get("explanation"),
        "advice": res.get("actionSteps", [])
    }
    return res


# ========================================================
# Gmail / Feedback Integration
# ========================================================

# Scope required to manage labels and send emails
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# The email that will receive the feedback.
# Use "me" to send it to the authenticated Gmail account.
ADMIN_EMAIL = "me"

def get_gmail_service():
    """Handles OAuth2 authentication with Gmail."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)

            creds = flow.run_local_server(
                port=8001,
                access_type='offline',  # Ensures we get a refresh_token
                prompt='consent'        # Forces Google to ask for permission again, ensuring refresh_token is returned
            )

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds, cache_discovery=False)

def get_or_create_label(service, label_name):
    """Checks if a label exists, creates it if it doesn't, and returns the Label ID."""
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        # Check if label already exists
        for label in labels:
            if label['name'].lower() == label_name.lower():
                return label['id']

        # Create the label if it doesn't exist
        label_body = {
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show"
        }
        created_label = service.users().labels().create(userId='me', body=label_body).execute()
        return created_label['id']
    except HttpError as error:
        print(f'An error occurred managing labels: {error}')
        return None

@app.post("/api/feedback")
def receive_feedback(data: FeedbackRequest):
    """API endpoint to receive JSON and send the Gmail."""
    try:
        service = get_gmail_service()

        # Get the actual email address of the authenticated user to use in headers
        profile = service.users().getProfile(userId='me').execute()
        user_email = profile['emailAddress']

        # 1. Get or create the 'feedback' label
        label_id = get_or_create_label(service, 'feedback')
        if not label_id:
            logger.error("Could not create/find 'feedback' label.")
            raise HTTPException(status_code=500, detail="Failed to create or find 'feedback' label.")

        # 2. Format the email
        subject = f"Feedback | Safe"
        body = f"Submitted By: {data.email}\nMessage:\n{data.message}"

        mime_message = MIMEText(body)

        # CRITICAL FIX: Use the actual email address for headers
        mime_message['to'] = user_email
        mime_message['from'] = user_email
        mime_message['subject'] = subject

        raw_message = base64.urlsafe_b64encode(mime_message.as_bytes()).decode('utf-8')

        # 3. Send the email
        # Initially, apply ONLY the custom feedback label
        send_body = {
            "raw": raw_message,
            "labelIds": [label_id]
        }

        sent_message = service.users().messages().send(userId='me', body=send_body).execute()

        # 4. CRITICAL: Remove default folders/labels
        # When you send an email to yourself, Gmail automatically applies the
        # INBOX, SENT, and UNREAD labels. We must explicitly remove them so the
        # message lives ONLY in the 'feedback' label and nowhere else.
        service.users().messages().modify(
            userId='me',
            id=sent_message['id'],
            body={
                "removeLabelIds": ["INBOX", "SENT", "UNREAD"]
            }
        ).execute()

        return {
            "success": True,
            "message": "Feedback received and archived to 'feedback' label successfully.",
            "messageId": sent_message['id']
        }

    except HttpError as error:
        logger.error(f"Gmail API Error: {error}")
        logger.error(f"Error Content: {error.content}")
        raise HTTPException(status_code=500, detail=f"Gmail API error: {error}")
    except Exception as e:
        logger.error(f"General Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
