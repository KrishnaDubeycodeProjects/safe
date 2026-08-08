# Digital Arrest Detector - Multi-Channel Fraud Prevention API
# app.py (Phase 5 - Enhanced with ScoringEngine + SuggestionEngine + FastAPI Feedback)

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    joblib = None
    HAS_JOBLIB = False
import re
import wave
import json
try:
    import soundfile as sf
    HAS_SOUNDFILE = True
except ImportError:
    sf = None
    HAS_SOUNDFILE = False
try:
    import cv2
    HAS_CV2 = True
except ImportError:
    cv2 = None
    HAS_CV2 = False
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None
    HAS_NUMPY = False
import os
import base64
# REMOVED: from flask import Flask, request, jsonify
from email.mime.text import MIMEText
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

try:
    import tensorflow as tf
    HAS_TENSORFLOW = True
except Exception:
    tf = None
    HAS_TENSORFLOW = False

try:
    from vosk import Model, KaldiRecognizer
    HAS_VOSK = True
except ImportError:
    Model = None
    KaldiRecognizer = None
    HAS_VOSK = False
from pathlib import Path
try:
    from nltk.sentiment.vader import SentimentIntensityAnalyzer
    import nltk
    HAS_NLTK = True
except ImportError:
    SentimentIntensityAnalyzer = None
    nltk = None
    HAS_NLTK = False
import unicodedata
import logging
from typing import List, Optional

from utils.rag_utils import is_ollama_available, rag_verify_text, rag_refine_transcription, query_ollama
from utils.scoring_engine import ScoringEngine, quick_score
from utils.suggestion_engine import SuggestionEngine, quick_suggestions

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

if HAS_NLTK and nltk:
    nltk.download("vader_lexicon", quiet=True)
    sent_analyzer = SentimentIntensityAnalyzer()
else:
    logger.warning("⚠️ NLTK not installed; sentiment analysis disabled.")
    sent_analyzer = None

# ============================
# Paths
# ============================
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
TEXT_MODEL_PATH = MODEL_DIR / "text_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"
DEEPFAKE_MODEL_PATH = MODEL_DIR / "Deepfakes_detection_model.keras"
VOSK_BASE_PATH = MODEL_DIR

# ============================
# Load Models
# ============================
def load_text_models():
    if not HAS_JOBLIB:
        logger.warning("⚠️ joblib not installed; ML text models disabled.")
        return None, None
    try:
        text_model = joblib.load(TEXT_MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        return text_model, vectorizer
    except Exception as e:
        logger.error(f"❌ Failed to load text models: {e}")
        return None, None

def load_deepfake_model():
    if not HAS_TENSORFLOW or tf is None:
        logger.warning("⚠️ TensorFlow not available. Deepfake detection bypassed.")
        return None
    try:
        model = tf.keras.models.load_model(DEEPFAKE_MODEL_PATH, compile=False)
        return model
    except Exception as e:
        logger.error(f"❌ Failed to load deepfake model: {e}")
        return None

text_model, vectorizer = load_text_models()
deepfake_model = load_deepfake_model()

# ============================
# Cascade Engines Setup
# ============================
from utils.text_cascade import TextCascade
from utils.link_cascade import LinkCascade
from utils.image_cascade import ImageCascade

text_cascade_engine = TextCascade(text_model, vectorizer, sent_analyzer)
link_cascade_engine = LinkCascade()
image_cascade_engine = ImageCascade(text_cascade_engine, link_cascade_engine, deepfake_model)

# ============================
# NEW: Scoring & Suggestion Engines
# ============================
scoring_engine = ScoringEngine()
suggestion_engine = SuggestionEngine()

# ============================
# Risky keywords (unchanged from original)
# ============================
RISKY_KEYWORDS = {
    "otp": 3, "one time password": 3, "cvv": 3, "upi pin": 3, "password": 3,
    "aadhar": 3, "aadhaar": 3, "pin": 3, "atm pin": 3,
    "verify now": 2, "verify account": 2, "account verification": 2,
    "bank": 2, "bank account": 2, "suspend account": 2, "suspended": 2,
    "transaction": 2, "unauthorized transaction": 2, "transaction failed": 2,
    "payment": 2, "refund": 2, "transfer": 2, "fund transfer": 2,
    "credit card": 2, "debit card": 2,
    "lottery": 2, "winner": 2, "prize": 2, "claim": 2, "reward": 2,
    "urgent": 2, "immediately": 2, "act now": 1, "final notice": 1,
    "click here": 1, "click the link": 1, "download": 1,
    "kyc": 2, "complete kyc": 2, "digital arrest": 3, "cbi": 2.5,
    "blocked": 2, "suspended": 2, "security alert": 2,
    "pay now": 2, "payment link": 2, "collect request": 2,
    "share otp": 3, "share password": 3, "share pin": 3,
    "login": 2, "reset password": 2,
}

# ============================
# Hybrid Text Scam Detection (unchanged)
# ============================
def detect_message(text: str):
    if not text:
        return {
            "label": "✅ Likely Safe", "ml_prob": 0.0, "keyword_score": 0,
            "sentiment": {"compound": 0.0}, "combined_prob": 0.0,
            "keywords": [], "rag": None
        }

    text = unicodedata.normalize("NFKC", text)
    text_lower = text.lower()

    found_keywords = []
    keyword_score = 0
    for kw, weight in RISKY_KEYWORDS.items():
        pattern = rf'(?<!\w){re.escape(kw)}(?!\w)'
        if re.search(pattern, text_lower, flags=re.UNICODE):
            found_keywords.append(kw)
            keyword_score += weight

    if sent_analyzer is not None:
        sentiment = sent_analyzer.polarity_scores(text)
    else:
        sentiment = {"compound": 0.0, "neg": 0.0, "neu": 1.0, "pos": 0.0}
    neg_score = sentiment.get("neg", 0.0)
    compound = sentiment.get("compound", 0.0)
    sentiment_boost = 0.1 if neg_score > 0.3 or compound < -0.2 else 0.0

    ml_prob = 0.0
    if text_model and vectorizer:
        try:
            vec = vectorizer.transform([text])
            ml_prob = float(text_model.predict_proba(vec)[0][1])
        except Exception:
            ml_prob = 0.0

    KEYWORD_MULTIPLIER = 0.06
    base_combined = ml_prob + (keyword_score * KEYWORD_MULTIPLIER) + sentiment_boost
    base_combined = max(0.0, min(base_combined, 1.0))

    rag_result = None
    llm_prob = None
    try:
        if is_ollama_available():
            rag_result = rag_verify_text(text=text, ml_prob=ml_prob, keywords=found_keywords, sentiment=sentiment)
            if rag_result.get("risk_percent") is not None:
                try:
                    llm_prob = float(rag_result["risk_percent"]) / 100.0
                except Exception:
                    llm_prob = None
    except Exception:
        rag_result = None

    if llm_prob is not None:
        combined_prob = (llm_prob * 0.55) + (base_combined * 0.45)
    else:
        combined_prob = base_combined

    combined_prob = max(0.0, min(combined_prob, 1.0))
    label = "🚨 Likely Scam" if combined_prob > 0.35 else "✅ Likely Safe"

    return {
        "label": label, "ml_prob": ml_prob, "keyword_score": keyword_score,
        "sentiment": sentiment, "combined_prob": combined_prob,
        "keywords": found_keywords, "rag": rag_result
    }

# ============================
# Scam Categorization (unchanged)
# ============================
def categorize_scam(keywords, sentiment):
    keywords = [kw.lower() for kw in keywords]
    compound = sentiment.get("compound", 0)
    if any(k in keywords for k in ["lottery", "winner", "prize", "gift", "reward"]):
        return "🎁 Reward / Lottery Scam"
    elif any(k in keywords for k in ["bank", "account", "otp", "password", "verify", "transaction"]):
        return "🏦 Banking / Verification Scam"
    elif compound < -0.3:
        return "⚠️ Fear / Threat-Based Scam"
    else:
        return "🧠 Unknown / Generic Scam"

# ============================
# Speech-to-Text (unchanged)
# ============================
def transcribe_audio(audio_file, lang="en-in"):
    if not HAS_VOSK or not HAS_SOUNDFILE:
        logger.warning("⚠️ Vosk or soundfile not installed; audio transcription disabled.")
        return ""
    model_path = VOSK_BASE_PATH / f"vosk-model-small-{lang}"
    if not model_path.exists():
        logger.error(f"❌ Missing Vosk model: {model_path}")
        return ""
    try:
        vosk_model = Model(str(model_path))
    except Exception as e:
        logger.error(f"❌ Failed to load Vosk model: {e}")
        return ""
    try:
        data, samplerate = sf.read(audio_file)
    except Exception as e:
        logger.error(f"❌ Could not read audio file: {e}")
        return ""
    if len(data.shape) > 1:
        data = data.mean(axis=1)
    sf.write("temp.wav", data, samplerate)
    result_text = ""
    try:
        with wave.open("temp.wav", "rb") as wf:
            rec = KaldiRecognizer(vosk_model, wf.getframerate())
            rec.SetWords(False)
            while True:
                chunk = wf.readframes(4000)
                if len(chunk) == 0:
                    break
                if rec.AcceptWaveform(chunk):
                    res = json.loads(rec.Result())
                    result_text += " " + res.get("text", "")
            res = json.loads(rec.FinalResult())
            result_text += " " + res.get("text", "")
    except Exception as e:
        logger.warning(f"Vosk transcription failed: {e}")
    try:
        if Path("temp.wav").exists():
            Path("temp.wav").unlink()
    except Exception:
        pass
    result_text = result_text.strip()
    if not result_text:
        return ""
    if is_ollama_available():
        try:
            refine = rag_refine_transcription(result_text)
            return refine.get("cleaned_text") or result_text
        except Exception:
            return result_text
    return result_text



# ============================
# NEW: Build Enhanced Image Response
# ============================
def build_enhanced_image_response(cascade_result: dict) -> dict:
    """
    Takes the raw image cascade result and enriches it with
    ScoringEngine (score out of 10) and SuggestionEngine (contextual advice).
    """
    sub_results = cascade_result.get("sub_results", {})
    meta = cascade_result.get("meta", {})

    # --- Extract sub-results for the ScoringEngine ---
    ocr_text_result = sub_results.get("ocr_text_result")
    url_results = sub_results.get("url_results", [])
    extracted_urls = meta.get("extracted_urls", [])

    # Aggregate link results: use the worst (highest risk) URL result
    worst_link_result = None
    if url_results:
        worst_link_result = max(url_results, key=lambda x: x.get("result", {}).get("combined_prob", 0.0)).get("result")

    # The image cascade result itself serves as the image manipulation result
    image_manipulation_result = cascade_result

    # --- Run ScoringEngine ---
    score_report = scoring_engine.format_detailed_report(
        scoring_engine.calculate_score(
            ocr_text_result=ocr_text_result,
            link_analysis_result=worst_link_result,
            image_manipulation_result=image_manipulation_result,
            extracted_urls_count=len(extracted_urls)
        )
    )

    # --- Run SuggestionEngine ---
    suggestions = suggestion_engine.generate_suggestions(score_report)

    # --- Build the final enhanced response ---
    response = {
        # Original cascade fields (backward compatibility)
        "label": cascade_result.get("label", "✅ Likely Safe"),
        "score": cascade_result.get("score", 0.9),
        "combined_prob": cascade_result.get("combined_prob", 0.0),
        "explanation": cascade_result.get("explanation", ""),
        "actionSteps": cascade_result.get("actionSteps", []),
        "cascade_steps": cascade_result.get("cascade_steps", []),

        # NEW: Enhanced scoring (score out of 10)
        "scam_score": score_report.get("scam_score", 0.0),
        "max_score": score_report.get("max_score", 10.0),
        "risk_level": score_report.get("risk_level", "SAFE"),
        "score_label": score_report.get("label", "✅ SAFE"),

        # NEW: Detailed breakdown
        "breakdown": score_report.get("breakdown", {}),
        "summary": score_report.get("summary", {}),

        # NEW: Contextual suggestions
        "suggestions": suggestions,

        # NEW: Extracted data from image
        "extracted_data": {
            "ocr_text": meta.get("ocr_text", ""),
            "urls": meta.get("extracted_urls", []),
            "phones": meta.get("extracted_phones", []),
            "emails": meta.get("extracted_emails", []),
            "qr_content": meta.get("qr_content", ""),
            "urls_analyzed": meta.get("url_analysis_count", 0)
        },

        # NEW: Individual URL analysis results
        "url_analysis": [
            {
                "url": item.get("url", ""),
                "label": item.get("result", {}).get("label", ""),
                "combined_prob": item.get("result", {}).get("combined_prob", 0.0),
                "explanation": item.get("result", {}).get("explanation", "")
            }
            for item in url_results
        ],

        # Backward compatibility
        "meta": meta,
        "rag": {
            "explanation": cascade_result.get("explanation"),
            "advice": cascade_result.get("actionSteps", [])
        }
    }

    return response

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
    description="Community reporting, scam detection cascade, and digital arrest detection.",
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

from routes.community_routes import router as community_router
app.include_router(community_router)

@app.exception_handler(RequestValidationError)
async def handle_request_validation_error(request: Request, exc: RequestValidationError):
    print(">>> EXCEPTION HANDLER CALLED!", exc.errors())
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

@app.post("/api/scan/text")
@limiter.limit("30/minute")
def api_scan_text(request: Request, req: TextScanRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text content cannot be empty.")
    res = text_cascade_engine.scan(req.text)
    res["ml_prob"] = res.get("combined_prob", 0.0)
    res["keywords"] = []
    res["rag"] = {
        "explanation": res.get("explanation"),
        "advice": res.get("actionSteps", [])
    }
    return res

@app.post("/api/scan/link")
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
# ENHANCED: Image Scan Endpoint with Score/10 + Suggestions
# ========================================================
@app.post("/api/scan/image")
async def api_scan_image(file: UploadFile = File(...)):
    suffix = Path(file.filename).suffix or ".png"
    temp_path = f"temp_uploaded_image{suffix}"
    try:
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)

        # Step 1: Run the full image cascade (OCR + QR + Hash + CV + Deepfake + URL analysis)
        cascade_result = image_cascade_engine.scan(temp_path)

        # Step 2: Enrich with ScoringEngine + SuggestionEngine
        enhanced_response = build_enhanced_image_response(cascade_result)

        return enhanced_response

    except Exception as e:
        logger.error(f"Error in image analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass



# ========================================================
# Gmail / Feedback Integration (Converted to FastAPI)
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
            
            # --- CHANGES START HERE ---
            creds = flow.run_local_server(
                port=8001, 
                access_type='offline',  # Ensures we get a refresh_token
                prompt='consent'        # Forces Google to ask for permission again, ensuring refresh_token is returned
            )
            # --- CHANGES END HERE ---
            
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