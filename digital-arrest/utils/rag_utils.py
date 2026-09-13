# utils/rag_utils.py
import requests
import json
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

OLLAMA_API = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "phi3:mini"


def is_ollama_available(timeout: float = 2.0) -> bool:
    try:
        r = requests.get("http://localhost:11434", timeout=timeout)
        return r.status_code in (200, 404)
    except Exception:
        return False


def query_ollama(prompt: str,
                 model: str = DEFAULT_MODEL,
                 max_tokens: int = 512,
                 temperature: float = 0.0,
                 stop: Optional[list] = None,
                 timeout: float = 120.0) -> Dict:
    """
    Handle Ollama's streaming JSON responses line-by-line.
    Concatenate the 'response' fields until done:true.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": True
    }
    if stop:
        payload["stop"] = stop

    headers = {"Content-Type": "application/json"}
    try:
        with requests.post(OLLAMA_API, headers=headers, json=payload, stream=True, timeout=timeout) as resp:
            resp.raise_for_status()
            text_output = ""
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    j = json.loads(line)
                    if "response" in j:
                        text_output += j["response"]
                    if j.get("done"):
                        break
                except Exception:
                    continue
            return {"text": text_output}
    except Exception as e:
        logger.exception("Ollama stream query failed: %s", e)
        raise


# ── Message scam verdict (single system prompt, one line + tag) ──────────────

MESSAGE_SYSTEM_PROMPT = """You are a scam-detection assistant. You will receive a raw message (SMS, email, WhatsApp, or chat text). Decide whether it shows signs of being a scam.

Respond with EXACTLY one line in this format, nothing else — no markdown, no extra text, never repeat the input:

TAG|one-line perspective

TAG must be exactly one of:
- SAFE            the message shows no signs of being a scam
- LIKELY_SCAM     the message has some suspicious signs but you are not fully certain
- SCAM_CONFIRMED  the message clearly matches a known scam pattern (e.g. OTP/PIN/CVV requests, fake arrest or police threats, lottery/prize wins, urgent payment demands, impersonation of banks/government/customs, KYC-update pressure)

The one-line perspective is a single plain-English sentence (max ~20 words) giving the reader's-eye-view reason for the verdict.

Example: SAFE|This reads like a normal message between friends with no request for money or personal information.
Example: LIKELY_SCAM|This message pressures you to act urgently and points to an unfamiliar link.
Example: SCAM_CONFIRMED|This demands your OTP and threatens arrest, a classic digital-arrest scam pattern."""

_VALID_TAGS = {"SAFE", "LIKELY_SCAM", "SCAM_CONFIRMED"}
_TAG_DISPLAY = {"SAFE": "Safe", "LIKELY_SCAM": "Likely Scam", "SCAM_CONFIRMED": "Scam Confirmed"}


def _parse_verdict(raw: str) -> Dict:
    """Parse the strict 'TAG|one-line perspective' output into a display-ready dict."""
    raw = (raw or "").strip()
    tag_part, sep, message_part = raw.partition("|")
    tag = tag_part.strip().upper()
    message = message_part.strip() if sep else raw

    if tag not in _VALID_TAGS:
        logger.warning("Unrecognized verdict tag in model output: %r", raw)
        return {"tag": "Likely Scam", "message": message or "Could not confidently classify this message — treat it with caution."}

    return {"tag": _TAG_DISPLAY[tag], "message": message or "No further detail provided."}


def classify_message(text: str, model: str = DEFAULT_MODEL) -> Dict:
    """
    Sends a message to the local Ollama LLM with the scam-detection system
    prompt and returns a display-ready verdict:

        {"tag": "Safe" | "Likely Scam" | "Scam Confirmed", "message": "<one-line perspective>"}

    Raises RuntimeError if Ollama is unavailable or the call fails.
    """
    if not is_ollama_available():
        raise RuntimeError("Ollama is not available.")

    prompt = f'{MESSAGE_SYSTEM_PROMPT}\n\nMessage:\n"""{text}"""\n\nYour one-line answer:'
    try:
        resp = query_ollama(prompt, model=model, max_tokens=80, temperature=0.0)
        raw = resp.get("text", "") if isinstance(resp, dict) else str(resp)
        return _parse_verdict(raw)
    except Exception as e:
        logger.exception("Message classification failed: %s", e)
        raise RuntimeError(f"Ollama classify failed: {e}") from e