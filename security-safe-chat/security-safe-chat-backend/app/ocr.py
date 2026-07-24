"""
ocr.py — OCR.space integration for extracting text from images.

Supports three input modes:
  1. URL    — pass a public image URL directly to OCR.space
  2. Base64 — encode the image as base64 and send it inline
  3. File   — upload the raw image bytes as multipart form data

All modes return the extracted text as a plain string.
"""

from __future__ import annotations

import base64
import logging
from io import BytesIO

import httpx
from PIL import Image

from app.config import settings

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
_OCR_TIMEOUT = 30  # seconds
_MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB hard limit from OCR.space free tier

# ── Helpers ────────────────────────────────────────────────────────────────────

def _common_params() -> dict[str, str]:
    """Return parameters common to all OCR.space API calls."""
    return {
        "apikey": settings.ocr_space_api_key,
        "language": settings.ocr_language,
        "isOverlayRequired": "false",
        "detectOrientation": "true",
        "scale": "true",
        "OCREngine": "2",          # Engine 2 handles handwriting + mixed text better
    }


def _extract_text(response_json: dict) -> str:
    """Pull extracted text out of the OCR.space JSON response."""
    if response_json.get("IsErroredOnProcessing"):
        error_msg = response_json.get("ErrorMessage", ["Unknown OCR error"])
        if isinstance(error_msg, list):
            error_msg = "; ".join(error_msg)
        raise RuntimeError(f"OCR.space processing error: {error_msg}")

    parsed_results = response_json.get("ParsedResults") or []
    texts = [r.get("ParsedText", "") for r in parsed_results]
    combined = "\n".join(t.strip() for t in texts if t.strip())

    if not combined:
        raise RuntimeError("OCR returned no text from the image.")

    return combined


def _auto_compress(image_bytes: bytes, content_type: str) -> tuple[bytes, str]:
    """
    If image_bytes exceeds the OCR.space 5 MB limit, compress it with Pillow
    and return JPEG bytes.  Returns (bytes, content_type).
    """
    if len(image_bytes) <= _MAX_IMAGE_BYTES:
        return image_bytes, content_type

    logger.info("Image %d bytes > 5 MB limit — compressing to JPEG", len(image_bytes))
    img = Image.open(BytesIO(image_bytes)).convert("RGB")

    quality = 85
    while quality >= 30:
        buf = BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=True)
        data = buf.getvalue()
        if len(data) <= _MAX_IMAGE_BYTES:
            return data, "image/jpeg"
        quality -= 15

    raise ValueError("Image is too large to compress within the 5 MB OCR.space limit.")


# ── Public functions ───────────────────────────────────────────────────────────

async def ocr_from_url(image_url: str) -> str:
    """Extract text from a publicly accessible image URL."""
    params = _common_params()
    params["url"] = image_url

    async with httpx.AsyncClient(timeout=_OCR_TIMEOUT) as client:
        resp = await client.post(settings.ocr_space_api_url, data=params)
        resp.raise_for_status()

    logger.info("OCR.space URL response status: %s", resp.status_code)
    return _extract_text(resp.json())


async def ocr_from_base64(b64_string: str, content_type: str = "image/png") -> str:
    """
    Extract text from a base64-encoded image string.

    b64_string may include or omit the 'data:<mime>;base64,' prefix.
    """
    # Strip the data URI prefix if present
    if "base64," in b64_string:
        header, b64_string = b64_string.split("base64,", 1)
        ct_part = header.replace("data:", "").replace(";", "").strip()
        if ct_part:
            content_type = ct_part

    image_bytes = base64.b64decode(b64_string)
    image_bytes, content_type = _auto_compress(image_bytes, content_type)

    # Re-encode as base64 after optional compression
    compressed_b64 = base64.b64encode(image_bytes).decode()
    data_uri = f"data:{content_type};base64,{compressed_b64}"

    params = _common_params()
    params["base64Image"] = data_uri

    async with httpx.AsyncClient(timeout=_OCR_TIMEOUT) as client:
        resp = await client.post(settings.ocr_space_api_url, data=params)
        resp.raise_for_status()

    logger.info("OCR.space base64 response status: %s", resp.status_code)
    return _extract_text(resp.json())


async def ocr_from_bytes(image_bytes: bytes, filename: str = "upload.jpg", content_type: str = "image/jpeg") -> str:
    """
    Extract text from raw image bytes (e.g. from a multipart file upload).
    """
    image_bytes, content_type = _auto_compress(image_bytes, content_type)

    params = _common_params()

    async with httpx.AsyncClient(timeout=_OCR_TIMEOUT) as client:
        resp = await client.post(
            settings.ocr_space_api_url,
            data=params,
            files={"file": (filename, BytesIO(image_bytes), content_type)},
        )
        resp.raise_for_status()

    logger.info("OCR.space file upload response status: %s", resp.status_code)
    return _extract_text(resp.json())
