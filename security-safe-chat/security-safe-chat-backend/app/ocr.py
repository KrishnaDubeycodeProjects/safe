"""
ocr.py — OCR.space integration for extracting text from images.
Extracts visible text from screenshots, documents, photos, payment receipts, etc.
"""

from __future__ import annotations

import base64
import logging
from io import BytesIO

import httpx
from PIL import Image

from app.config import settings

logger = logging.getLogger(__name__)

_OCR_TIMEOUT = 25  # seconds
_MAX_IMAGE_BYTES = 1024 * 1024  # 1 MB threshold for fast OCR upload


def _common_params() -> dict[str, str]:
    return {
        "apikey": settings.ocr_space_api_key or "K84422890888957",
        "language": settings.ocr_language or "eng",
        "isOverlayRequired": "false",
        "detectOrientation": "true",
        "scale": "true",
        "OCREngine": "2",
    }


def _extract_text(response_json: dict) -> str:
    if response_json.get("IsErroredOnProcessing"):
        error_msg = response_json.get("ErrorMessage", ["Unknown OCR error"])
        if isinstance(error_msg, list):
            error_msg = "; ".join(error_msg)
        logger.warning("OCR processing warning/error: %s", error_msg)
        return ""

    parsed_results = response_json.get("ParsedResults") or []
    texts = [r.get("ParsedText", "") for r in parsed_results]
    combined = "\n".join(t.strip() for t in texts if t.strip())
    return combined.strip()


def _auto_compress(image_bytes: bytes, content_type: str) -> tuple[bytes, str]:
    """If image exceeds 1MB, compress to JPEG for fast OCR."""
    if len(image_bytes) <= _MAX_IMAGE_BYTES:
        return image_bytes, content_type

    try:
        img = Image.open(BytesIO(image_bytes)).convert("RGB")
        # Resize if very large resolution
        max_dim = 1600
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)

        buf = BytesIO()
        img.save(buf, format="JPEG", quality=80, optimize=True)
        return buf.getvalue(), "image/jpeg"
    except Exception as exc:
        logger.warning("Auto-compression failed, using raw bytes: %s", exc)
        return image_bytes, content_type


async def ocr_from_bytes(image_bytes: bytes, filename: str = "upload.jpg", content_type: str = "image/jpeg") -> str:
    """Extract text from raw image bytes."""
    try:
        image_bytes, content_type = _auto_compress(image_bytes, content_type)
        params = _common_params()
        url = settings.ocr_space_api_url or "https://api.ocr.space/parse/image"

        async with httpx.AsyncClient(timeout=_OCR_TIMEOUT) as client:
            resp = await client.post(
                url,
                data=params,
                files={"file": (filename, BytesIO(image_bytes), content_type)},
            )
            resp.raise_for_status()

        return _extract_text(resp.json())
    except Exception as exc:
        logger.warning("OCR from bytes failed gracefully: %s", exc)
        return ""


async def ocr_from_base64(b64_string: str) -> str:
    """Extract text from a base64 encoded image."""
    try:
        content_type = "image/jpeg"
        if "base64," in b64_string:
            header, b64_string = b64_string.split("base64,", 1)
            ct_part = header.replace("data:", "").replace(";", "").strip()
            if ct_part:
                content_type = ct_part

        image_bytes = base64.b64decode(b64_string)
        return await ocr_from_bytes(image_bytes, "image.jpg", content_type)
    except Exception as exc:
        logger.warning("OCR from base64 failed gracefully: %s", exc)
        return ""
