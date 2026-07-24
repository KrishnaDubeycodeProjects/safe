"""
utils/image_cascade.py — Image scam analysis pipeline.

Replaces the original Digital-arrest-detector image_cascade that used:
  • pytesseract / local OCR          → OCR.space API (httpx, async)
  • OpenCV deepfake model (keras)     → removed (no model files required)
  • QR code scanning via pyzbar       → retained (optional, graceful skip)

Required only:
  Pillow, httpx (both already in requirements.txt)

Optional:
  pyzbar  — QR code reading (graceful skip if not installed)
  opencv-python — perceptual hash / manipulation detection (graceful skip)
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
import zlib
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("safe_backend.image_cascade")

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False
    logger.info("opencv-python not installed — CV manipulation check skipped.")

try:
    from pyzbar import pyzbar
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False
    logger.info("pyzbar not installed — QR code scanning skipped.")

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ── Known scam image hashes (SHA-256 of known scam screenshots) ──────────────
KNOWN_SCAM_HASHES: set[str] = set()   # populate from a DB/file in production


class ImageCascade:
    """
    Multi-layer image analysis pipeline.

    Layer 0: SHA-256 hash blocklist check
    Layer 1: QR code extraction + link_cascade scan
    Layer 2: OCR text extraction (OCR.space) + text_cascade scan
    Layer 3: CV-based manipulation detection (optional — requires opencv)
    Layer 4: Deepfake model — REMOVED (no model files; slot reserved for future)
    """

    def __init__(self, text_cascade, link_cascade, ocr_module=None):
        self.text_cascade = text_cascade
        self.link_cascade = link_cascade
        self.ocr = ocr_module   # app.ocr module (async)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def calculate_sha256(self, image_path: str) -> str:
        h = hashlib.sha256()
        with open(image_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def calculate_dhash(self, img) -> str:
        """Perceptual difference-hash for similarity matching (requires cv2)."""
        if not HAS_CV2:
            return ""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        resized = cv2.resize(gray, (9, 8))
        diff = resized[:, 1:] > resized[:, :-1]
        return "".join(str(int(b)) for b in diff.flatten())

    def extract_urls_from_text(self, text: str) -> List[str]:
        return re.findall(r"https?://[^\s,\"'>]+|www\.[^\s,\"'>]+", text)

    def extract_phone_numbers(self, text: str) -> List[str]:
        return re.findall(r"(?:\+91[-\s]?|0)?[6-9]\d{9}", text)

    def extract_emails(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)

    # ── Layer 2: OCR via OCR.space ────────────────────────────────────────────

    async def _ocr_text(self, image_path: str) -> str:
        """Extract text using OCR.space. Falls back to empty string on error."""
        if not self.ocr:
            return ""
        try:
            with open(image_path, "rb") as f:
                image_bytes = f.read()
            suffix = Path(image_path).suffix.lstrip(".").lower() or "jpg"
            ct_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                      "webp": "image/webp", "bmp": "image/bmp", "tiff": "image/tiff"}
            content_type = ct_map.get(suffix, "image/jpeg")
            return await self.ocr.ocr_from_bytes(
                image_bytes, filename=Path(image_path).name, content_type=content_type
            )
        except Exception as exc:
            logger.warning("OCR.space failed: %s", exc)
            return ""

    # ── Layer 1: QR code scanning ──────────────────────────────────────────────

    def _scan_qr(self, image_path: str) -> str:
        if not HAS_PYZBAR or not HAS_PIL:
            return ""
        try:
            img = Image.open(image_path)
            codes = pyzbar.decode(img)
            if codes:
                return codes[0].data.decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.debug("QR scan error: %s", exc)
        return ""

    # ── Layer 3: CV manipulation ──────────────────────────────────────────────

    def analyze_cv_manipulations(self, img) -> tuple[float, list[str]]:
        if not HAS_CV2 or img is None:
            return 0.0, []
        reasons: list[str] = []
        score = 0.0
        try:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150)
            edge_density = float(edges.sum()) / (edges.size + 1)
            if edge_density > 0.15:
                score += 0.3
                reasons.append("High edge density — possible text overlay or digital editing.")
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            if len(contours) > 500:
                score += 0.2
                reasons.append(f"High contour count ({len(contours)}) — possible digital composite.")
        except Exception as exc:
            logger.debug("CV analysis error: %s", exc)
        return min(score, 1.0), reasons

    # ── Main scan ──────────────────────────────────────────────────────────────

    async def scan_async(self, image_path: str) -> dict:
        cascade_steps: list[str] = []
        meta: dict = {}
        sub_results: dict = {}

        # Layer 0 — Hash check
        cascade_steps.append("Layer 0: SHA-256 hash blocklist check")
        sha = self.calculate_sha256(image_path)
        meta["sha256"] = sha
        if sha in KNOWN_SCAM_HASHES:
            return {
                "label": "🚨 Likely Scam",
                "score": 0.01,
                "combined_prob": 0.99,
                "explanation": "Image matched known scam hash blocklist.",
                "actionSteps": ["Do not respond to this image.", "Report it immediately."],
                "cascade_steps": cascade_steps,
                "sub_results": sub_results,
                "meta": meta,
            }

        # Layer 1 — QR
        cascade_steps.append("Layer 1: QR code extraction")
        qr_content = self._scan_qr(image_path)
        meta["qr_content"] = qr_content
        qr_result = None
        if qr_content:
            try:
                qr_result = self.link_cascade.scan(qr_content)
                sub_results["qr_result"] = qr_result
            except Exception as exc:
                logger.warning("QR link scan failed: %s", exc)

        # Layer 2 — OCR + text scan
        cascade_steps.append("Layer 2: OCR text extraction (OCR.space)")
        ocr_text = await self._ocr_text(image_path)
        meta["ocr_text"] = ocr_text

        urls = self.extract_urls_from_text(ocr_text)
        phones = self.extract_phone_numbers(ocr_text)
        emails = self.extract_emails(ocr_text)
        meta["extracted_urls"] = urls
        meta["extracted_phones"] = phones
        meta["extracted_emails"] = emails

        ocr_text_result = None
        url_results = []

        if ocr_text.strip():
            cascade_steps.append("Layer 2a: Text cascade on OCR content")
            try:
                ocr_text_result = await self.text_cascade.scan_async(ocr_text)
                sub_results["ocr_text_result"] = ocr_text_result
            except Exception as exc:
                logger.warning("Text cascade on OCR failed: %s", exc)

            if urls:
                cascade_steps.append(f"Layer 2b: Link cascade on {len(urls)} extracted URL(s)")
                meta["url_analysis_count"] = 0
                for url in urls[:3]:   # cap at 3 to keep latency reasonable
                    try:
                        url_res = self.link_cascade.scan(url)
                        url_results.append({"url": url, "result": url_res})
                        meta["url_analysis_count"] += 1
                    except Exception as exc:
                        logger.warning("Link scan failed for %s: %s", url, exc)
                sub_results["url_results"] = url_results

        # Layer 3 — CV manipulation
        cascade_steps.append("Layer 3: CV image manipulation analysis")
        cv_score = 0.0
        cv_reasons: list[str] = []
        if HAS_CV2:
            try:
                img = cv2.imread(image_path)
                if img is not None:
                    cv_score, cv_reasons = self.analyze_cv_manipulations(img)
            except Exception as exc:
                logger.debug("CV load error: %s", exc)
        sub_results["cv_manipulation"] = {"score": cv_score, "reasons": cv_reasons}

        # ── Aggregate ─────────────────────────────────────────────────────────
        text_prob = (ocr_text_result or {}).get("combined_prob", 0.0)
        worst_link_prob = max(
            ((r.get("result") or {}).get("combined_prob", 0.0) for r in url_results),
            default=0.0
        )
        qr_prob = (qr_result or {}).get("combined_prob", 0.0)

        combined_prob = max(text_prob * 0.5, worst_link_prob * 0.4, cv_score * 0.2, qr_prob * 0.4)
        label = "🚨 Likely Scam" if combined_prob > 0.4 else "✅ Likely Safe"

        explanation_parts = []
        if text_prob > 0.3:
            explanation_parts.append(f"OCR text shows {int(text_prob*100)}% scam probability.")
        if worst_link_prob > 0.3:
            explanation_parts.append(f"Extracted URL shows {int(worst_link_prob*100)}% risk.")
        if cv_score > 0.2:
            explanation_parts.append("; ".join(cv_reasons))
        if qr_prob > 0.3:
            explanation_parts.append("QR code points to a suspicious URL.")
        if not explanation_parts:
            explanation_parts.append("No significant scam indicators found in image.")

        return {
            "label": label,
            "score": max(0.05, 1.0 - combined_prob),
            "combined_prob": round(combined_prob, 4),
            "explanation": " ".join(explanation_parts),
            "actionSteps": _action_steps(combined_prob),
            "cascade_steps": cascade_steps,
            "sub_results": sub_results,
            "meta": meta,
        }

    def scan(self, image_path: str) -> dict:
        """Synchronous wrapper around scan_async."""
        import asyncio, concurrent.futures
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, self.scan_async(image_path)).result(timeout=60)
            return loop.run_until_complete(self.scan_async(image_path))
        except Exception as exc:
            logger.exception("ImageCascade.scan error: %s", exc)
            return {
                "label": "✅ Likely Safe",
                "score": 0.9,
                "combined_prob": 0.1,
                "explanation": "Image analysis error — defaulted to safe.",
                "actionSteps": ["Try uploading the image again."],
                "cascade_steps": ["Error fallback"],
                "sub_results": {},
                "meta": {},
            }


def _action_steps(prob: float) -> list[str]:
    if prob > 0.7:
        return [
            "Do not click any links or QR codes in this image.",
            "Block and report the sender immediately.",
            "Call 1930 (Cyber Crime Helpline) if you have already interacted.",
        ]
    elif prob > 0.4:
        return [
            "Verify with the official organization before taking any action.",
            "Do not share personal or financial information.",
        ]
    return ["No immediate action required.", "Stay vigilant."]
