"""
utils/text_cascade.py — Tiered text scam detection pipeline.

Layers
──────
Layer 0  Preprocessing & normalization
Layer 1  Rule-based keyword heuristics (fast, no deps)
Layer 2  AWS Bedrock (Claude 3 Haiku) via the taxonomy parser  ← replaces Ollama + sklearn
Fallback Aggregate layer-1 score if Bedrock is unavailable

All heavy ML deps (joblib, sklearn, vosk, tensorflow) have been removed.
"""

from __future__ import annotations

import asyncio
import logging
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("safe_backend.text_cascade")

# ── Whitelist ─────────────────────────────────────────────────────────────────
WHITELIST_PATTERNS = [
    r"^your OTP for.*transaction is \d{4,8}$",
]

# ── Scam keyword weights ───────────────────────────────────────────────────────
SCAM_KEYWORDS: Dict[str, float] = {
    "otp": 3.0, "one-time password": 3.0, "cvv": 3.0, "upi pin": 3.0,
    "aadhaar": 2.5, "aadhar": 2.5,
    "blocked": 2.0, "suspended": 2.0, "kyc": 2.5,
    "lucky draw": 3.0, "lottery": 3.0, "winner": 2.5, "won": 2.0,
    "digital arrest": 3.0, "cbi": 2.5, "customs": 2.0, "drugs": 1.5,
    "refund": 2.0, "click here": 1.5, "verify": 1.5,
    "urgent": 2.0, "immediate": 2.0, "seized": 2.0,
    "electricity bill": 2.5, "disconnect": 2.0,
    "share otp": 3.0, "share password": 3.0, "share pin": 3.0,
    "bank account": 2.0, "pay now": 2.0, "payment link": 2.0,
    "security alert": 2.0, "login": 1.5, "reset password": 2.0,
}


class TextCascade:
    """
    Pure Python, no-ML text scam cascade.

    layer_1_only=True forces the scan to stop after heuristics — useful when
    Bedrock is not configured or you need a synchronous fast path.
    """

    def __init__(self, bedrock_client=None, parser=None):
        """
        Parameters
        ----------
        bedrock_client : module | None
            Pass the app.bedrock module so we can call classify_text().
            If None, cascade falls back to heuristics only.
        parser : module | None
            Pass the app.parser module so we can call parse().
        """
        self.bedrock = bedrock_client
        self.parser = parser

    # ── Layer 0 ───────────────────────────────────────────────────────────────

    def normalize_text(self, text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    # ── Layer 1 ───────────────────────────────────────────────────────────────

    def match_rules(self, text: str) -> Tuple[float, Optional[str], List[str]]:
        text_lower = text.lower()

        for pattern in WHITELIST_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return 0.0, "whitelisted", ["Message matches trusted whitelist pattern."]

        found: List[str] = []
        score = 0.0
        for kw, weight in SCAM_KEYWORDS.items():
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                found.append(kw)
                score += weight

        has_link = 2.0 if re.search(r"https?://|www\.", text_lower) else 0.0
        has_phone = 1.5 if re.search(r"\b\d{10}\b|\+\d{12}", text_lower) else 0.0
        total = score + has_link + has_phone

        if total >= 6.0:
            reasons = [f"High-risk terms found: {', '.join(found)}."]
            if has_link:
                reasons.append("Contains a web link.")
            if has_phone:
                reasons.append("Contains a phone number.")
            return 0.95, "high_heuristic", reasons

        return min(total / 10.0, 1.0), None, found

    # ── Layer 2 — Bedrock ─────────────────────────────────────────────────────

    async def _bedrock_classify(self, text: str) -> Optional[dict]:
        """Call Bedrock and parse the response. Returns parser dict or None."""
        if not self.bedrock or not self.parser:
            return None
        try:
            raw = await self.bedrock.classify_text(text)
            return self.parser.parse(raw)
        except Exception as exc:
            logger.warning("Bedrock classify failed: %s", exc)
            return None

    # ── Public sync/async scan ────────────────────────────────────────────────

    async def scan_async(self, raw_text: str) -> dict:
        steps: List[str] = []

        steps.append("Layer 0: Preprocessing & Normalization")
        clean = self.normalize_text(raw_text)

        steps.append("Layer 1: Rule-Based Heuristics")
        rule_prob, rule_flag, rule_details = self.match_rules(clean)

        if rule_flag == "whitelisted":
            return {
                "label": "✅ Likely Safe",
                "score": 1.0,
                "combined_prob": 0.05,
                "explanation": "Verified safe via automated whitelist check.",
                "actionSteps": ["This matches a trusted system communication.", "Stay vigilant and verify caller identity."],
                "cascade_steps": steps,
                "bedrock_result": None,
            }

        if rule_prob >= 0.9:
            logger.info("Text scan stopped at Layer 1 (high-confidence heuristics)")
            return {
                "label": "🚨 Likely Scam",
                "score": 0.05,
                "combined_prob": rule_prob,
                "explanation": f"Heuristics flagged suspicious elements: {'; '.join(rule_details)}",
                "actionSteps": ["Do not share OTPs, card details, or click links.", "Block and report immediately."],
                "cascade_steps": steps,
                "bedrock_result": None,
            }

        steps.append("Layer 2: AWS Bedrock (Claude 3 Haiku) Taxonomy Classification")
        bedrock_parsed = await self._bedrock_classify(clean)

        if bedrock_parsed:
            case = bedrock_parsed.get("case", 5)
            is_scam = bedrock_parsed.get("is_scam", False)
            score_val = bedrock_parsed.get("score", 0)

            if case in (1, 2, 3):
                combined_prob = max(rule_prob, score_val / 100.0 if score_val else 0.85)
                label = "🚨 Likely Scam"
            elif case == 4:
                combined_prob = max(rule_prob, 0.4)
                label = "⚠️ Uncertain"
            else:  # case 5 — err/safe
                combined_prob = min(rule_prob, 0.2)
                label = "✅ Likely Safe"

            match = (bedrock_parsed.get("matches") or [{}])[0]
            return {
                "label": label,
                "score": max(0.05, 1.0 - combined_prob),
                "combined_prob": round(combined_prob, 4),
                "explanation": match.get("detection_message") or bedrock_parsed.get("detection_message") or "AI classification completed.",
                "actionSteps": match.get("red_flags", []) or ["Exercise caution with this message."],
                "cascade_steps": steps,
                "bedrock_result": bedrock_parsed,
            }

        # Fallback aggregator
        steps.append("Fallback: Heuristic Aggregator")
        label = "🚨 Likely Scam" if rule_prob > 0.4 else "✅ Likely Safe"
        return {
            "label": label,
            "score": max(0.1, 1.0 - rule_prob),
            "combined_prob": round(rule_prob, 4),
            "explanation": "Combined heuristic check. Bedrock unavailable.",
            "actionSteps": ["Always verify with official sources.", "Do not click links from unknown senders."],
            "cascade_steps": steps,
            "bedrock_result": None,
        }

    def scan(self, raw_text: str) -> dict:
        """Synchronous wrapper — runs the async pipeline in the current event loop or a new one."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside async context (FastAPI): schedule as coroutine and wait
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.scan_async(raw_text))
                    return future.result(timeout=30)
            else:
                return loop.run_until_complete(self.scan_async(raw_text))
        except Exception as exc:
            logger.exception("TextCascade.scan error: %s", exc)
            # Safe fallback
            rule_prob, _, rule_details = self.match_rules(raw_text)
            label = "🚨 Likely Scam" if rule_prob > 0.4 else "✅ Likely Safe"
            return {
                "label": label, "score": 1.0 - rule_prob,
                "combined_prob": rule_prob,
                "explanation": "Heuristic fallback (error in full pipeline).",
                "actionSteps": ["Verify this message manually."],
                "cascade_steps": ["Error fallback"],
                "bedrock_result": None,
            }
