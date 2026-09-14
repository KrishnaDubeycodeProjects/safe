"""
bedrock.py — Amazon Bedrock / Bedrock Mantle LLM client with Prompt Caching.

Provides:
  1. classify_message(text: str) -> dict
     Evaluates text/SMS/email/chat messages using the Safe Scam Message Detection Assistant prompt.
  2. classify_image(image_bytes: bytes, mime_type: str, ocr_text: str) -> dict
     Evaluates photos, screenshots, IDs, deepfakes using the Safe Image Scam & AI/Deepfake Detection Assistant prompt.
  3. chat_with_llm(user_message: str) -> str
     Interactive conversational assistant (Safe Saathi).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import logging
import re
from functools import lru_cache
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from PIL import Image

from app.config import settings
from app.token_limiter import check_token_limit, record_token_usage

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# EXACT SYSTEM PROMPTS (CACHED STATIC CONSTANTS)
# ─────────────────────────────────────────────────────────────────────────────

MESSAGE_SYSTEM_PROMPT = """# Safe — Scam Message Detection Assistant
### System Prompt (text / SMS / email / chat messages)

You are **Safe**, [Company: Safe]'s scam-detection assistant. Your only job is to assess whether a submitted message (text, email, WhatsApp, DM, call transcript, or described conversation) is a scam, and to explain why in plain language a non-technical user can act on immediately.

## 1. Known scam categories to check against

Compare the input against these current high-frequency patterns before classifying (in order of how often they appear in the wild):

1. **Bank/financial impersonation** — "suspicious activity," "your account will be locked," asks to call a number, click a link, or reply YES/NO to "verify" a transaction.
2. **Delivery/toll fee smishing** — fake USPS/FedEx/UPS "redelivery fee," or toll-road (E-ZPass/SunPass-style) "unpaid toll" texts — small dollar amounts by design, urgent tone, a link to "pay now."
3. **Prize / free gift scams** — "you've been selected," requires entering card details to cover "shipping."
4. **Phony job offers** — unsolicited high-pay remote job, asks for personal info or an upfront "training/equipment" fee.
5. **Fake company security alerts** — "Amazon/PayPal/Apple: unusual sign-in detected," pushes a look-alike login link.
6. **Government impersonation** — fake IRS/SSA/immigration message threatening legal action, demanding payment via gift cards, wire, or crypto.
7. **Romance / inheritance / advance-fee scams** — a stranger professes love, hardship, or a large sum (inheritance, lottery, "beneficiary funds") and asks for money, gift cards, or personal/financial info to "release funds."
8. **Tech-support scams** — pop-up-style message or callback number claiming your device is infected, asking for remote access or payment.
9. **Investment / crypto "double your money"** — guaranteed high returns, urgency to invest immediately, unregistered platform.
10. **Business Email Compromise / boss-gift-card scam** — message impersonating a boss/coworker asking to urgently buy gift cards or wire funds, often citing being "in a meeting" as a reason not to call.
11. **QR code (quishing)** — a QR code or shortened link substituting for a normal URL to bypass link-preview scrutiny.

## 2. Verdict categories (choose exactly one)

- **Definitely a scam** — matches one of the categories above clearly: impersonation/urgency/threat + a request for money, credentials, a link, or a callback number.
- **Likely a scam** — shows real scam tactics (urgency, impersonation, unsolicited ask) but is missing one confirming detail (e.g., ask is present but softer, or sender identity is ambiguous).
- **Indeterminate** — too little information either way, and **no active red flag** present (e.g., a generic reminder/confirmation with no link, no payment ask, no threat). Always state the one missing detail that would resolve it.
- **Likely legitimate** — matches an expected low-risk pattern (ride confirmation, standard appointment reminder) with no request for money/credentials/suspicious link.
- **Invalid request** — input is not a message to evaluate at all (ordinary unrelated conversation with zero ambiguity, or genuine gibberish/non-text). Never use this for a message that describes a scam-relevant scenario just because it isn't phrased as a question.

**Guardrails against the two most common errors:**
- A short, friendly, low-content message ("Hey, long time no talk!", "Running a bit late") is **not** automatically a scam — score Indeterminate unless it also asks for money, a link, or personal info. Do not flag brevity alone as "likely a scam."
- A vague message that **does** include a payment/credential ask should be at least "Likely a scam" even with few other details — the ask itself is the signal.

## 3. Required output format (always, exactly)

```
Verdict: <one of the five categories>
Scam type: <category name from Section 1, or "N/A">
Why: <2-4 sentences citing only details actually present in this input — the sender claim, the specific ask, the specific pressure tactic. Never reuse details from any other message.>
Confidence: <High / Medium / Low>

Next steps:
1. <action>
2. <action>
3. <action>
```

Next-step actions should be concrete and category-appropriate (e.g., "Don't click the link — go to the bank's app or official site directly and check your account," "Verify by calling the person back on a number you already have, not one provided in the message," "Report to your carrier by forwarding to 7726 (SPAM)").

## 4. Consistency & accuracy rules

- Base every explanation strictly on the literal text of the current input — never carry over details from a previous message analyzed in this session.
- Apply the same rule set to identical/near-identical inputs every time; do not vary the verdict across repeated runs.
- Never invent unverifiable facts about a company's real policy; stick to general, well-established rules (e.g., "the IRS contacts by mail first and never demands gift cards," "banks never ask for your full PIN by text").
- If the message contains a link or phone number, do not visit/call it — describe why it's suspicious (mismatched domain, shortened URL, unfamiliar number) based only on the text given.
- Always disclose: "This is guidance based on the message text alone, not a guarantee — when in doubt, verify independently through an official channel."
"""


IMAGE_SYSTEM_PROMPT = """# Safe — Image Scam & AI/Deepfake Detection Assistant
### System Prompt (photos, screenshots, ads, profile pictures, documents)

You are **Safe**, [Company: Safe]'s image analysis assistant. Your only job is to look at a submitted image and determine (a) whether it is being used as part of a scam, (b) whether it appears to be AI-generated or a deepfake, and (c) which — since these overlap but are not the same thing. You do not identify or name real private individuals; you describe visual evidence only.

## 1. What you are classifying

Every image gets scored on **two independent axes**, then combined into one verdict:

**Axis A — Scam usage** (is this image being used to deceive/defraud?)
Common patterns to check for:
- Fake payment/bank-transfer screenshot (mismatched fonts, inconsistent alignment, no matching transaction history visible, unrealistic balance).
- Fake official document/badge/ID (law enforcement, courier, government) with logo distortion, wrong seals, or inconsistent formatting.
- Counterfeit/too-good-to-be-true product listing image (stock photo reused across many listings, watermark evidence, mismatched branding).
- QR code substituted for a normal link or payment field ("quishing").
- Romance-scam profile photo (professionally lit stock/model photo inconsistent with a casual dating context, or reused image signs).
- Fake charity/disaster photo reused from an unrelated event (check for stock-photo look, inconsistent captions/context clues visible in the image).
- Celebrity/executive "endorsement" image used to promote a crypto or investment scheme.

**Axis B — AI-generation / deepfake likelihood**
Look for these current, evidence-based visual tells (no single one is conclusive on its own — weigh them together):
- **Face boundary artifacts**: discoloration, blurring, or texture mismatch where a face meets hairline, jaw, ears, or neck.
- **Eyes**: irises with inconsistent reflections/highlights that don't match a single light source; unnaturally symmetric or "glassy" eyes.
- **Hands, fingers, teeth, ears**: extra/missing/fused fingers, irregular tooth count or spacing, asymmetric or oddly shaped ears — still among the most common generator failures.
- **Texture uniformity**: skin, hair, or fabric that looks unnaturally smooth, waxy, or repetitive, lacking the fine irregular detail of a real photo.
- **Lighting/shadow inconsistency**: shadows on the subject that don't match the direction/color of light elsewhere in the frame; reflections in eyes/glasses that don't match the scene.
- **Background/text distortion**: warped or nonsensical background objects, garbled text on signs/labels/clothing (a strong generator tell).
- **Unnatural symmetry or blending**: a face that looks slightly "pasted on" relative to the body, or oddly perfect symmetry a real photo rarely has.
- **Compression/metadata clues** (only if provided/visible): repeated or absent EXIF data, or a resolution/compression signature inconsistent with the claimed source (e.g., a claimed "phone photo" with no camera metadata at all).

## 2. Verdict categories (choose exactly one combined verdict)

- **Scam image — AI-generated/deepfake** — evidence of both: it's being used deceptively AND shows generation artifacts (e.g., an AI-generated "crypto guru" endorsement, a fabricated ID, a synthetic romance-scam profile photo).
- **Scam image — authentic photo, deceptive context** — the image itself looks like a real, unaltered photo but is being reused/mislabeled to deceive (e.g., a real disaster photo from a different event, a stolen real photo used for a fake profile).
- **Likely AI-generated / deepfake — no scam context evident** — shows generation artifacts but no deceptive framing is present in what was submitted (e.g., a labeled AI art image, an obvious meme).
- **Indeterminate** — mixed or insufficient visual evidence to call it confidently either way. Always name the single most useful next check (e.g., "run a reverse image search," "check EXIF metadata," "ask for the original, unedited file").
- **Likely authentic, no scam indicators** — no generation artifacts and no deceptive use pattern visible.
- **Invalid request** — the image is unrelated to scam/authenticity analysis (e.g., a vacation photo shared with no claim attached) or the file isn't a usable image.

## 3. Required output format (always, exactly)

```
Verdict: <one of the six categories>
Scam type: <category from Axis A, or "N/A">
AI/deepfake likelihood: <High / Medium / Low / N/A> 
Visual evidence:
- <specific artifact observed, tied to what's actually visible in this image>
- <specific artifact observed>
Why this matters: <2-3 sentences connecting the evidence to the verdict>

Next steps:
1. <action>
2. <action>
```

Next-step actions should be concrete (e.g., "Reverse-image-search this photo before trusting the profile," "Do not send payment based on this screenshot — confirm directly in your banking app," "Ask the sender for a live video call, since real-time interaction is much harder to fake convincingly than a single photo").

## 4. Consistency & accuracy rules

- Only cite artifacts actually visible in the submitted image — never describe generic deepfake tells that aren't observable in this specific case.
- State confidence honestly: modern generators increasingly erase classic tells (perfect lighting, correct hands), so a "clean" image is **not** proof of authenticity — reflect this by capping confidence at "Medium" for any "Likely authentic" verdict unless corroborating context (metadata, reverse-search result) is also provided.
- Never claim certainty ("this is definitely AI") from visual inspection alone if the image is high-resolution and shows no artifacts — say "no visual evidence of manipulation found" rather than "confirmed authentic."
- Do not attempt to identify who a real person in the photo is; focus only on authenticity and deceptive use.
- Always disclose: "This assessment is based on visual inspection alone; for high-stakes decisions (payments, identity verification), use a dedicated forensic tool or reverse image search in addition to this analysis."
"""


CHAT_SYSTEM_PROMPT = """You are SAFE Saathi, a strict digital-safety assistant for Indian users. Your ONLY purpose is helping users identify scams, frauds, and cyber crimes. You speak in clear, simple English.

STRICT RULES — NEVER BREAK THESE:
1. ONLY answer questions about scams, fraud, cybercrime, digital safety, and online security.
2. If the user asks ANYTHING unrelated — respond ONLY with: "I can only help with scam detection and digital safety. Please share a suspicious message, link, or describe a scam situation."
3. Keep responses UNDER 100 words. Be direct. No fluff, no filler.
4. When a user shares a suspicious message/link — analyze it immediately and state clearly: LIKELY SCAM or LOOKS SAFE, then give 1-2 specific red flags.
5. Always end with one concrete safety action (e.g. "Do not click.", "Call 1930 Cyber Helpline.", "Report on cybercrime.gov.in").
"""


# ─────────────────────────────────────────────────────────────────────────────
# IN-MEMORY LRU PROMPT / RESPONSE CACHE
# ─────────────────────────────────────────────────────────────────────────────
_MESSAGE_CACHE: Dict[str, dict] = {}
_IMAGE_CACHE: Dict[str, dict] = {}
_MAX_CACHE_ENTRIES = 200


# ─────────────────────────────────────────────────────────────────────────────
# CLIENT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _use_mantle() -> bool:
    return bool(settings.bedrock_mantle_api_key)


@lru_cache(maxsize=1)
def _get_mantle_client():
    from openai import OpenAI
    base_url = f"https://bedrock-mantle.{settings.aws_region}.api.aws/v1"
    logger.info("Initializing Mantle OpenAI client → %s", base_url)
    return OpenAI(
        api_key=settings.bedrock_mantle_api_key,
        base_url=base_url,
    )


@lru_cache(maxsize=1)
def _get_boto3_client():
    return boto3.client(
        service_name="bedrock-runtime",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT PARSERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_message_verdict(raw: str) -> dict:
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json|markdown|text)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw).strip()

    # Handle pipe-separated format: TAG|message
    if "|" in raw and "\n" not in raw:
        parts = raw.split("|", 1)
        tag_str = parts[0].strip().upper()
        msg_str = parts[1].strip()
        tag_map = {
            "SAFE": ("Safe", "Likely legitimate"),
            "LIKELY_SCAM": ("Likely Scam", "Likely a scam"),
            "SCAM_CONFIRMED": ("Scam Confirmed", "Definitely a scam"),
            "INDETERMINATE": ("Indeterminate", "Indeterminate"),
        }
        if tag_str in tag_map:
            t, v = tag_map[tag_str]
            return {
                "verdict": v,
                "scam_type": "N/A",
                "why": msg_str,
                "why_title": "Why",
                "confidence": "High",
                "next_steps": [],
                "tag": t,
                "message": msg_str,
                "raw": raw,
            }

    verdict = "Indeterminate"
    scam_type = "N/A"
    why = ""
    confidence = "Medium"
    next_steps: List[str] = []

    # Extract Verdict
    m_verdict = re.search(r"^Verdict:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_verdict:
        verdict = m_verdict.group(1).strip()

    # Extract Scam type
    m_type = re.search(r"^Scam type:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_type:
        scam_type = m_type.group(1).strip()

    # Extract Why
    m_why = re.search(r"^Why(?:\s+it's\s+\w+)?:\s*(.+?)(?=\n(?:Confidence:|Next steps:|$))", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if m_why:
        why = m_why.group(1).strip()

    # Extract Confidence
    m_conf = re.search(r"^Confidence:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_conf:
        confidence = m_conf.group(1).strip()

    # Extract Next steps
    m_steps = re.search(r"^Next steps:\s*(.+)$", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if m_steps:
        lines = m_steps.group(1).strip().splitlines()
        for l in lines:
            cleaned = re.sub(r"^\d+[\.\)]\s*", "", l).strip()
            if cleaned.startswith("```"):
                continue
            if cleaned and not cleaned.startswith("This is guidance"):
                next_steps.append(cleaned)

    if not why:
        why = raw

    # Section title
    v_lower = verdict.lower()
    if "invalid" in v_lower:
        why_title = "Why it's invalid"
        tag = "Invalid Request"
    elif "definitely a scam" in v_lower or "likely a scam" in v_lower:
        why_title = "Why it's a scam"
        tag = "Scam Confirmed" if "definitely" in v_lower else "Likely Scam"
    elif "legitimate" in v_lower or "authentic" in v_lower:
        why_title = "Why it's likely legitimate"
        tag = "Safe"
    else:
        why_title = "Why"
        tag = "Indeterminate"

    return {
        "verdict": verdict,
        "scam_type": scam_type,
        "why": why,
        "why_title": why_title,
        "confidence": confidence,
        "next_steps": next_steps,
        "tag": tag,
        "message": why,
        "raw": raw,
    }


_parse_verdict = _parse_message_verdict


def _parse_image_verdict(raw: str, ocr_text: str = "") -> dict:
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json|markdown|text)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw).strip()
    verdict = "Indeterminate"
    scam_type = "N/A"
    ai_likelihood = "N/A"
    visual_evidence: List[str] = []
    why_it_matters = ""
    next_steps: List[str] = []

    m_verdict = re.search(r"^Verdict:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_verdict:
        verdict = m_verdict.group(1).strip()

    m_type = re.search(r"^Scam type:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_type:
        scam_type = m_type.group(1).strip()

    m_ai = re.search(r"^AI/deepfake likelihood:\s*(.+)$", raw, re.MULTILINE | re.IGNORECASE)
    if m_ai:
        ai_likelihood = m_ai.group(1).strip()

    m_vis = re.search(r"^Visual evidence:\s*(.+?)(?=\nWhy this matters:|\nWhy it's\s+\w+:|\nNext steps:|$)", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if m_vis:
        for line in m_vis.group(1).strip().splitlines():
            cleaned = re.sub(r"^[-*•]\s*", "", line).strip()
            if cleaned:
                visual_evidence.append(cleaned)

    m_why = re.search(r"^(?:Why this matters|Why it's\s+\w+|Why):\s*(.+?)(?=\nNext steps:|$)", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if m_why:
        why_it_matters = m_why.group(1).strip()

    m_steps = re.search(r"^Next steps:\s*(.+)$", raw, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if m_steps:
        for line in m_steps.group(1).strip().splitlines():
            cleaned = re.sub(r"^\d+[\.\)]\s*", "", line).strip()
            if cleaned.startswith("```"):
                continue
            if cleaned and not cleaned.startswith("This assessment is based on"):
                next_steps.append(cleaned)

    if not why_it_matters:
        why_it_matters = raw

    v_lower = verdict.lower()
    if "invalid" in v_lower:
        why_title = "Why it's invalid"
        tag = "Invalid Request"
    elif "scam image" in v_lower:
        why_title = "Why it's a scam"
        tag = "Scam Confirmed"
    elif "likely ai" in v_lower:
        why_title = "Why it's likely manipulated / AI-generated"
        tag = "Likely Scam"
    elif "likely authentic" in v_lower:
        why_title = "Why it's likely authentic"
        tag = "Safe"
    else:
        why_title = "Why this matters"
        tag = "Indeterminate"

    return {
        "verdict": verdict,
        "scam_type": scam_type,
        "ai_likelihood": ai_likelihood,
        "visual_evidence": visual_evidence,
        "why_it_matters": why_it_matters,
        "why_title": why_title,
        "next_steps": next_steps,
        "ocr_text": ocr_text,
        "tag": tag,
        "message": why_it_matters,
        "raw": raw,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION WITH PROMPT CACHING & RESULT CACHING
# ─────────────────────────────────────────────────────────────────────────────

async def classify_message(message: str) -> dict:
    """Classify text message according to Safe Scam Message Detection Assistant prompt."""
    cache_key = hashlib.sha256(message.strip().encode("utf-8")).hexdigest()
    if cache_key in _MESSAGE_CACHE:
        logger.info("Serving message classification from cache [key=%s]", cache_key[:8])
        return _MESSAGE_CACHE[cache_key]

    # Enforce daily 10k token limit
    check_token_limit()

    if _use_mantle():
        client = _get_mantle_client()
        def _call():
            resp = client.chat.completions.create(
                model=settings.bedrock_model_id,
                messages=[
                    {"role": "system", "content": MESSAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Please assess this submitted message:\n\n{message[:4000]}"},
                ],
                max_tokens=600,
                temperature=0.0,
            )
            return resp.choices[0].message.content.strip()

        text = await asyncio.to_thread(_call)
        logger.info("Mantle message classify output: %r", text[:120])
        parsed = _parse_message_verdict(text)
        record_token_usage((len(message) + len(text)) // 4 + 100)
        if len(_MESSAGE_CACHE) > _MAX_CACHE_ENTRIES:
            _MESSAGE_CACHE.clear()
        _MESSAGE_CACHE[cache_key] = parsed
        return parsed

    # Fallback boto3
    client = _get_boto3_client()
    body = json.dumps({
        "anthropic_version": settings.bedrock_anthropic_version,
        "max_tokens": 600,
        "temperature": 0.0,
        "system": MESSAGE_SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": message[:4000]}],
    })
    resp = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=body,
    )
    raw_body = json.loads(resp["body"].read())
    text = raw_body["content"][0]["text"].strip()
    parsed = _parse_message_verdict(text)
    record_token_usage((len(message) + len(text)) // 4 + 100)
    _MESSAGE_CACHE[cache_key] = parsed
    return parsed


async def classify_image(image_bytes: bytes, mime_type: str = "image/jpeg", ocr_text: str = "") -> dict:
    """
    Classify an image according to Safe Image Scam & AI/Deepfake Detection Assistant prompt.
    Passes the image to the multimodal model along with any extracted OCR text.
    """
    cache_key = hashlib.sha256(image_bytes + ocr_text.encode("utf-8")).hexdigest()
    if cache_key in _IMAGE_CACHE:
        logger.info("Serving image classification from cache [key=%s]", cache_key[:8])
        return _IMAGE_CACHE[cache_key]

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        w, h = img.size
        if w < 64 or h < 64:
            img = img.resize((max(w, 64), max(h, 64)), Image.Resampling.NEAREST)
        max_dim = 1400
        if max(img.size) > max_dim:
            img.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        image_bytes = buf.getvalue()
        mime_type = "image/jpeg"
    except Exception as exc:
        logger.warning("Image normalization exception: %s", exc)

    b64_data = base64.b64encode(image_bytes).decode("utf-8")
    data_uri = f"data:{mime_type};base64,{b64_data}"

    prompt_text = "Please analyze this submitted image according to your instructions."
    if ocr_text:
        prompt_text += f"\n\n[OCR Text Extracted from Image]:\n\"\"\"\n{ocr_text[:2000]}\n\"\"\""

    # Enforce daily 10k token limit
    check_token_limit()

    if _use_mantle():
        client = _get_mantle_client()
        def _call():
            resp = client.chat.completions.create(
                model=settings.bedrock_model_id,
                messages=[
                    {"role": "system", "content": IMAGE_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt_text},
                            {"type": "image_url", "image_url": {"url": data_uri}},
                        ],
                    },
                ],
                max_tokens=700,
                temperature=0.0,
            )
            return resp.choices[0].message.content.strip()

        text = await asyncio.to_thread(_call)
        logger.info("Mantle image classify output: %r", text[:120])
        parsed = _parse_image_verdict(text, ocr_text=ocr_text)
        record_token_usage((len(ocr_text) + len(text)) // 4 + 300)
        if len(_IMAGE_CACHE) > _MAX_CACHE_ENTRIES:
            _IMAGE_CACHE.clear()
        _IMAGE_CACHE[cache_key] = parsed
        return parsed

    client = _get_boto3_client()
    body = json.dumps({
        "anthropic_version": settings.bedrock_anthropic_version,
        "max_tokens": 700,
        "temperature": 0.0,
        "system": IMAGE_SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": f"{prompt_text}\n(Image analyzed via text/OCR extraction)"}],
    })
    resp = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=body,
    )
    raw_body = json.loads(resp["body"].read())
    text = raw_body["content"][0]["text"].strip()
    parsed = _parse_image_verdict(text, ocr_text=ocr_text)
    record_token_usage((len(ocr_text) + len(text)) // 4 + 300)
    _IMAGE_CACHE[cache_key] = parsed
    return parsed


async def chat_with_llm(user_message: str) -> str:
    """Conversational safety advice with Safe Saathi."""
    check_token_limit()

    if _use_mantle():
        client = _get_mantle_client()
        def _call():
            resp = client.chat.completions.create(
                model=settings.bedrock_model_id,
                messages=[
                    {"role": "system", "content": CHAT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_message[:1000]},
                ],
                max_tokens=150,
                temperature=0.0,
            )
            return resp.choices[0].message.content.strip()
        text = await asyncio.to_thread(_call)
        record_token_usage((len(user_message) + len(text)) // 4 + 50)
        return text

    client = _get_boto3_client()
    body = json.dumps({
        "anthropic_version": settings.bedrock_anthropic_version,
        "max_tokens": 150,
        "temperature": 0.0,
        "system": CHAT_SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_message[:1000]}],
    })
    resp = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=body,
    )
    raw_body = json.loads(resp["body"].read())
    text = raw_body["content"][0]["text"].strip()
    record_token_usage((len(user_message) + len(text)) // 4 + 50)
    return text
