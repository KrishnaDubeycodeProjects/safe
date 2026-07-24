"""
schemas.py — Pydantic request/response models for all API endpoints.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ── Shared ────────────────────────────────────────────────────────────────────

class EntityMap(BaseModel):
    """Extracted key-value entities from the scam message."""
    name: Optional[str] = None
    money: Optional[str] = None
    fee: Optional[str] = None
    value: Optional[str] = None
    item: Optional[str] = None
    authority: Optional[str] = None
    country: Optional[str] = None
    destination: Optional[str] = None
    brand: Optional[str] = None
    celebrity: Optional[str] = None
    influencer: Optional[str] = None
    service: Optional[str] = None

    model_config = {"extra": "allow"}   # allow any dynamic placeholder key


class ScamMatch(BaseModel):
    """A single matched taxonomy entry."""
    id: str
    label: str
    category: str = ""
    subcategory: str = ""
    verdict: str
    score: int = Field(ge=0, le=100)
    red_flags: list[str] = []
    detection_message: str
    entities: dict[str, str] = {}


# ── /analyze ──────────────────────────────────────────────────────────────────

class AnalyzeTextRequest(BaseModel):
    """Body for POST /analyze/text"""
    message: str = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="Raw message text to classify (SMS, email, chat, etc.)",
    )

    @field_validator("message")
    @classmethod
    def strip_message(cls, v: str) -> str:
        return v.strip()


class AnalyzeBase64Request(BaseModel):
    """Body for POST /analyze/base64"""
    image: str = Field(
        ...,
        description="Base64-encoded image string. May include or omit the data URI prefix.",
    )
    content_type: str = Field(
        default="image/png",
        description="MIME type of the image (e.g. image/png, image/jpeg).",
    )


class AnalyzeResponse(BaseModel):
    """Unified response for all /analyze/* endpoints."""
    case: int = Field(
        ...,
        ge=1, le=5,
        description="Classification case: 1=single, 2=multi, 3=generic, 4=unsure, 5=safe",
    )
    is_scam: bool
    score: Optional[int] = Field(
        default=None,
        ge=0, le=100,
        description="Confidence score 0-100. None for case 4 and 5.",
    )
    matches: list[ScamMatch] = Field(default=[], description="Matched taxonomy entries.")
    entities: dict[str, str] = Field(default={}, description="Extracted entities (name, money, etc.)")
    detection_message: Optional[str] = Field(
        default=None,
        description="Human-readable detection explanation (case 3 only).",
    )
    ambiguous: Optional[bool] = Field(default=None)
    generic_scam: Optional[bool] = Field(default=None)
    raw_model_output: str = Field(
        ...,
        description="The raw single-line output from the classification model.",
    )
    extracted_text: Optional[str] = Field(
        default=None,
        description="Text extracted via OCR (present only for image endpoints).",
    )
    parse_error: Optional[str] = Field(
        default=None,
        description="Set if the model output could not be parsed.",
    )


# ── /health ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    environment: str
