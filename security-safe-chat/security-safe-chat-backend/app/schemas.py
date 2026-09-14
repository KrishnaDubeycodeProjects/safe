"""
schemas.py — Pydantic request/response models for all API endpoints.
"""

from __future__ import annotations
from typing import Optional, List

from pydantic import BaseModel, Field


# ── /health ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    environment: str


class MessageVerdict(BaseModel):
    verdict: Optional[str] = None
    scam_type: Optional[str] = None
    why: Optional[str] = None
    why_title: Optional[str] = None
    confidence: Optional[str] = None
    next_steps: List[str] = Field(default_factory=list)
    tag: str = Field(description="Safe | Likely Scam | Scam Confirmed | Invalid Request")
    message: str = Field(description="Explanation of verdict")
    raw: Optional[str] = None

class ImageVerdict(BaseModel):
    verdict: Optional[str] = None
    scam_type: Optional[str] = None
    ai_likelihood: Optional[str] = None
    visual_evidence: List[str] = Field(default_factory=list)
    why_it_matters: Optional[str] = None
    why_title: Optional[str] = None
    next_steps: List[str] = Field(default_factory=list)
    ocr_text: Optional[str] = ""
    tag: str = Field(description="Safe | Likely Scam | Scam Confirmed | Invalid Request")
    message: str = Field(description="Explanation of verdict")
    raw: Optional[str] = None
