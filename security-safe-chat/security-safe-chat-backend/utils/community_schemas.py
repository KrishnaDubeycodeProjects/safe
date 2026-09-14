"""
utils/community_schemas.py — Pydantic models for the Community Scam Reporting & Search System.

Covers:
  • Social media profiles, job postings, recruiter DMs, informal group posts
  • Search query and result cards
  • Moderation actions and dispute filings
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


class PlatformEnum(str, Enum):
    INSTAGRAM = "instagram"
    FACEBOOK = "facebook"
    X_TWITTER = "x_twitter"
    TIKTOK = "tiktok"
    SNAPCHAT = "snapchat"
    TELEGRAM = "telegram"
    WHATSAPP = "whatsapp"
    DISCORD = "discord"
    REDDIT = "reddit"
    YOUTUBE = "youtube"
    PINTEREST = "pinterest"
    THREADS = "threads"
    LINKEDIN = "linkedin"
    INDEED = "indeed"
    NAUKRI = "naukri"
    MONSTER = "monster"
    GLASSDOOR = "glassdoor"
    ZIPRECRUITER = "ziprecruiter"
    ANGELLIST_WELLFOUND = "angellist_wellfound"
    INTERNSHALA = "internshala"
    UPWORK = "upwork"
    FIVERR = "fiverr"
    FREELANCER_COM = "freelancer_com"
    OTHER = "other"


class ReportCategoryEnum(str, Enum):
    SOCIAL_MEDIA_PROFILE = "social_media_profile"
    JOB_POSTING = "job_posting"
    RECRUITER_MESSAGE = "recruiter_message"
    INFORMAL_GROUP_POST = "informal_group_post"


class ModerationTierEnum(str, Enum):
    UNCONFIRMED = "unconfirmed"
    CORROBORATED = "corroborated"
    CONFIRMED = "confirmed"
    DISPUTED = "disputed"
    REJECTED = "rejected"


class IdentifierInput(BaseModel):
    handle_raw: Optional[str] = Field(None, description="Raw handle e.g. @quick_forex_returns or URL")
    profile_url: Optional[str] = Field(None, description="Direct URL to social profile or job listing")
    display_name_seen: Optional[str] = Field(None, description="Display name e.g. Rahul Investments Pro")
    company_name_seen: Optional[str] = Field(None, description="Claimed company e.g. Global Tech Careers")


class IdentifierOutput(BaseModel):
    handle_raw: str
    handle_normalized: str
    profile_url: Optional[str] = None
    display_name_seen: Optional[str] = None
    company_name_seen: Optional[str] = None
    company_name_normalized: Optional[str] = None


class ClassifiedScamInfo(BaseModel):
    llm_output_raw: str = ""
    case: str = "single"  # "single" | "multi" | "unfitted" | "undecided" | "not_scam"
    matched_ids: List[str] = []
    category_label: Optional[str] = None
    detection_message: Optional[str] = None


class ReportCreateRequest(BaseModel):
    report_category: ReportCategoryEnum = ReportCategoryEnum.SOCIAL_MEDIA_PROFILE
    platform: PlatformEnum = PlatformEnum.INSTAGRAM
    platform_other_name: Optional[str] = None
    handle_raw: Optional[str] = None
    profile_url: Optional[str] = None
    display_name_seen: Optional[str] = None
    company_name_seen: Optional[str] = None
    message_text: str = Field(..., min_length=3, description="Raw text of DM, post, comment or job listing")
    evidence_urls: List[str] = Field(default_factory=list)
    reporter_id: Optional[str] = Field(None, description="Optional reporter hash / identifier")


class ReportResponse(BaseModel):
    report_id: str
    report_category: str
    platform: str
    platform_other_name: Optional[str] = None
    identifier: IdentifierOutput
    message_text: str
    evidence_urls: List[str]
    classified_scam: ClassifiedScamInfo
    reporter: Dict[str, Any]
    status: ModerationTierEnum
    linked_aliases: List[str]
    created_at: str
    last_reported_at: str
    report_count: int


class CorroborateRequest(BaseModel):
    platform: PlatformEnum
    handle_raw: str
    message_text: str = Field(..., min_length=3)
    evidence_urls: List[str] = Field(default_factory=list)
    reporter_id: Optional[str] = None


class DisputeRequest(BaseModel):
    platform: PlatformEnum
    handle_raw: str
    evidence_text: str = Field(..., min_length=10)
    owner_proof_url: Optional[str] = None
    contact_email: Optional[str] = None


class ModerateActionRequest(BaseModel):
    cluster_key: str = Field(..., description="e.g. instagram:quickforexreturns")
    action: str = Field(..., description="approve_confirmed | reject | resolve_dispute | link_aliases")
    linked_aliases: List[str] = Field(default_factory=list)
    moderator_notes: Optional[str] = None


class SearchResultCard(BaseModel):
    cluster_key: str
    platform: str
    handle_raw: str
    handle_normalized: str
    display_name_seen: Optional[str] = None
    company_name_seen: Optional[str] = None
    status: ModerationTierEnum
    status_badge: str
    report_count: int
    first_reported_at: str
    last_reported_at: str
    matched_categories: List[str]
    sample_messages_redacted: List[str]
    known_aliases: List[str]
    match_type: str  # "exact_handle" | "fuzzy_handle" | "company_name" | "message_content"
    match_score: float  # 0.0 to 1.0


class SearchResponse(BaseModel):
    query: str
    total_matches: int
    results: List[SearchResultCard]
