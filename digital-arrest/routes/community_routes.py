"""
routes/community_routes.py — FastAPI endpoints for the Community Scam Reporting & Search System.

Endpoints:
  POST /api/community/report          — Submit a scam report
  GET  /api/community/search          — Basic 4-layer search (backward-compatible)
  GET  /api/community/search/advanced — 7-layer search w/ TF-IDF, pagination, trend scores
  GET  /api/community/search/autocomplete — Handle/company name autocomplete suggestions
  GET  /api/community/profile/{handle} — Cross-platform identity profile
  GET  /api/community/reports/{id}    — Get full report by ID
  POST /api/community/corroborate     — One-tap corroboration
  POST /api/community/dispute         — File ownership dispute
  GET  /api/community/queue           — Moderation review queue
  POST /api/community/moderate        — Moderator action
  GET  /api/community/stats           — System analytics
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from utils.community_schemas import (
    ReportCreateRequest,
    ReportResponse,
    CorroborateRequest,
    DisputeRequest,
    ModerateActionRequest,
    SearchResponse,
)
from utils.advanced_search_engine import (
    advanced_engine,
    AdvancedSearchResponse,
)

router = APIRouter(prefix="/api/community", tags=["Community Scam Registry"])


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/report",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit a scam report",
)
async def submit_report(payload: ReportCreateRequest):
    """
    Submit a new community scam report against a social media handle, recruiter DM, or job listing.

    Automatically normalizes handle/URL, runs AI text classifier, calculates moderation tier,
    and updates both local persistent JSON index and Supabase database.
    """
    try:
        return await advanced_engine.submit_report(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit report: {exc}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Search  (backward-compatible basic search)
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/search",
    response_model=SearchResponse,
    summary="Search the community scam registry (basic 4-layer)",
)
def search_registry(
    q: str = Query(..., min_length=2, description="Handle (@username), profile URL, company name, or message snippet"),
    platform: Optional[str] = Query(None, description="Optional platform filter e.g. instagram, linkedin"),
    category: Optional[str] = Query(None, description="Optional category filter"),
    include_unconfirmed: bool = Query(False, description="Set True to include unconfirmed single reports"),
):
    """
    Backward-compatible 4-Layer Search Engine:
      1. Exact handle / profile URL lookup
      2. Fuzzy handle match (Levenshtein distance <= 2)
      3. Full-text message content similarity search
      4. Company name lookup (recruiter / job scams)

    For richer results (TF-IDF, cross-platform, trend scores) use /search/advanced.
    """
    return advanced_engine.search(
        query=q,
        platform_filter=platform,
        category_filter=category,
        include_unconfirmed=include_unconfirmed,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Search
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/search/advanced",
    response_model=AdvancedSearchResponse,
    summary="Advanced 7-layer search with TF-IDF, pagination, and trend analysis",
)
def advanced_search(
    q: str = Query(..., min_length=2, description="Handle, URL, phone, email, company name, or scam message text"),
    platform: Optional[str] = Query(None, description="Filter by platform slug e.g. instagram, linkedin, whatsapp"),
    category: Optional[str] = Query(None, description="Filter by scam category keyword"),
    tier: Optional[str] = Query(None, description="Filter by tier: confirmed | corroborated | disputed | unconfirmed"),
    include_unconfirmed: bool = Query(False, description="Also return unconfirmed and rejected results"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page (max 100)"),
):
    """
    7-Layer Advanced Search Engine:

      **Layer 1**: Exact handle / URL lookup (score = 1.0)
      **Layer 2**: Fuzzy Levenshtein handle match ≤2 edits (score = 0.7–0.99)
      **Layer 3**: TF-IDF full-text message similarity (score = 0.35–1.0)
      **Layer 4**: Company / recruiter name lookup (score = 0.90)
      **Layer 5**: Phone number / email / display name direct lookup (score = 0.95–1.0)
      **Layer 6**: Cross-platform identity grouping (score = 0.95)
      **Layer 7**: Alias transitive closure search (score = 0.85–1.0)

    Results are ranked by: moderation tier → match score → trend spike → total report count.

    Response includes:
      - `trend_score`: 0.0–1.0 recent activity spike score
      - `trend_label`: "spiking" | "rising" | "stable"
      - `recent_7d_count`: reports in the last 7 days
      - `cross_platform_hits`: other platforms where same handle was spotted
      - `autocomplete_hints`: prefix-based handle suggestions
      - `search_took_ms`: query performance in milliseconds
    """
    return advanced_engine.advanced_search(
        query=q,
        platform_filter=platform,
        category_filter=category,
        tier_filter=tier,
        include_unconfirmed=include_unconfirmed,
        page=page,
        page_size=page_size,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Autocomplete
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/search/autocomplete",
    summary="Autocomplete handle and company name suggestions",
)
def autocomplete(
    prefix: str = Query(..., min_length=2, description="Prefix string to autocomplete"),
    limit: int = Query(10, ge=1, le=50, description="Max suggestions to return"),
    include_unconfirmed: bool = Query(False, description="Include unconfirmed handles"),
):
    """
    Returns up to `limit` handle / company name suggestions starting with the given prefix.
    Results are ranked by total report count (most-reported scammers appear first).

    Useful for search-as-you-type UI implementations.
    """
    return advanced_engine.get_autocomplete(
        prefix=prefix,
        limit=limit,
        include_unconfirmed=include_unconfirmed,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Cross-Platform Identity Profile
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/profile/{handle}",
    summary="Cross-platform identity profile for a handle",
)
def cross_platform_profile(
    handle: str,
):
    """
    Returns a complete cross-platform identity profile for a normalized handle.

    Shows all platforms where the same handle was reported as a scammer,
    aggregated report counts, moderation tiers, and any linked aliases.

    Example: `/api/community/profile/quickforexreturns`
    Returns activity on Instagram, LinkedIn, Telegram etc. if all found.
    """
    try:
        return advanced_engine.get_cross_platform_profile(handle)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Individual Report Lookup
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/reports/{report_id}", summary="Get specific report details")
def get_report_by_id(report_id: str):
    """Fetch full details of an individual report by report_id."""
    report = advanced_engine.get_report_by_id(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )
    return report


# ─────────────────────────────────────────────────────────────────────────────
# Corroborate / Dispute
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/corroborate", summary="One-tap corroboration of an existing scam handle")
async def corroborate_handle(payload: CorroborateRequest):
    """One-tap corroboration of a scam handle by a user who received the same scam message."""
    try:
        return await advanced_engine.corroborate(payload)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/dispute", summary="File an ownership dispute for a flagged handle")
async def dispute_handle(payload: DisputeRequest):
    """File an ownership dispute if your account/business handle was wrongly flagged."""
    try:
        return await advanced_engine.dispute(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Moderation
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/queue", summary="Moderator review queue")
def get_moderation_queue():
    """Retrieve unconfirmed and disputed reports requiring manual moderator review."""
    return {
        "count": len(advanced_engine.get_moderation_queue()),
        "queue": advanced_engine.get_moderation_queue(),
    }


@router.post("/moderate", summary="Moderator action on a report cluster")
async def moderate_action(payload: ModerateActionRequest):
    """
    Moderator decision on a report cluster:
      • approve_confirmed: promote to Confirmed Scam
      • reject: mark as rejected
      • resolve_dispute: resolve ownership dispute
      • link_aliases: link related handles used by the same scammer
    """
    try:
        return await advanced_engine.moderate_action(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Analytics
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/stats", summary="Get community scam registry statistics")
def get_stats():
    """Returns analytics: total reports, unique handles indexed, top flagged scam accounts."""
    return advanced_engine.get_system_stats()
