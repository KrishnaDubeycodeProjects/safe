"""
utils/youtube_search.py — Related scam-awareness videos via YouTube Data API v3.

Server-side only: the API key never reaches the frontend. Whatever the user
searches in the Community Registry gets a " scam" suffix and is sent to
YouTube's search.list endpoint; results are then re-ranked by how well the
video *title* actually matches the search terms (YouTube's own relevance
ranking is decent but not tuned for "is this really about the same scam").

Quota note: search.list costs 100 units per call, and the default free quota
is 10,000 units/day — i.e. ~100 searches/day per key. An in-memory TTL cache
keeps repeated/duplicate searches (autocomplete re-triggers, page refreshes,
popular queries) from burning through that budget.
"""

import logging
import os
import re
import time
from typing import Dict, List, Optional

import requests

logger = logging.getLogger("safe_backend.youtube_search")

YOUTUBE_SEARCH_URL = "https://www.googleapis.com/youtube/v3/search"
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY", "").strip()

REQUEST_TIMEOUT = 6  # seconds — this must never block the main search response for long
CACHE_TTL_SECONDS = 3600  # 1 hour — protects the ~100 searches/day free quota
MAX_RESULTS = 8

# query -> (expires_at_epoch, results)
_cache: Dict[str, "tuple[float, List[dict]]"] = {}

_STOPWORDS = {
    "the", "a", "an", "is", "was", "this", "that", "of", "on", "in", "to",
    "and", "or", "for", "with", "my", "me", "i", "scam", "review",
}


def _tokenize(text: str) -> List[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return [w for w in words if w not in _STOPWORDS and len(w) > 1]


def _title_match_score(title: str, query_tokens: List[str]) -> float:
    """How many distinct query tokens actually show up in the video title."""
    if not query_tokens:
        return 0.0
    title_lower = title.lower()
    hits = sum(1 for t in query_tokens if t in title_lower)
    return hits / len(query_tokens)


def is_configured() -> bool:
    return bool(YOUTUBE_API_KEY)


def search_related_videos(query: str, max_results: int = MAX_RESULTS) -> dict:
    """
    Search YouTube for videos related to a scam/community-registry query.

    Returns: {"query": str, "search_query": str, "videos": [...], "cached": bool}
    Never raises — on any failure (missing key, quota, network) returns an
    empty video list so it can't break the main search flow.
    """
    query = (query or "").strip()
    if not query:
        return {"query": query, "search_query": "", "videos": [], "cached": False}

    query_words = set(re.findall(r"[a-z0-9]+", query.lower()))
    search_query = query if ("scam" in query_words or "review" in query_words) else f"{query} scam"
    cache_key = search_query.lower()

    cached = _cache.get(cache_key)
    if cached and cached[0] > time.monotonic():
        return {"query": query, "search_query": search_query, "videos": cached[1], "cached": True}

    if not YOUTUBE_API_KEY:
        logger.warning("YOUTUBE_API_KEY not set — skipping video search.")
        return {"query": query, "search_query": search_query, "videos": [], "cached": False}

    params = {
        "part": "snippet",
        "type": "video",
        "q": search_query,
        "maxResults": max_results,
        "safeSearch": "strict",
        "relevanceLanguage": "en",
        "videoEmbeddable": "true",
        "order": "relevance",
        "key": YOUTUBE_API_KEY,
    }

    try:
        resp = requests.get(YOUTUBE_SEARCH_URL, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.warning(f"YouTube search request failed: {exc}")
        return {"query": query, "search_query": search_query, "videos": [], "cached": False}

    if resp.status_code != 200:
        # Don't leak upstream error bodies (may hint at key validity) to the client.
        logger.warning(f"YouTube search returned HTTP {resp.status_code}: {resp.text[:300]}")
        return {"query": query, "search_query": search_query, "videos": [], "cached": False}

    try:
        items = resp.json().get("items", [])
    except ValueError:
        logger.error("YouTube search returned non-JSON response.")
        return {"query": query, "search_query": search_query, "videos": [], "cached": False}

    query_tokens = _tokenize(query) or _tokenize(search_query)
    videos = []
    for item in items:
        video_id = item.get("id", {}).get("videoId")
        snippet = item.get("snippet", {})
        title = snippet.get("title", "")
        if not video_id or not title:
            continue
        thumbs = snippet.get("thumbnails", {})
        thumbnail = (
            thumbs.get("medium", {}).get("url")
            or thumbs.get("high", {}).get("url")
            or thumbs.get("default", {}).get("url")
            or ""
        )
        videos.append({
            "videoId": video_id,
            "title": title,
            "channelTitle": snippet.get("channelTitle", ""),
            "publishedAt": snippet.get("publishedAt", ""),
            "thumbnail": thumbnail,
            "titleMatchScore": round(_title_match_score(title, query_tokens), 3),
        })

    # Re-rank: strongest title match first, keep YouTube's relevance order as tiebreak.
    videos.sort(key=lambda v: v["titleMatchScore"], reverse=True)

    result = {"query": query, "search_query": search_query, "videos": videos, "cached": False}
    _cache[cache_key] = (time.monotonic() + CACHE_TTL_SECONDS, videos)
    return result
