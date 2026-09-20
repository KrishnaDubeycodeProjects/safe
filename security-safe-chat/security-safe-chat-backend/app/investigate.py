"""
investigate_engine.py — Complete native Python implementation of the
Creator Trust Investigation Agent (migrated 1:1 from n8n workflow).
Directly uses:
- YouTube Data API v3
- Tavily Search API
- AWS Bedrock Mantle / Google Gemma 4 (31B)
Zero external n8n dependency.
"""

from __future__ import annotations
import os
import re
import html
import json
import math
import logging
import datetime
import urllib.parse
import urllib.request
from typing import Dict, Any, List, Optional

logger = logging.getLogger("investigate")

# API Keys loaded strictly from environment variables
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "")
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
BEDROCK_API_KEY = (
    os.getenv("BEDROCK_MANTLE_API_KEY")
    or os.getenv("BEDROCK_API_KEY", "")
)
BEDROCK_ENDPOINT = os.getenv(
    "BEDROCK_ENDPOINT",
    "https://bedrock-mantle.us-east-2.api.aws/openai/v1/chat/completions"
)

# ── STEP 1: Parse input & classify domain ──
def parse_input_and_classify_domain(raw_input: str) -> Dict[str, Any]:
    raw = (raw_input or "").strip()
    if not raw:
        raise ValueError('Missing input field: send {"input": "<url|handle|text>"}')

    out = {"raw": raw, "type": None, "id": None, "domain": "general"}

    # YouTube video regex
    m = re.search(r"(?:youtube\.com\/watch\?v=|youtu\.be\/)([\w-]{11})", raw)
    if m:
        out["type"] = "yt_video"
        out["id"] = m.group(1)

    if not out["type"]:
        m = re.search(r"youtube\.com\/(?:c\/|channel\/|@)([\w.-]+)", raw)
        if m:
            out["type"] = "yt_channel"
            out["id"] = m.group(1)

    if not out["type"]:
        m = re.search(r"^@([\w.-]{3,})$", raw)
        if m:
            out["type"] = "yt_channel"
            out["id"] = m.group(1)

    if not out["type"]:
        m = re.search(r"(?:t\.me\/|^@)([\w_]{5,})", raw)
        if m:
            out["type"] = "telegram"
            out["id"] = m.group(1)

    if not out["type"]:
        out["type"] = "scenario"
        out["id"] = raw

    lower = raw.lower()
    domains = {
        "finance": ["invest", "stock", "trading", "crypto", "returns", "mutual fund", "sip", "forex"],
        "education": ["course", "learn", "tutorial", "class", "study", "exam", "upsc", "neet"],
        "gaming": ["gameplay", "gaming", "stream", "esports", "pubg", "bgmi", "valorant"],
        "health": ["health", "medicine", "doctor", "cure", "remedy", "ayurveda"],
        "scam": ["scam", "fraud", "fake", "exposed", "cheat"]
    }
    for d, kws in domains.items():
        if any(k in lower for k in kws):
            out["domain"] = d
            break

    return out


# ── STEP 2: Load MD rules + domain weights ──
def load_md_rules(domain: str) -> Dict[str, Any]:
    domain_weights = {
        "finance":   {"fake": 0.20, "sentiment": 0.15, "engagement": 0.15, "transcript": 0.20, "negative": 0.25, "cross": 0.05},
        "education": {"fake": 0.10, "sentiment": 0.20, "engagement": 0.25, "transcript": 0.20, "negative": 0.15, "cross": 0.10},
        "gaming":    {"fake": 0.10, "sentiment": 0.15, "engagement": 0.30, "transcript": 0.10, "negative": 0.15, "cross": 0.20},
        "health":    {"fake": 0.20, "sentiment": 0.15, "engagement": 0.15, "transcript": 0.25, "negative": 0.20, "cross": 0.05},
        "scam":      {"fake": 0.20, "sentiment": 0.10, "engagement": 0.10, "transcript": 0.15, "negative": 0.35, "cross": 0.10},
        "general":   {"fake": 0.15, "sentiment": 0.15, "engagement": 0.20, "transcript": 0.15, "negative": 0.20, "cross": 0.15}
    }
    rules = {
        "fake_patterns": [
            r"bit\.ly|t\.me\/join|whatsapp|telegram\.me",
            r"^(nice|great|good|wow|super)\s(video|content|bhai|sir)!?$",
            r"^[\U00010000-\U0010ffff\s]+$"
        ],
        "spam_keywords": ["dm me", "click here", "free money", "link in bio", "whatsapp me", "join my"],
        "domain_weights": domain_weights,
        "banned_words": ["scam", "fraud", "fake", "liar", "cheat", "avoid", "stay away", "confirmed scam"]
    }
    rules["weights"] = domain_weights.get(domain, domain_weights["general"])
    return rules


# ── STEP 3: Fetch YouTube data ──
def fetch_youtube_data(parsed_input: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("YOUTUBE_API_KEY") or YOUTUBE_API_KEY
    if not api_key:
        logger.warning("YOUTUBE_API_KEY is not configured.")
        return {"lookupFailed": True, "lookupReason": "YouTube API key not configured in environment"}
    type_ = parsed_input["type"]
    id_ = parsed_input["id"]
    base = "https://www.googleapis.com/youtube/v3"

    def yt_get(path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        params["key"] = api_key
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(f"{base}/{path}?{qs}", headers={"User-Agent": "SecuritySafe/1.0"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            return json.loads(resp.read().decode("utf-8"))

    channel_id = id_
    channel_info = None
    videos = []
    comments = []

    try:
        if type_ == "yt_video":
            v = yt_get("videos", {"part": "snippet", "id": id_})
            items = v.get("items", [])
            if items:
                channel_id = items[0].get("snippet", {}).get("channelId", id_)

        if type_ == "yt_channel" and not str(channel_id).startswith("UC"):
            handle = str(channel_id).lstrip("@")
            # First try direct forHandle lookup (fastest and exact)
            try:
                fh = yt_get("channels", {"part": "snippet,statistics", "forHandle": handle})
                if fh.get("items"):
                    channel_info = fh["items"][0]
                    channel_id = channel_info.get("id")
            except Exception as e:
                logger.warning(f"forHandle lookup failed for {handle}: {e}")

            # If forHandle didn't find it, fallback to search API
            if not channel_info:
                s = yt_get("search", {"part": "snippet", "q": handle, "type": "channel", "maxResults": 1})
                items = s.get("items", [])
                if items:
                    channel_id = items[0].get("snippet", {}).get("channelId") or items[0].get("id", {}).get("channelId") or channel_id

        if not channel_info:
            ch = yt_get("channels", {"part": "snippet,statistics", "id": channel_id})
            ch_items = ch.get("items", [])
            if ch_items:
                channel_info = ch_items[0]

        if not channel_info:
            return {
                "channelId": channel_id,
                "channelInfo": None,
                "videos": [],
                "comments": [],
                "lookupFailed": True,
                "lookupReason": f'YouTube channel not found for input: "{id_}".'
            }

        srch = yt_get("search", {"part": "id", "channelId": channel_id, "order": "date", "maxResults": 20, "type": "video"})
        video_ids = [i.get("id", {}).get("videoId") for i in srch.get("items", []) if i.get("id", {}).get("videoId")]

        if video_ids:
            vids = yt_get("videos", {"part": "statistics,snippet", "id": ",".join(video_ids)})
            for v in vids.get("items", []):
                stat = v.get("statistics", {})
                snip = v.get("snippet", {})
                videos.append({
                    "id": v.get("id"),
                    "title": snip.get("title", ""),
                    "publishedAt": snip.get("publishedAt", ""),
                    "views": int(stat.get("viewCount", 0)),
                    "likes": int(stat.get("likeCount", 0)),
                    "comments": int(stat.get("commentCount", 0))
                })

            target_video_id = id_ if type_ == "yt_video" else videos[0]["id"]
            try:
                c = yt_get("commentThreads", {
                    "part": "snippet",
                    "videoId": target_video_id,
                    "maxResults": 100,
                    "order": "relevance"
                })
                for t in c.get("items", []):
                    snip = t.get("snippet", {}).get("topLevelComment", {}).get("snippet", {})
                    comments.append({
                        "text": snip.get("textDisplay", ""),
                        "author": snip.get("authorDisplayName", ""),
                        "publishedAt": snip.get("publishedAt", ""),
                        "likeCount": snip.get("likeCount", 0)
                    })
            except Exception as comment_err:
                logger.warning(f"Could not fetch comments for video {target_video_id}: {comment_err}")

        return {
            "channelId": channel_id,
            "channelInfo": channel_info,
            "videos": videos,
            "comments": comments,
            "lookupFailed": False
        }

    except Exception as e:
        logger.error(f"YouTube fetch error: {e}")
        return {
            "channelId": channel_id,
            "channelInfo": None,
            "videos": [],
            "comments": [],
            "lookupFailed": True,
            "lookupReason": f"YouTube API error: {str(e)}"
        }


# ── STEP 4: Fetch Web Mentions via Tavily ──
def fetch_web_mentions(name: str) -> Dict[str, Any]:
    if not name or len(str(name)) < 3:
        return {"webMentions": [], "tavilyAnswer": None}

    t_api_key = os.getenv("TAVILY_API_KEY") or TAVILY_API_KEY
    if not t_api_key:
        logger.info("TAVILY_API_KEY is not configured; skipping web mentions.")
        return {"webMentions": [], "tavilyAnswer": None}

    queries = [f"{name} scam", f"{name} exposed", f"{name} review"]
    mentions: List[Dict[str, Any]] = []
    tavily_answer: Optional[str] = None
    seen_links = set()

    for q in queries:
        try:
            payload = json.dumps({
                "api_key": t_api_key,
                "query": q,
                "max_results": 5,
                "include_answer": True,
                "search_depth": "basic"
            }).encode("utf-8")

            req = urllib.request.Request(
                "https://api.tavily.com/search",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "SecuritySafe/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                r = json.loads(resp.read().decode("utf-8"))

            if r.get("answer") and not tavily_answer:
                tavily_answer = r.get("answer")

            for o in r.get("results", []):
                link = o.get("url", "")
                if link in seen_links:
                    continue
                seen_links.add(link)

                source = "web"
                if link:
                    try:
                        source = urllib.parse.urlparse(link).hostname or "web"
                    except Exception:
                        source = "web"

                # Exclude target creator's own YouTube channel from 3rd-party mentions
                t_lower = (o.get("title") or "").lower()
                n_lower = name.lower()
                if "youtube.com" in source and (t_lower == n_lower or t_lower == f"@{n_lower}" or (len(n_lower) > 3 and t_lower.startswith(n_lower) and len(t_lower) < len(n_lower) + 5)):
                    continue

                content_str = (o.get("title", "") + " " + o.get("content", "")).lower()
                sentiment = "neutral"
                if re.search(r"scam|fraud|fake|exposed|worst|avoid", content_str):
                    sentiment = "negative"
                elif re.search(r"review|best|honest|great|helpful", content_str):
                    sentiment = "positive"

                mentions.append({
                    "title": o.get("title", ""),
                    "source": source,
                    "link": link,
                    "snippet": (o.get("content") or "")[:200],
                    "sentiment": sentiment
                })
        except Exception as tavily_err:
            logger.warning(f"Tavily query failed for {q}: {tavily_err}")

    return {"webMentions": mentions, "tavilyAnswer": tavily_answer}


# ── STEP 5: Filter comments + sentiment split ──
def filter_comments_and_split_sentiment(comments: List[Dict[str, Any]], md_rules: Dict[str, Any]) -> Dict[str, Any]:
    fake_patterns = md_rules.get("fake_patterns", [])
    spam_keywords = [s.lower() for s in md_rules.get("spam_keywords", [])]

    def is_fake(c: Dict[str, Any]) -> bool:
        text = (c.get("text") or "").lower()
        for p in fake_patterns:
            try:
                if re.search(p, text, re.IGNORECASE):
                    return True
            except Exception:
                pass
        if any(k in text for k in spam_keywords):
            return True
        if len(text.split()) < 4 and re.search(r"nice|good|great|wow", text):
            return True
        return False

    real = [c for c in comments if not is_fake(c)]
    fake = [c for c in comments if is_fake(c)]

    pos_words = ['love','amazing','helpful','best','thank','great','excellent','superb','useful','clear']
    neg_words = ['worst','bad','waste','misleading','lie','wrong','useless','avoid','fake','scam']

    pos = 0
    neg = 0
    neu = 0

    pos_samples: List[str] = []
    neg_samples: List[str] = []
    neu_samples: List[str] = []
    fake_samples: List[str] = []

    def clean_comment_text(raw_text: str) -> str:
        if not raw_text:
            return ""
        no_tags = re.sub(r"<[^>]+>", " ", str(raw_text))
        unescaped = html.unescape(no_tags)
        return " ".join(unescaped.split()).strip()

    def is_promotional_or_link(text_val: str) -> bool:
        low = text_val.lower()
        return any(k in low for k in ["coupon", "discount", "join the course", "sign the petition", "academy.", "http://", "https://", "utm_"])

    for c in real:
        clean_t = clean_comment_text(c.get("text") or "")
        if not clean_t or len(clean_t) < 8:
            continue
        t_low = clean_t.lower()
        p_count = sum(1 for w in pos_words if w in t_low)
        n_count = sum(1 for w in neg_words if w in t_low)
        if p_count > n_count:
            pos += 1
            if not is_promotional_or_link(clean_t) and len(pos_samples) < 3 and len(clean_t) >= 12 and clean_t not in pos_samples:
                pos_samples.append(clean_t)
        elif n_count > p_count:
            neg += 1
            if not is_promotional_or_link(clean_t) and len(neg_samples) < 3 and len(clean_t) >= 12 and clean_t not in neg_samples:
                neg_samples.append(clean_t)
        else:
            neu += 1
            if not is_promotional_or_link(clean_t) and len(neu_samples) < 3 and len(clean_t) >= 12 and clean_t not in neu_samples:
                neu_samples.append(clean_t)

    # Fallback to any remaining clean comments if samples list is not yet 3
    if len(pos_samples) < 3:
        for c in real:
            clean_t = clean_comment_text(c.get("text") or "")
            if clean_t and not is_promotional_or_link(clean_t) and clean_t not in pos_samples and any(w in clean_t.lower() for w in pos_words):
                pos_samples.append(clean_t)
                if len(pos_samples) >= 3:
                    break

    if len(neg_samples) < 3:
        for c in real:
            clean_t = clean_comment_text(c.get("text") or "")
            if clean_t and not is_promotional_or_link(clean_t) and clean_t not in neg_samples and any(w in clean_t.lower() for w in neg_words):
                neg_samples.append(clean_t)
                if len(neg_samples) >= 3:
                    break

    if len(neu_samples) < 3:
        for c in real:
            clean_t = clean_comment_text(c.get("text") or "")
            if clean_t and not is_promotional_or_link(clean_t) and clean_t not in neu_samples and clean_t not in pos_samples and clean_t not in neg_samples:
                neu_samples.append(clean_t)
                if len(neu_samples) >= 3:
                    break

    for c in fake:
        clean_t = clean_comment_text(c.get("text") or "")
        if clean_t and clean_t not in fake_samples:
            fake_samples.append(clean_t)
            if len(fake_samples) >= 3:
                break

    total = len(real) or 1
    total_comments = len(comments) or 1

    return {
        "commentStats": {
            "total": len(comments),
            "fake": len(fake),
            "real": len(real),
            "fake_ratio": round(len(fake) / total_comments, 3),
            "positive_pct": round(pos / total, 3),
            "negative_pct": round(neg / total, 3),
            "neutral_pct": round(neu / total, 3)
        },
        "commentSamples": {
            "positive": pos_samples,
            "negative": neg_samples,
            "neutral": neu_samples,
            "filtered": fake_samples
        }
    }


# ── STEP 6: Compute engagement metrics ──
def compute_engagement_metrics(videos: List[Dict[str, Any]], channel_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    ch = channel_info or {}
    subs = int(ch.get("statistics", {}).get("subscriberCount", 0))

    total_views = sum(v.get("views", 0) for v in videos)
    total_likes = sum(v.get("likes", 0) for v in videos)
    total_cmt = sum(v.get("comments", 0) for v in videos)
    n = len(videos) or 1
    avg_views = total_views / n

    like_to_view = total_likes / total_views if total_views else 0.0
    comment_to_view = total_cmt / total_views if total_views else 0.0
    sub_to_view = subs / avg_views if avg_views else 0.0

    arr = [v.get("views", 0) for v in videos]
    mean = sum(arr) / n
    variance = sum(math.pow(v - mean, 2) for v in arr) / n
    std_dev = math.sqrt(variance)
    view_stability = max(0.0, 1.0 - (std_dev / mean)) if mean else 0.0

    red_flags = []
    if len(videos) == 0:
        red_flags.append("no_video_data")
    if sub_to_view > 10:
        red_flags.append("sub_to_view_above_typical")
    if 0 < like_to_view < 0.005:
        red_flags.append("like_ratio_below_typical")
    if 0 < comment_to_view < 0.0005:
        red_flags.append("comment_ratio_below_typical")
    if len(videos) > 0 and view_stability < 0.3:
        red_flags.append("view_volatility_high")

    return {
        "subs": subs,
        "avgViews": round(avg_views),
        "likeToView": round(like_to_view, 4),
        "commentToView": round(comment_to_view, 4),
        "subToView": round(sub_to_view, 2),
        "viewStability": round(view_stability, 3),
        "redFlags": red_flags
    }


# ── STEP 7 & 8: Build LLM Prompt & Call Gemma 4 ──
def score_evidence_with_gemma_4(evidence: Dict[str, Any]) -> Dict[str, Any]:
    comment_count = evidence.get("dataAvailable", {}).get("commentCount", 0)
    video_count = evidence.get("dataAvailable", {}).get("videoCount", 0)

    if comment_count < 10 or video_count < 3:
        return {
            "fake_comment_score": None,
            "sentiment_score": None,
            "engagement_score": None,
            "transcript_credibility_score": None,
            "negative_signal_score": None,
            "cross_platform_score": None,
            "reasoning": f"Insufficient data available ({comment_count} comments, {video_count} videos). At least 10 comments and 3 videos required for empirical scoring."
        }

    system_prompt = (
        "You are a forensic analyst. Score each section from 0 (weak) to 5 (strong).\n"
        "Return ONLY valid JSON — no markdown fences, no prose.\n\n"
        "Sections to score:\n"
        "- fake_comment_score        (5 = very few fake comments, 0 = mostly fake)\n"
        "- sentiment_score           (5 = overwhelmingly positive organic, 0 = overwhelmingly negative)\n"
        "- engagement_score          (5 = healthy like/comment/sub ratios, 0 = highly anomalous)\n"
        "- transcript_credibility_score (5 = no problematic claims, 0 = strong fear/urgency promises)\n"
        "- negative_signal_score     (5 = no negative external mentions, 0 = strong negative consensus)\n"
        "- cross_platform_score      (5 = consistent across platforms, 0 = wildly inconsistent)\n\n"
        'Output format:\n{"fake_comment_score":n,"sentiment_score":n,"engagement_score":n,"transcript_credibility_score":n,"negative_signal_score":n,"cross_platform_score":n,"reasoning":"2-3 sentences"}'
    )
    user_prompt = "Evidence:\n" + json.dumps(evidence, indent=2)

    b_key = (
        os.getenv("BEDROCK_MANTLE_API_KEY")
        or os.getenv("BEDROCK_API_KEY")
        or BEDROCK_API_KEY
    )

    if b_key:
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {b_key}"
            }
            body = json.dumps({
                "model": "google.gemma-4-31b",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 1500
            }).encode("utf-8")

            req = urllib.request.Request(BEDROCK_ENDPOINT, data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=25) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            raw_text = ""
            choices = data.get("choices", [])
            if choices and "message" in choices[0]:
                raw_text = choices[0]["message"].get("content", "")

            # Extract JSON blob
            m = re.search(r"\{[\s\S]*\}", raw_text)
            if m:
                return json.loads(m.group(0))
        except Exception as llm_err:
            logger.warning(f"Gemma 4 Bedrock call failed or timed out: {llm_err}. Using deterministic heuristic fallback.")

    # Resilient heuristic fallback scoring based on computed stats
    cs = evidence.get("comments", {})
    mt = evidence.get("metrics", {})
    mentions = evidence.get("externalMentions", [])

    fake_ratio = cs.get("fake_ratio", 0.05)
    f_score = 5 if fake_ratio < 0.05 else (4 if fake_ratio < 0.15 else (2 if fake_ratio < 0.35 else 1))

    pos_pct = cs.get("positive_pct", 0.5)
    neg_pct = cs.get("negative_pct", 0.05)
    s_score = 4 if pos_pct > 0.4 and neg_pct < 0.05 else (3 if neg_pct < 0.15 else 2)

    red_flags = mt.get("redFlags", [])
    e_score = 5 if len(red_flags) == 0 else (3 if len(red_flags) <= 2 else 1)

    neg_mentions = sum(1 for m in mentions if m.get("sentiment") == "negative")
    n_score = 5 if neg_mentions == 0 else (3 if neg_mentions <= 2 else 1)

    return {
        "fake_comment_score": f_score,
        "sentiment_score": s_score,
        "engagement_score": e_score,
        "transcript_credibility_score": None,
        "negative_signal_score": n_score,
        "cross_platform_score": 3,
        "reasoning": "Engagement metrics and comment patterns evaluated. Organic sentiment balances against audience velocity anomalies."
    }


# ── STEP 9: Weighted composite indicator ──
def compute_weighted_composite(scores: Dict[str, Any], weights: Dict[str, float]) -> Dict[str, Any]:
    score_weights = {
        "fake_comment_score": weights.get("fake", 0.15),
        "sentiment_score": weights.get("sentiment", 0.15),
        "engagement_score": weights.get("engagement", 0.20),
        "transcript_credibility_score": weights.get("transcript", 0.15),
        "negative_signal_score": weights.get("negative", 0.20),
        "cross_platform_score": weights.get("cross", 0.15)
    }

    all_null = all(scores.get(k) is None for k in score_weights)
    if all_null:
        breakdown = [{"section": k, "raw": None, "weight": wt, "contribution": None} for k, wt in score_weights.items()]
        return {"composite": None, "breakdown": breakdown, "insufficientData": True}

    sum_val = 0.0
    total_w = 0.0
    breakdown = []

    for k, wt in score_weights.items():
        raw = scores.get(k)
        if raw is None:
            breakdown.append({"section": k, "raw": None, "weight": wt, "contribution": None})
            continue

        score = max(0.0, min(5.0, float(raw)))
        contribution = (score / 5.0) * wt
        sum_val += contribution
        total_w += wt
        breakdown.append({"section": k, "raw": score, "weight": wt, "contribution": round(contribution * 100, 1)})

    composite = round((sum_val / total_w) * 100, 1) if total_w else None
    return {"composite": composite, "breakdown": breakdown, "insufficientData": False}


# ── STEP 10: Both-sides balancer ──
def balance_evidence(data: Dict[str, Any]) -> Dict[str, Any]:
    cs = data.get("commentStats", {})
    pos = cs.get("positive_pct", 0)
    neg = cs.get("negative_pct", 0)
    flags = data.get("metrics", {}).get("redFlags", [])
    mentions = data.get("webMentions", [])
    ch = data.get("channelInfo") or {}
    video_count = int(ch.get("statistics", {}).get("videoCount", 0))

    supported = []
    questioned = []

    if pos > 0.5:
        supported.append(f"{int(pos * 100)}% of organic comments are positive")
    if video_count > 50:
        supported.append("Consistent long-term upload history")
    if 0 < neg < 0.2:
        supported.append(f"Low organic negative sentiment ({int(neg * 100)}%)")
    if any(m.get("sentiment") == "positive" for m in mentions):
        supported.append("Positive third-party mentions found")
    if data.get("metrics", {}).get("likeToView", 0) >= 0.01:
        supported.append("Like-to-view ratio within typical range")

    if "no_video_data" in flags:
        questioned.append("No video data available from YouTube")
    if "sub_to_view_above_typical" in flags:
        questioned.append("Subscriber-to-view ratio above typical range")
    if "like_ratio_below_typical" in flags:
        questioned.append("Like-to-view ratio below typical range")
    if "comment_ratio_below_typical" in flags:
        questioned.append("Comment-to-view ratio below typical range")
    if "view_volatility_high" in flags:
        questioned.append("High volatility across recent videos")
    if cs.get("fake_ratio", 0) > 0.3:
        questioned.append(f"{int(cs['fake_ratio'] * 100)}% of comments flagged by bot-pattern rules")
    if any(m.get("sentiment") == "negative" for m in mentions):
        questioned.append("Negative third-party mentions found")

    if not supported:
        supported.append("No strong positive signals detected in available data")
    if not questioned:
        questioned.append("No strong negative signals detected in available data")

    return {"supported": supported, "questioned": questioned}


# ── STEP 11: Format markdown report ──
def format_markdown_report(data: Dict[str, Any]) -> str:
    ch = data.get("channelInfo") or {}
    creator = ch.get("snippet", {}).get("title") or data.get("raw", "Target Creator")
    date = datetime.date.today().isoformat()
    cs = data.get("commentStats", {})
    mt = data.get("metrics", {})
    bd = data.get("breakdown", [])
    bal = data.get("balanced", {})
    mentions = data.get("webMentions", [])
    insufficient = data.get("insufficientData", False) or data.get("composite") is None

    pct = lambda v: f"{round(v * 100)}%"

    lines = []
    lines.append(f"# Investigation Report: {creator}")
    sources_str = "YouTube" + (", Web" if mentions else "")
    lines.append(f"**Generated:** {date}  |  **Domain:** {data.get('domain', 'general')}  |  **Sources:** {sources_str}")
    lines.append(f"**Coverage:** {cs.get('total', 0)} comments · {len(data.get('videos', []))} videos · {len(mentions)} external mentions")
    lines.append("")
    lines.append("---")
    lines.append("")

    if insufficient:
        lines.append("## ⚠️ Insufficient Data for Scoring")
        lines.append("")
        reason = data.get("lookupReason") or f"Only {cs.get('total', 0)} comments and {len(data.get('videos', []))} videos available. The composite indicator requires at least 10 comments and 3 videos."
        lines.append(reason)
        lines.append("")

    lines.append("## Comment Analysis")
    lines.append("")
    lines.append("| Category | Count | % |")
    lines.append("|---|---|---|")
    lines.append(f"| Total fetched | {cs.get('total', 0)} | 100% |")
    lines.append(f"| Filtered (possible bot/spam) | {cs.get('fake', 0)} | {pct(cs.get('fake_ratio', 0))} |")
    lines.append(f"| Organic — Positive | — | {pct(cs.get('positive_pct', 0))} |")
    lines.append(f"| Organic — Negative | — | {pct(cs.get('negative_pct', 0))} |")
    lines.append(f"| Organic — Neutral | — | {pct(cs.get('neutral_pct', 0))} |")
    lines.append("")

    samples = data.get("commentSamples", {})
    if samples and any(samples.values()):
        lines.append("### Representative Comment Samples")
        lines.append("")
        if samples.get("positive"):
            lines.append("**Organic Positive (Top Verified Audience Quotes):**")
            for s in samples["positive"][:3]:
                lines.append(f'- "{s}"')
            lines.append("")
        if samples.get("negative"):
            lines.append("**Organic Negative (Top Critical Audience Quotes):**")
            for s in samples["negative"][:3]:
                lines.append(f'- "{s}"')
            lines.append("")
        if samples.get("neutral"):
            lines.append("**Organic Neutral (Top Conversational Audience Quotes):**")
            for s in samples["neutral"][:3]:
                lines.append(f'- "{s}"')
            lines.append("")
        if samples.get("filtered"):
            lines.append("**Filtered Bot / Spam Patterns:**")
            for s in samples["filtered"][:3]:
                lines.append(f'- "{s}"')
            lines.append("")

    lines.append("## Engagement Signals")
    lines.append("")
    lines.append("| Metric | This creator | Typical range |")
    lines.append("|---|---|---|")
    subs_val = mt.get('subs', 0)
    subs_str = f"{(subs_val / 1000000):.2f}M" if subs_val >= 1000000 else (f"{(subs_val / 1000):.1f}K" if subs_val >= 1000 else str(subs_val))
    views_val = mt.get('avgViews', 0)
    views_str = f"{(views_val / 1000000):.2f}M" if views_val >= 1000000 else (f"{(views_val / 1000):.0f}K" if views_val >= 1000 else str(views_val))
    lines.append(f"| Subscribers | {subs_str} | — |")
    lines.append(f"| Avg Views | {views_str} | — |")
    lines.append(f"| Like-to-view | {((mt.get('likeToView', 0)) * 100):.2f}% | 1–5% |")
    lines.append(f"| Comment-to-view | {((mt.get('commentToView', 0)) * 100):.2f}% | 0.1–0.5% |")
    lines.append(f"| Sub-to-view | {mt.get('subToView', 0)}x | 1–5x |")
    lines.append(f"| View stability | {((mt.get('viewStability', 0)) * 100):.1f}% | > 50% |")
    lines.append("")

    lines.append("## Forensic Dimension Indicators")
    lines.append("")
    lines.append("| Forensic Dimension | Signal Rating (out of 5) |")
    lines.append("|---|---|")
    dim_names = {
        "fake_comment_score": "Bot / Spam Comments",
        "sentiment_score": "Audience Sentiment",
        "engagement_score": "Engagement Velocity",
        "transcript_credibility_score": "Transcript Verification",
        "negative_signal_score": "Negative Exposure Signals",
        "cross_platform_score": "Cross-Platform Footprint"
    }
    for b in bd:
        sc = "N/A" if b.get("raw") is None else f"{b.get('raw')} / 5"
        dim_label = dim_names.get(b.get('section'), b.get('section', '').replace('_', ' ').title())
        lines.append(f"| {dim_label} | {sc} |")
    lines.append("")

    lines.append("## ⚠️ Signals Raising Questions")
    lines.append("")
    for x in bal.get("questioned", []):
        lines.append(f"- {x}")
    lines.append("")

    lines.append("## ✅ Signals Supporting Credibility")
    lines.append("")
    for x in bal.get("supported", []):
        lines.append(f"- {x}")
    lines.append("")

    lines.append("## 🔎 External Mentions")
    lines.append("")
    if mentions:
        for m in mentions:
            src_part = f" — {m.get('source')}" if m.get("source") else ""
            link = m.get("link") or ""
            if link:
                lines.append(f"- [{m.get('sentiment')}] [{m.get('title')}]({link}){src_part}")
            else:
                lines.append(f"- [{m.get('sentiment')}] {m.get('title')}{src_part}")
    else:
        lines.append("- None found")
    lines.append("")

    lines.append("## 🧾 Methodology & Limitations")
    lines.append("")
    lines.append(f"- Only top {cs.get('total', 0)} comments analyzed (not full corpus)")
    lines.append("- Bot detection is heuristic, not certain")
    lines.append("- No fact-checking performed on claims made in videos")
    lines.append("- LLM scoring is probabilistic; treat as a signal, not ground truth")
    lines.append("")

    lines.append("## 💡 What You Could Do Next")
    lines.append("")
    lines.append("- Verify claims independently at: **PIB Fact Check**, **SEBI**, **cybercrime.gov.in**")
    lines.append("- Compare with peer creators in the same niche")
    lines.append("- Seek advice from a licensed professional before acting")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*This is an automated investigation. We do not conclude. Not legal or financial advice.*")

    return "\n".join(lines)


# ── STEP 12: Polish + Guardrails & Complete Runner ──
def run_complete_investigation_pipeline(raw_input: str) -> Dict[str, Any]:
    """
    Executes the exact 13-step Creator Trust Investigation Agent workflow natively.
    Zero n8n dependency.
    """
    clean_input = (raw_input or "").strip()
    logger.info(f"Starting native investigation pipeline for input: {clean_input[:80]}")

    # 1. Parse Input
    parsed = parse_input_and_classify_domain(clean_input)

    # 2. Load Rules
    rules = load_md_rules(parsed["domain"])

    # 3. Fetch YouTube Data
    yt_data = fetch_youtube_data(parsed)
    channel_info = yt_data.get("channelInfo") or {}

    # 4. Fetch Web Mentions
    creator_name = (channel_info.get("snippet") or {}).get("title") or parsed.get("id") or parsed.get("raw") or "Creator"
    tavily_data = fetch_web_mentions(creator_name)

    # 5. Filter Comments
    comments_data = filter_comments_and_split_sentiment(yt_data.get("comments") or [], rules)

    # 6. Compute Metrics
    metrics_data = compute_engagement_metrics(yt_data.get("videos") or [], channel_info)

    # 7 & 8. Build Prompt & Score with Gemma 4
    evidence = {
        "creator": creator_name,
        "domain": parsed["domain"],
        "dataAvailable": {
            "commentCount": comments_data["commentStats"]["total"],
            "videoCount": len(yt_data.get("videos", [])),
            "webMentionCount": len(tavily_data.get("webMentions", []))
        },
        "comments": comments_data["commentStats"],
        "samples": comments_data["commentSamples"],
        "metrics": metrics_data,
        "externalMentions": tavily_data.get("webMentions", [])[:10],
        "webSummary": tavily_data.get("tavilyAnswer")
    }
    scores = score_evidence_with_gemma_4(evidence)

    # 9. Weighted Composite
    composite_data = compute_weighted_composite(scores, rules["weights"])

    # 10. Balance Evidence
    pipeline_state = {
        **parsed,
        **yt_data,
        **tavily_data,
        **comments_data,
        "metrics": metrics_data,
        "scores": scores,
        **composite_data
    }
    balanced = balance_evidence(pipeline_state)
    pipeline_state["balanced"] = balanced

    # 11. Format Report
    report = format_markdown_report(pipeline_state)

    # 12. Guardrails check
    banned = rules.get("banned_words", [])
    own_text = "\n".join(
        line for line in report.split("\n")
        if not re.match(r"^- \[(negative|positive|neutral)\]", line)
    )
    found_banned = [w for w in banned if re.search(rf"\b{re.escape(w)}\b", own_text, re.IGNORECASE)]
    has_both_sides = "Signals Raising Questions" in report and "Signals Supporting Credibility" in report
    verdict_phrases = [r"\bis (a )?scam\b", r"\btrust score\b", r"\bverdict:\b"]
    verdict_leak = any(re.search(rx, own_text, re.IGNORECASE) for rx in verdict_phrases)

    guardrail = {
        "failed": len(found_banned) > 0 or not has_both_sides or verdict_leak,
        "banned_found": found_banned,
        "both_sides_present": has_both_sides,
        "verdict_leak": verdict_leak
    }

    composite_val = composite_data.get("composite") or 50.0

    return {
        "report": report,
        "guardrail": guardrail,
        "composite": composite_data.get("composite"),
        "insufficientData": composite_data.get("insufficientData", False),
        "balanced": balanced,
        "breakdown": composite_data.get("breakdown", []),
        "commentStats": comments_data["commentStats"],
        "commentSamples": comments_data.get("commentSamples", {}),
        "metrics": metrics_data,
        "scores": scores,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "query": clean_input,
        "risk_score": composite_val,
        "markdown_report": report,
        "risk_label": "High Risk Anomaly" if composite_val >= 70 else ("Moderate Signal Density" if composite_val >= 40 else "Low Risk Profile"),
        "externalMentions": tavily_data.get("webMentions", []),
        "mentions": tavily_data.get("webMentions", [])
    }


# Backwards-compatibility aliases
run_n8n_investigation = run_complete_investigation_pipeline
