"""
utils/advanced_search_engine.py — Advanced Search Engine (v2)
==============================================================

Upgrades over 4-Layer v1:
  Layer 1  : Exact handle / URL lookup                          [unchanged]
  Layer 2  : Fuzzy Levenshtein handle match (distance ≤ 2)     [unchanged]
  Layer 3  : Full-text search w/ TF-IDF scoring               [UPGRADED]
  Layer 4  : Company / recruiter name lookup                   [unchanged]
  Layer 5  : Phone / email / display-name direct lookup        [NEW]
  Layer 6  : Cross-platform identity grouping                  [NEW]
  Layer 7  : Alias transitive closure search                   [NEW]

Additional features:
  • Paginated results  (limit / offset)
  • Autocomplete suggestions endpoint
  • Trend spike detection  (recent 7d vs lifetime report ratio)
  • Cross-platform cluster grouping by normalized handle
  • Search audit logging for analytics
"""

from __future__ import annotations

import datetime
import math
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.community_reporting import (
    CommunityReportingEngine,
    levenshtein_distance,
    normalize_company,
    normalize_handle,
    redact_sample_message,
)
from utils.community_schemas import ModerationTierEnum, SearchResultCard, SearchResponse


# ─────────────────────────────────────────────────────────────────────────────
# Helper: TF-IDF Scorer
# ─────────────────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> List[str]:
    """Lowercase word tokenizer, strips punctuation."""
    return re.findall(r"[a-z0-9]{2,}", text.lower())


def _build_tfidf_index(documents: List[str]) -> Tuple[List[Dict[str, float]], Dict[str, float]]:
    """
    Build TF-IDF vectors for a list of document strings.

    Returns:
        tf_vectors  : List of {term: tf_score} dicts (one per doc)
        idf_scores  : {term: idf_score} global dict
    """
    N = len(documents)
    if N == 0:
        return [], {}

    df: Dict[str, int] = defaultdict(int)  # document frequency
    tf_vectors: List[Dict[str, float]] = []

    for doc in documents:
        tokens = _tokenize(doc)
        token_count = len(tokens) or 1
        freq: Dict[str, int] = defaultdict(int)
        for t in tokens:
            freq[t] += 1
        # TF = frequency / total tokens
        tf_vec = {t: cnt / token_count for t, cnt in freq.items()}
        tf_vectors.append(tf_vec)
        for t in freq:
            df[t] += 1

    # IDF = log(N / df)
    idf_scores = {t: math.log(N / d) for t, d in df.items()}
    return tf_vectors, idf_scores


def _tfidf_similarity(query_tokens: List[str], tf_vec: Dict[str, float], idf_scores: Dict[str, float]) -> float:
    """Cosine-style similarity between query terms and a TF-IDF document vector."""
    if not query_tokens or not tf_vec:
        return 0.0
    score = 0.0
    for t in query_tokens:
        if t in tf_vec:
            score += tf_vec[t] * idf_scores.get(t, 0.0)
    # Normalize by query length for fairness
    return score / len(query_tokens)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Phone / Email pattern normalization
# ─────────────────────────────────────────────────────────────────────────────

def _extract_phone(text: str) -> Optional[str]:
    """Extract and normalize 10-digit phone number from text."""
    phone = re.search(r"(\+?91[-.\s]?)?(\d[\d\s.\-]{8,}\d)", text)
    if phone:
        digits = re.sub(r"\D", "", phone.group())
        if len(digits) >= 10:
            return digits[-10:]
    return None


def _extract_email(text: str) -> Optional[str]:
    """Extract email and return lowercased."""
    match = re.search(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    return match.group().lower() if match else None


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Trend Spike Detector
# ─────────────────────────────────────────────────────────────────────────────

def _compute_trend_score(cluster: Dict[str, Any]) -> float:
    """
    Returns a 0.0–1.0 trend score.
    High score = reports are recent (spike in last 7 days).
    """
    recent_reports = cluster.get("recent_7d_count", 0)
    total_reports = cluster.get("report_count", 1)

    if total_reports == 0:
        return 0.0

    # Count reports submitted in last 7 days from report_ids via engine
    ratio = min(recent_reports / total_reports, 1.0)
    return round(ratio, 3)


def _count_recent_reports(cluster: Dict[str, Any], engine: "AdvancedSearchEngine") -> int:
    """Count reports submitted within last 7 days for a cluster."""
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=7)
    count = 0
    for r_id in cluster.get("report_ids", []):
        rep = engine.get_report_by_id(r_id)
        if rep:
            try:
                ts = datetime.datetime.fromisoformat(rep["created_at"].replace("Z", ""))
                if ts >= cutoff:
                    count += 1
            except (ValueError, KeyError):
                pass
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Extended Search Result Card (adds advanced fields)
# ─────────────────────────────────────────────────────────────────────────────

class AdvancedSearchResultCard(SearchResultCard):
    trend_score: float = 0.0               # 0.0–1.0 spike score
    trend_label: str = "stable"            # "spiking" | "rising" | "stable"
    recent_7d_count: int = 0              # reports in last 7 days
    cross_platform_hits: List[str] = []   # other platforms where same handle found
    layer_matched: str = "exact_handle"   # which search layer matched


class AdvancedSearchResponse(SearchResponse):
    results: List[AdvancedSearchResultCard] = []
    total_matches: int = 0
    page: int = 1
    page_size: int = 20
    total_pages: int = 1
    search_took_ms: float = 0.0
    autocomplete_hints: List[str] = []


class AutocompleteResponse(SearchResponse):
    suggestions: List[str] = []
    results: List[SearchResultCard] = []


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Search Engine — extends CommunityReportingEngine
# ─────────────────────────────────────────────────────────────────────────────

class AdvancedSearchEngine(CommunityReportingEngine):
    """
    Drop-in replacement for CommunityReportingEngine with advanced search.
    All existing report/corroborate/dispute/moderate APIs remain identical.
    """

    def __init__(self):
        super().__init__()

        # Pre-build TF-IDF index on first use (lazy, rebuilt on demand)
        self._tfidf_dirty = True
        self._tfidf_corpus: List[str] = []
        self._tfidf_cluster_keys: List[str] = []
        self._tf_vectors: List[Dict[str, float]] = []
        self._idf_scores: Dict[str, float] = {}

        # Alias graph: handle_norm → set of cluster_keys
        self._alias_graph: Dict[str, Set[str]] = defaultdict(set)

        # Phone / email index: value → cluster_key
        self._contact_index: Dict[str, List[str]] = defaultdict(list)

        # Cross-platform index: handle_norm → list of platforms
        self._xplatform_index: Dict[str, List[str]] = defaultdict(list)

        self._rebuild_indexes()

    # ── Index Management ──────────────────────────────────────────────────────

    def _rebuild_indexes(self):
        """Rebuild all secondary indexes from current clusters."""
        self._alias_graph.clear()
        self._contact_index.clear()
        self._xplatform_index.clear()

        corpus = []
        keys = []

        for key, c in self.clusters.items():
            handle_n = c.get("handle_normalized", "")
            platform = c.get("platform", "other")

            # TF-IDF corpus: combine sample messages + category labels
            doc_parts = c.get("sample_messages", []) + c.get("matched_categories", [])
            corpus_doc = " ".join(doc_parts)
            corpus.append(corpus_doc)
            keys.append(key)

            # Alias graph
            self._alias_graph[handle_n].add(key)
            for alias in c.get("linked_aliases", []):
                self._alias_graph[alias].add(key)

            # Cross-platform index
            if handle_n:
                self._xplatform_index[handle_n].append(platform)

            # Contact index: scan original reports for phones/emails
            for r_id in c.get("report_ids", []):
                rep = self.get_report_by_id(r_id)
                if rep:
                    raw_text = rep.get("message_text", "")
                    phone = _extract_phone(raw_text)
                    email = _extract_email(raw_text)
                    if phone:
                        self._contact_index[phone].append(key)
                    if email:
                        self._contact_index[email].append(key)

                    # Also index display name
                    display = (rep.get("identifier") or {}).get("display_name_seen", "")
                    if display:
                        dnorm = re.sub(r"[^a-z0-9]", "", display.lower())
                        if len(dnorm) >= 3:
                            self._contact_index[dnorm].append(key)

        # Build TF-IDF
        self._tfidf_corpus = corpus
        self._tfidf_cluster_keys = keys
        self._tf_vectors, self._idf_scores = _build_tfidf_index(corpus)
        self._tfidf_dirty = False

    def invalidate_indexes(self):
        """Call after any mutation to force index rebuild on next search."""
        self._tfidf_dirty = True

    # ── Alias Transitive Closure ──────────────────────────────────────────────

    def _alias_closure(self, handle_norm: str) -> Set[str]:
        """
        BFS over alias graph to find all cluster_keys reachable from handle_norm.
        Handles A→B→C chains.
        """
        visited_handles: Set[str] = set()
        result_keys: Set[str] = set()
        queue = [handle_norm]

        while queue:
            h = queue.pop()
            if h in visited_handles:
                continue
            visited_handles.add(h)

            cluster_keys = self._alias_graph.get(h, set())
            for key in cluster_keys:
                result_keys.add(key)
                cluster = self.clusters.get(key, {})
                for alias in cluster.get("linked_aliases", []):
                    if alias not in visited_handles:
                        queue.append(alias)

        return result_keys

    # ── Card Builder (Advanced) ───────────────────────────────────────────────

    def _make_advanced_card(
        self,
        c: Dict[str, Any],
        match_type: str,
        match_score: float,
        recent_7d: Optional[int] = None,
    ) -> AdvancedSearchResultCard:
        tier = c.get("status", ModerationTierEnum.UNCONFIRMED.value)
        handle_n = c.get("handle_normalized", "")

        # Trend computation
        if recent_7d is None:
            recent_7d = _count_recent_reports(c, self)
        trend_score = round(min(recent_7d / max(c.get("report_count", 1), 1), 1.0), 3)
        if trend_score >= 0.6:
            trend_label = "spiking"
        elif trend_score >= 0.3:
            trend_label = "rising"
        else:
            trend_label = "stable"

        # Cross-platform hits
        xp = self._xplatform_index.get(handle_n, [])
        cross = [p for p in xp if p != c.get("platform", "")]

        return AdvancedSearchResultCard(
            cluster_key=c["cluster_key"],
            platform=c["platform"],
            handle_raw=c.get("handle_raw", "@" + handle_n),
            handle_normalized=handle_n,
            display_name_seen=c.get("display_name_seen"),
            company_name_seen=c.get("company_name_seen"),
            status=ModerationTierEnum(tier),
            status_badge=self.get_badge_text(tier),
            report_count=c.get("report_count", 1),
            first_reported_at=c.get("first_reported_at", ""),
            last_reported_at=c.get("last_reported_at", ""),
            matched_categories=c.get("matched_categories", ["Scam"]),
            sample_messages_redacted=c.get("sample_messages", []),
            known_aliases=c.get("linked_aliases", []),
            match_type=match_type,
            match_score=match_score,
            trend_score=trend_score,
            trend_label=trend_label,
            recent_7d_count=recent_7d,
            cross_platform_hits=cross,
            layer_matched=match_type,
        )

    # ── Main Advanced Search ──────────────────────────────────────────────────

    def advanced_search(
        self,
        query: str,
        platform_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        tier_filter: Optional[str] = None,
        include_unconfirmed: bool = False,
        page: int = 1,
        page_size: int = 20,
    ) -> AdvancedSearchResponse:
        """
        7-Layer Advanced Search with pagination, trend info, and cross-platform grouping.

        Layers:
          1. Exact handle / URL
          2. Fuzzy Levenshtein handle (distance ≤ 2)
          3. TF-IDF full-text message similarity
          4. Company / recruiter name
          5. Phone / email / display name direct lookup
          6. Cross-platform identity grouping
          7. Alias transitive closure

        Args:
            query           : Search string (handle, URL, name, phone, email, message text)
            platform_filter : Filter by platform slug e.g. "instagram"
            category_filter : Filter by category label substring
            tier_filter     : Filter by status tier e.g. "confirmed"
            include_unconfirmed: Also return unconfirmed / rejected results
            page            : Page number (1-indexed)
            page_size       : Results per page (max 100)

        Returns:
            AdvancedSearchResponse with paginated results, trend metadata, autocomplete hints
        """
        import time
        t0 = time.monotonic()

        # Rebuild indexes if dirty (mutations happened since last search)
        if self._tfidf_dirty:
            self._rebuild_indexes()

        query_strip = query.strip()
        if not query_strip:
            return AdvancedSearchResponse(query=query, total_matches=0, results=[])

        query_norm = normalize_handle(query_strip)
        query_company = normalize_company(query_strip)
        query_phone = _extract_phone(query_strip)
        query_email = _extract_email(query_strip)
        query_display = re.sub(r"[^a-z0-9]", "", query_strip.lower())
        query_tokens = _tokenize(query_strip)

        cards: Dict[str, AdvancedSearchResultCard] = {}  # cluster_key → best card
        seen_keys: Set[str] = set()

        def _add_or_upgrade(c: Dict, mtype: str, score: float):
            """Add card if not seen, or upgrade if new score is higher."""
            key = c["cluster_key"]
            if key not in seen_keys or score > cards[key].match_score:
                cards[key] = self._make_advanced_card(c, mtype, score)
                seen_keys.add(key)

        def _passes_filters(c: Dict) -> bool:
            tier = c.get("status", ModerationTierEnum.UNCONFIRMED.value)
            if not include_unconfirmed and tier in [
                ModerationTierEnum.UNCONFIRMED.value,
                ModerationTierEnum.REJECTED.value,
            ]:
                return False
            if platform_filter and c.get("platform", "").lower() != platform_filter.lower():
                return False
            if category_filter and not any(
                category_filter.lower() in cat.lower() for cat in c.get("matched_categories", [])
            ):
                return False
            if tier_filter and c.get("status", "") != tier_filter:
                return False
            return True

        # ── Layer 5: Contact / display-name direct lookup (highest priority for specifics) ──
        layer5_keys: Set[str] = set()
        if query_phone and query_phone in self._contact_index:
            for key in self._contact_index[query_phone]:
                c = self.clusters.get(key)
                if c and _passes_filters(c):
                    _add_or_upgrade(c, "phone_match", 1.0)
                    layer5_keys.add(key)
        if query_email and query_email in self._contact_index:
            for key in self._contact_index[query_email]:
                c = self.clusters.get(key)
                if c and _passes_filters(c):
                    _add_or_upgrade(c, "email_match", 0.98)
                    layer5_keys.add(key)
        if len(query_display) >= 4 and query_display in self._contact_index:
            for key in self._contact_index[query_display]:
                c = self.clusters.get(key)
                if c and _passes_filters(c):
                    _add_or_upgrade(c, "display_name_match", 0.95)
                    layer5_keys.add(key)

        # ── Layer 7: Alias transitive closure ──────────────────────────────────
        alias_cluster_keys = self._alias_closure(query_norm)
        for key in alias_cluster_keys:
            c = self.clusters.get(key)
            if c and _passes_filters(c) and key not in seen_keys:
                # Determine score based on whether it's direct or transitive
                handle_n = c.get("handle_normalized", "")
                is_direct = handle_n == query_norm or query_norm in c.get("linked_aliases", [])
                score = 1.0 if is_direct else 0.85
                _add_or_upgrade(c, "alias_closure", score)

        # ── Main cluster scan ──────────────────────────────────────────────────
        for idx, (key, c) in enumerate(self.clusters.items()):
            if not _passes_filters(c):
                continue

            handle_n = c.get("handle_normalized", "")
            company_n = c.get("company_name_normalized", "")
            aliases = c.get("linked_aliases", [])

            # ── Layer 1: Exact handle ──────────────────────────────────────────
            if query_norm == handle_n:
                _add_or_upgrade(c, "exact_handle", 1.0)
                continue

            # ── Layer 2: Fuzzy Levenshtein ────────────────────────────────────
            if len(query_norm) >= 3 and handle_n:
                dist = levenshtein_distance(query_norm, handle_n)
                if dist <= 2:
                    score = round(1.0 - (dist / max(len(query_norm), len(handle_n), 1)), 3)
                    _add_or_upgrade(c, "fuzzy_handle", score)
                    continue

            # ── Layer 4: Company name ──────────────────────────────────────────
            if query_company and company_n and len(query_company) >= 4:
                if query_company in company_n or company_n in query_company:
                    _add_or_upgrade(c, "company_name", 0.90)
                    continue

            # ── Layer 3: TF-IDF + Jaccard hybrid full-text ────────────────────
            if query_tokens and idx < len(self._tf_vectors):
                tfidf_score = _tfidf_similarity(query_tokens, self._tf_vectors[idx], self._idf_scores)
                # Normalize to 0–1
                tfidf_norm = min(tfidf_score * 5.0, 1.0)

                # Jaccard fallback: word overlap / query length (robust with N=1 corpus)
                corpus_text = self._tfidf_corpus[idx] if idx < len(self._tfidf_corpus) else ""
                corpus_tokens_set = set(_tokenize(corpus_text))
                query_tokens_set = set(query_tokens)
                if query_tokens_set:
                    jaccard = len(query_tokens_set & corpus_tokens_set) / len(query_tokens_set)
                else:
                    jaccard = 0.0

                # Use whichever is higher
                best_text_score = max(tfidf_norm, jaccard)
                if best_text_score >= 0.35:
                    _add_or_upgrade(c, "message_tfidf", round(best_text_score, 3))
                    continue

            # ── Layer 6: Cross-platform identity ──────────────────────────────
            # If query handle appears in any platform for this handle_norm
            if handle_n and query_norm and handle_n == query_norm:
                _add_or_upgrade(c, "cross_platform", 0.95)

        # ── Sorting: confirmed > corroborated > others, then score, then trend ──
        tier_order = {
            ModerationTierEnum.CONFIRMED.value: 5,
            ModerationTierEnum.CORROBORATED.value: 4,
            ModerationTierEnum.DISPUTED.value: 3,
            ModerationTierEnum.UNCONFIRMED.value: 2,
            ModerationTierEnum.REJECTED.value: 1,
        }

        all_cards = list(cards.values())
        all_cards.sort(
            key=lambda x: (
                tier_order.get(x.status.value, 0),
                x.match_score,
                x.trend_score,
                x.report_count,
            ),
            reverse=True,
        )

        # Pagination
        page = max(1, page)
        page_size = min(max(1, page_size), 100)
        total = len(all_cards)
        total_pages = max(1, math.ceil(total / page_size))
        start = (page - 1) * page_size
        end = start + page_size
        paged_cards = all_cards[start:end]

        # Autocomplete hints from confirmed/corroborated handles
        hints = self._build_autocomplete_hints(query_strip, limit=5, include_unconfirmed=include_unconfirmed)

        elapsed_ms = round((time.monotonic() - t0) * 1000, 2)

        return AdvancedSearchResponse(
            query=query,
            total_matches=total,
            results=paged_cards,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            search_took_ms=elapsed_ms,
            autocomplete_hints=hints,
        )

    # ── Autocomplete ──────────────────────────────────────────────────────────

    def _build_autocomplete_hints(
        self,
        prefix: str,
        limit: int = 10,
        include_unconfirmed: bool = False,
    ) -> List[str]:
        """
        Return sorted list of handle suggestions matching prefix.
        Only returns handles from corroborated/confirmed clusters unless include_unconfirmed.
        """
        prefix_norm = re.sub(r"[^a-z0-9]", "", prefix.lower())
        if len(prefix_norm) < 2:
            return []

        suggestions: List[Tuple[int, str]] = []  # (report_count, handle)

        for key, c in self.clusters.items():
            tier = c.get("status", "")
            if not include_unconfirmed and tier in [
                ModerationTierEnum.UNCONFIRMED.value,
                ModerationTierEnum.REJECTED.value,
            ]:
                continue

            handle_n = c.get("handle_normalized", "")
            if handle_n.startswith(prefix_norm) and handle_n != prefix_norm:
                label = f"@{c.get('handle_raw', handle_n)} ({c.get('platform', '')})"
                suggestions.append((c.get("report_count", 1), label))

            # Also suggest company names
            company_n = c.get("company_name_normalized", "") or ""
            if company_n.startswith(prefix_norm):
                company_raw = c.get("company_name_seen", company_n)
                label = f'"{company_raw}" (company)'
                suggestions.append((c.get("report_count", 1), label))

        # Sort by report count desc and return top N
        suggestions.sort(key=lambda x: x[0], reverse=True)
        return [s[1] for s in suggestions[:limit]]

    def get_autocomplete(
        self,
        prefix: str,
        limit: int = 10,
        include_unconfirmed: bool = False,
    ) -> Dict[str, Any]:
        """Public autocomplete endpoint handler."""
        if self._tfidf_dirty:
            self._rebuild_indexes()
        suggestions = self._build_autocomplete_hints(prefix, limit, include_unconfirmed)
        return {
            "prefix": prefix,
            "suggestions": suggestions,
            "count": len(suggestions),
        }

    # ── Cross-Platform Profile Linker ─────────────────────────────────────────

    def get_cross_platform_profile(self, handle_raw: str) -> Dict[str, Any]:
        """
        Return all clusters across all platforms matching this normalized handle.
        Useful to see if the same scammer operates on Instagram, LinkedIn, and WhatsApp.
        """
        if self._tfidf_dirty:
            self._rebuild_indexes()

        handle_norm = normalize_handle(handle_raw)
        platform_data: List[Dict[str, Any]] = []

        for key, c in self.clusters.items():
            if c.get("handle_normalized") == handle_norm:
                platform_data.append({
                    "platform": c.get("platform"),
                    "cluster_key": key,
                    "handle_raw": c.get("handle_raw"),
                    "report_count": c.get("report_count", 1),
                    "status": c.get("status"),
                    "status_badge": self.get_badge_text(c.get("status", "")),
                    "last_reported_at": c.get("last_reported_at", ""),
                    "matched_categories": c.get("matched_categories", []),
                })

        # Also traverse aliases
        alias_keys = self._alias_closure(handle_norm)
        for key in alias_keys:
            c = self.clusters.get(key)
            if c and c["cluster_key"] not in [p["cluster_key"] for p in platform_data]:
                platform_data.append({
                    "platform": c.get("platform"),
                    "cluster_key": key,
                    "handle_raw": c.get("handle_raw"),
                    "report_count": c.get("report_count", 1),
                    "status": c.get("status"),
                    "status_badge": self.get_badge_text(c.get("status", "")),
                    "last_reported_at": c.get("last_reported_at", ""),
                    "matched_categories": c.get("matched_categories", []),
                    "linked_via_alias": True,
                })

        total_reports = sum(p["report_count"] for p in platform_data)
        return {
            "handle_normalized": handle_norm,
            "handle_raw_query": handle_raw,
            "platforms_found": len(platform_data),
            "total_reports_all_platforms": total_reports,
            "platform_breakdown": sorted(platform_data, key=lambda x: x["report_count"], reverse=True),
        }

    # ── Override: submit_report invalidates index on write ───────────────────

    async def submit_report(self, req):
        result = await super().submit_report(req)
        self.invalidate_indexes()
        return result

    async def moderate_action(self, req):
        result = await super().moderate_action(req)
        self.invalidate_indexes()
        return result


# Global singleton of the advanced engine (replaces reporting_engine)
advanced_engine = AdvancedSearchEngine()
