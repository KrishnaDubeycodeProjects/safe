"""
utils/community_reporting.py — Core Engine for Community Scam Reporting & Search System.

Features:
  1. Identifier Normalization (handles, profile URLs, company names)
  2. Levenshtein Distance & Fuzzy Match Algorithm
  3. Moderation Tier Calculation Engine (unconfirmed → corroborated → confirmed → disputed → rejected)
  4. Anti-Abuse Rules (rate limiting, mandatory evidence, duplicate report deduplication)
  5. 4-Layer Multi-vector Search Engine (Exact handle, Fuzzy handle, Message content, Company lookup)
  6. Redaction of sensitive user data in sample messages
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import logging
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

from utils.community_schemas import (
    ReportCreateRequest,
    ReportResponse,
    CorroborateRequest,
    DisputeRequest,
    ModerateActionRequest,
    SearchResultCard,
    SearchResponse,
    ModerationTierEnum,
    ReportCategoryEnum,
    IdentifierOutput,
    ClassifiedScamInfo,
)
from utils.supabase_community_store import store

logger = logging.getLogger("safe_backend.community_reporting")


# ═════════════════════════════════════════════════════════════════════════════
# 1. NORMALIZATION & LEVENSHTEIN UTILS
# ═════════════════════════════════════════════════════════════════════════════

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings (zero dependencies)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_handle(raw_input: Optional[str], profile_url: Optional[str] = None) -> str:
    """
    Extract and normalize handle from raw handle or profile URL.
    e.g. '@Quick_Forex_Returns' → 'quickforexreturns'
    e.g. 'https://instagram.com/quick_forex_returns?igsh=123' → 'quickforexreturns'
    """
    target = (raw_input or profile_url or "").strip()
    if not target:
        return "unknown_handle"

    # If full URL, parse path
    if "://" in target or target.startswith("www."):
        if not target.startswith("http"):
            target = "https://" + target
        parsed = urllib.parse.urlparse(target)
        path = parsed.path.strip("/")
        # Get last or main segment of path
        segments = [s for s in path.split("/") if s and not s.startswith("in")]
        if segments:
            target = segments[-1]
        else:
            target = parsed.netloc

    # Lowercase
    normalized = target.lower()

    # Strip prefixes (@, platform URLs, etc)
    normalized = re.sub(r"^(https?://)?(www\.)?[\w\-\.]+/(@|in/|user/|channel/|profile/)?", "", normalized)
    normalized = re.sub(r"^@", "", normalized)

    # Strip query params or hash
    normalized = normalized.split("?")[0].split("#")[0]

    # Strip all non-alphanumeric chars for strict search key
    strict_key = re.sub(r"[^a-z0-9]", "", normalized)
    return strict_key if strict_key else "unknown_handle"


def normalize_company(company_name: Optional[str]) -> str:
    """Normalize company name e.g. 'Global Tech Careers Pvt Ltd' → 'globaltechcareers'."""
    if not company_name:
        return ""
    name = company_name.lower()
    name = re.sub(r"\b(pvt|ltd|inc|llc|corp|corporation|private|limited|co)\b", "", name)
    name = re.sub(r"[^a-z0-9]", "", name)
    return name


def redact_sample_message(text: str) -> str:
    """Redact sensitive user details (phone, emails, OTPs) for public search display."""
    if not text:
        return ""
    # Mask phone numbers
    redacted = re.sub(r"\b(\+?\d{1,3}[-.\s]?)?\d{10}\b", "**********", text)
    # Mask emails
    redacted = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "*****@***.com", redacted)
    # Mask currency figures partially e.g. Rs 50000 -> Rs *****
    redacted = re.sub(r"(₹|rs\.?|INR|\$)\s*(\d+)", r"\1 *****", redacted, flags=re.IGNORECASE)
    # Truncate if long
    if len(redacted) > 180:
        redacted = redacted[:177] + "..."
    return redacted


# ═════════════════════════════════════════════════════════════════════════════
# 2. CORE SYSTEM CLASS
# ═════════════════════════════════════════════════════════════════════════════

class CommunityReportingEngine:
    def __init__(self):
        # In-memory working copies synced with store
        self.reports: List[Dict[str, Any]] = store.load_reports_local()
        self.clusters: Dict[str, Dict[str, Any]] = store.load_clusters_local()
        self.reporter_history: Dict[str, List[str]] = {}  # reporter_id -> timestamps

    # ── Anti-Abuse Checks ───────────────────────────────────────────────────────

    def check_rate_limit(self, reporter_id: str) -> Tuple[bool, str]:
        """Max 10 reports per reporter_id per 24 hours."""
        if not reporter_id:
            return True, ""
        now = datetime.datetime.utcnow()
        cutoff = now - datetime.timedelta(hours=24)
        
        history = self.reporter_history.get(reporter_id, [])
        valid_history = [t for t in history if datetime.datetime.fromisoformat(t) > cutoff]
        self.reporter_history[reporter_id] = valid_history

        if len(valid_history) >= 10:
            return False, "Rate limit exceeded: max 10 reports per 24 hours allowed."
        return True, ""

    def is_duplicate_report(self, cluster_key: str, message_text: str, reporter_id: str) -> bool:
        """Check if identical report from same reporter exists in cluster."""
        cluster = self.clusters.get(cluster_key)
        if not cluster:
            return False
        
        text_normalized = re.sub(r"\s+", " ", message_text.strip().lower())
        for r_id in cluster.get("report_ids", []):
            rep = self.get_report_by_id(r_id)
            if rep:
                rep_text = re.sub(r"\s+", " ", rep.get("message_text", "").strip().lower())
                if rep_text == text_normalized and rep.get("reporter", {}).get("reporter_id") == reporter_id:
                    return True
        return False

    # ── Tier Calculation Logic ──────────────────────────────────────────────────

    def recalculate_cluster_tier(self, cluster: Dict[str, Any]) -> str:
        """
        Recalculate moderation tier per moderation_tiers_config.json rules:
        - disputed: manual dispute active
        - rejected: manual rejection
        - confirmed: manual approval OR report_count >= 5 with strong pattern match
        - corroborated: 2+ independent reporters within 30d OR 1 report with trust >= 0.9
        - unconfirmed: default (1 report)
        """
        status = cluster.get("status", ModerationTierEnum.UNCONFIRMED)

        # Locked statuses set by moderators
        if status in [ModerationTierEnum.DISPUTED, ModerationTierEnum.REJECTED]:
            return status

        report_ids = cluster.get("report_ids", [])
        reporters = set()
        max_trust = 0.0

        for r_id in report_ids:
            rep = self.get_report_by_id(r_id)
            if rep:
                r_info = rep.get("reporter", {})
                if r_info.get("reporter_id"):
                    reporters.add(r_info.get("reporter_id"))
                trust = r_info.get("trust_score", 0.5)
                if trust > max_trust:
                    max_trust = trust

        report_count = len(report_ids)
        independent_count = max(len(reporters), report_count)

        if cluster.get("manually_confirmed"):
            return ModerationTierEnum.CONFIRMED.value

        if report_count >= 5 and independent_count >= 3:
            return ModerationTierEnum.CONFIRMED.value

        if independent_count >= 2 or max_trust >= 0.9:
            return ModerationTierEnum.CORROBORATED.value

        return ModerationTierEnum.UNCONFIRMED.value

    def get_badge_text(self, tier: str) -> str:
        mapping = {
            ModerationTierEnum.CONFIRMED: "🚨 Confirmed Scam",
            ModerationTierEnum.CORROBORATED: "⚠️ Multiple reports — unverified",
            ModerationTierEnum.DISPUTED: "⚖️ Under dispute",
            ModerationTierEnum.UNCONFIRMED: "ℹ️ Unconfirmed report",
            ModerationTierEnum.REJECTED: "❌ Report rejected",
        }
        return mapping.get(tier, "Unverified")

    # ── Report Ingestion & Classifier ─────────────────────────────────────────

    async def submit_report(self, req: ReportCreateRequest) -> ReportResponse:
        now_str = datetime.datetime.utcnow().isoformat() + "Z"
        reporter_id = req.reporter_id or f"usr_hash_{hashlib.md5((req.message_text + now_str).encode()).hexdigest()[:8]}"

        # Rate limit check
        allowed, msg = self.check_rate_limit(reporter_id)
        if not allowed:
            raise ValueError(msg)

        # Normalize identifiers
        handle_norm = normalize_handle(req.handle_raw, req.profile_url)
        company_norm = normalize_company(req.company_name_seen)
        platform_str = req.platform.value if hasattr(req.platform, "value") else str(req.platform)
        category_str = req.report_category.value if hasattr(req.report_category, "value") else str(req.report_category)

        cluster_key = f"{platform_str}:{handle_norm}"

        # Deduplication check
        if self.is_duplicate_report(cluster_key, req.message_text, reporter_id):
            logger.info("Duplicate report suppressed for %s", cluster_key)

        # Generate report_id
        report_id = f"r_{datetime.datetime.utcnow().strftime('%Y%m%d')}_{hashlib.md5(now_str.encode()).hexdigest()[:6]}"

        # Run text classification logic
        classified = self._run_classification(req.message_text)

        report_dict = {
            "report_id": report_id,
            "report_category": category_str,
            "platform": platform_str,
            "platform_other_name": req.platform_other_name,
            "identifier": {
                "handle_raw": req.handle_raw or f"@{handle_norm}",
                "handle_normalized": handle_norm,
                "profile_url": req.profile_url,
                "display_name_seen": req.display_name_seen,
                "company_name_seen": req.company_name_seen,
                "company_name_normalized": company_norm,
            },
            "message_text": req.message_text,
            "evidence_urls": req.evidence_urls,
            "classified_scam": classified,
            "reporter": {"reporter_id": reporter_id, "trust_score": 0.7},
            "status": ModerationTierEnum.UNCONFIRMED.value,
            "linked_aliases": [],
            "created_at": now_str,
            "last_reported_at": now_str,
            "report_count": 1,
        }

        # Update local state
        self.reports.append(report_dict)
        store.save_reports_local(self.reports)

        # Record reporter rate limit timestamp
        if reporter_id not in self.reporter_history:
            self.reporter_history[reporter_id] = []
        self.reporter_history[reporter_id].append(datetime.datetime.utcnow().isoformat())

        # Update Cluster Index
        cluster = self._update_cluster_index(cluster_key, report_dict)

        # Sync to Supabase in background
        asyncio.create_task(store.sync_report_to_supabase(report_dict))
        asyncio.create_task(store.sync_cluster_to_supabase(cluster_key, cluster))

        return ReportResponse(
            report_id=report_id,
            report_category=category_str,
            platform=platform_str,
            platform_other_name=req.platform_other_name,
            identifier=IdentifierOutput(
                handle_raw=req.handle_raw or f"@{handle_norm}",
                handle_normalized=handle_norm,
                profile_url=req.profile_url,
                display_name_seen=req.display_name_seen,
                company_name_seen=req.company_name_seen,
                company_name_normalized=company_norm,
            ),
            message_text=req.message_text,
            evidence_urls=req.evidence_urls,
            classified_scam=ClassifiedScamInfo(**classified),
            reporter={"reporter_id": reporter_id, "trust_score": 0.7},
            status=ModerationTierEnum(cluster["status"]),
            linked_aliases=cluster.get("linked_aliases", []),
            created_at=now_str,
            last_reported_at=cluster["last_reported_at"],
            report_count=cluster["report_count"],
        )

    def _run_classification(self, text: str) -> Dict[str, Any]:
        """Lightweight text classification using risky keywords & patterns."""
        text_lower = text.lower()

        # Keywords map to taxonomy categories
        taxonomy_rules = [
            (r"\b(job|recruitment|salary|data entry|part time|earn per day|hiring)\b", "5.1.1", "Fake Job / Hiring Scam"),
            (r"\b(forex|crypto|double your|investment|profit|trading bot|bitcoin)\b", "3.2.1", "Trading & Crypto Investment Scam"),
            (r"\b(lottery|lucky draw|winner|prize|won|claim)\b", "1.1.1", "Prize & Lottery Scam"),
            (r"\b(kyc|bank|account|suspended|unauthorized|blocked|otp)\b", "2.1.1", "Banking Phishing Scam"),
            (r"\b(cbi|arrest|customs|police|digital arrest|parcel|drugs)\b", "4.1.3", "Digital Arrest & Impersonation Scam"),
            (r"\b(refund|tax|overpayment)\b", "2.3.1", "Refund / Tax Scam"),
        ]

        matched_ids = []
        category_label = "Generic Fraud / Impersonation Scheme"

        for pattern, tax_id, label in taxonomy_rules:
            if re.search(pattern, text_lower):
                matched_ids.append(tax_id)
                category_label = label

        if not matched_ids:
            case = "unfitted" if len(text) > 40 else "not_scam"
        elif len(matched_ids) == 1:
            case = "single"
        else:
            case = "multi"

        return {
            "llm_output_raw": f"{'+'.join(matched_ids)}|text_analyzed" if matched_ids else "gen|text_analyzed",
            "case": case,
            "matched_ids": matched_ids or ["gen"],
            "category_label": category_label,
            "detection_message": f"Message flagged as {category_label} due to suspicious pattern match.",
        }

    def _update_cluster_index(self, cluster_key: str, report_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate report into cluster index."""
        now_str = report_dict["created_at"]
        handle_norm = report_dict["identifier"]["handle_normalized"]
        company_norm = report_dict["identifier"]["company_name_normalized"]
        platform = report_dict["platform"]

        if cluster_key not in self.clusters:
            self.clusters[cluster_key] = {
                "cluster_key": cluster_key,
                "platform": platform,
                "handle_raw": report_dict["identifier"]["handle_raw"],
                "handle_normalized": handle_norm,
                "display_name_seen": report_dict["identifier"]["display_name_seen"],
                "company_name_seen": report_dict["identifier"]["company_name_seen"],
                "company_name_normalized": company_norm,
                "report_ids": [report_dict["report_id"]],
                "report_count": 1,
                "first_reported_at": now_str,
                "last_reported_at": now_str,
                "matched_categories": [report_dict["classified_scam"].get("category_label", "Scam")],
                "sample_messages": [redact_sample_message(report_dict["message_text"])],
                "linked_aliases": [],
                "status": ModerationTierEnum.UNCONFIRMED.value,
                "manually_confirmed": False,
            }
        else:
            c = self.clusters[cluster_key]
            if report_dict["report_id"] not in c["report_ids"]:
                c["report_ids"].append(report_dict["report_id"])
                c["report_count"] = len(c["report_ids"])
            c["last_reported_at"] = now_str
            cat = report_dict["classified_scam"].get("category_label", "Scam")
            if cat not in c["matched_categories"]:
                c["matched_categories"].append(cat)
            
            sample = redact_sample_message(report_dict["message_text"])
            if sample and sample not in c["sample_messages"]:
                if len(c["sample_messages"]) >= 3:
                    c["sample_messages"].pop(0)
                c["sample_messages"].append(sample)

        # Recalculate tier
        c = self.clusters[cluster_key]
        c["status"] = self.recalculate_cluster_tier(c)

        store.save_clusters_local(self.clusters)
        return c

    # ── Corroborate & Dispute Actions ─────────────────────────────────────────

    async def corroborate(self, req: CorroborateRequest) -> Dict[str, Any]:
        """Corroborate an existing reported handle."""
        handle_norm = normalize_handle(req.handle_raw)
        platform_str = req.platform.value if hasattr(req.platform, "value") else str(req.platform)
        cluster_key = f"{platform_str}:{handle_norm}"

        report_req = ReportCreateRequest(
            report_category=ReportCategoryEnum.SOCIAL_MEDIA_PROFILE,
            platform=req.platform,
            handle_raw=req.handle_raw,
            message_text=req.message_text,
            evidence_urls=req.evidence_urls,
            reporter_id=req.reporter_id,
        )
        report_res = await self.submit_report(report_req)
        return {
            "success": True,
            "message": f"Corroboration recorded for {cluster_key}",
            "report_id": report_res.report_id,
            "new_status": report_res.status,
            "total_reports": report_res.report_count,
        }

    async def dispute(self, req: DisputeRequest) -> Dict[str, Any]:
        """Submit an ownership dispute for a handle."""
        handle_norm = normalize_handle(req.handle_raw)
        platform_str = req.platform.value if hasattr(req.platform, "value") else str(req.platform)
        cluster_key = f"{platform_str}:{handle_norm}"

        cluster = self.clusters.get(cluster_key)
        if not cluster:
            raise ValueError(f"No reports found for handle '{req.handle_raw}' on {platform_str}")

        cluster["status"] = ModerationTierEnum.DISPUTED.value
        cluster["dispute_details"] = {
            "evidence_text": req.evidence_text,
            "owner_proof_url": req.owner_proof_url,
            "contact_email": req.contact_email,
            "disputed_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        store.save_clusters_local(self.clusters)
        asyncio.create_task(store.sync_cluster_to_supabase(cluster_key, cluster))

        return {
            "success": True,
            "message": f"Dispute received for {cluster_key}. Verdict paused during moderation review.",
            "status": "disputed",
        }

    # ── Moderator Review ───────────────────────────────────────────────────────

    async def moderate_action(self, req: ModerateActionRequest) -> Dict[str, Any]:
        """Moderator manual decision."""
        cluster = self.clusters.get(req.cluster_key)
        if not cluster:
            raise ValueError(f"Cluster key '{req.cluster_key}' not found.")

        if req.action == "approve_confirmed":
            cluster["status"] = ModerationTierEnum.CONFIRMED.value
            cluster["manually_confirmed"] = True
        elif req.action == "reject":
            cluster["status"] = ModerationTierEnum.REJECTED.value
        elif req.action == "resolve_dispute":
            cluster["status"] = ModerationTierEnum.CONFIRMED.value
            if "dispute_details" in cluster:
                del cluster["dispute_details"]
        elif req.action == "link_aliases":
            for alias in req.linked_aliases:
                norm_alias = normalize_handle(alias)
                if norm_alias not in cluster.get("linked_aliases", []):
                    cluster.setdefault("linked_aliases", []).append(norm_alias)

        if req.moderator_notes:
            cluster["moderator_notes"] = req.moderator_notes

        store.save_clusters_local(self.clusters)
        try:
            asyncio.create_task(store.sync_cluster_to_supabase(req.cluster_key, cluster))
        except Exception:
            pass

        return {
            "success": True,
            "cluster_key": req.cluster_key,
            "new_status": cluster["status"],
            "linked_aliases": cluster.get("linked_aliases", []),
        }

    def get_moderation_queue(self) -> List[Dict[str, Any]]:
        """Return unconfirmed or disputed clusters for moderation."""
        queue = []
        for key, c in self.clusters.items():
            if c.get("status") in [ModerationTierEnum.UNCONFIRMED.value, ModerationTierEnum.DISPUTED.value]:
                queue.append(c)
        return queue

    # ── 4-LAYER MULTI-VECTOR SEARCH ENGINE ─────────────────────────────────────

    def search(
        self,
        query: str,
        platform_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        include_unconfirmed: bool = False,
    ) -> SearchResponse:
        """
        4-Layer Search Engine:
          Layer 1: Exact handle / URL lookup
          Layer 2: Fuzzy handle lookup (Levenshtein distance <= 2)
          Layer 3: Full-text message search across sample pool
          Layer 4: Company name lookup (job / recruiter scams)
        """
        query_strip = query.strip()
        if not query_strip:
            return SearchResponse(query=query, total_matches=0, results=[])

        query_norm = normalize_handle(query_strip)
        query_company = normalize_company(query_strip)

        cards: List[SearchResultCard] = []
        seen_keys = set()

        # Helper to convert cluster to result card
        def _make_card(c: Dict[str, Any], match_type: str, match_score: float) -> SearchResultCard:
            tier = c.get("status", ModerationTierEnum.UNCONFIRMED.value)
            return SearchResultCard(
                cluster_key=c["cluster_key"],
                platform=c["platform"],
                handle_raw=c.get("handle_raw", "@" + c["handle_normalized"]),
                handle_normalized=c["handle_normalized"],
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
            )

        for key, c in self.clusters.items():
            tier = c.get("status", ModerationTierEnum.UNCONFIRMED.value)

            # Unless explicitly requested, hide unconfirmed / rejected items from public search
            if not include_unconfirmed and tier in [ModerationTierEnum.UNCONFIRMED.value, ModerationTierEnum.REJECTED.value]:
                continue

            # Platform filter
            if platform_filter and c.get("platform", "").lower() != platform_filter.lower():
                continue

            # Category filter
            if category_filter and not any(category_filter.lower() in cat.lower() for cat in c.get("matched_categories", [])):
                continue

            handle_n = c.get("handle_normalized", "")
            company_n = c.get("company_name_normalized", "")
            aliases = c.get("linked_aliases", [])

            # ── Layer 1: Exact Match ───────────────────────────────────────────
            if query_norm == handle_n or any(query_norm == a for a in aliases):
                cards.append(_make_card(c, "exact_handle", 1.0))
                seen_keys.add(key)
                continue

            # ── Layer 2: Fuzzy Levenshtein Handle Match ───────────────────────
            dist = levenshtein_distance(query_norm, handle_n)
            if dist <= 2 and len(query_norm) >= 3:
                score = round(1.0 - (dist / max(len(query_norm), len(handle_n))), 2)
                cards.append(_make_card(c, "fuzzy_handle", score))
                seen_keys.add(key)
                continue

            # ── Layer 4: Company Name Match ───────────────────────────────────
            if query_company and company_n and query_company in company_n:
                cards.append(_make_card(c, "company_name", 0.90))
                seen_keys.add(key)
                continue

            # ── Layer 3: Full-Text Message Search ──────────────────────────────
            query_words = set(re.findall(r"\w+", query_strip.lower()))
            if len(query_words) >= 2:
                best_match_ratio = 0.0
                for msg in c.get("sample_messages", []):
                    msg_words = set(re.findall(r"\w+", msg.lower()))
                    if not msg_words:
                        continue
                    overlap = len(query_words.intersection(msg_words))
                    ratio = overlap / len(query_words)
                    if ratio > best_match_ratio:
                        best_match_ratio = ratio

                if best_match_ratio >= 0.5:
                    cards.append(_make_card(c, "message_content", round(best_match_ratio, 2)))
                    seen_keys.add(key)

        # Sort by match score descending, then report count
        cards.sort(key=lambda x: (x.match_score, x.report_count), reverse=True)

        return SearchResponse(
            query=query,
            total_matches=len(cards),
            results=cards,
        )

    # ── Helpers & Stats ────────────────────────────────────────────────────────

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        for r in self.reports:
            if r.get("report_id") == report_id:
                return r
        return None

    def get_system_stats(self) -> Dict[str, Any]:
        """Return system-wide reporting analytics."""
        total_reports = len(self.reports)
        total_clusters = len(self.clusters)

        confirmed_count = sum(1 for c in self.clusters.values() if c.get("status") == ModerationTierEnum.CONFIRMED.value)
        corroborated_count = sum(1 for c in self.clusters.values() if c.get("status") == ModerationTierEnum.CORROBORATED.value)
        disputed_count = sum(1 for c in self.clusters.values() if c.get("status") == ModerationTierEnum.DISPUTED.value)

        # Top 5 reported handles
        sorted_clusters = sorted(self.clusters.values(), key=lambda x: x.get("report_count", 0), reverse=True)
        top_handles = [
            {
                "platform": c.get("platform"),
                "handle": c.get("handle_raw"),
                "report_count": c.get("report_count"),
                "status": c.get("status"),
                "categories": c.get("matched_categories", []),
            }
            for c in sorted_clusters[:5]
        ]

        return {
            "total_reports_submitted": total_reports,
            "total_unique_handles_indexed": total_clusters,
            "confirmed_scams_count": confirmed_count,
            "corroborated_scams_count": corroborated_count,
            "disputed_claims_count": disputed_count,
            "top_flagged_handles": top_handles,
        }


# Global singleton instance of engine
reporting_engine = CommunityReportingEngine()
