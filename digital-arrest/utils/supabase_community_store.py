"""
utils/supabase_community_store.py — Storage layer for Community Scam Reports & Clusters.

Handles:
  1. Persistent local JSON files:
     - data/community_reports.json
     - data/community_clusters.json
  2. Async Supabase sync (via PostgREST API) if SUPABASE_URL and SUPABASE_SERVICE_KEY (or SUPABASE_KEY) are configured.

Guarantees 100% availability even if Supabase is offline or not configured.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("safe_backend.community_store")

DATA_DIR = Path("data")
REPORTS_FILE = DATA_DIR / "community_reports.json"
CLUSTERS_FILE = DATA_DIR / "community_clusters.json"


class CommunityStore:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._init_local_files()
        
        # Env setup
        self.supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
        self.supabase_key = os.getenv("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY") or ""
        
        if self.supabase_url and self.supabase_key:
            logger.info("Supabase community store enabled for %s", self.supabase_url)
        else:
            logger.info("Supabase not fully configured; using local JSON file store.")

    def _init_local_files(self):
        if not REPORTS_FILE.exists():
            with open(REPORTS_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)
        if not CLUSTERS_FILE.exists():
            with open(CLUSTERS_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f)

    # ── Local File Operations ───────────────────────────────────────────────────

    def load_reports_local(self) -> List[Dict[str, Any]]:
        try:
            with open(REPORTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Error loading local reports file: %s", exc)
            return []

    def save_reports_local(self, reports: List[Dict[str, Any]]) -> None:
        try:
            with open(REPORTS_FILE, "w", encoding="utf-8") as f:
                json.dump(reports, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.error("Error saving local reports file: %s", exc)

    def load_clusters_local(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(CLUSTERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Error loading local clusters file: %s", exc)
            return {}

    def save_clusters_local(self, clusters: Dict[str, Dict[str, Any]]) -> None:
        try:
            with open(CLUSTERS_FILE, "w", encoding="utf-8") as f:
                json.dump(clusters, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.error("Error saving local clusters file: %s", exc)

    # ── Supabase Async Sync ─────────────────────────────────────────────────────

    @property
    def is_supabase_enabled(self) -> bool:
        return bool(self.supabase_url and self.supabase_key)

    async def sync_report_to_supabase(self, report_data: Dict[str, Any]) -> None:
        """Fire-and-forget sync of report to Supabase 'community_reports' table."""
        if not self.is_supabase_enabled:
            return
        
        endpoint = f"{self.supabase_url}/rest/v1/community_reports"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(endpoint, headers=headers, json=report_data)
                if res.status_code not in (200, 201, 204):
                    logger.warning("Supabase report sync returned %s: %s", res.status_code, res.text[:200])
        except Exception as exc:
            logger.warning("Supabase report sync non-fatal error: %s", exc)

    async def sync_cluster_to_supabase(self, cluster_key: str, cluster_data: Dict[str, Any]) -> None:
        """Fire-and-forget sync of cluster to Supabase 'community_clusters' table."""
        if not self.is_supabase_enabled:
            return
        
        endpoint = f"{self.supabase_url}/rest/v1/community_clusters"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
        }
        payload = {"cluster_key": cluster_key, **cluster_data}
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.post(endpoint, headers=headers, json=payload)
                if res.status_code not in (200, 201, 204):
                    logger.warning("Supabase cluster sync returned %s: %s", res.status_code, res.text[:200])
        except Exception as exc:
            logger.warning("Supabase cluster sync non-fatal error: %s", exc)


# Global singleton instance
store = CommunityStore()
