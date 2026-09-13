"""
feedback_loop.py
Community feedback loop: provides reputation overrides for URLs based on
human-verified scam reports collected via the /api/community/ endpoints.

If a URL has been confirmed as a scam by community reports, these functions
return an override verdict so the link cascade can fast-path to a "SCAM"
verdict without running the full analysis again.
"""

import os
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("safe_backend.feedback_loop")

# ──────────────────────────────────────────────────────────────────────────────
# Storage paths (simple JSON flat-files; swap for a DB in production)
# ──────────────────────────────────────────────────────────────────────────────
_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
_URL_REPUTATION_FILE = os.path.join(_DATA_DIR, "url_reputation_overrides.json")


def _load_json(path: str) -> Dict[str, Any]:
    """Load a JSON file, returning an empty dict on any error."""
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as exc:
        logger.warning("feedback_loop: failed to load %s — %s", path, exc)
    return {}


def get_url_reputation_override(url: str) -> Optional[Dict[str, Any]]:
    """
    Check whether the community has verified *url* as a known scam/safe URL.

    Returns a dict like:
        {"verdict": "SCAM", "confidence": 0.95, "reports": 12, "label": "Phishing"}
    or None if no override exists for this URL.
    """
    if not url:
        return None

    overrides: Dict[str, Any] = _load_json(_URL_REPUTATION_FILE)
    # Normalise the URL key (strip trailing slash, lowercase scheme+host)
    key = url.strip().rstrip("/").lower()
    entry = overrides.get(key) or overrides.get(url.strip())
    if entry:
        logger.info("feedback_loop: URL reputation override found for %s → %s", url, entry.get("verdict"))
    return entry


def register_url_override(url: str, verdict: str, label: str = "", confidence: float = 0.9) -> bool:
    """
    Persist a community-verified URL override to the JSON store.
    Called internally by community reporting routes after enough confirmations.
    """
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        overrides = _load_json(_URL_REPUTATION_FILE)
        key = url.strip().rstrip("/").lower()
        overrides[key] = {
            "verdict": verdict.upper(),
            "label": label,
            "confidence": confidence,
            "reports": overrides.get(key, {}).get("reports", 0) + 1,
        }
        with open(_URL_REPUTATION_FILE, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2)
        return True
    except Exception as exc:
        logger.error("feedback_loop: failed to register URL override — %s", exc)
        return False


