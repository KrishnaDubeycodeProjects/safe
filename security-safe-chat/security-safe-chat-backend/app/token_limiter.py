"""
token_limiter.py — Daily Token Usage Tracker & Enforcement (10k tokens/day).
"""
import os
import json
import logging
from datetime import date
from fastapi import HTTPException

logger = logging.getLogger("token_limiter")

DAILY_TOKEN_LIMIT = 10_000
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BACKEND_DIR, "data")
USAGE_FILE = os.path.join(DATA_DIR, "daily_token_usage.json")

def _load_usage() -> dict:
    today_str = date.today().isoformat()
    try:
        if os.path.exists(USAGE_FILE):
            with open(USAGE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if data.get("date") == today_str:
                    return data
    except Exception as exc:
        logger.warning(f"Failed to read token usage file: {exc}")
    
    return {"date": today_str, "tokens_used": 0}

def _save_usage(data: dict):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(USAGE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        logger.warning(f"Failed to save token usage file: {exc}")

def check_token_limit():
    """Raises HTTPException 429 if the daily limit of 10k tokens is reached."""
    usage = _load_usage()
    tokens_used = usage.get("tokens_used", 0)
    if tokens_used >= DAILY_TOKEN_LIMIT:
        logger.warning(f"Daily token limit reached: {tokens_used}/{DAILY_TOKEN_LIMIT} on {usage.get('date')}")
        raise HTTPException(
            status_code=429,
            detail=f"Daily AI processing limit reached ({DAILY_TOKEN_LIMIT:,} tokens). Usage resets at midnight UTC."
        )

def record_token_usage(tokens: int):
    """Records consumed tokens against today's quota."""
    if tokens <= 0:
        return
    usage = _load_usage()
    usage["tokens_used"] = usage.get("tokens_used", 0) + tokens
    _save_usage(usage)
    logger.info(f"Recorded {tokens} tokens. Total today: {usage['tokens_used']}/{DAILY_TOKEN_LIMIT}")

def get_token_status() -> dict:
    """Returns current token usage metrics for today."""
    usage = _load_usage()
    used = usage.get("tokens_used", 0)
    return {
        "date": usage.get("date"),
        "tokens_used": used,
        "daily_limit": DAILY_TOKEN_LIMIT,
        "tokens_remaining": max(0, DAILY_TOKEN_LIMIT - used),
        "is_blocked": used >= DAILY_TOKEN_LIMIT
    }
