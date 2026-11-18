"""
token_limiter.py — Strict Daily Token Usage Tracker (10k tokens/day) & IP Ban Limiter (30 requests/IP).
"""
import os
import json
import logging
import threading
from datetime import date, datetime, timezone
from typing import Tuple, Dict, Set
from fastapi import HTTPException, Request

logger = logging.getLogger("token_limiter")

DAILY_TOKEN_LIMIT = 10_000
MAX_IP_REQUESTS = 30

IS_LAMBDA = bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("LAMBDA_TASK_ROOT"))
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Candidate storage directories for persistence
CANDIDATE_DATA_DIRS = [
    "/tmp/data",
    "/tmp",
    os.path.join(BACKEND_DIR, "data"),
    BACKEND_DIR,
]

_lock = threading.Lock()

# In-memory thread-safe state cache
_MEM_CACHE: Dict = {
    "date": "",
    "tokens_used": 0,
    "is_locked": False,
    "ip_counts": {},
    "banned_ips": set(),
}

def _get_candidate_paths(filename: str):
    return [os.path.join(d, filename) for d in CANDIDATE_DATA_DIRS]

def _load_token_state() -> dict:
    today_str = date.today().isoformat()
    if _MEM_CACHE["date"] == today_str and _MEM_CACHE["tokens_used"] > 0:
        return {
            "date": today_str,
            "tokens_used": _MEM_CACHE["tokens_used"],
            "is_locked": _MEM_CACHE["is_locked"],
        }

    for path in _get_candidate_paths("daily_token_usage.json"):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("date") == today_str:
                        _MEM_CACHE["date"] = today_str
                        _MEM_CACHE["tokens_used"] = max(_MEM_CACHE.get("tokens_used", 0), data.get("tokens_used", 0))
                        _MEM_CACHE["is_locked"] = _MEM_CACHE["tokens_used"] >= DAILY_TOKEN_LIMIT or data.get("is_locked", False)
                        return {
                            "date": today_str,
                            "tokens_used": _MEM_CACHE["tokens_used"],
                            "is_locked": _MEM_CACHE["is_locked"],
                        }
            except Exception as exc:
                logger.warning(f"Error reading token file {path}: {exc}")

    _MEM_CACHE["date"] = today_str
    return {"date": today_str, "tokens_used": _MEM_CACHE.get("tokens_used", 0), "is_locked": _MEM_CACHE.get("is_locked", False)}

def _save_token_state(data: dict):
    _MEM_CACHE["date"] = data.get("date", date.today().isoformat())
    _MEM_CACHE["tokens_used"] = data.get("tokens_used", 0)
    _MEM_CACHE["is_locked"] = data.get("is_locked", False)

    for path in _get_candidate_paths("daily_token_usage.json"):
        try:
            d = os.path.dirname(path)
            if d and not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

def _load_ip_state() -> dict:
    today_str = date.today().isoformat()
    for path in _get_candidate_paths("ip_bans.json"):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    banned = set(data.get("banned_ips", []))
                    _MEM_CACHE["banned_ips"].update(banned)
                    counts = data.get("ip_counts", {})
                    for ip, cnt in counts.items():
                        _MEM_CACHE["ip_counts"][ip] = max(_MEM_CACHE["ip_counts"].get(ip, 0), cnt)
                    return data
            except Exception as exc:
                logger.warning(f"Error reading IP ban file {path}: {exc}")

    return {
        "date": today_str,
        "banned_ips": list(_MEM_CACHE["banned_ips"]),
        "ip_counts": _MEM_CACHE["ip_counts"],
    }

def _save_ip_state():
    data = {
        "date": date.today().isoformat(),
        "banned_ips": list(_MEM_CACHE["banned_ips"]),
        "ip_counts": _MEM_CACHE["ip_counts"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    for path in _get_candidate_paths("ip_bans.json"):
        try:
            d = os.path.dirname(path)
            if d and not os.path.exists(d):
                os.makedirs(d, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

def get_client_ip(request: Request) -> str:
    """Extract real client IP address from headers or socket connection."""
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and forwarded.strip():
        client_ip = forwarded.split(",")[0].strip()
        if client_ip:
            return client_ip

    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()

    if request.client and request.client.host:
        return request.client.host.strip()

    return "unknown_client"

def is_ip_banned(ip: str) -> bool:
    """Check if an IP address is banned."""
    if not ip or ip in ("127.0.0.1", "localhost", "::1", "unknown_client"):
        return False
    with _lock:
        if not _MEM_CACHE["banned_ips"]:
            _load_ip_state()
        return ip in _MEM_CACHE["banned_ips"]

def check_ip_ban(ip: str):
    """Raises HTTPException 403 if the IP address has been banned."""
    if is_ip_banned(ip):
        logger.warning(f"Access Denied: Banned IP attempted request: {ip}")
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Your IP address ({ip}) has been permanently banned after exceeding 30 requests.",
        )

def record_ip_request(ip: str) -> Tuple[bool, int]:
    """
    Records an incoming request from an IP address.
    If count >= 30, bans the IP permanently and returns (True, count).
    Otherwise returns (False, count).
    """
    if not ip or ip in ("127.0.0.1", "localhost", "::1"):
        return (False, 1)

    with _lock:
        if not _MEM_CACHE["banned_ips"]:
            _load_ip_state()

        if ip in _MEM_CACHE["banned_ips"]:
            return (True, _MEM_CACHE["ip_counts"].get(ip, MAX_IP_REQUESTS))

        count = _MEM_CACHE["ip_counts"].get(ip, 0) + 1
        _MEM_CACHE["ip_counts"][ip] = count

        if count >= MAX_IP_REQUESTS:
            _MEM_CACHE["banned_ips"].add(ip)
            _save_ip_state()
            logger.warning(f"🚫 IP BANNED: {ip} reached {count}/{MAX_IP_REQUESTS} requests.")
            return (True, count)

        # Persist every 5 requests or on first request
        if count % 5 == 0 or count == 1:
            _save_ip_state()

        return (False, count)

def is_token_blocked() -> bool:
    """Check if the daily 10k token limit is currently reached."""
    with _lock:
        state = _load_token_state()
        return state.get("tokens_used", 0) >= DAILY_TOKEN_LIMIT or state.get("is_locked", False)

def check_token_limit():
    """Raises HTTPException 429 if the daily limit of 10k tokens is reached."""
    with _lock:
        state = _load_token_state()
        tokens_used = state.get("tokens_used", 0)
        if tokens_used >= DAILY_TOKEN_LIMIT or state.get("is_locked", False):
            logger.warning(f"🚫 STRICT TOKEN LIMIT REACHED: {tokens_used}/{DAILY_TOKEN_LIMIT}. Rejecting all API calls.")
            raise HTTPException(
                status_code=429,
                detail=f"Daily AI processing limit strictly reached ({DAILY_TOKEN_LIMIT:,} tokens). All API calls are paused until midnight UTC.",
            )

def record_token_usage(tokens: int):
    """Records consumed tokens and locks when 10,000 is reached."""
    if tokens <= 0:
        return
    with _lock:
        state = _load_token_state()
        new_total = state.get("tokens_used", 0) + tokens
        state["tokens_used"] = new_total
        if new_total >= DAILY_TOKEN_LIMIT:
            state["is_locked"] = True
            logger.warning(f"🔒 10K TOKEN LIMIT HIT ({new_total}/{DAILY_TOKEN_LIMIT}). Locking all API access.")
        _save_token_state(state)
        logger.info(f"Recorded {tokens} tokens. Total today: {new_total}/{DAILY_TOKEN_LIMIT}")

def get_token_status(ip: str = "") -> dict:
    """Returns today's token consumption, 10k limit, and client IP request quota."""
    with _lock:
        state = _load_token_state()
        used = state.get("tokens_used", 0)
        is_blocked = used >= DAILY_TOKEN_LIMIT or state.get("is_locked", False)
        ip_count = _MEM_CACHE["ip_counts"].get(ip, 0) if ip else 0
        ip_banned = ip in _MEM_CACHE["banned_ips"] if ip else False
        return {
            "date": state.get("date"),
            "tokens_used": used,
            "daily_limit": DAILY_TOKEN_LIMIT,
            "tokens_remaining": max(0, DAILY_TOKEN_LIMIT - used),
            "is_blocked": is_blocked,
            "client_ip": ip,
            "ip_request_count": ip_count,
            "ip_max_requests": MAX_IP_REQUESTS,
            "is_ip_banned": ip_banned,
        }
