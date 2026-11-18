"""
middleware.py — APIKeyMiddleware and IPRateLimitMiddleware (30 requests/IP Ban & 10k Token Quota).
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings
from app.token_limiter import (
    get_client_ip,
    is_ip_banned,
    record_ip_request,
    is_token_blocked,
    DAILY_TOKEN_LIMIT,
    MAX_IP_REQUESTS,
)


class IPRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Strictly enforces:
    1. 30 requests per IP limit -> permanently bans IP upon reaching 30 requests.
    2. 10,000 daily token quota -> immediately blocks requests if tokens are exhausted.
    Zero external APIs are called if either limit is breached.
    """
    EXEMPT_PATHS = {"/health", "/", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        if request.method == "OPTIONS" or request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        client_ip = get_client_ip(request)

        # 1. Immediate Ban Check (Prior banned IPs)
        if is_ip_banned(client_ip):
            return JSONResponse(
                status_code=403,
                content={
                    "error": "IP_BANNED",
                    "detail": f"Access Denied: Your IP ({client_ip}) has been banned after exceeding {MAX_IP_REQUESTS} requests limit.",
                    "banned": True,
                    "ip": client_ip,
                },
                headers={"X-IP-Banned": "true"}
            )

        # 2. Track requests for functional scan, chat, and investigate endpoints
        path = request.url.path
        if (
            path.startswith("/api/scan")
            or path.startswith("/api/investigate")
            or path.startswith("/api/v1/chat")
            or path.startswith("/api/chat")
        ):
            # Enforce 30 requests per IP
            is_banned, count = record_ip_request(client_ip)
            if is_banned:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "IP_BANNED",
                        "detail": f"Access Denied: Your IP ({client_ip}) has been banned after exceeding {MAX_IP_REQUESTS} requests limit.",
                        "banned": True,
                        "ip": client_ip,
                        "request_count": count,
                        "max_requests": MAX_IP_REQUESTS,
                    },
                    headers={"X-IP-Banned": "true", "X-IP-Requests-Count": str(count)}
                )

            # Enforce 10k Token limit: if locked, DO NOT call any API
            if is_token_blocked():
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "TOKEN_LIMIT_REACHED",
                        "detail": f"Daily AI token limit reached ({DAILY_TOKEN_LIMIT:,} tokens). To prevent cloud quota exhaustion, all AI/API requests are strictly blocked until midnight UTC.",
                        "is_blocked": True,
                        "daily_limit": DAILY_TOKEN_LIMIT,
                    },
                    headers={"X-Tokens-Blocked": "true", "Retry-After": "3600"}
                )

        response = await call_next(request)
        response.headers["X-Client-IP"] = client_ip
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    EXEMPT_PATHS = {"/health", "/", "/docs", "/openapi.json", "/redoc"}

    async def dispatch(self, request: Request, call_next):
        if not settings.auth_enabled or request.method == "OPTIONS":
            return await call_next(request)

        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        api_key = request.headers.get("X-API-Key", "")
        if api_key != settings.api_secret_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing X-API-Key header."},
            )

        return await call_next(request)
