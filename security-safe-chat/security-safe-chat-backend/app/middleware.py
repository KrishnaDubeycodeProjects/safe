"""
middleware.py — Optional X-API-Key auth middleware.

When settings.api_secret_key is set, every request must include the header:
    X-API-Key: <your-key>

Health check (/health) is always exempted so load balancers can probe freely.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings


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
