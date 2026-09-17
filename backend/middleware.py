"""
AegisAI Security Middleware
- Injects security headers on every response
- Logs requests with structlog (request ID, method, path, status, duration)
"""
from __future__ import annotations

import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = structlog.get_logger("aegis.http")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every HTTP response."""

    # Content-Security-Policy: allow CDN for Chart.js (legacy dashboard),
    # ws/wss for WebSocket, and 'self' for everything else.
    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "font-src 'self';"
    )

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = self.CSP
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Remove server identification
        if "server" in response.headers:
            del response.headers["server"]
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with timing, request ID, and status code via structlog."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Bind request ID to this log context
        bound_log = log.bind(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )
        bound_log.info("request_started")

        try:
            response = await call_next(request)
        except Exception as exc:
            bound_log.error("request_failed", error=str(exc))
            raise

        duration_ms = (time.perf_counter() - start) * 1000
        bound_log.info(
            "request_finished",
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
        )

        # Propagate request ID in response for client-side tracing
        response.headers["X-Request-ID"] = request_id
        return response
