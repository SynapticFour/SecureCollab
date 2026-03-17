# SPDX-License-Identifier: Apache-2.0
"""Auth, rate limiting helpers, sanitization, security middleware."""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address

    _limiter = Limiter(key_func=get_remote_address)

    def get_limiter():
        return _limiter

    def rate_limit(s: str):
        return _limiter.limit(s)
except ImportError:
    _limiter = None

    def get_limiter():
        return None

    def rate_limit(s: str):
        def noop(f):
            return f
        return noop

_logger = logging.getLogger("securecollab")


def add_security_middleware(app: FastAPI) -> None:
    """Register exception handler, security headers, and CORS. No business logic."""
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        error_id = str(uuid.uuid4())
        _logger.error("Unhandled exception %s: %s", error_id, exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "error_id": error_id},
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        from app.config import settings
        if settings.production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    from app.config import settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def secure_filename(filename: str) -> str:
    """Path traversal prevention: only alphanumeric, underscore, dot."""
    if not filename or not filename.strip():
        return "unnamed.bin"
    name = Path(filename).name
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe or "unnamed.bin"


def sanitize_text(value: str, max_len: int = 2000) -> str:
    """Strip HTML/script tags and enforce max length."""
    if not value:
        return ""
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"javascript:", "", value, flags=re.IGNORECASE)
    return value.strip()[:max_len]


def sha3_256_hex(*parts: bytes | str) -> str:
    """SHA3-256 hash of concatenated parts, hex-encoded."""
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p.encode("utf-8") if isinstance(p, str) else p)
    return h.hexdigest()


@dataclass
class AuthUser:
    """Lightweight auth context for pilots (header-based, no sessions)."""

    email: str
    role: str


def _resolve_role(email: str) -> str:
    """
    Map email to a simple role based on config lists.

    Order: admin > provider > researcher > guest.
    """
    from app.config import settings

    if email in settings.admin_emails:
        return "admin"
    if email in settings.provider_emails:
        return "provider"
    if email in settings.researcher_emails:
        return "researcher"
    return "guest"


def get_current_user(request: Request) -> AuthUser:
    """
    Extract user from X-User-Email header.

    This is intentionally lightweight and header-based, intended for pilots and demos.
    It does not implement sessions, passwords, or production-grade authentication.
    """
    email = (request.headers.get("X-User-Email") or "").strip()
    role = _resolve_role(email) if email else "anonymous"
    return AuthUser(email=email, role=role)


def require_admin(request: Request) -> AuthUser:
    """
    Require that the caller is configured as admin.

    - If the header is missing: 401
    - If the email is not in admin_emails: 403
    """
    email = (request.headers.get("X-User-Email") or "").strip()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-User-Email header",
        )
    role = _resolve_role(email)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return AuthUser(email=email, role=role)
