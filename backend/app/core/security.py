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

from app.core.tokens import TokenError, parse_access_token

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
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        if isinstance(exc, HTTPException):
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        from app.core.exceptions import AlgorithmNotAllowedError, NotFoundError, SecureCollabError

        if isinstance(exc, AlgorithmNotAllowedError):
            return JSONResponse(status_code=400, content={"detail": str(exc)})
        if isinstance(exc, NotFoundError):
            return JSONResponse(status_code=404, content={"detail": str(exc)})
        if isinstance(exc, SecureCollabError):
            return JSONResponse(status_code=400, content={"detail": str(exc)})
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
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
    )
    limiter = get_limiter()
    if limiter is not None:
        try:
            from slowapi.errors import RateLimitExceeded
            from slowapi import _rate_limit_exceeded_handler

            app.state.limiter = limiter
            app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
        except ImportError:
            pass


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
    """Authenticated caller. Email comes from a signed access token, not the client."""

    email: str
    role: str


def _bearer_email(request: Request) -> str:
    header = (request.headers.get("Authorization") or "").strip()
    if not header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )
    token = header[7:].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
        )
    try:
        return parse_access_token(token)
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e) or "Invalid token",
        ) from e


def get_current_user(request: Request) -> AuthUser:
    """Optional auth: anonymous if no Bearer token, otherwise the token subject."""
    header = (request.headers.get("Authorization") or "").strip()
    if not header:
        return AuthUser(email="", role="anonymous")
    email = _bearer_email(request)
    return AuthUser(email=email, role=_resolve_role(email))


def require_user(request: Request) -> AuthUser:
    """Require a valid HMAC access token. Identity is the token subject."""
    email = _bearer_email(request)
    return AuthUser(email=email, role=_resolve_role(email))


def assert_actor(user: AuthUser, claimed: str | None) -> str:
    """If the client sent an actor email, it must match the authenticated subject."""
    if claimed and claimed.strip() and claimed.strip().lower() != user.email.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated email does not match the requested actor",
        )
    return user.email


def require_admin(request: Request) -> AuthUser:
    """
    Require that the caller is configured as admin.

    - If the token is missing/invalid: 401
    - If the email is not in admin_emails: 403
    """
    email = _bearer_email(request)
    role = _resolve_role(email)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return AuthUser(email=email, role=role)


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
