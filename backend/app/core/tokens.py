# SPDX-License-Identifier: Apache-2.0
"""HMAC-SHA256 access tokens. SECRET_KEY is the signing key."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from app.config import DEFAULT_SECRET_KEY, settings

TOKEN_TTL_SECONDS = 24 * 60 * 60


class TokenError(ValueError):
    """Token missing, expired, or forged."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_access_token(email: str, ttl: int = TOKEN_TTL_SECONDS) -> str:
    payload = {"sub": email.strip().lower(), "exp": int(time.time()) + ttl}
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(settings.secret_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64url(sig)}"


def parse_access_token(token: str) -> str:
    """Return email (sub) or raise TokenError."""
    try:
        body, sig_b64 = token.strip().split(".", 1)
    except ValueError as e:
        raise TokenError("Malformed token") from e
    expected = hmac.new(
        settings.secret_key.encode("utf-8"), body.encode("ascii"), hashlib.sha256
    ).digest()
    try:
        given = _b64url_decode(sig_b64)
    except (ValueError, TypeError) as e:
        raise TokenError("Malformed token") from e
    if not hmac.compare_digest(expected, given):
        raise TokenError("Invalid token signature")
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        raise TokenError("Malformed token") from e
    if int(payload.get("exp") or 0) < int(time.time()):
        raise TokenError("Token expired")
    email = str(payload.get("sub") or "").strip().lower()
    if not email or "@" not in email:
        raise TokenError("Token missing subject")
    return email


def secret_key_is_default() -> bool:
    return settings.secret_key == DEFAULT_SECRET_KEY
