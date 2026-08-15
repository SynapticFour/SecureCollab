# SPDX-License-Identifier: Apache-2.0
"""PBKDF2-SHA256 password hashing. No plaintext storage."""
from __future__ import annotations

import hashlib
import hmac
import os

_ITERATIONS = 600_000
_SALT_LEN = 16
_PREFIX = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    salt = os.urandom(_SALT_LEN)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"{_PREFIX}${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, iter_s, salt_hex, digest_hex = stored.split("$", 3)
        if prefix != _PREFIX:
            return False
        iterations = int(iter_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, TypeError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)
