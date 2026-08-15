# SPDX-License-Identifier: Apache-2.0
"""Result-release share: bound to join-time key_commitment. Not a partial decrypt."""
from __future__ import annotations

import hmac
import re

from app.core.security import sha3_256_hex

_COMMITMENT_RE = re.compile(r"^[0-9a-f]{64}$")


def is_key_commitment(value: str) -> bool:
    return bool(_COMMITMENT_RE.fullmatch((value or "").strip().lower()))


def expected_release_share(job_id: int, email: str, key_commitment: str) -> str:
    return sha3_256_hex(f"{int(job_id)}|{email.strip().lower()}|{key_commitment.strip().lower()}")


def shares_match(submitted: str, expected: str) -> bool:
    a = (submitted or "").strip().lower()
    b = (expected or "").strip().lower()
    if len(a) != len(b) or not a:
        return False
    return hmac.compare_digest(a, b)
