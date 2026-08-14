# SPDX-License-Identifier: Apache-2.0
"""Timezone-aware UTC helpers. Audit hashes must use the same timestamp string
the API later returns — keep one formatter."""
from __future__ import annotations

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Aware UTC datetime for storage."""
    return datetime.now(timezone.utc)


def audit_timestamp(dt: datetime) -> str:
    """Canonical UTC timestamp for audit hashing and API responses.

    Always microseconds + Z, so SQLite round-trips and SDK verification agree.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
