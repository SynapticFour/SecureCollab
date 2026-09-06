# SPDX-License-Identifier: Apache-2.0
"""Codebase integrity: hash computation and verification."""
from __future__ import annotations

import logging
from collections.abc import Callable

from app.core.timeutils import audit_timestamp, utc_now

logger = logging.getLogger("securecollab")

_DEPLOYMENT_INTEGRITY: dict = {}

compute_codebase_hash: Callable[[], dict] | None
try:
    from integrity import compute_codebase_hash
except Exception as e:
    logger.warning("Integrity module unavailable: %s", e)
    compute_codebase_hash = None


def _init_integrity() -> dict:
    global _DEPLOYMENT_INTEGRITY
    if not _DEPLOYMENT_INTEGRITY:
        if compute_codebase_hash is not None:
            try:
                _DEPLOYMENT_INTEGRITY = compute_codebase_hash()
            except Exception as e:
                logger.warning("Codebase integrity computation failed: %s", e)
                _DEPLOYMENT_INTEGRITY = _unknown_integrity()
        else:
            _DEPLOYMENT_INTEGRITY = _unknown_integrity()
    return _DEPLOYMENT_INTEGRITY


def _unknown_integrity() -> dict:
    return {
        "codebase_hash": "unknown",
        "git_commit": "unknown",
        "computed_at": audit_timestamp(utc_now()),
        "file_count": 0,
        "files_included": [],
    }


def get_deployment_integrity() -> dict:
    """Return current codebase hash and metadata (for audit and /system/integrity)."""
    return _init_integrity()


def verify_codebase_hash(expected: str) -> dict:
    """Re-walk the tree and compare to expected. Does not use the startup cache."""
    if compute_codebase_hash is None:
        return {
            "verified": False,
            "expected_hash": expected,
            "current_hash": "unknown",
            "error": "Integrity module unavailable",
        }
    current = compute_codebase_hash()
    current_hash = current.get("codebase_hash", "unknown")
    return {
        "verified": current_hash == expected,
        "expected_hash": expected,
        "current_hash": current_hash,
        "computed_at": current.get("computed_at", ""),
        "file_count": current.get("file_count", 0),
    }
