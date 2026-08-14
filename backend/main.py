# SPDX-License-Identifier: Apache-2.0
"""Deprecated entrypoint. Use `uvicorn app.main:app`.

This module used to be a ~1850-line monolith. It now re-exports the live app so
`uvicorn main:app` still works but does not run the old CORS-* copy.
"""
from __future__ import annotations

import warnings

warnings.warn(
    "backend/main.py is deprecated. Run `uvicorn app.main:app` instead.",
    DeprecationWarning,
    stacklevel=2,
)

from app.main import app  # noqa: E402,F401

__all__ = ["app"]
