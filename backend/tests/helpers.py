# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers."""
from app.services.bundle import dump_bundle


def auth_headers(email: str) -> dict[str, str]:
    return {"X-User-Email": email}


def dummy_bundle_bytes(columns: list[str] | None = None, n: int = 1) -> bytes:
    cols = columns or ["col1"]
    return dump_bundle({
        "public_context": b"test-public-context",
        "vectors": {c: b"test-ciphertext" for c in cols},
        "columns": cols,
        "n": n,
    })
