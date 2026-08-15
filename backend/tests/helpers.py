# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers."""
from app.core.tokens import issue_access_token
from app.services.bundle import dump_bundle
from app.services.user_service import ensure_user

TEST_PASSWORD = "test-pass-ok"


def auth_headers(email: str) -> dict[str, str]:
    ensure_user(email, TEST_PASSWORD)
    token = issue_access_token(email)
    return {"Authorization": f"Bearer {token}"}


def dummy_bundle_bytes(columns: list[str] | None = None, n: int = 1) -> bytes:
    cols = columns or ["col1"]
    return dump_bundle({
        "public_context": b"test-public-context",
        "vectors": {c: b"test-ciphertext" for c in cols},
        "columns": cols,
        "n": n,
    })
