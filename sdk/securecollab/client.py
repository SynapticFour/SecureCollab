# SPDX-License-Identifier: Apache-2.0
"""Main SDK class: SecureCollabClient."""
from __future__ import annotations

from typing import Any

from .http import api_get


class SecureCollabClient:
    """Client for SecureCollab API and local HE operations."""

    def __init__(self, api_base_url: str = "http://localhost:8000", email: str = ""):
        self.api_base_url = api_base_url.rstrip("/")
        self.email = email

    def get_algorithms(self) -> dict[str, Any]:
        data = api_get(self.api_base_url, "/algorithms", email=self.email)
        if not isinstance(data, dict):
            raise TypeError("Unexpected /algorithms response")
        return data
