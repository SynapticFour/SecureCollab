# SPDX-License-Identifier: Apache-2.0
"""Lightweight header-based auth and role checks."""
from app.config import settings
from app.main import app
from fastapi.testclient import TestClient


def test_config_summary_requires_admin_header():
    """GET /system/config-summary enforces simple header-based admin role."""
    client = TestClient(app)
    original_admins = list(settings.admin_emails)
    try:
        settings.admin_emails = ["admin@test.com"]

        # No header -> 401
        r = client.get("/system/config-summary")
        assert r.status_code == 401

        # Non-admin header -> 403
        r2 = client.get("/system/config-summary", headers={"X-User-Email": "user@test.com"})
        assert r2.status_code == 403

        # Admin header -> 200
        r3 = client.get("/system/config-summary", headers={"X-User-Email": "admin@test.com"})
        assert r3.status_code == 200
        body = r3.json()
        assert "db_type" in body
        assert "app_title" in body
    finally:
        settings.admin_emails = original_admins

