# SPDX-License-Identifier: Apache-2.0
"""Password + HMAC token auth. Header spoofing must fail."""
import uuid

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from tests.helpers import TEST_PASSWORD, auth_headers

client = TestClient(app)


def test_header_spoof_is_ignored():
    r = client.get("/studies", headers={"X-User-Email": "victim@hospital.com"})
    assert r.status_code == 401


def test_register_login_roundtrip():
    email = f"auth-roundtrip-{uuid.uuid4().hex[:10]}@test.com"
    r = client.post("/auth/register", json={"email": email, "password": TEST_PASSWORD})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    r2 = client.get("/studies", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    r3 = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert r3.status_code == 200
    r4 = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    assert r4.status_code == 401


def test_forged_token_rejected():
    r = client.get("/studies", headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401


def test_config_summary_requires_admin_token():
    original_admins = list(settings.admin_emails)
    try:
        settings.admin_emails = ["admin@test.com"]
        r = client.get("/system/config-summary")
        assert r.status_code == 401
        r2 = client.get("/system/config-summary", headers=auth_headers("user@test.com"))
        assert r2.status_code == 403
        r3 = client.get("/system/config-summary", headers=auth_headers("admin@test.com"))
        assert r3.status_code == 200
        assert "db_type" in r3.json()
    finally:
        settings.admin_emails = original_admins


def test_cannot_reuse_another_users_token_subject_via_header():
    headers = auth_headers("alice@test.com")
    headers["X-User-Email"] = "bob@test.com"
    r = client.get("/studies", params={"participant_email": "bob@test.com"}, headers=headers)
    assert r.status_code == 403
