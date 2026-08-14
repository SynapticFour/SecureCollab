# SPDX-License-Identifier: Apache-2.0
"""Participants router API tests."""
from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_headers

client = TestClient(app)
EMAIL = "nobody@example.com"


def test_participant_studies_empty():
    r = client.get(f"/participants/studies/{EMAIL}", headers=auth_headers(EMAIL))
    assert r.status_code == 200
    assert r.json() == []


def test_participant_studies_requires_auth():
    r = client.get(f"/participants/studies/{EMAIL}")
    assert r.status_code == 401
