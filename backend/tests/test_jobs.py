# SPDX-License-Identifier: Apache-2.0
"""API integration tests for jobs."""
from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_headers

client = TestClient(app)
EMAIL = "nobody@example.com"


def test_jobs_my_empty():
    r = client.get(f"/jobs/my/{EMAIL}", headers=auth_headers(EMAIL))
    assert r.status_code == 200
    assert r.json() == []


def test_jobs_my_requires_auth():
    r = client.get(f"/jobs/my/{EMAIL}")
    assert r.status_code == 401


def test_jobs_request_invalid_algorithm():
    r = client.post(
        "/jobs/request",
        headers=auth_headers("r@test.com"),
        json={
            "dataset_id": 1,
            "requester_email": "r@test.com",
            "algorithm": "invalid_algo",
            "selected_columns": [],
        },
    )
    assert r.status_code == 400


def test_jobs_approve_404():
    r = client.post("/jobs/99999/approve", headers=auth_headers("owner@test.com"))
    assert r.status_code == 404


def test_jobs_reject_404():
    r = client.post("/jobs/99999/reject", headers=auth_headers("owner@test.com"))
    assert r.status_code == 404


def test_jobs_result_404():
    r = client.get("/jobs/99999/result", headers=auth_headers("owner@test.com"))
    assert r.status_code == 404


def test_jobs_pending_empty():
    r = client.get("/jobs/pending/no-owner@example.com", headers=auth_headers("no-owner@example.com"))
    assert r.status_code == 200
    assert r.json() == []
