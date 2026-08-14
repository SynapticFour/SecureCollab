# SPDX-License-Identifier: Apache-2.0
"""Datasets router API tests."""
from fastapi.testclient import TestClient

from app.main import app
from tests.helpers import auth_headers

client = TestClient(app)
EMAIL = "nobody@example.com"


def test_dataset_columns_404():
    r = client.get("/datasets/99999/columns", headers=auth_headers(EMAIL))
    assert r.status_code == 404


def test_datasets_list_requires_auth():
    r = client.get("/datasets")
    assert r.status_code == 401


def test_datasets_list():
    r = client.get("/datasets", headers=auth_headers(EMAIL))
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_datasets_accessible_empty():
    r = client.get(f"/datasets/accessible/{EMAIL}", headers=auth_headers(EMAIL))
    assert r.status_code == 200
    assert r.json() == []


def test_access_datasets_by_owner_empty():
    r = client.get(f"/access/datasets/{EMAIL}", headers=auth_headers(EMAIL))
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert r.json() == []


def test_access_datasets_requires_matching_header():
    r = client.get(f"/access/datasets/{EMAIL}", headers=auth_headers("other@example.com"))
    assert r.status_code == 403
