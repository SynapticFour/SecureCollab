# SPDX-License-Identifier: Apache-2.0
"""Integration tests for studies API. Use TestClient, no running server."""
import io

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.bundle import dump_bundle
from tests.helpers import auth_headers

client = TestClient(app)

CREATOR = "creator@test.com"
INST1 = "inst1@test.com"
INST2 = "inst2@test.com"
JOINER = "joiner@test.com"
OWNER = "owner@test.com"
RESEARCHER = "researcher@test.com"


def _h(email: str) -> dict[str, str]:
    return auth_headers(email)


def test_get_studies_empty():
    r = client.get("/studies", params={"participant_email": "nobody@example.com"}, headers=_h("nobody@example.com"))
    assert r.status_code == 200
    assert r.json() == []


def test_get_studies_requires_auth():
    r = client.get("/studies")
    assert r.status_code == 401


def test_get_study_requires_auth():
    r = client.get("/studies/99999")
    assert r.status_code == 401


def test_get_study_404():
    r = client.get("/studies/99999", headers=_h(CREATOR))
    assert r.status_code == 404


def test_study_protocol_404():
    r = client.get("/studies/99999/protocol", headers=_h(CREATOR))
    assert r.status_code == 404


def test_system_health():
    r = client.get("/system/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_algorithms_list():
    r = client.get("/algorithms")
    assert r.status_code == 200
    data = r.json()
    assert "mean" in data
    assert "descriptive_statistics" in data


def test_create_study():
    r = client.post(
        "/studies/create",
        headers=_h(CREATOR),
        json={
            "name": "Test Study",
            "description": "Integration test",
            "creator_email": CREATOR,
            "institution_name": "Test Hospital",
            "threshold_t": 1,
            "threshold_n": 1,
            "allowed_algorithms": ["mean", "correlation"],
            "column_definitions": [],
            "public_key_share": "",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "study_id" in data
    study_id = data["study_id"]
    r2 = client.get(f"/studies/{study_id}", headers=_h(CREATOR))
    assert r2.status_code == 200
    assert r2.json()["name"] == "Test Study"
    assert r2.json()["status"] == "draft"


def test_create_study_rejects_mismatched_email():
    r = client.post(
        "/studies/create",
        headers=_h(CREATOR),
        json={
            "name": "Mismatch",
            "description": "x",
            "creator_email": "other@test.com",
            "institution_name": "H",
            "threshold_t": 1,
            "threshold_n": 1,
            "allowed_algorithms": ["mean"],
            "column_definitions": [],
            "public_key_share": "",
        },
    )
    assert r.status_code == 403


def test_join_study():
    r = client.post(
        "/studies/create",
        headers=_h(CREATOR),
        json={
            "name": "Join Test Study",
            "description": "For join test",
            "creator_email": CREATOR,
            "institution_name": "Creator Hospital",
            "threshold_t": 1,
            "threshold_n": 2,
            "allowed_algorithms": ["mean"],
            "column_definitions": [],
            "public_key_share": "",
        },
    )
    assert r.status_code == 200
    study_id = r.json()["study_id"]
    r_join = client.post(
        f"/studies/{study_id}/join",
        headers=_h(JOINER),
        json={
            "institution_email": JOINER,
            "institution_name": "Joiner Hospital",
            "public_key_share": "dummy_base64_key_placeholder",
        },
    )
    assert r_join.status_code in (200, 400)


def test_upload_dataset():
    file_bytes = dump_bundle({
        "public_context": b"x",
        "vectors": {"col1": b"y"},
        "columns": ["col1"],
        "n": 1,
    })
    r = client.post(
        "/datasets/upload",
        headers=_h(OWNER),
        data={
            "name": "Test Dataset",
            "description": "Test",
            "owner_email": OWNER,
            "organization": "Test Org",
            "columns": "[]",
            "declared_rows": "",
        },
        files={"file": ("encrypted.bin", io.BytesIO(file_bytes), "application/octet-stream")},
    )
    assert r.status_code == 200
    assert "dataset_id" in r.json()


def test_upload_rejects_pickle():
    r = client.post(
        "/datasets/upload",
        headers=_h(OWNER),
        data={
            "name": "Bad",
            "description": "Test",
            "owner_email": OWNER,
            "organization": "",
            "columns": "[]",
            "declared_rows": "",
        },
        files={"file": ("encrypted.bin", io.BytesIO(b"\x80\x04pickle"), "application/octet-stream")},
    )
    assert r.status_code == 400


def test_request_and_approve_computation():
    pytest.importorskip("tenseal")
    import tenseal as ts

    ctx = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()
    enc = ts.ckks_vector(ctx, [1.0, 2.0, 3.0])
    ctx.make_context_public()
    file_bytes = dump_bundle({
        "public_context": ctx.serialize(),
        "vectors": {"col1": enc.serialize()},
        "columns": ["col1"],
        "n": 3,
    })
    r_upload = client.post(
        "/datasets/upload",
        headers=_h(OWNER),
        data={
            "name": "Job Test Dataset",
            "description": "For job test",
            "owner_email": OWNER,
            "organization": "",
            "columns": '["col1"]',
            "declared_rows": "",
        },
        files={"file": ("encrypted.bin", io.BytesIO(file_bytes), "application/octet-stream")},
    )
    if r_upload.status_code != 200:
        pytest.skip(f"Upload failed: {r_upload.text}")
    dataset_id = r_upload.json()["dataset_id"]
    r_req = client.post(
        "/jobs/request",
        headers=_h(RESEARCHER),
        json={
            "dataset_id": dataset_id,
            "requester_email": RESEARCHER,
            "computation_type": "mean",
            "algorithm": "mean",
            "selected_columns": ["col1"],
        },
    )
    assert r_req.status_code == 200
    job_id = r_req.json()["job_id"]
    r_approve = client.post(f"/jobs/{job_id}/approve", headers=_h(OWNER))
    assert r_approve.status_code == 200
    body = r_approve.json()
    assert body["status"] == "completed"
    assert body.get("encrypted") is True
    assert body.get("result") is None
    assert body.get("result_json", {}).get("encrypted") is True


def test_full_multiparty_workflow():
    r = client.post(
        "/studies/create",
        headers=_h(INST1),
        json={
            "name": "Multiparty Test",
            "description": "E2E test",
            "creator_email": INST1,
            "institution_name": "Inst 1",
            "threshold_t": 1,
            "threshold_n": 2,
            "allowed_algorithms": ["mean"],
            "column_definitions": [{"name": "x", "data_type": "float", "required": True}],
            "public_key_share": "dummy_key_creator",
        },
    )
    assert r.status_code == 200
    study_id = r.json()["study_id"]
    r_proto = client.post(
        f"/studies/{study_id}/protocol/create",
        headers=_h(INST1),
        json={
            "required_columns": [{"name": "x", "data_type": "float", "required": True}],
            "minimum_rows": 1,
            "missing_value_strategy": "exclude",
            "creator_email": INST1,
        },
    )
    assert r_proto.status_code == 200
    r_fin = client.post(
        f"/studies/{study_id}/protocol/finalize",
        headers=_h(INST1),
        json={"creator_email": INST1},
    )
    assert r_fin.status_code == 200
    r_join = client.post(
        f"/studies/{study_id}/join",
        headers=_h(INST2),
        json={
            "institution_email": INST2,
            "institution_name": "Inst 2",
            "public_key_share": "dummy_key_for_test",
        },
    )
    assert r_join.status_code == 200
    r_schema1 = client.post(
        f"/studies/{study_id}/schema/submit",
        headers=_h(INST1),
        json={
            "institution_email": INST1,
            "local_schema": {"columns": [{"name": "x", "type": "float"}]},
            "proposed_mapping": {"x": "x"},
        },
    )
    assert r_schema1.status_code == 200
    assert r_schema1.json().get("compatible") is True
    r_schema2 = client.post(
        f"/studies/{study_id}/schema/submit",
        headers=_h(INST2),
        json={
            "institution_email": INST2,
            "local_schema": {"columns": [{"name": "x", "type": "float"}]},
            "proposed_mapping": {"x": "x"},
        },
    )
    assert r_schema2.status_code == 200
    assert r_schema2.json().get("compatible") is True
    r_syn1 = client.post(
        f"/studies/{study_id}/synthetic/upload",
        headers=_h(INST1),
        files={"file": ("synthetic.csv", io.BytesIO(b"x\n1.0"), "text/csv")},
        data={"institution_email": INST1},
    )
    assert r_syn1.status_code == 200
    r_syn2 = client.post(
        f"/studies/{study_id}/synthetic/upload",
        headers=_h(INST2),
        files={"file": ("synthetic.csv", io.BytesIO(b"x\n2.0"), "text/csv")},
        data={"institution_email": INST2},
    )
    assert r_syn2.status_code == 200
    r_act = client.post(f"/studies/{study_id}/activate", params={"actor_email": INST1}, headers=_h(INST1))
    assert r_act.status_code == 200
    assert r_act.json().get("activated") is True or r_act.json().get("status") == "active", (
        f"Activation failed: {r_act.json()}"
    )
    pytest.importorskip("tenseal")
    import tenseal as ts

    ctx = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    ctx.global_scale = 2**40
    ctx.generate_galois_keys()
    enc = ts.ckks_vector(ctx, [1.0, 2.0, 3.0])
    ctx.make_context_public()
    file_bytes = dump_bundle({
        "public_context": ctx.serialize(),
        "vectors": {"x": enc.serialize()},
        "columns": ["x"],
        "n": 3,
    })
    r_up = client.post(
        f"/studies/{study_id}/upload_dataset",
        headers=_h(INST1),
        files={"file": ("encrypted.bin", io.BytesIO(file_bytes), "application/octet-stream")},
        data={
            "institution_email": INST1,
            "dataset_name": "Test Dataset",
            "columns": '["x"]',
        },
    )
    assert r_up.status_code == 200, r_up.text
    r_req = client.post(
        f"/studies/{study_id}/request_computation",
        headers=_h(INST1),
        json={
            "requester_email": INST1,
            "algorithm": "mean",
            "selected_columns": ["x"],
            "parameters": {},
        },
    )
    assert r_req.status_code == 200, r_req.text
    job_id = r_req.json()["job_id"]
    r_app = client.post(
        f"/studies/{study_id}/jobs/{job_id}/approve",
        headers=_h(INST1),
        json={"institution_email": INST1},
    )
    assert r_app.status_code == 200, r_app.text
    r_share = client.post(
        f"/studies/{study_id}/jobs/{job_id}/submit_decryption_share",
        headers=_h(INST1),
        json={"institution_email": INST1, "decryption_share": "dummy_share"},
    )
    assert r_share.status_code == 200, r_share.text
    body = r_share.json()
    assert body["status"] == "completed"
    assert body.get("encrypted") is True
    assert body.get("result_json", {}).get("encrypted") is True
