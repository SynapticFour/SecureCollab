# SPDX-License-Identifier: Apache-2.0
"""
Seed demo data: one study, two participants, protocol, schema submissions,
synthetic dry-runs, activation, optional study dataset, one pending job.
Run from backend dir: python -m scripts.seed_demo (or python scripts/seed_demo.py with PYTHONPATH=.).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path

# Ensure app is importable when run as script
import sys
if __name__ == "__main__" and (sys.path[0] or ".") != ".":
    pass  # assume already in path when run via python -m
try:
    from app.config import settings
    from app.core.security import sha3_256_hex
    from app.database import Session, create_db_and_tables, engine
    from app.models import (
        Job,
        ProtocolColumn,
        SchemaSubmission,
        Study,
        StudyDataset,
        StudyParticipant,
        StudyProtocol,
        SyntheticSubmission,
    )
    from app.services.audit_service import write_audit_log
    from app.services.schema_service import check_schema_compatibility, protocol_payload_for_hash
except ImportError as e:
    print("Import error (run from backend with PYTHONPATH=. or: python -m scripts.seed_demo):", e)
    raise

DEMO_CREATOR = "demo@test.com"
DEMO_CREATOR_NAME = "Demo Hospital A"
DEMO_PARTICIPANT_EMAIL = "participant@test.com"
DEMO_PARTICIPANT_NAME = "Demo Hospital B"
DEMO_STUDY_NAME = "Demo Study"
DEMO_STUDY_DESC = "Pre-seeded demo study for pilots and showcases."
REQUIRED_COLUMNS = [
    {"name": "value", "aliases": [], "data_type": "float", "required": True},
    {"name": "id", "aliases": ["subject_id"], "data_type": "float", "required": True},
]


def _ensure_upload_dirs(study_id: int) -> Path:
    study_dir = settings.studies_upload_dir_path / str(study_id)
    study_dir.mkdir(parents=True, exist_ok=True)
    return study_dir


def run_seed() -> dict:
    """Create demo study, participants, protocol, schemas, synthetic data, activate, add job. Idempotent by study name."""
    create_db_and_tables()
    settings.upload_dir_path.mkdir(parents=True, exist_ok=True)
    settings.studies_upload_dir_path.mkdir(parents=True, exist_ok=True)

    with Session(engine) as session:
        from sqlmodel import select
        existing = list(session.exec(select(Study).where(Study.name == DEMO_STUDY_NAME)))
        if existing:
            study = existing[0]
            return {"message": "Demo study already exists", "study_id": study.id}

        # 1) Study + creator participant (with dummy key so activation can succeed)
        protocol_json = json.dumps({
            "allowed_algorithms": ["mean", "variance", "descriptive_statistics"],
            "column_definitions": REQUIRED_COLUMNS,
        })
        study = Study(
            name=DEMO_STUDY_NAME,
            description=DEMO_STUDY_DESC,
            protocol=protocol_json,
            status="draft",
            threshold_n=2,
            threshold_t=2,
            created_by=DEMO_CREATOR,
        )
        session.add(study)
        session.commit()
        session.refresh(study)
        study_id = study.id

        part1 = StudyParticipant(
            study_id=study_id,
            institution_name=DEMO_CREATOR_NAME,
            institution_email=DEMO_CREATOR,
            public_key_share="dummy_key_creator",
            key_share_committed_at=datetime.utcnow(),
        )
        session.add(part1)
        session.commit()

        write_audit_log(
            session, study_id, "study_created", DEMO_CREATOR,
            {"study_id": study_id, "name": DEMO_STUDY_NAME, "threshold_n": 2, "threshold_t": 2},
        )
        session.commit()

        # 2) Protocol create + finalize
        payload_str = protocol_payload_for_hash(REQUIRED_COLUMNS, 1, "exclude")
        protocol_hash = sha3_256_hex(payload_str)
        sp = StudyProtocol(
            study_id=study_id,
            protocol_version="1.0",
            required_columns=json.dumps(REQUIRED_COLUMNS),
            minimum_rows=1,
            missing_value_strategy="exclude",
            protocol_hash=protocol_hash,
            status="draft",
        )
        session.add(sp)
        session.commit()
        session.refresh(sp)
        for c in REQUIRED_COLUMNS:
            pc = ProtocolColumn(
                protocol_id=sp.id,
                column_name=c.get("name", ""),
                aliases=json.dumps(c.get("aliases") or []),
                data_type=c.get("data_type", "float"),
                required=c.get("required", True),
            )
            session.add(pc)
        write_audit_log(session, study_id, "protocol_created", DEMO_CREATOR, {"protocol_hash": protocol_hash})
        session.commit()

        sp.status = "finalized"
        sp.finalized_at = datetime.utcnow()
        session.add(sp)
        write_audit_log(session, study_id, "protocol_finalized", DEMO_CREATOR, {"protocol_hash": protocol_hash})
        session.commit()

        # 3) Second participant
        part2 = StudyParticipant(
            study_id=study_id,
            institution_name=DEMO_PARTICIPANT_NAME,
            institution_email=DEMO_PARTICIPANT_EMAIL,
            public_key_share="dummy_key_participant",
            key_share_committed_at=datetime.utcnow(),
        )
        session.add(part2)
        session.commit()
        write_audit_log(
            session, study_id, "participant_joined", DEMO_PARTICIPANT_EMAIL,
            {"institution": DEMO_PARTICIPANT_NAME, "total_participants": 2},
        )
        session.commit()

        # 4) Schema submissions (both compatible)
        local_schema = {"columns": [{"name": "value", "type": "float"}, {"name": "id", "type": "float"}]}
        mapping = {"value": "value", "id": "id"}
        for email in (DEMO_CREATOR, DEMO_PARTICIPANT_EMAIL):
            result = check_schema_compatibility(REQUIRED_COLUMNS, local_schema, mapping)
            mapping_json = json.dumps(mapping, sort_keys=True)
            sig = sha3_256_hex(mapping_json, protocol_hash, email)
            sub = SchemaSubmission(
                study_id=study_id,
                institution_email=email,
                submitted_schema=json.dumps(local_schema),
                mapping=mapping_json,
                fingerprint=json.dumps({}),
                compatibility_result=json.dumps(result),
                institution_signature=sig,
                signed_at=datetime.utcnow(),
            )
            session.add(sub)
            write_audit_log(
                session, study_id, "schema_submitted", email,
                {"compatible": result["compatible"], "issue_count": len(result.get("issues", []))},
            )
        session.commit()

        # 5) Synthetic dry-run CSVs
        study_dir = _ensure_upload_dirs(study_id)
        for email in (DEMO_CREATOR, DEMO_PARTICIPANT_EMAIL):
            path = study_dir / f"synthetic_{uuid.uuid4().hex}.csv"
            path.write_text("value,id\n1.0,1\n2.0,2\n", encoding="utf-8")
            syn = SyntheticSubmission(
                study_id=study_id,
                institution_email=email,
                file_path=str(path),
                validation_result=json.dumps({"schema_valid": True, "issues": [], "algorithms_tested": []}),
            )
            session.add(syn)
            write_audit_log(session, study_id, "dry_run_completed", email, {"schema_valid": True})
        session.commit()

        # 6) Activate study
        study.status = "active"
        study.combined_public_key = "dummy_combined"
        study.public_key_fingerprint = sha3_256_hex(b"dummy_combined")
        study.updated_at = datetime.utcnow()
        session.add(study)
        schema_subs = list(session.exec(select(SchemaSubmission).where(SchemaSubmission.study_id == study_id)))
        write_audit_log(
            session, study_id, "study_activated", "system",
            {"protocol_hash": protocol_hash, "participant_count": 2, "schema_signatures": [s.institution_signature for s in schema_subs]},
        )
        session.commit()

        # 7) Optional: one study dataset (placeholder .bin so UI shows something)
        try:
            import pickle
            placeholder = {"n": 1, "columns": "[]", "public_context": b"demo", "secret_context": b"demo", "vectors": {}}
            bin_path = study_dir / f"{uuid.uuid4().hex}.bin"
            bin_path.write_bytes(pickle.dumps(placeholder))
            ts_str = datetime.utcnow().isoformat()
            commitment_hash = sha3_256_hex(bin_path.read_bytes(), study.public_key_fingerprint, ts_str, DEMO_CREATOR)
            sd = StudyDataset(
                study_id=study_id,
                dataset_name="demo_dataset",
                institution_email=DEMO_CREATOR,
                file_path=str(bin_path),
                commitment_hash=commitment_hash,
                columns=json.dumps(["value", "id"]),
                committed_at=datetime.utcnow(),
            )
            session.add(sd)
            write_audit_log(
                session, study_id, "dataset_uploaded", DEMO_CREATOR,
                {"commitment_hash": commitment_hash, "dataset_name": "demo_dataset", "size_bytes": len(placeholder)},
            )
            session.commit()
        except Exception:
            pass  # optional

        # 8) One pending job
        job = Job(
            study_id=study_id,
            dataset_id=None,
            requester_email="researcher@test.com",
            algorithm="mean",
            computation_type="mean",
            selected_columns=json.dumps(["value"]),
            parameters=json.dumps({}),
            status="pending_approval",
        )
        session.add(job)
        session.commit()
        write_audit_log(
            session, study_id, "computation_requested", "researcher@test.com",
            {"job_id": job.id, "algorithm": "mean", "selected_columns": ["value"]},
        )
        session.commit()

    return {"message": "Demo seed completed", "study_id": study_id}


if __name__ == "__main__":
    result = run_seed()
    print(result)
