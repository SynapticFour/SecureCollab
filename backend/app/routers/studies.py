# SPDX-License-Identifier: Apache-2.0
"""Study endpoints. Identity from signed access token. HE compute never decrypts."""
from __future__ import annotations

import base64
import csv
import io
import json
import logging
import secrets
import uuid
from pathlib import Path

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Request, UploadFile
from sqlmodel import select

from app.config import (
    ALLOWED_UPLOAD_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_MB,
    STUDIES_UPLOADS_DIR,
)
from app.core.algorithms import ALGORITHM_REGISTRY
from app.core.release import expected_release_share, is_key_commitment, shares_match
from app.core.security import AuthUser, assert_actor, rate_limit, require_user, sha3_256_hex
from app.core.timeutils import audit_timestamp, utc_now
from app.database import Session, engine
from app.models import (
    AuditLog,
    Job,
    JobApproval,
    JobDecryptionShare,
    ProtocolColumn,
    SchemaSubmission,
    Study,
    StudyDataset,
    StudyParticipant,
    StudyProtocol,
    SyntheticSubmission,
)
from app.schemas import (
    ProtocolCreate,
    ProtocolFinalize,
    SchemaSubmit,
    StudyApprove,
    StudyCreate,
    StudyJoin,
    StudyRequestComputation,
    StudySubmitDecryptionShare,
)
from app.services.audit_service import write_audit_log
from app.services.bundle import BundleError, load_bundle
from app.services.compute_pool import ComputeBusyError, ComputeTimeoutError, run_he
from app.services.he_service import run_on_datasets
from app.services.schema_service import check_schema_compatibility, protocol_payload_for_hash

router = APIRouter(prefix="", tags=["studies"])
_log = logging.getLogger("securecollab")


def _ts(dt) -> str:
    return audit_timestamp(dt)


def _require_participant(session: Session, study_id: int, email: str) -> StudyParticipant:
    participant = session.exec(
        select(StudyParticipant).where(
            StudyParticipant.study_id == study_id,
            StudyParticipant.institution_email == email,
        )
    ).first()
    if not participant:
        raise HTTPException(status_code=403, detail="Institution ist kein Teilnehmer")
    return participant


def _study_encryption_key(study: Study, participants: list[StudyParticipant]) -> str:
    """Study public key is the creator's share. This is not threshold DKG."""
    for p in participants:
        if p.institution_email == study.created_by and p.public_key_share:
            return p.public_key_share
    return next((p.public_key_share for p in participants if p.public_key_share), "") or ""


def _fingerprint(combined: str) -> str:
    try:
        raw = base64.b64decode(combined) if isinstance(combined, str) else combined
    except Exception:
        raw = combined.encode("utf-8") if isinstance(combined, str) else combined
    return sha3_256_hex(raw)


def _get_activation_status(study_id: int, session: Session) -> dict:
    study = session.get(Study, study_id)
    if not study:
        raise HTTPException(status_code=404, detail="Study nicht gefunden")
    sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
    participants = list(session.exec(select(StudyParticipant).where(StudyParticipant.study_id == study_id)))
    schema_submissions = list(session.exec(select(SchemaSubmission).where(SchemaSubmission.study_id == study_id)))
    synthetic = list(session.exec(select(SyntheticSubmission).where(SyntheticSubmission.study_id == study_id)))
    n_compatible = 0
    for s in schema_submissions:
        try:
            if (json.loads(s.compatibility_result or "{}")).get("compatible"):
                n_compatible += 1
        except (json.JSONDecodeError, TypeError):
            continue
    n_keys = sum(1 for p in participants if p.public_key_share)
    protocol_finalized = sp is not None and sp.status == "finalized"
    all_schemas = len(schema_submissions) >= len(participants) and n_compatible == len(participants)
    emails_syn = {s.institution_email for s in synthetic}
    emails_part = {p.institution_email for p in participants}
    all_dry_run = emails_part <= emails_syn and len(participants) > 0
    all_keys = len(participants) >= study.threshold_n and n_keys >= study.threshold_n
    can_activate = protocol_finalized and all_schemas and all_dry_run and all_keys
    return {
        "can_activate": can_activate,
        "conditions": [
            {"condition": "protocol_finalized", "met": protocol_finalized},
            {"condition": "all_schemas_compatible", "met": all_schemas, "details": {"n_submitted": len(schema_submissions), "n_compatible": n_compatible, "n_required": len(participants)}},
            {"condition": "dry_run_completed", "met": all_dry_run, "details": {"n_completed": len(emails_syn), "n_required": len(participants)}},
            {"condition": "all_keys_submitted", "met": all_keys, "details": {"n_submitted": n_keys, "n_required": study.threshold_n}},
        ],
    }


@router.get("")
def studies_list(participant_email: str = "", user: AuthUser = Depends(require_user)):
    """Studies the authenticated institution participates in."""
    if participant_email:
        assert_actor(user, participant_email)
    with Session(engine) as session:
        participants = list(
            session.exec(
                select(StudyParticipant).where(StudyParticipant.institution_email == user.email)
            )
        )
        study_ids = list({p.study_id for p in participants})
        if not study_ids:
            return []
        studies = [s for s in (session.get(Study, sid) for sid in study_ids) if s is not None]
        if not studies:
            return []
        ids = [s.id for s in studies]
        from sqlalchemy import func
        part_counts = {r[0]: r[1] for r in session.exec(
            select(StudyParticipant.study_id, func.count(StudyParticipant.id))
            .where(StudyParticipant.study_id.in_(ids))
            .group_by(StudyParticipant.study_id)
        ).all()}
        ds_counts = {r[0]: r[1] for r in session.exec(
            select(StudyDataset.study_id, func.count(StudyDataset.id))
            .where(StudyDataset.study_id.in_(ids))
            .group_by(StudyDataset.study_id)
        ).all()}
        pending_counts = {r[0]: r[1] for r in session.exec(
            select(Job.study_id, func.count(Job.id))
            .where(Job.study_id.in_(ids), Job.status == "pending_approval")
            .group_by(Job.study_id)
        ).all()}
        return [
            {
                "id": study.id,
                "name": study.name,
                "description": study.description,
                "status": study.status,
                "threshold_n": study.threshold_n,
                "threshold_t": study.threshold_t,
                "participant_count": part_counts.get(study.id, 0),
                "dataset_count": ds_counts.get(study.id, 0),
                "pending_approvals": pending_counts.get(study.id, 0),
                "created_at": _ts(study.created_at),
            }
            for study in studies
        ]


@router.get("/{study_id}")
def studies_get(study_id: int, user: AuthUser = Depends(require_user)):
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        try:
            protocol = json.loads(study.protocol or "{}")
        except (json.JSONDecodeError, TypeError):
            protocol = {}
        return {
            "id": study.id,
            "name": study.name,
            "description": study.description,
            "status": study.status,
            "threshold_n": study.threshold_n,
            "threshold_t": study.threshold_t,
            "public_key_fingerprint": study.public_key_fingerprint,
            "combined_public_key": study.combined_public_key if study.status == "active" else None,
            "protocol": protocol,
            "created_by": study.created_by,
            "invite_code": study.invite_code if study.created_by.lower() == user.email.lower() else None,
            "created_at": _ts(study.created_at),
            "updated_at": _ts(study.updated_at),
        }


@router.post("/create")
@rate_limit("30/hour")
def studies_create(request: Request, body: StudyCreate, user: AuthUser = Depends(require_user)):
    assert_actor(user, body.creator_email)
    commitment = (body.key_commitment or "").strip().lower()
    if commitment and not is_key_commitment(commitment):
        raise HTTPException(status_code=400, detail="key_commitment must be 64 lowercase hex chars")
    protocol = {
        "allowed_algorithms": body.allowed_algorithms,
        "column_definitions": body.column_definitions,
    }
    with Session(engine) as session:
        study = Study(
            name=body.name,
            description=body.description,
            protocol=json.dumps(protocol),
            status="draft",
            threshold_n=body.threshold_n,
            threshold_t=min(body.threshold_t, body.threshold_n),
            created_by=user.email,
            invite_code=secrets.token_urlsafe(16),
        )
        session.add(study)
        session.commit()
        session.refresh(study)
        part = StudyParticipant(
            study_id=study.id,
            institution_name=body.institution_name,
            institution_email=user.email,
            public_key_share=body.public_key_share or "",
            key_commitment=commitment,
            key_share_committed_at=utc_now() if (body.public_key_share or commitment) else None,
        )
        session.add(part)
        session.commit()
        write_audit_log(
            session, study.id, "study_created", user.email,
            {"study_id": study.id, "name": body.name, "threshold_n": body.threshold_n, "threshold_t": study.threshold_t},
        )
        session.commit()
        return {
            "study_id": study.id,
            "invite_code": study.invite_code,
            "instructions": "Share invite_code with participants. They join via POST /studies/{id}/join.",
        }


@router.post("/{study_id}/protocol/create")
def studies_protocol_create(study_id: int, body: ProtocolCreate, user: AuthUser = Depends(require_user)):
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        if study.created_by != user.email:
            raise HTTPException(status_code=403, detail="Nur der Study-Creator darf das Protocol anlegen")
        existing = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        if existing:
            raise HTTPException(status_code=400, detail="Protocol existiert bereits für diese Study")
        required_columns = [c.model_dump() if hasattr(c, "model_dump") else c for c in body.required_columns]
        for c in required_columns:
            if isinstance(c, dict) and "valid_range" not in c and ("valid_range_min" in c or "valid_range_max" in c):
                c["valid_range"] = [c.get("valid_range_min"), c.get("valid_range_max")]
        payload_str = protocol_payload_for_hash(required_columns, body.minimum_rows, body.missing_value_strategy)
        protocol_hash = sha3_256_hex(payload_str)
        sp = StudyProtocol(
            study_id=study_id,
            protocol_version="1.0",
            required_columns=json.dumps(required_columns),
            minimum_rows=body.minimum_rows,
            missing_value_strategy=body.missing_value_strategy,
            protocol_hash=protocol_hash,
            status="draft",
        )
        session.add(sp)
        session.commit()
        session.refresh(sp)
        for c in body.required_columns:
            cd = c.model_dump() if hasattr(c, "model_dump") else c
            valid_range = cd.get("valid_range") or []
            vmin = valid_range[0] if len(valid_range) > 0 else cd.get("valid_range_min")
            vmax = valid_range[1] if len(valid_range) > 1 else cd.get("valid_range_max")
            session.add(ProtocolColumn(
                protocol_id=sp.id,
                column_name=cd.get("name", ""),
                aliases=json.dumps(cd.get("aliases") or []),
                data_type=cd.get("data_type", "float"),
                unit=cd.get("unit"),
                valid_range_min=vmin,
                valid_range_max=vmax,
                allowed_values=json.dumps(cd.get("allowed_values")) if cd.get("allowed_values") else None,
                required=cd.get("required", True),
                description=cd.get("description", ""),
            ))
        session.commit()
        write_audit_log(session, study_id, "protocol_created", user.email, {"protocol_hash": protocol_hash})
        session.commit()
        return {"protocol_hash": protocol_hash, "status": "draft"}


@router.post("/{study_id}/protocol/finalize")
def studies_protocol_finalize(
    study_id: int,
    body: ProtocolFinalize = Body(default=ProtocolFinalize()),
    user: AuthUser = Depends(require_user),
):
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        if study.created_by != user.email:
            raise HTTPException(status_code=403, detail="Nur der Study-Creator darf finalisieren")
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        if not sp:
            raise HTTPException(status_code=404, detail="Kein Protocol vorhanden. Zuerst protocol/create aufrufen.")
        if sp.status == "finalized":
            return {"status": "finalized", "protocol_hash": sp.protocol_hash}
        sp.status = "finalized"
        sp.finalized_at = utc_now()
        session.add(sp)
        write_audit_log(session, study_id, "protocol_finalized", user.email, {"protocol_hash": sp.protocol_hash})
        session.commit()
        return {"status": "finalized", "protocol_hash": sp.protocol_hash}


@router.post("/{study_id}/join")
@rate_limit("30/hour")
def studies_join(request: Request, study_id: int, body: StudyJoin, user: AuthUser = Depends(require_user)):
    assert_actor(user, body.institution_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        if study.status == "active":
            raise HTTPException(status_code=400, detail="Study ist bereits aktiv")
        if not study.invite_code or body.invite_code.strip() != study.invite_code:
            raise HTTPException(status_code=403, detail="Invalid or missing invite_code")
        commitment = (body.key_commitment or "").strip().lower()
        if not is_key_commitment(commitment):
            raise HTTPException(status_code=400, detail="key_commitment must be SHA3-256 hex of the local secret context")
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        if sp and sp.status != "finalized":
            raise HTTPException(status_code=400, detail="Study kann erst Teilnehmer aufnehmen, wenn das Protocol finalisiert ist. Creator muss protocol/finalize aufrufen.")
        participants = list(session.exec(select(StudyParticipant).where(StudyParticipant.study_id == study_id)))
        if any(p.institution_email == user.email for p in participants):
            raise HTTPException(status_code=400, detail="Institution bereits Teilnehmer")
        part = StudyParticipant(
            study_id=study_id,
            institution_name=body.institution_name,
            institution_email=user.email,
            public_key_share=body.public_key_share,
            key_commitment=commitment,
            key_share_committed_at=utc_now(),
        )
        session.add(part)
        session.commit()
        write_audit_log(
            session, study_id, "participant_joined",
            user.email,
            {"institution": body.institution_name, "total_participants": len(participants) + 1},
        )
        participants = list(session.exec(select(StudyParticipant).where(StudyParticipant.study_id == study_id)))
        if not sp and len(participants) >= study.threshold_n:
            combined = _study_encryption_key(study, participants)
            if combined:
                study.combined_public_key = combined
                study.public_key_fingerprint = _fingerprint(combined)
                study.status = "active"
                study.updated_at = utc_now()
                session.add(study)
                write_audit_log(
                    session, study_id, "study_activated", "system",
                    {
                        "public_key_fingerprint": study.public_key_fingerprint,
                        "participant_count": len(participants),
                        "key_source": "creator_public_key",
                    },
                )
        session.commit()
        return {
            "study_id": study_id,
            "status": study.status,
            "combined_public_key": study.combined_public_key if study.status == "active" else None,
            "message": "Bei Schema-Protocol: Aktivierung über POST /studies/{id}/activate." if sp else None,
        }


@router.get("/{study_id}/public_key")
def studies_public_key(study_id: int, user: AuthUser = Depends(require_user)):
    """Public encryption key for the study (creator's key in this prototype). Participants only."""
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        datasets = list(session.exec(select(StudyDataset).where(StudyDataset.study_id == study_id)))
        return {
            "combined_public_key": study.combined_public_key,
            "public_key_fingerprint": study.public_key_fingerprint,
            "key_model": "creator_public_key",
            "upload_commitments": [
                {"dataset_name": d.dataset_name, "commitment_hash": d.commitment_hash, "institution_email": d.institution_email}
                for d in datasets
            ],
        }


@router.post("/{study_id}/schema/submit")
def studies_schema_submit(study_id: int, body: SchemaSubmit, user: AuthUser = Depends(require_user)):
    assert_actor(user, body.institution_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        if not sp or sp.status != "finalized":
            raise HTTPException(status_code=400, detail="Protocol muss finalisiert sein")
        try:
            required_columns = json.loads(sp.required_columns or "[]")
        except (json.JSONDecodeError, TypeError):
            required_columns = []
        for c in required_columns:
            if isinstance(c, dict) and "valid_range" not in c:
                c["valid_range"] = [c.get("valid_range_min"), c.get("valid_range_max")]
        local_schema = body.local_schema or {}
        result = check_schema_compatibility(required_columns, local_schema, body.proposed_mapping or {})
        mapping_json = json.dumps(body.proposed_mapping or {}, sort_keys=True)
        # Attestation hash bound to the authenticated email (not a digital signature).
        institution_attestation = sha3_256_hex(mapping_json, sp.protocol_hash, user.email)
        sub = SchemaSubmission(
            study_id=study_id,
            institution_email=user.email,
            submitted_schema=json.dumps(local_schema),
            mapping=mapping_json,
            fingerprint=json.dumps({}),
            compatibility_result=json.dumps(result),
            institution_signature=institution_attestation,
            signed_at=utc_now(),
        )
        session.add(sub)
        write_audit_log(
            session, study_id, "schema_submitted", user.email,
            {"compatible": result["compatible"], "issue_count": len(result.get("issues", []))},
        )
        session.commit()
        return {
            "compatible": result["compatible"],
            "approved_mappings": result.get("approved_mappings", []),
            "issues": result.get("issues", []),
            "warnings": result.get("warnings", []),
        }


@router.post("/{study_id}/synthetic/upload")
@rate_limit("10/hour")
def studies_synthetic_upload(
    request: Request,
    study_id: int,
    file: UploadFile = File(...),
    institution_email: str = Form(...),
    user: AuthUser = Depends(require_user),
):
    assert_actor(user, institution_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        if not sp or sp.status != "finalized":
            raise HTTPException(status_code=400, detail="Protocol muss finalisiert sein")
        content = file.file.read(MAX_UPLOAD_BYTES + 1)
        file.file.close()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB} MB)")
        try:
            required_columns = json.loads(sp.required_columns or "[]")
        except (json.JSONDecodeError, TypeError):
            required_columns = []
        schema_valid = True
        issues: list[str] = []
        try:
            reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
            rows = list(reader)
            if len(rows) < sp.minimum_rows:
                schema_valid = False
                issues.append(f"Zeilen: {len(rows)}, Minimum: {sp.minimum_rows}")
            col_names = list(rows[0].keys()) if rows else []
            for c in required_columns:
                name = c.get("name", "") if isinstance(c, dict) else ""
                if name and name not in col_names and name not in (c.get("aliases") or []):
                    aliases = c.get("aliases") or []
                    if not any(a in col_names for a in aliases):
                        schema_valid = False
                        issues.append(f"Fehlende Spalte: {name}")
        except Exception as e:
            schema_valid = False
            issues.append(str(e))
        study_dir = STUDIES_UPLOADS_DIR / str(study_id)
        study_dir.mkdir(parents=True, exist_ok=True)
        path = study_dir / f"synthetic_{uuid.uuid4().hex}.csv"
        path.write_bytes(content)
        syn = SyntheticSubmission(
            study_id=study_id,
            institution_email=user.email,
            file_path=str(path),
            validation_result=json.dumps({"schema_valid": schema_valid, "issues": issues, "algorithms_tested": []}),
        )
        session.add(syn)
        write_audit_log(session, study_id, "dry_run_completed", user.email, {"schema_valid": schema_valid})
        session.commit()
        return {"schema_valid": schema_valid, "issues": issues, "algorithms_tested": [], "sample_results": {}}


@router.get("/{study_id}/activation_status")
def studies_activation_status(study_id: int, user: AuthUser = Depends(require_user)):
    with Session(engine) as session:
        _require_participant(session, study_id, user.email)
        return _get_activation_status(study_id, session)


@router.post("/{study_id}/activate")
def studies_activate(study_id: int, actor_email: str = "", user: AuthUser = Depends(require_user)):
    if actor_email:
        assert_actor(user, actor_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        if study.created_by != user.email:
            raise HTTPException(status_code=403, detail="Nur der Study-Creator darf aktivieren")
        if study.status == "active":
            return {"status": "active", "message": "Bereits aktiv"}
        status = _get_activation_status(study_id, session)
        if not status["can_activate"]:
            return {"activated": False, "message": "Preconditions nicht erfüllt", "conditions": status["conditions"]}
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        participants = list(session.exec(select(StudyParticipant).where(StudyParticipant.study_id == study_id)))
        schema_submissions = list(session.exec(select(SchemaSubmission).where(SchemaSubmission.study_id == study_id)))
        combined = _study_encryption_key(study, participants)
        study.combined_public_key = combined
        study.public_key_fingerprint = _fingerprint(combined) if combined else ""
        study.status = "active"
        study.updated_at = utc_now()
        session.add(study)
        schema_signatures = [s.institution_signature for s in schema_submissions]
        write_audit_log(
            session, study_id, "study_activated", user.email,
            {
                "protocol_hash": sp.protocol_hash if sp else "",
                "participant_count": len(participants),
                "schema_attestations": schema_signatures,
                "key_source": "creator_public_key",
            },
        )
        session.commit()
        return {"activated": True, "status": "active", "public_key_fingerprint": study.public_key_fingerprint}


@router.post("/{study_id}/upload_dataset")
@rate_limit("10/hour")
def studies_upload_dataset(
    request: Request,
    study_id: int,
    file: UploadFile = File(...),
    institution_email: str = Form(...),
    dataset_name: str = Form(""),
    columns: str = Form("[]"),
    commitment_timestamp: str = Form(""),
    user: AuthUser = Depends(require_user),
):
    assert_actor(user, institution_email)
    if Path(file.filename or "").suffix.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .bin files are allowed")
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        if study.status != "active":
            raise HTTPException(status_code=400, detail="Study muss aktiv sein zum Upload")
        file_bytes = file.file.read(MAX_UPLOAD_BYTES + 1)
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB} MB)")
        file.file.close()
        try:
            load_bundle(file_bytes)
        except BundleError as e:
            raise HTTPException(status_code=400, detail=f"Invalid ciphertext bundle: {e}") from e
        ts_str = commitment_timestamp.strip() or _ts(utc_now())
        fp = study.public_key_fingerprint or ""
        commitment_hash = sha3_256_hex(file_bytes, fp, ts_str, user.email)
        study_dir = STUDIES_UPLOADS_DIR / str(study_id)
        study_dir.mkdir(parents=True, exist_ok=True)
        path = study_dir / f"{uuid.uuid4().hex}.bin"
        path.write_bytes(file_bytes)
        try:
            cols = json.loads(columns) if columns else []
        except (json.JSONDecodeError, TypeError):
            cols = []
        sd = StudyDataset(
            study_id=study_id,
            dataset_name=dataset_name or file.filename or "dataset",
            institution_email=user.email,
            file_path=str(path),
            commitment_hash=commitment_hash,
            columns=json.dumps(cols) if isinstance(cols, list) else "[]",
            committed_at=utc_now(),
        )
        session.add(sd)
        session.commit()
        write_audit_log(
            session, study_id, "dataset_uploaded", user.email,
            {"commitment_hash": commitment_hash, "dataset_name": sd.dataset_name, "size_bytes": len(file_bytes)},
        )
        session.commit()
        return {"commitment_hash": commitment_hash}


@router.post("/{study_id}/request_computation")
def studies_request_computation(
    study_id: int, body: StudyRequestComputation, user: AuthUser = Depends(require_user)
):
    assert_actor(user, body.requester_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        if study.status != "active":
            raise HTTPException(status_code=400, detail="Study muss aktiv sein")
        try:
            protocol = json.loads(study.protocol or "{}")
            allowed = protocol.get("allowed_algorithms", [])
        except (json.JSONDecodeError, TypeError):
            allowed = []
        if allowed and body.algorithm not in allowed:
            raise HTTPException(status_code=400, detail=f"Algorithmus {body.algorithm} nicht erlaubt")
        if body.algorithm not in ALGORITHM_REGISTRY:
            raise HTTPException(status_code=400, detail="Algorithm not in approved registry")
        job = Job(
            study_id=study_id,
            dataset_id=None,
            requester_email=user.email,
            algorithm=body.algorithm,
            computation_type=body.algorithm,
            selected_columns=json.dumps(body.selected_columns),
            parameters=json.dumps(body.parameters),
            status="pending_approval",
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        write_audit_log(
            session, study_id, "computation_requested", user.email,
            {"job_id": job.id, "algorithm": body.algorithm, "selected_columns": body.selected_columns},
        )
        session.commit()
        return {"job_id": job.id, "status": "pending_approval"}


@router.post("/{study_id}/jobs/{job_id}/approve")
def studies_job_approve(
    study_id: int, job_id: int, body: StudyApprove, user: AuthUser = Depends(require_user)
):
    """Collect authorizations. At threshold, run HE on all study datasets (no decrypt)."""
    assert_actor(user, body.institution_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        job = session.get(Job, job_id)
        if not study or not job or job.study_id != study_id:
            raise HTTPException(status_code=404, detail="Study oder Job nicht gefunden")
        if job.status != "pending_approval":
            raise HTTPException(status_code=400, detail=f"Job hat status {job.status}")
        participant = _require_participant(session, study_id, user.email)
        existing = session.exec(
            select(JobApproval).where(JobApproval.job_id == job_id, JobApproval.institution_email == user.email)
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Bereits genehmigt")
        session.add(JobApproval(job_id=job_id, institution_email=user.email))
        participant.has_approved_result = True
        session.add(participant)
        session.commit()
        approvals = list(session.exec(select(JobApproval).where(JobApproval.job_id == job_id)))
        if len(approvals) < study.threshold_t:
            return {
                "job_id": job_id,
                "status": "pending_approval",
                "approvals": len(approvals),
                "required": study.threshold_t,
            }
        datasets = list(session.exec(select(StudyDataset).where(StudyDataset.study_id == study_id)))
        if not datasets:
            raise HTTPException(status_code=400, detail="Keine Datensätze in der Study")
        missing = [d.file_path for d in datasets if not Path(d.file_path).exists()]
        if missing:
            raise HTTPException(status_code=404, detail="Dataset-Datei nicht gefunden")
        algorithm = job.algorithm or "mean"
        if algorithm not in ALGORITHM_REGISTRY:
            raise HTTPException(status_code=400, detail="Algorithm not in approved registry")
        try:
            sel_cols = json.loads(job.selected_columns or "[]")
        except (json.JSONDecodeError, TypeError):
            sel_cols = []
        try:
            params = json.loads(job.parameters or "{}")
        except (json.JSONDecodeError, TypeError):
            params = {}
        paths = [d.file_path for d in datasets]
        try:
            result_obj = run_he(run_on_datasets, paths, algorithm, sel_cols, params)
        except BundleError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except ComputeBusyError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        except ComputeTimeoutError as e:
            raise HTTPException(status_code=504, detail=str(e)) from e
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except Exception:
            _log.exception("HE computation failed for study job %s", job_id)
            raise HTTPException(status_code=500, detail="Computation failed. Check algorithm and columns.")
        result_json_str = json.dumps(result_obj)
        result_commitment = sha3_256_hex(result_json_str.encode("utf-8"))
        job.result_json = result_json_str
        job.result_commitment = result_commitment
        job.result = None
        job.status = "awaiting_decryption"
        session.add(job)
        write_audit_log(
            session, study_id, "computation_executed", "system",
            {"job_id": job_id, "algorithm": algorithm, "result_commitment": result_commitment, "encrypted": True},
        )
        session.commit()
        return {
            "job_id": job_id,
            "status": "awaiting_decryption",
            "result_commitment": result_commitment,
            "encrypted": True,
        }


@router.post("/{study_id}/jobs/{job_id}/submit_decryption_share")
def studies_job_submit_decryption_share(
    study_id: int, job_id: int, body: StudySubmitDecryptionShare, user: AuthUser = Depends(require_user)
):
    """Authorization to release the encrypted result. Shares are not cryptographic partial decrypts."""
    assert_actor(user, body.institution_email)
    with Session(engine) as session:
        study = session.get(Study, study_id)
        job = session.get(Job, job_id)
        if not study or not job or job.study_id != study_id:
            raise HTTPException(status_code=404, detail="Study oder Job nicht gefunden")
        if job.status != "awaiting_decryption":
            raise HTTPException(status_code=400, detail=f"Job hat status {job.status}")
        participant = _require_participant(session, study_id, user.email)
        existing = session.exec(
            select(JobDecryptionShare).where(
                JobDecryptionShare.job_id == job_id,
                JobDecryptionShare.institution_email == user.email,
            )
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Decryption Share bereits eingereicht")
        if not is_key_commitment(participant.key_commitment):
            raise HTTPException(status_code=400, detail="Participant has no key_commitment; re-join is required")
        expected = expected_release_share(job_id, user.email, participant.key_commitment)
        if not shares_match(body.decryption_share, expected):
            raise HTTPException(status_code=400, detail="Invalid release share")
        session.add(JobDecryptionShare(
            job_id=job_id,
            institution_email=user.email,
            decryption_share=body.decryption_share,
        ))
        session.commit()
        shares = list(session.exec(select(JobDecryptionShare).where(JobDecryptionShare.job_id == job_id)))
        if len(shares) < study.threshold_t:
            return {
                "job_id": job_id,
                "status": "awaiting_decryption",
                "shares": len(shares),
                "required": study.threshold_t,
            }
        job.status = "completed"
        session.add(job)
        write_audit_log(
            session, study_id, "result_released", user.email,
            {"job_id": job_id, "authorizations": len(shares), "encrypted": True},
        )
        session.commit()
        result_json = json.loads(job.result_json) if job.result_json else None
        return {"job_id": job_id, "status": "completed", "result_json": result_json, "encrypted": True}


@router.get("/{study_id}/audit_trail")
def studies_audit_trail(study_id: int, user: AuthUser = Depends(require_user)):
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        entries = list(session.exec(select(AuditLog).where(AuditLog.study_id == study_id).order_by(AuditLog.id)))
        return [
            {
                "id": e.id,
                "action_type": e.action_type,
                "actor_email": e.actor_email,
                "details": json.loads(e.details) if e.details else {},
                "previous_hash": e.previous_hash,
                "entry_hash": e.entry_hash,
                "created_at": _ts(e.created_at),
            }
            for e in entries
        ]


@router.get("/{study_id}/protocol")
def studies_protocol(study_id: int, user: AuthUser = Depends(require_user)):
    with Session(engine) as session:
        study = session.get(Study, study_id)
        if not study:
            raise HTTPException(status_code=404, detail="Study nicht gefunden")
        _require_participant(session, study_id, user.email)
        participants = list(session.exec(select(StudyParticipant).where(StudyParticipant.study_id == study_id)))
        datasets = list(session.exec(select(StudyDataset).where(StudyDataset.study_id == study_id)))
        jobs = list(session.exec(select(Job).where(Job.study_id == study_id)))
        audit_entries = list(session.exec(select(AuditLog).where(AuditLog.study_id == study_id).order_by(AuditLog.id)))
        try:
            protocol_data = json.loads(study.protocol or "{}")
        except (json.JSONDecodeError, TypeError):
            protocol_data = {}
        sp = session.exec(select(StudyProtocol).where(StudyProtocol.study_id == study_id)).first()
        protocol_hash = None
        required_columns = protocol_data.get("column_definitions", [])
        if sp:
            protocol_hash = sp.protocol_hash
            pc_rows = list(session.exec(select(ProtocolColumn).where(ProtocolColumn.protocol_id == sp.id)))
            if pc_rows:
                required_columns = [
                    {
                        "name": pc.column_name,
                        "aliases": json.loads(pc.aliases or "[]"),
                        "data_type": pc.data_type,
                        "unit": pc.unit,
                        "valid_range": [pc.valid_range_min, pc.valid_range_max],
                        "required": pc.required,
                        "description": pc.description,
                    }
                    for pc in pc_rows
                ]
            else:
                try:
                    required_columns = json.loads(sp.required_columns or "[]")
                except (json.JSONDecodeError, TypeError):
                    pass
        return {
            "study_metadata": {
                "id": study.id,
                "name": study.name,
                "description": study.description,
                "status": study.status,
                "threshold_n": study.threshold_n,
                "threshold_t": study.threshold_t,
                "public_key_fingerprint": study.public_key_fingerprint,
                "created_by": study.created_by,
                "created_at": _ts(study.created_at),
                "updated_at": _ts(study.updated_at),
            },
            "protocol_hash": protocol_hash,
            "required_columns": required_columns,
            "protocol_status": sp.status if sp else None,
            "minimum_rows": sp.minimum_rows if sp else 1,
            "missing_value_strategy": sp.missing_value_strategy if sp else "exclude",
            "participants": [
                {"institution_name": p.institution_name, "institution_email": p.institution_email, "joined_at": _ts(p.joined_at)}
                for p in participants
            ],
            "allowed_algorithms": protocol_data.get("allowed_algorithms", []),
            "column_definitions": required_columns,
            "datasets": [
                {
                    "dataset_name": d.dataset_name,
                    "institution_email": d.institution_email,
                    "commitment_hash": d.commitment_hash,
                    "committed_at": _ts(d.committed_at),
                }
                for d in datasets
            ],
            "jobs": [
                {
                    "id": j.id,
                    "requester_email": j.requester_email,
                    "algorithm": j.algorithm,
                    "status": j.status,
                    "created_at": _ts(j.created_at),
                }
                for j in jobs
            ],
            "audit_summary": {
                "total_entries": len(audit_entries),
                "last_entry_hash": audit_entries[-1].entry_hash if audit_entries else None,
            },
        }
