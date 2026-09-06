# SPDX-License-Identifier: Apache-2.0
"""Dataset upload, list, columns, accessible. Identity from signed access token."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlmodel import col, select

from app.config import (
    ALLOWED_UPLOAD_EXTENSIONS,
    CKKS_BYTES_PER_SLOT_HEURISTIC,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_MB,
    UPLOADS_DIR,
)
from app.core.security import AuthUser, assert_actor, rate_limit, require_user, sanitize_text, secure_filename
from app.core.timeutils import audit_timestamp
from app.database import Session, engine
from app.models import Dataset, Job
from app.services.bundle import BundleError, load_bundle

router = APIRouter(tags=["datasets"])


async def _read_limited(file: UploadFile, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB} MB)")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/upload")
@rate_limit("10/hour")
async def datasets_upload(
    request: Request,
    file: UploadFile = File(..., description="encrypted.bin"),
    name: str = Form(...),
    description: str = Form(...),
    owner_email: str = Form(...),
    organization: str = Form(""),
    columns: str = Form("[]"),
    declared_rows: str = Form(""),
    allow_external_requests: str = Form("false"),
    user: AuthUser = Depends(require_user),
):
    """Binary file + form fields. Owner is the authenticated user. JSON bundles only."""
    assert_actor(user, owner_email)
    if Path(file.filename or "").suffix.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HTTPException(status_code=400, detail="Only .bin files are allowed")
    safe_name = secure_filename(file.filename or "encrypted.bin")
    if not safe_name.lower().endswith(".bin"):
        safe_name = f"{uuid.uuid4().hex}.bin"
    else:
        safe_name = f"{uuid.uuid4().hex}_{safe_name}"
    file_path = (UPLOADS_DIR / safe_name).resolve()
    uploads_resolved = UPLOADS_DIR.resolve()
    try:
        file_path.relative_to(uploads_resolved)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid upload path")
    contents = await _read_limited(file, MAX_UPLOAD_BYTES)
    try:
        load_bundle(contents)
    except BundleError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ciphertext bundle: {e}") from e
    if declared_rows:
        try:
            n_rows = int(declared_rows)
            arr = json.loads(columns)
            n_cols = len(arr) if isinstance(arr, list) else 1
            max_plausible = n_cols * max(n_rows, 1) * CKKS_BYTES_PER_SLOT_HEURISTIC * 2
            if len(contents) > max_plausible:
                raise HTTPException(status_code=400, detail="File size exceeds plausible range for declared columns/rows")
        except HTTPException:
            raise
        except (ValueError, json.JSONDecodeError) as e:
            raise HTTPException(status_code=400, detail="declared_rows/columns must be valid integers/JSON") from e
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(contents)
    columns_clean = "[]"
    try:
        arr = json.loads(columns)
        if isinstance(arr, list):
            columns_clean = json.dumps([str(x) for x in arr])
    except (json.JSONDecodeError, TypeError) as e:
        raise HTTPException(status_code=400, detail="columns must be a JSON array") from e
    name = sanitize_text(name, 200)
    description = sanitize_text(description, 2000)
    organization = sanitize_text(organization, 200)
    allow_ext = allow_external_requests.strip().lower() in ("1", "true", "yes")
    with Session(engine) as session:
        dataset = Dataset(
            name=name,
            description=description,
            file_path=str(file_path),
            owner_email=user.email[:254],
            organization=organization or "",
            columns=columns_clean,
            allow_external_requests=allow_ext,
        )
        session.add(dataset)
        session.commit()
        session.refresh(dataset)
        return {"dataset_id": dataset.id}


@router.get("/{dataset_id}/columns")
def dataset_columns(dataset_id: int, user: AuthUser = Depends(require_user)):
    """Return stored column names. Owner or requester of a completed job only."""
    with Session(engine) as session:
        dataset = session.get(Dataset, dataset_id)
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset nicht gefunden")
        allowed = dataset.owner_email.lower() == user.email.lower()
        if not allowed:
            completed = session.exec(
                select(Job).where(
                    Job.dataset_id == dataset_id,
                    Job.requester_email == user.email,
                    Job.status == "completed",
                )
            ).first()
            allowed = completed is not None
        if not allowed:
            raise HTTPException(status_code=403, detail="Not allowed to view this dataset")
        try:
            cols = json.loads(dataset.columns or "[]")
            return cols if isinstance(cols, list) else []
        except (json.JSONDecodeError, TypeError):
            return []


@router.get("")
def datasets_list(user: AuthUser = Depends(require_user)):
    """Datasets visible to the caller (own datasets)."""
    with Session(engine) as session:
        rows = session.exec(select(Dataset).where(Dataset.owner_email == user.email)).all()
        out = []
        for d in rows:
            item: dict[str, Any] = {
                "id": d.id,
                "name": d.name,
                "description": d.description,
                "owner_email": d.owner_email,
                "organization": d.organization or "",
                "created_at": audit_timestamp(d.created_at),
            }
            try:
                item["columns"] = json.loads(d.columns or "[]")
            except (json.JSONDecodeError, TypeError):
                item["columns"] = []
            out.append(item)
        return out


@router.get("/accessible/{requester_email}")
def datasets_accessible(requester_email: str, user: AuthUser = Depends(require_user)):
    """Datasets for which this researcher has at least one completed job."""
    assert_actor(user, requester_email)
    with Session(engine) as session:
        stmt = (
            select(Dataset)
            .join(Job, col(Job.dataset_id) == col(Dataset.id))
            .where(Job.requester_email == user.email, Job.status == "completed")
            .distinct()
        )
        result = []
        for d in session.exec(stmt).all():
            item: dict[str, Any] = {
                "id": d.id,
                "name": d.name,
                "description": d.description,
                "owner_email": d.owner_email,
                "organization": d.organization or "",
                "created_at": audit_timestamp(d.created_at),
            }
            try:
                item["columns"] = json.loads(d.columns or "[]")
            except (json.JSONDecodeError, TypeError):
                item["columns"] = []
            result.append(item)
        return result
