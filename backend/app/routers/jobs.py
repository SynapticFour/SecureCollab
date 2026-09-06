# SPDX-License-Identifier: Apache-2.0
"""Job request, approve, reject, result, list. Identity from signed access token."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlmodel import col, select

from app.core.algorithms import ALGORITHM_REGISTRY
from app.core.security import AuthUser, assert_actor, rate_limit, require_user
from app.core.timeutils import audit_timestamp
from app.database import Session, engine
from app.models import Dataset, Job
from app.schemas import JobRequest
from app.services.bundle import BundleError
from app.services.compute_pool import ComputeBusyError, ComputeTimeoutError, run_he
from app.services.he_service import run_computation

router = APIRouter(tags=["jobs"])
_log = logging.getLogger("securecollab")


def _job_public_view(j: Job, *, include_result: bool) -> dict:
    out = {
        "id": j.id,
        "dataset_id": j.dataset_id,
        "requester_email": j.requester_email,
        "computation_type": j.computation_type,
        "algorithm": j.algorithm or "mean",
        "selected_columns": json.loads(j.selected_columns or "[]"),
        "status": j.status,
        "result": None,
        "created_at": audit_timestamp(j.created_at),
    }
    if include_result and j.status == "completed" and j.result_json:
        try:
            out["result_json"] = json.loads(j.result_json)
        except (json.JSONDecodeError, TypeError):
            out["result_json"] = None
    else:
        out["result_json"] = None
    return out


@router.get("/my/{requester_email}")
def jobs_my(requester_email: str, user: AuthUser = Depends(require_user)):
    """All jobs for the authenticated researcher."""
    assert_actor(user, requester_email)
    with Session(engine) as session:
        jobs = session.exec(select(Job).where(Job.requester_email == user.email)).all()
        return [_job_public_view(j, include_result=j.status == "completed") for j in jobs]


@router.post("/request")
@rate_limit("30/hour")
def jobs_request(request: Request, body: JobRequest, user: AuthUser = Depends(require_user)):
    """Create job. Algorithm must be in registry. Requester is the authenticated user."""
    assert_actor(user, body.requester_email)
    if body.algorithm not in ALGORITHM_REGISTRY:
        raise HTTPException(status_code=400, detail="Algorithm not in approved registry")
    sel_cols_str = json.dumps(body.selected_columns if isinstance(body.selected_columns, list) else [])
    with Session(engine) as session:
        dataset = session.get(Dataset, body.dataset_id)
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset nicht gefunden")
        owner = dataset.owner_email.lower() == user.email.lower()
        if not owner and not dataset.allow_external_requests:
            raise HTTPException(status_code=403, detail="This dataset does not accept external job requests")
        job = Job(
            dataset_id=body.dataset_id,
            requester_email=user.email,
            computation_type=body.computation_type or body.algorithm,
            algorithm=body.algorithm or "mean",
            selected_columns=sel_cols_str,
            parameters=json.dumps({}),
            status="pending",
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        return {"job_id": job.id}


@router.post("/{job_id}/approve")
@rate_limit("60/hour")
def jobs_approve(request: Request, job_id: int, user: AuthUser = Depends(require_user)):
    """Owner-only: run HE (no decrypt), store encrypted result_json."""
    with Session(engine) as session:
        job = session.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job nicht gefunden")
        if job.status != "pending":
            raise HTTPException(status_code=400, detail=f"Job hat status {job.status}")
        dataset = session.get(Dataset, job.dataset_id)
        if not dataset:
            raise HTTPException(status_code=404, detail="Dataset nicht gefunden")
        if dataset.owner_email.lower() != user.email.lower():
            raise HTTPException(status_code=403, detail="Only the dataset owner can approve this job")
        path = Path(dataset.file_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Dataset-Datei nicht gefunden")
        algorithm = job.algorithm or job.computation_type or "mean"
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
        try:
            result_obj = run_he(run_computation, path, algorithm, sel_cols, params)
        except BundleError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except ComputeBusyError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        except ComputeTimeoutError as e:
            raise HTTPException(status_code=504, detail=str(e)) from e
        except Exception:
            _log.exception("HE computation failed for job %s", job_id)
            raise HTTPException(status_code=500, detail="Computation failed. Check algorithm and columns.")
        result_json_str = json.dumps(result_obj)
        job.status = "completed"
        job.result_json = result_json_str
        job.result = None
        session.add(job)
        session.commit()
        session.refresh(job)
        return {
            "job_id": job.id,
            "status": "completed",
            "result": None,
            "result_json": result_obj,
            "encrypted": True,
        }


@router.post("/{job_id}/reject")
def jobs_reject(job_id: int, user: AuthUser = Depends(require_user)):
    """Owner-only reject."""
    with Session(engine) as session:
        job = session.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job nicht gefunden")
        if job.status != "pending":
            raise HTTPException(status_code=400, detail=f"Job hat status {job.status}")
        dataset = session.get(Dataset, job.dataset_id)
        if not dataset or dataset.owner_email.lower() != user.email.lower():
            raise HTTPException(status_code=403, detail="Only the dataset owner can reject this job")
        job.status = "rejected"
        session.add(job)
        session.commit()
        return {"job_id": job.id, "status": "rejected"}


@router.get("/{job_id}/result")
def jobs_result(job_id: int, user: AuthUser = Depends(require_user)):
    """Return job; encrypted result_json if completed and caller is owner or requester."""
    with Session(engine) as session:
        job = session.get(Job, job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job nicht gefunden")
        dataset = session.get(Dataset, job.dataset_id) if job.dataset_id else None
        allowed = user.email.lower() == job.requester_email.lower() or (
            dataset is not None and dataset.owner_email.lower() == user.email.lower()
        )
        if not allowed:
            raise HTTPException(status_code=403, detail="Not allowed to view this job")
        return _job_public_view(job, include_result=True)


@router.get("/pending/{owner_email}")
def jobs_pending_by_owner(owner_email: str, user: AuthUser = Depends(require_user)):
    """Pending jobs for datasets owned by the authenticated user."""
    assert_actor(user, owner_email)
    with Session(engine) as session:
        stmt = select(Job).join(Dataset, col(Job.dataset_id) == col(Dataset.id)).where(
            Dataset.owner_email == user.email, Job.status == "pending"
        )
        jobs = session.exec(stmt).all()
        return [
            {
                "id": j.id,
                "dataset_id": j.dataset_id,
                "requester_email": j.requester_email,
                "computation_type": j.computation_type,
                "algorithm": j.algorithm or "mean",
                "status": j.status,
                "created_at": audit_timestamp(j.created_at),
            }
            for j in jobs
        ]
