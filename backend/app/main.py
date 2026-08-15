# SPDX-License-Identifier: Apache-2.0
"""FastAPI app factory. Thin layer: security middleware + routers only."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlmodel import select

from app.config import settings
from app.core.algorithms import ALGORITHM_REGISTRY
from app.core.security import AuthUser, add_security_middleware, assert_actor, get_limiter, require_user
from app.core.timeutils import audit_timestamp
from app.database import Session, create_db_and_tables, engine
from app.models import Dataset, Job
from app.routers import auth, datasets, jobs, participants, studies, system


@asynccontextmanager
async def lifespan(app: FastAPI):
    from app.config import DEFAULT_SECRET_KEY

    if settings.production and settings.secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be changed when SECURECOLLAB_PRODUCTION is set")
    settings.upload_dir_path.mkdir(parents=True, exist_ok=True)
    settings.studies_upload_dir_path.mkdir(parents=True, exist_ok=True)
    create_db_and_tables()
    if settings.compute_codebase_hash_on_startup:
        from app.services.integrity_service import get_deployment_integrity
        get_deployment_integrity()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="SecureCollab API", version="0.1.0", lifespan=lifespan)
    limiter = get_limiter()
    if limiter is not None:
        app.state.limiter = limiter

    add_security_middleware(app)

    app.include_router(auth.router, prefix="/auth")
    app.include_router(studies.router, prefix="/studies")
    app.include_router(datasets.router, prefix="/datasets")
    app.include_router(jobs.router, prefix="/jobs")
    app.include_router(system.router, prefix="/system")
    app.include_router(participants.router, prefix="/participants")

    @app.get("/algorithms")
    def algorithms_list():
        """Full algorithm registry for frontend and SDK."""
        return ALGORITHM_REGISTRY

    @app.get("/access/datasets/{owner_email}")
    def access_datasets_by_owner(owner_email: str, user: AuthUser = Depends(require_user)):
        """Per dataset of owner: researchers with completed jobs (one SQL join)."""
        assert_actor(user, owner_email)
        with Session(engine) as session:
            stmt = (
                select(Dataset.id, Dataset.name, Job.requester_email, Job.created_at)
                .join(Job, Job.dataset_id == Dataset.id)
                .where(Dataset.owner_email == user.email, Job.status == "completed")
                .order_by(Dataset.id, Job.created_at.asc())
            )
            rows = session.exec(stmt).all()
            by_ds: dict[int, dict] = {}
            for ds_id, ds_name, email, created_at in rows:
                bucket = by_ds.setdefault(ds_id, {"dataset_id": ds_id, "dataset_name": ds_name, "researchers": {}, "order": []})
                if email not in bucket["researchers"]:
                    bucket["researchers"][email] = created_at
                    bucket["order"].append(email)
            # Include owned datasets with no completed jobs
            owned = session.exec(select(Dataset).where(Dataset.owner_email == user.email)).all()
            result = []
            for d in owned:
                if d.id in by_ds:
                    b = by_ds[d.id]
                    result.append({
                        "dataset_id": d.id,
                        "dataset_name": d.name,
                        "researchers": [
                            {"email": email, "first_completed_at": audit_timestamp(b["researchers"][email])}
                            for email in b["order"]
                        ],
                    })
                else:
                    result.append({"dataset_id": d.id, "dataset_name": d.name, "researchers": []})
            return result

    return app


app = create_app()
