# SPDX-License-Identifier: Apache-2.0
"""Health, integrity, config-summary, and algorithms endpoints."""
import sys

from fastapi import APIRouter, Depends, Query, Request

from app.config import settings
from app.core.security import AuthUser, get_limiter, rate_limit, require_admin
from app.services.integrity_service import get_deployment_integrity, verify_codebase_hash

router = APIRouter(tags=["system"])


@router.get("/health")
def health():
    """Liveness/readiness."""
    return {"status": "ok"}


@router.get("/integrity")
@rate_limit("100/hour")
def system_integrity(request: Request):
    """Codebase hash, Git commit, versions for verification."""
    integrity = get_deployment_integrity()
    try:
        import tenseal as ts
        tenseal_version = getattr(ts, "__version__", "unknown")
    except ImportError:
        tenseal_version = "not installed"
    try:
        import fastapi
        fastapi_version = getattr(fastapi, "__version__", "unknown")
    except ImportError:
        fastapi_version = "unknown"
    return {
        "codebase_hash": integrity.get("codebase_hash", "unknown"),
        "git_commit": integrity.get("git_commit", "unknown"),
        "computed_at": integrity.get("computed_at", ""),
        "tenseal_version": tenseal_version,
        "fastapi_version": fastapi_version,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }


@router.get("/integrity/verify")
@rate_limit("100/hour")
def system_integrity_verify(request: Request, expected: str = Query(..., alias="expected_hash")):
    """Verify current codebase hash matches expected."""
    try:
        return verify_codebase_hash(expected)
    except Exception:
        return {"verified": False, "expected_hash": expected, "current_hash": "unknown", "error": "Verification failed"}


@router.get("/config-summary")
@rate_limit("60/hour")
def system_config_summary(request: Request, current_user: AuthUser = Depends(require_admin)):
    """
    Non-sensitive configuration summary for operators.
    Does NOT include secrets. Intended for debugging/ops, not compliance statements.
    """
    db_url = settings.database_url
    db_type = "sqlite" if "sqlite" in db_url else "postgresql" if "postgres" in db_url else "other"
    limiter = get_limiter()
    return {
        "db_type": db_type,
        "upload_dir": str(settings.upload_dir_path),
        "max_upload_size_mb": settings.max_upload_size_mb,
        "max_concurrent_computations": settings.max_concurrent_computations,
        "rate_limiting_enabled": limiter is not None,
        "app_title": "SecureCollab API",
        "app_version": "0.1.0",
    }
