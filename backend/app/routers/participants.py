# SPDX-License-Identifier: Apache-2.0
"""Participant-related endpoints (studies listing by participant)."""
from fastapi import APIRouter, Depends, Request

from app.core.security import AuthUser, require_user
from app.routers.studies import studies_list

router = APIRouter(tags=["participants"])


@router.get("/studies/{participant_email}")
def participant_studies(request: Request, participant_email: str, user: AuthUser = Depends(require_user)):
    """List studies the authenticated participant is part of."""
    return studies_list(participant_email=participant_email, user=user)
