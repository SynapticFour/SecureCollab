# SPDX-License-Identifier: Apache-2.0
"""Register and login. Identity is a signed token, not a client-supplied header."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.config import settings
from app.core.security import rate_limit
from app.core.tokens import issue_access_token, secret_key_is_default
from app.services.user_service import authenticate_user, create_user

router = APIRouter(tags=["auth"])


class AuthCredentials(BaseModel):
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=256)


@router.post("/register")
@rate_limit("10/hour")
def auth_register(request: Request, body: AuthCredentials):
    if not settings.allow_register:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Registration is disabled")
    if "@" not in body.email:
        raise HTTPException(status_code=400, detail="Invalid email")
    try:
        user = create_user(body.email, body.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    token = issue_access_token(user.email, ttl=settings.token_ttl_seconds)
    return {"token": token, "email": user.email, "token_type": "bearer"}


@router.post("/login")
@rate_limit("30/hour")
def auth_login(request: Request, body: AuthCredentials):
    user = authenticate_user(body.email, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    token = issue_access_token(user.email, ttl=settings.token_ttl_seconds)
    return {
        "token": token,
        "email": user.email,
        "token_type": "bearer",
        "using_default_secret": secret_key_is_default(),
    }
