# SPDX-License-Identifier: Apache-2.0
"""User register/login. Passwords are PBKDF2-hashed; tokens are HMAC-signed."""
from __future__ import annotations

from sqlmodel import select

from app.core.passwords import hash_password, verify_password
from app.database import Session, engine
from app.models.user import User


def get_user_by_email(email: str) -> User | None:
    with Session(engine) as session:
        return session.exec(select(User).where(User.email == email.strip().lower())).first()


def create_user(email: str, password: str) -> User:
    email_n = email.strip().lower()
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.email == email_n)).first()
        if existing:
            raise ValueError("Email already registered")
        user = User(email=email_n, password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def authenticate_user(email: str, password: str) -> User | None:
    user = get_user_by_email(email)
    if user is None or not verify_password(password, user.password_hash):
        return None
    return user


def ensure_user(email: str, password: str) -> User:
    """Create the user if missing (tests and seed). Existing users are left unchanged."""
    email_n = email.strip().lower()
    existing = get_user_by_email(email_n)
    if existing:
        return existing
    return create_user(email_n, password)
