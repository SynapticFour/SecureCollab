# SPDX-License-Identifier: Apache-2.0
"""Registered user. Password-bound identity; email is not verified."""
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.core.timeutils import utc_now


class User(SQLModel, table=True):
    __tablename__ = "users"
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True, max_length=254)
    password_hash: str
    created_at: datetime = Field(default_factory=utc_now)
