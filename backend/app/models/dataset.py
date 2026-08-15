# SPDX-License-Identifier: Apache-2.0
"""Dataset model."""
from datetime import datetime

from sqlmodel import Field, SQLModel

from app.core.timeutils import utc_now


class Dataset(SQLModel, table=True):
    __tablename__ = "datasets"
    id: int | None = Field(default=None, primary_key=True)
    name: str
    description: str
    file_path: str
    owner_email: str
    columns: str = "[]"
    organization: str = ""
    allow_external_requests: bool = False
    created_at: datetime = Field(default_factory=utc_now)
