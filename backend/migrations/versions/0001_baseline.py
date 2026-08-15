# SPDX-License-Identifier: Apache-2.0
"""Baseline: create current SQLModel schema.

Production: alembic upgrade head
Local demo: create_db_and_tables() still runs at API startup for SQLite.
"""
from alembic import op
from sqlmodel import SQLModel

from app.models import *  # noqa: F401,F403

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    SQLModel.metadata.create_all(bind)


def downgrade() -> None:
    bind = op.get_bind()
    SQLModel.metadata.drop_all(bind)
