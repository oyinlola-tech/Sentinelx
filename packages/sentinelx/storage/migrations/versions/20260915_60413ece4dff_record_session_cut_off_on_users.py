"""Record each user's session cut-off in the database.

Sign-out, a password change or a password reset refuses every access token issued
before that moment. The cut-off used to live only in Redis (or process memory), so a
Redis outage made signed-out sessions valid again until their tokens expired.

Revision ID: 60413ece4dff
Revises: a8829c9a233e
Create Date: 2026-09-15 07:24:44.476954
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "60413ece4dff"
down_revision: str | None = "a8829c9a233e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A plain ALTER, not batch mode: batch mode rebuilds the table on SQLite and cannot
    # carry over the expression index on lower(username).
    op.add_column(
        "users", sa.Column("sessions_ended_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "sessions_ended_at")  # SQLite 3.35+ supports DROP COLUMN
