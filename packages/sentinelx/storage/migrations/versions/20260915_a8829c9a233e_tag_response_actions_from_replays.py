"""Tag response actions from replays; index detections by triage status.

Replay decisions stay out of the live firewall log, and the status filter used by
triage and analytics no longer scans the detections table.

Revision ID: a8829c9a233e
Revises: 540eb200aacd
Create Date: 2026-09-15 01:20:59.984659
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a8829c9a233e"
down_revision: str | None = "540eb200aacd"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("response_actions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("replay_id", sa.Text(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_response_actions_replay_id"), ["replay_id"], unique=False
        )
    with op.batch_alter_table("detections", schema=None) as batch_op:
        batch_op.create_index(
            "ix_detections_status_timestamp", ["status", "timestamp"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("detections", schema=None) as batch_op:
        batch_op.drop_index("ix_detections_status_timestamp")
    with op.batch_alter_table("response_actions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_response_actions_replay_id"))
        batch_op.drop_column("replay_id")
