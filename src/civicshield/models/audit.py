from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from civicshield.db.base import Base, utcnow


class AuditEvent(Base):
    """Append-only, hash-chained audit log. See civicshield.audit for the chain logic.

    No foreign keys to orgs/users: audit history must survive deletion of the things it
    describes, so ids are stored as plain values.
    """

    __tablename__ = "audit_events"

    # BigInteger on Postgres, plain INTEGER on SQLite (needed for SQLite autoincrement).
    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    org_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    actor_user_id: Mapped[uuid.UUID | None]
    actor_label: Mapped[str] = mapped_column(String(320))  # "user:<email>" or "system:worker"
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. "scan.blocked"
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)
