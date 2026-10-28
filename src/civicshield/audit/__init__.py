"""Hash-chained, append-only audit log.

Each event stores ``hash = sha256(prev_hash || canonical_json(event))``. Changing or
deleting any past row breaks every hash after it, and ``verify_chain`` reports the first
broken link. Postgres also blocks UPDATE/DELETE with a trigger (see the initial
migration); the chain is the second layer that makes tampering *evident* even to someone
who disabled the trigger.

Concurrency: two events written at the same time could both read the same "last hash"
and fork the chain. On Postgres we take a transaction-scoped advisory lock so audit
writes are serialized. Audit writes are rare (per scan / admin action, not per HTTP
request), so the lock never becomes a bottleneck.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.db.base import utcnow
from civicshield.models import AuditEvent, User

GENESIS_HASH = "0" * 64
_AUDIT_LOCK_KEY = 0x0C1C5  # arbitrary constant identifying "the audit chain" lock


@dataclass(frozen=True)
class Actor:
    user_id: uuid.UUID | None
    label: str

    @classmethod
    def user(cls, user: User) -> Actor:
        return cls(user.id, f"user:{user.email}")

    @classmethod
    def system(cls, component: str) -> Actor:
        return cls(None, f"system:{component}")


def _canonical(event: dict[str, Any]) -> bytes:
    return json.dumps(event, sort_keys=True, separators=(",", ":"), default=str).encode()


def compute_hash(
    prev_hash: str,
    created_at: datetime,
    org_id: uuid.UUID | None,
    actor_label: str,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any],
) -> str:
    payload = _canonical(
        {
            "created_at": created_at.isoformat(),
            "org_id": str(org_id) if org_id else None,
            "actor": actor_label,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details,
        }
    )
    return hashlib.sha256(prev_hash.encode() + payload).hexdigest()


async def record(
    db: AsyncSession,
    *,
    actor: Actor,
    action: str,
    target_type: str,
    target_id: str | uuid.UUID,
    org_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an audit event within the caller's transaction (commits with it)."""
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _AUDIT_LOCK_KEY})
    prev = (
        await db.execute(select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1))
    ).scalar_one_or_none() or GENESIS_HASH
    created_at = utcnow()
    details = json.loads(_canonical(details or {}))  # normalize so re-hashing is exact
    tid = str(target_id)
    event = AuditEvent(
        created_at=created_at,
        org_id=org_id,
        actor_user_id=actor.user_id,
        actor_label=actor.label,
        action=action,
        target_type=target_type,
        target_id=tid,
        details=details,
        prev_hash=prev,
        hash=compute_hash(prev, created_at, org_id, actor.label, action, target_type, tid, details),
    )
    db.add(event)
    await db.flush()
    return event


async def verify_chain(db: AsyncSession) -> int | None:
    """Return the id of the first tampered event, or None if the chain is intact."""
    prev = GENESIS_HASH
    rows = await db.stream_scalars(select(AuditEvent).order_by(AuditEvent.id))
    async for ev in rows:
        expected = compute_hash(
            prev,
            ev.created_at,
            ev.org_id,
            ev.actor_label,
            ev.action,
            ev.target_type,
            ev.target_id,
            ev.details,
        )
        if ev.prev_hash != prev or ev.hash != expected:
            return ev.id
        prev = ev.hash
    return None
