"""Decide what (if anything) may be scanned for an organization right now.

A domain is scannable only if BOTH hold:
1. it is VERIFIED, and its last successful verification is recent enough; and
2. an authorization that is not revoked and not expired covers it.

The API calls this before queueing a scan; the worker calls it *again* when the scan
starts (after re-verifying ownership), because things can change in between.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from civicshield.engine.net import Scope
from civicshield.engine.net.scope import ScopeEntry
from civicshield.enums import DomainStatus, Impact
from civicshield.models import Authorization, Domain


class NotAuthorizedError(Exception):
    """No domain is currently in scope. The message is safe to show to the user."""


@dataclass(frozen=True)
class ScanPermission:
    scope: Scope
    authorization_id: uuid.UUID
    max_impact: Impact
    domains: tuple[Domain, ...] = field(default_factory=tuple)
    skipped: dict[str, str] = field(default_factory=dict)  # domain → reason excluded


async def active_authorizations(
    db: AsyncSession, org_id: uuid.UUID, now: datetime | None = None
) -> list[Authorization]:
    now = now or datetime.now(UTC)
    rows = await db.execute(
        select(Authorization)
        .where(
            Authorization.org_id == org_id,
            Authorization.revoked_at.is_(None),
            Authorization.expires_at > now,
            Authorization.granted_at <= now,
        )
        .options(selectinload(Authorization.domains))
        .order_by(Authorization.granted_at.desc())
    )
    return list(rows.scalars())


async def resolve_permission(
    db: AsyncSession, org_id: uuid.UUID, max_verification_age_days: int, now: datetime | None = None
) -> ScanPermission:
    now = now or datetime.now(UTC)
    auths = await active_authorizations(db, org_id, now)
    if not auths:
        raise NotAuthorizedError("No active written authorization. Record one before scanning.")
    # Use the most recent active authorization; it defines both scope and impact level.
    auth = auths[0]
    entries: list[ScopeEntry] = []
    allowed: list[Domain] = []
    skipped: dict[str, str] = {}
    max_age = timedelta(days=max_verification_age_days)
    for d in auth.domains:
        if d.org_id != org_id:  # defense in depth; the API never links foreign domains
            continue
        if d.status is not DomainStatus.VERIFIED or d.verified_at is None:
            skipped[d.name] = "domain ownership not verified"
        elif now - d.verified_at > max_age:
            skipped[d.name] = "verification is stale; re-check ownership"
        else:
            entries.append(ScopeEntry(d.name, d.scope_kind))
            allowed.append(d)
    if not entries:
        reasons = "; ".join(f"{k}: {v}" for k, v in skipped.items()) or "no domains"
        raise NotAuthorizedError(f"No domain is currently scannable ({reasons}).")
    return ScanPermission(Scope(tuple(entries)), auth.id, auth.max_impact, tuple(allowed), skipped)


async def org_domains(db: AsyncSession, org_id: uuid.UUID) -> list[Domain]:
    rows = await db.execute(select(Domain).where(Domain.org_id == org_id).order_by(Domain.name))
    return list(rows.scalars())
