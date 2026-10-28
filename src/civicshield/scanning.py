"""Scan lifecycle: request (API side) and execute (worker side).

    API: request_scan()  →  Scan(status=queued) + audit, committed → enqueue Celery task
    Worker: execute_scan() → claim → re-verify → authorize → run checks → persist + diff

Design notes worth knowing:

* **At-least-once delivery.** Celery with ``acks_late`` may deliver a task twice (e.g. a
  worker dies mid-task). ``_claim`` flips queued→running with a conditional UPDATE, so
  only one execution ever proceeds. That makes the task idempotent.
* **The dual-write gap.** We commit the Scan row, *then* enqueue. If the process dies in
  between, the scan sits in ``queued`` with no task. The periodic sweeper
  (``requeue_stale_scans``) finds those and re-enqueues them. Postgres-as-queue would avoid
  this; see docs/adr/0002 for the trade-off.
* **"Fixed" requires evidence of absence.** An open issue is only marked fixed if the
  same check ran *successfully* on the same asset and didn't report it. A timeout or
  error leaves the issue open, because "we couldn't look" is not "it's gone".
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from civicshield import __version__
from civicshield.audit import Actor, record
from civicshield.authz.scope_builder import (
    NotAuthorizedError,
    active_authorizations,
    resolve_permission,
)
from civicshield.authz.verification import verify_domain
from civicshield.config import Settings
from civicshield.engine.checks import ALL_CHECKS
from civicshield.engine.checks.base import Check, CheckContext
from civicshield.engine.fingerprint import fingerprint
from civicshield.engine.net.factory import NetFactory, build_net
from civicshield.engine.runner import CheckOutcome, plan_targets, run_checks
from civicshield.enums import CheckRunStatus, IssueStatus, ScanStatus, ScanTrigger
from civicshield.log import get_logger
from civicshield.models import CheckRun, Issue, Observation, Organization, Scan, User

log = get_logger(__name__)

Enqueue = Callable[[uuid.UUID], None]


class ScanConflictError(Exception):
    """A scan for this org is already queued or running."""


async def request_scan(
    db: AsyncSession,
    org: Organization,
    actor: Actor,
    trigger: ScanTrigger,
    settings: Settings,
    user: User | None = None,
) -> Scan:
    """Validate permission and create a queued scan. Caller enqueues *after* commit."""
    busy = (
        await db.execute(
            select(Scan.id).where(
                Scan.org_id == org.id, Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
            )
        )
    ).first()
    if busy:
        raise ScanConflictError("a scan is already queued or running for this organization")
    permission = await resolve_permission(db, org.id, settings.verification_max_age_days)
    scan = Scan(
        org_id=org.id,
        trigger=trigger,
        status=ScanStatus.QUEUED,
        requested_by_user_id=user.id if user else None,
        authorization_id=permission.authorization_id,
        engine_version=__version__,
    )
    db.add(scan)
    await db.flush()
    await record(
        db,
        actor=actor,
        action="scan.requested",
        target_type="scan",
        target_id=scan.id,
        org_id=org.id,
        details={"trigger": trigger.value, "domains": [d.name for d in permission.domains]},
    )
    return scan


async def _claim(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    result = await db.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED)
        .values(status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
    )
    await db.commit()
    return bool(result.rowcount)  # type: ignore[attr-defined]


@dataclass
class DiffSummary:
    new: list[uuid.UUID]
    regressed: list[uuid.UUID]
    resolved: list[uuid.UUID]
    still_open: int


async def persist_outcomes(
    db: AsyncSession, scan: Scan, outcomes: Sequence[CheckOutcome]
) -> DiffSummary:
    now = datetime.now(UTC)
    existing = {
        i.fingerprint: i
        for i in (await db.execute(select(Issue).where(Issue.org_id == scan.org_id))).scalars()
    }
    seen: set[str] = set()
    new: list[uuid.UUID] = []
    regressed: list[uuid.UUID] = []
    checked_ok: set[tuple[str, str]] = set()  # (check_id, asset) that ran successfully

    for o in outcomes:
        db.add(
            CheckRun(
                scan_id=scan.id,
                check_id=o.check.meta.id,
                check_version=o.check.meta.version,
                target=o.target.name,
                status=o.status,
                duration_ms=o.duration_ms,
                error=o.error,
            )
        )
        if o.status is CheckRunStatus.OK:
            checked_ok.add((o.check.meta.id, o.target.name.lower()))
        for f in o.findings:
            fp = fingerprint(o.check.meta.id, f)
            if fp in seen:
                continue
            seen.add(fp)
            issue = existing.get(fp)
            if issue is None:
                issue = Issue(
                    org_id=scan.org_id,
                    fingerprint=fp,
                    check_id=o.check.meta.id,
                    finding_type=f.finding_type,
                    asset=f.asset,
                    title=f.title,
                    severity=f.severity,
                    confidence=f.confidence,
                    remediation_key=f.remediation_key,
                    facts=f.facts,
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(issue)
                await db.flush()
                existing[fp] = issue
                new.append(issue.id)
            else:
                if issue.status is IssueStatus.FIXED:
                    issue.status = IssueStatus.OPEN
                    issue.resolved_at = None
                    issue.regressed_count += 1
                    regressed.append(issue.id)
                # Refresh volatile fields (title "expires in 12 days", severity ramps up).
                issue.title, issue.severity, issue.confidence = f.title, f.severity, f.confidence
                issue.facts = f.facts
                issue.last_seen_at = now
            db.add(
                Observation(
                    scan_id=scan.id,
                    issue_id=issue.id,
                    severity=f.severity,
                    confidence=f.confidence,
                    evidence=[e.model_dump() for e in f.evidence],
                    facts=f.facts,
                    references=[r.model_dump() for r in f.references],
                )
            )

    resolved: list[uuid.UUID] = []
    for fp, issue in existing.items():
        if (
            fp not in seen
            and issue.status is IssueStatus.OPEN
            and (issue.check_id, issue.asset.lower()) in checked_ok
        ):
            issue.status = IssueStatus.FIXED
            issue.resolved_at = now
            resolved.append(issue.id)
    still_open = sum(1 for i in existing.values() if i.status is IssueStatus.OPEN)
    return DiffSummary(new, regressed, resolved, still_open)


async def execute_scan(
    scan_id: uuid.UUID,
    sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
    net_factory: NetFactory | None = None,
    checks: Sequence[Check] = ALL_CHECKS,
) -> ScanStatus | None:
    """Run one scan end to end. Returns the final status, or None if already claimed."""
    actor = Actor.system("worker")
    net_factory = net_factory or (lambda scope: build_net(scope, settings))
    async with sessionmaker() as db:
        if not await _claim(db, scan_id):
            log.info("scan.already_claimed", scan_id=str(scan_id))
            return None
        scan = await db.get(Scan, scan_id)
        if scan is None:  # pragma: no cover - claimed rows exist by definition
            return None
        try:
            # 1. Re-verify ownership right now: DNS may have changed since queueing.
            for auth in await active_authorizations(db, scan.org_id):
                for domain in auth.domains:
                    await verify_domain(domain, settings, net_factory)
            await db.flush()
            # 2. Re-check authorization (may have been revoked while queued).
            try:
                permission = await resolve_permission(
                    db, scan.org_id, settings.verification_max_age_days
                )
            except NotAuthorizedError as exc:
                scan.status, scan.error = ScanStatus.BLOCKED, str(exc)
                scan.finished_at = datetime.now(UTC)
                await record(
                    db,
                    actor=actor,
                    action="scan.blocked",
                    target_type="scan",
                    target_id=scan.id,
                    org_id=scan.org_id,
                    details={"reason": str(exc)},
                )
                await db.commit()
                return ScanStatus.BLOCKED

            # 3. Run checks within the verified scope only.
            net = net_factory(permission.scope)
            try:
                ctx = CheckContext(http=net.http, dns=net.dns, tls=net.tls)
                targets = plan_targets([(d.name, d.scope_kind) for d in permission.domains])
                outcomes = await run_checks(checks, targets, ctx, permission.max_impact)
            finally:
                await net.aclose()

            # 4. Persist + diff.
            diff = await persist_outcomes(db, scan, outcomes)
            statuses = Counter(o.status.value for o in outcomes)
            stats: dict[str, Any] = {
                "connections_per_host": net.stats(),
                "check_runs": dict(statuses),
                "new": len(diff.new),
                "regressed": len(diff.regressed),
                "resolved": len(diff.resolved),
                "open": diff.still_open,
                "skipped_domains": permission.skipped,
            }
            scan.stats = stats
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now(UTC)
            await record(
                db,
                actor=actor,
                action="scan.completed",
                target_type="scan",
                target_id=scan.id,
                org_id=scan.org_id,
                details=stats,
            )
            await db.commit()
            return ScanStatus.COMPLETED
        except Exception as exc:
            await db.rollback()
            log.exception("scan.failed", scan_id=str(scan_id))
            failed = await db.get(Scan, scan_id)
            if failed is not None:
                failed.status = ScanStatus.FAILED
                failed.error = f"internal error: {type(exc).__name__}"
                failed.finished_at = datetime.now(UTC)
                await record(
                    db,
                    actor=actor,
                    action="scan.failed",
                    target_type="scan",
                    target_id=scan_id,
                    org_id=failed.org_id,
                    details={"error": type(exc).__name__},
                )
                await db.commit()
            return ScanStatus.FAILED


async def requeue_stale_scans(
    db: AsyncSession,
    enqueue: Enqueue,
    queued_grace: timedelta = timedelta(minutes=10),
    running_timeout: timedelta = timedelta(hours=1),
) -> dict[str, int]:
    """Sweeper: re-enqueue orphaned queued scans; fail scans stuck in running."""
    now = datetime.now(UTC)
    queued = list(
        (
            await db.execute(
                select(Scan).where(
                    Scan.status == ScanStatus.QUEUED, Scan.created_at < now - queued_grace
                )
            )
        ).scalars()
    )
    for s in queued:
        enqueue(s.id)  # safe even if the original task still exists: _claim dedupes
    stuck = list(
        (
            await db.execute(
                select(Scan).where(
                    Scan.status == ScanStatus.RUNNING, Scan.started_at < now - running_timeout
                )
            )
        ).scalars()
    )
    for s in stuck:
        s.status, s.error, s.finished_at = ScanStatus.FAILED, "worker timed out", now
        await record(
            db,
            actor=Actor.system("sweeper"),
            action="scan.failed",
            target_type="scan",
            target_id=s.id,
            org_id=s.org_id,
            details={"error": "worker timed out"},
        )
    await db.commit()
    return {"requeued": len(queued), "failed": len(stuck)}
