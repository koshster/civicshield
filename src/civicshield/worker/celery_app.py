"""Celery application: scan execution and periodic maintenance.

Each task runs its async code with ``asyncio.run`` and a fresh, task-local DB engine.
Sharing one async engine across event loops (each ``asyncio.run`` creates a new loop)
leads to "attached to a different loop" errors, so we create and dispose per task.
NullPool keeps that cheap: no idle pool is left behind.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from celery import Celery
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from civicshield.audit import Actor
from civicshield.authz.scope_builder import NotAuthorizedError, active_authorizations
from civicshield.config import get_settings
from civicshield.enums import ScanTrigger
from civicshield.log import configure_logging, get_logger
from civicshield.models import Organization, Scan
from civicshield.scanning import ScanConflictError, execute_scan, request_scan, requeue_stale_scans

settings = get_settings()
configure_logging(settings.log_level, settings.log_json)
log = get_logger(__name__)

app = Celery("civicshield", broker=settings.redis_url)
app.conf.update(
    task_acks_late=True,  # ack after the task finishes → redelivered if a worker dies
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # scans are long; don't hoard them on one worker
    task_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    beat_schedule={
        "sweep-stale-scans": {"task": "civicshield.sweep", "schedule": 300.0},
        "schedule-weekly-rescans": {"task": "civicshield.schedule_rescans", "schedule": 6 * 3600.0},
    },
)


def _run[T](fn: Callable[[async_sessionmaker[AsyncSession]], Awaitable[T]]) -> T:
    async def wrapper() -> T:
        engine = create_async_engine(get_settings().database_url, poolclass=NullPool)
        try:
            return await fn(async_sessionmaker(engine, expire_on_commit=False))
        finally:
            await engine.dispose()

    return asyncio.run(wrapper())


def enqueue_scan(scan_id: uuid.UUID) -> None:
    run_scan.delay(str(scan_id))


@app.task(name="civicshield.run_scan")  # type: ignore[untyped-decorator]
def run_scan(scan_id: str) -> str | None:
    status = _run(lambda sm: execute_scan(uuid.UUID(scan_id), sm, get_settings()))
    return status.value if status else None


@app.task(name="civicshield.sweep")  # type: ignore[untyped-decorator]
def sweep() -> dict[str, int]:
    async def go(sm: async_sessionmaker[AsyncSession]) -> dict[str, int]:
        async with sm() as db:
            return await requeue_stale_scans(db, enqueue_scan)

    return _run(go)


@app.task(name="civicshield.schedule_rescans")  # type: ignore[untyped-decorator]
def schedule_rescans(interval_days: int = 7) -> list[str]:
    """Queue a rescan for every authorized org whose last scan is older than interval."""

    async def go(sm: async_sessionmaker[AsyncSession]) -> list[str]:
        queued: list[uuid.UUID] = []
        cutoff = datetime.now(UTC) - timedelta(days=interval_days)
        async with sm() as db:
            for org in (await db.execute(select(Organization))).scalars():
                if not await active_authorizations(db, org.id):
                    continue
                last: Any = (
                    await db.execute(select(func.max(Scan.created_at)).where(Scan.org_id == org.id))
                ).scalar()
                if last is not None and last > cutoff:
                    continue
                try:
                    scan = await request_scan(
                        db, org, Actor.system("scheduler"), ScanTrigger.SCHEDULED, get_settings()
                    )
                    await db.commit()
                    queued.append(scan.id)
                except (NotAuthorizedError, ScanConflictError) as exc:
                    await db.rollback()
                    log.info("rescan.skipped", org=str(org.id), reason=str(exc))
        for sid in queued:
            enqueue_scan(sid)
        return [str(s) for s in queued]

    return _run(go)
