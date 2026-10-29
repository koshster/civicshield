"""Scan pipeline tests: API request → worker execution → issues/diff, with fake checks."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from civicshield.config import get_settings
from civicshield.engine.checks.base import (
    CheckContext,
    CheckMeta,
    Finding,
    Target,
    TargetKind,
)
from civicshield.engine.net import TargetUnreachableError
from civicshield.engine.net.dns import FakeResolver
from civicshield.enums import Category, Confidence, Impact, IssueStatus, ScanStatus, Severity
from civicshield.models import AuditEvent, Issue, Scan
from civicshield.scanning import execute_scan, requeue_stale_scans
from tests.unit.conftest import net_factory


class ScriptedCheck:
    """A check whose output each test controls: a set of finding types, or 'error'."""

    meta: ClassVar[CheckMeta] = CheckMeta(
        id="fake",
        version="1",
        name="fake",
        category=Category.HEADERS,
        impact=Impact.PASSIVE,
        target_kind=TargetKind.HOST,
        finding_types=frozenset({"fake.a", "fake.b"}),
    )

    def __init__(self) -> None:
        self.emit: set[str] | str = set()
        self.targets: list[str] = []

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        self.targets.append(target.name)
        if self.emit == "error":
            raise TargetUnreachableError("down")
        if target.name != "example.org":
            return []
        return [
            Finding(
                finding_type=t,
                title=t,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                asset=target.name,
                remediation_key="r",
            )
            for t in sorted(self.emit)
        ]


async def _scan(
    ctx: dict[str, Any],
    queued: list[uuid.UUID],
    check: ScriptedCheck,
    sm: async_sessionmaker[AsyncSession],
    dns: FakeResolver,
) -> ScanStatus | None:
    resp = await ctx["api"].post(f"/api/v1/orgs/{ctx['org']}/scans")
    assert resp.status_code == 202, resp.text
    return await execute_scan(queued[-1], sm, get_settings(), net_factory(dns), checks=[check])


async def _issues(db: AsyncSession) -> dict[str, IssueStatus]:
    db.expire_all()
    return {i.finding_type: i.status for i in (await db.execute(select(Issue))).scalars()}


async def test_lifecycle_new_resolved_regressed(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
) -> None:
    check = ScriptedCheck()
    check.emit = {"fake.a", "fake.b"}
    assert await _scan(org_ready, queued, check, sessionmaker, dns) is ScanStatus.COMPLETED
    assert await _issues(db) == {"fake.a": IssueStatus.OPEN, "fake.b": IssueStatus.OPEN}
    assert set(check.targets) == {"example.org", "www.example.org"}  # planned from scope

    check.emit = {"fake.a"}  # b got fixed
    await _scan(org_ready, queued, check, sessionmaker, dns)
    assert await _issues(db) == {"fake.a": IssueStatus.OPEN, "fake.b": IssueStatus.FIXED}

    check.emit = {"fake.a", "fake.b"}  # b came back
    await _scan(org_ready, queued, check, sessionmaker, dns)
    b = (await db.execute(select(Issue).where(Issue.finding_type == "fake.b"))).scalar_one()
    assert b.status is IssueStatus.OPEN and b.regressed_count == 1
    scan = (await db.execute(select(Scan).order_by(Scan.created_at.desc()))).scalars().first()
    assert scan is not None and scan.stats["regressed"] == 1


async def test_check_error_never_marks_issues_fixed(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
) -> None:
    check = ScriptedCheck()
    check.emit = {"fake.a"}
    await _scan(org_ready, queued, check, sessionmaker, dns)
    check.emit = "error"
    assert await _scan(org_ready, queued, check, sessionmaker, dns) is ScanStatus.COMPLETED
    assert await _issues(db) == {"fake.a": IssueStatus.OPEN}


async def test_revoked_between_queue_and_run_blocks_scan(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
    db: AsyncSession,
) -> None:
    api, org = org_ready["api"], org_ready["org"]
    await api.post(f"/api/v1/orgs/{org}/scans")
    await api.post(f"/api/v1/orgs/{org}/authorizations/{org_ready['auth']}/revoke")
    check = ScriptedCheck()
    status = await execute_scan(
        queued[-1], sessionmaker, get_settings(), net_factory(dns), checks=[check]
    )
    assert status is ScanStatus.BLOCKED and check.targets == []
    actions = [a for a in (await db.execute(select(AuditEvent.action))).scalars()]
    assert "scan.blocked" in actions


async def test_verification_removed_before_run_blocks_scan(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await org_ready["api"].post(f"/api/v1/orgs/{org_ready['org']}/scans")
    del dns.records[("_civicshield-verification.example.org", "TXT")]
    check = ScriptedCheck()
    status = await execute_scan(
        queued[-1], sessionmaker, get_settings(), net_factory(dns), checks=[check]
    )
    assert status is ScanStatus.BLOCKED and check.targets == []


async def test_duplicate_delivery_runs_once(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    check = ScriptedCheck()
    assert await _scan(org_ready, queued, check, sessionmaker, dns) is ScanStatus.COMPLETED
    again = await execute_scan(
        queued[-1], sessionmaker, get_settings(), net_factory(dns), checks=[check]
    )
    assert again is None


async def test_concurrent_scan_rejected_and_unauthorized_org_refused(
    org_ready: dict[str, Any], queued: list[uuid.UUID]
) -> None:
    api, org = org_ready["api"], org_ready["org"]
    assert (await api.post(f"/api/v1/orgs/{org}/scans")).status_code == 202
    assert (await api.post(f"/api/v1/orgs/{org}/scans")).status_code == 409
    other = (await api.post("/api/v1/orgs", json={"name": "Other", "slug": "other"})).json()
    resp = await api.post(f"/api/v1/orgs/{other['id']}/scans")
    assert resp.status_code == 409 and "authorization" in resp.json()["detail"]
    assert len(queued) == 1


async def test_issue_status_changes_require_reason(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    check = ScriptedCheck()
    check.emit = {"fake.a"}
    await _scan(org_ready, queued, check, sessionmaker, dns)
    api, org = org_ready["api"], org_ready["org"]
    issue = (await api.get(f"/api/v1/orgs/{org}/issues")).json()[0]
    url = f"/api/v1/orgs/{org}/issues/{issue['id']}"
    assert (await api.patch(url, json={"status": "accepted_risk"})).status_code == 422
    assert (await api.patch(url, json={"status": "fixed", "reason": "x"})).status_code == 422
    ok = await api.patch(url, json={"status": "accepted_risk", "reason": "vendor-managed"})
    assert ok.json()["status"] == "accepted_risk"
    detail = (await api.get(url)).json()
    assert len(detail["observations"]) == 1


async def test_sweeper_requeues_orphans_and_fails_stuck(
    org_ready: dict[str, Any], queued: list[uuid.UUID], db: AsyncSession
) -> None:
    await org_ready["api"].post(f"/api/v1/orgs/{org_ready['org']}/scans")
    scan = (await db.execute(select(Scan))).scalar_one()
    scan.created_at = datetime.now(UTC) - timedelta(minutes=30)
    await db.commit()
    requeued: list[uuid.UUID] = []
    assert (await requeue_stale_scans(db, requeued.append))["requeued"] == 1
    assert requeued == [scan.id]

    scan.status, scan.started_at = ScanStatus.RUNNING, datetime.now(UTC) - timedelta(hours=2)
    await db.commit()
    assert (await requeue_stale_scans(db, requeued.append))["failed"] == 1
