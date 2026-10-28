from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from civicshield.api.deps import DB, CurrentUser, Enqueuer, Operator, OrgAccess
from civicshield.api.schemas import (
    AuditEventOut,
    CheckRunOut,
    IssueDetail,
    IssueOut,
    ObservationOut,
    ScanDetail,
    ScanOut,
)
from civicshield.audit import Actor, record
from civicshield.authz.scope_builder import NotAuthorizedError
from civicshield.config import get_settings
from civicshield.enums import IssueStatus, ScanTrigger
from civicshield.models import AuditEvent, Issue, Observation, Scan
from civicshield.scanning import ScanConflictError, request_scan

router = APIRouter(prefix="/orgs/{org_id}", tags=["scans"])


@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(org: OrgAccess, user: CurrentUser, db: DB, enqueue: Enqueuer) -> Scan:
    try:
        scan = await request_scan(
            db, org, Actor.user(user), ScanTrigger.MANUAL, get_settings(), user
        )
    except NotAuthorizedError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ScanConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await db.commit()
    # Enqueue only after the commit, so the worker can never see a scan id that doesn't
    # exist yet. If this line fails, the sweeper re-enqueues the scan later.
    enqueue(scan.id)
    return scan


@router.get("/scans", response_model=list[ScanOut])
async def list_scans(
    org: OrgAccess, db: DB, limit: Annotated[int, Query(ge=1, le=100)] = 20
) -> list[Scan]:
    rows = await db.execute(
        select(Scan).where(Scan.org_id == org.id).order_by(Scan.created_at.desc()).limit(limit)
    )
    return list(rows.scalars())


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: uuid.UUID, org: OrgAccess, db: DB) -> ScanDetail:
    scan = (
        await db.execute(
            select(Scan)
            .where(Scan.id == scan_id, Scan.org_id == org.id)
            .options(selectinload(Scan.check_runs))
        )
    ).scalar_one_or_none()
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return ScanDetail(
        **ScanOut.model_validate(scan).model_dump(),
        check_runs=[CheckRunOut.model_validate(c) for c in scan.check_runs],
    )


@router.get("/issues", response_model=list[IssueOut])
async def list_issues(
    org: OrgAccess,
    db: DB,
    status_filter: Annotated[IssueStatus | None, Query(alias="status")] = None,
) -> list[Issue]:
    query = select(Issue).where(Issue.org_id == org.id)
    if status_filter:
        query = query.where(Issue.status == status_filter)
    query = query.order_by(Issue.severity.desc(), Issue.confidence.desc(), Issue.first_seen_at)
    return list((await db.execute(query)).scalars())


async def _issue(db: DB, org_id: uuid.UUID, issue_id: uuid.UUID) -> Issue:
    issue = (
        await db.execute(select(Issue).where(Issue.id == issue_id, Issue.org_id == org_id))
    ).scalar_one_or_none()
    if issue is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "issue not found")
    return issue


@router.get("/issues/{issue_id}", response_model=IssueDetail)
async def get_issue(issue_id: uuid.UUID, org: OrgAccess, db: DB) -> IssueDetail:
    issue = await _issue(db, org.id, issue_id)
    obs = (
        await db.execute(
            select(Observation)
            .where(Observation.issue_id == issue.id)
            .order_by(Observation.created_at.desc())
            .limit(10)
        )
    ).scalars()
    return IssueDetail(
        **IssueOut.model_validate(issue).model_dump(),
        observations=[ObservationOut.model_validate(o) for o in obs],
    )


class IssueStatusUpdate(BaseModel):
    status: IssueStatus
    reason: Annotated[str, Field(max_length=1000)] = ""


@router.patch("/issues/{issue_id}", response_model=IssueOut)
async def update_issue(
    issue_id: uuid.UUID, body: IssueStatusUpdate, org: OrgAccess, user: CurrentUser, db: DB
) -> Issue:
    """Mark an issue as accepted risk / false positive (or reopen it). Audited."""
    if body.status is IssueStatus.FIXED:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "issues are marked fixed by a rescan, not by hand",
        )
    if body.status is not IssueStatus.OPEN and not body.reason.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "a reason is required")
    issue = await _issue(db, org.id, issue_id)
    previous = issue.status
    issue.status, issue.status_reason = body.status, body.reason or None
    await record(
        db,
        actor=Actor.user(user),
        action="issue.status_changed",
        target_type="issue",
        target_id=issue.id,
        org_id=org.id,
        details={"from": previous.value, "to": body.status.value, "reason": body.reason},
    )
    await db.commit()
    return issue


@router.get("/audit", response_model=list[AuditEventOut])
async def org_audit_log(
    org: OrgAccess, _op: Operator, db: DB, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[AuditEvent]:
    rows = await db.execute(
        select(AuditEvent)
        .where(AuditEvent.org_id == org.id)
        .order_by(AuditEvent.id.desc())
        .limit(limit)
    )
    return list(rows.scalars())
