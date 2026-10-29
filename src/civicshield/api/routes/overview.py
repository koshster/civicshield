"""The org overview: score, "fix these this week", and every open action, ranked.

Computed on read from the current issues: no stored scores to drift out of sync with
the issues they summarize. For a few hundred issues this costs milliseconds. Score
history (a trend chart) will need snapshots per scan, in a later phase.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

from fastapi import APIRouter
from sqlalchemy import select

from civicshield.api.deps import DB, OrgAccess
from civicshield.api.schemas import (
    ActionIssueOut,
    ActionOut,
    FactorOut,
    OverviewOut,
    PlanItemOut,
    RiskOut,
    ScanOut,
    ScoreOut,
)
from civicshield.config import get_settings
from civicshield.engine.checks import ALL_CHECKS
from civicshield.enums import IssueStatus, ScanStatus
from civicshield.models import Domain, Issue, Scan
from civicshield.prioritization import Action, Risk, Score, build_actions, org_score, weekly_plan

router = APIRouter(prefix="/orgs/{org_id}", tags=["overview"])


async def org_zones(db: DB, org_id: uuid.UUID) -> list[str]:
    return list((await db.scalars(select(Domain.name).where(Domain.org_id == org_id))).all())


def risk_out(risk: Risk) -> RiskOut:
    return RiskOut(
        score=round(risk.score, 1),
        factors=[
            FactorOut(symbol=f.symbol, name=f.name, value=f.value, explanation=f.explanation)
            for f in risk.factors
        ],
    )


# Annotated Action[Any], not Action[Issue]: mypy (2.4) checks a type argument's
# protocol bound during semantic analysis, before SQLAlchemy's Mapped[...] descriptors
# are resolved, then caches the (wrong) "not a subtype" for the whole run. Call sites
# such as build_actions(issues) are checked later and still verify Issue ⊂ IssueLike.
def action_out(a: Action[Any]) -> ActionOut:
    return ActionOut(
        key=a.key,
        title=a.title,
        category=a.category,
        zone=a.zone,
        effort=a.entry.effort,
        effort_minutes=a.entry.effort_minutes,
        risk_reduction=round(a.risk_reduction, 1),
        priority=round(a.priority, 1),
        effective_priority=round(a.effective_priority, 1),
        fix_now=a.fix_now,
        plannable=a.plannable,
        blocked_by=[b.title for b in a.blocked_by],
        unblocks=[u.title for u in a.unblocks],
        why=a.explain(),
        issues=[
            ActionIssueOut(
                id=r.issue.id,
                title=r.issue.title,
                asset=r.issue.asset,
                severity=r.issue.severity,
                confidence=r.issue.confidence,
                risk=round(r.risk.score, 1),
            )
            for r in a.issues
        ],
    )


def score_out(s: Score) -> ScoreOut:
    return ScoreOut(score=s.score, grade=s.grade, residual_risk=s.residual_risk)


@router.get("/overview", response_model=OverviewOut)
async def overview(org: OrgAccess, db: DB) -> OverviewOut:
    zones = await org_zones(db, org.id)
    issues = list((await db.scalars(select(Issue).where(Issue.org_id == org.id))).all())
    open_issues = [i for i in issues if i.status is IssueStatus.OPEN]
    # Accepting a risk is a decision, not a fix: it leaves the plan but still counts
    # against the score. Otherwise the fastest way to an "A" is to click "accept".
    scored = [i for i in issues if i.status in (IssueStatus.OPEN, IssueStatus.ACCEPTED_RISK)]

    actions = build_actions(open_issues, zones)
    budget = get_settings().weekly_budget_minutes
    plan = weekly_plan(actions, budget_minutes=budget)
    categories = dict.fromkeys(c.meta.category for c in ALL_CHECKS)
    overall, per_cat = org_score(build_actions(scored, zones), categories)

    last_scan = await db.scalar(
        select(Scan).where(Scan.org_id == org.id).order_by(Scan.created_at.desc()).limit(1)
    )
    last_completed = await db.scalar(
        select(Scan.finished_at)
        .where(Scan.org_id == org.id, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.finished_at.desc())
        .limit(1)
    )
    return OverviewOut(
        score=score_out(overall) if last_completed else None,
        categories={c: score_out(s) for c, s in per_cat.items()} if last_completed else {},
        plan=[PlanItemOut(action=action_out(p.action), reason=p.reason) for p in plan],
        actions=[action_out(a) for a in actions],
        budget_minutes=budget,
        issue_counts=dict(Counter(i.status for i in issues)),
        last_scan=ScanOut.model_validate(last_scan) if last_scan else None,
        last_completed_scan_at=last_completed,
    )
