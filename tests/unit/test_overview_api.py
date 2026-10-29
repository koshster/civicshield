"""Overview + issue detail through the API: ranking, plan, score and fix guidance."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from civicshield.config import get_settings
from civicshield.engine.checks.base import CheckContext, CheckMeta, Finding, Target, TargetKind
from civicshield.engine.net.dns import FakeResolver
from civicshield.enums import Category, Confidence, Impact, Severity
from civicshield.scanning import execute_scan
from tests.conftest import PASSWORD, login
from tests.unit.conftest import net_factory

# (finding_type, remediation_key, severity, facts)
FINDINGS: list[tuple[str, str, Severity, dict[str, Any]]] = [
    ("headers.hsts.missing", "headers.add_hsts", Severity.MEDIUM, {}),
    ("tls.redirect.missing", "tls.redirect_http_to_https", Severity.MEDIUM, {}),
    ("email.dmarc.policy_none", "email.enforce_dmarc", Severity.MEDIUM, {"policy": "none"}),
    ("headers.xcto.missing", "headers.add_xcto", Severity.LOW, {}),
]


class RealisticCheck:
    """Emits real finding types and remediation keys, so the real library is used."""

    meta: ClassVar[CheckMeta] = CheckMeta(
        id="realistic",
        version="1",
        name="realistic",
        category=Category.HEADERS,
        impact=Impact.PASSIVE,
        target_kind=TargetKind.HOST,
        finding_types=frozenset(f[0] for f in FINDINGS),
    )

    def __init__(self) -> None:
        self.emit = {f[0] for f in FINDINGS}

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        if target.name != "example.org":
            return []
        return [
            Finding(
                finding_type=ftype,
                title=ftype,
                severity=sev,
                confidence=Confidence.HIGH,
                asset=target.name,
                remediation_key=rkey,
                facts=facts,
            )
            for ftype, rkey, sev, facts in FINDINGS
            if ftype in self.emit
        ]


async def _scan(
    ctx: dict[str, Any],
    queued: list[uuid.UUID],
    check: RealisticCheck,
    sm: async_sessionmaker[AsyncSession],
    dns: FakeResolver,
) -> None:
    resp = await ctx["api"].post(f"/api/v1/orgs/{ctx['org']}/scans")
    assert resp.status_code == 202, resp.text
    await execute_scan(queued[-1], sm, get_settings(), net_factory(dns), checks=[check])


async def _overview(ctx: dict[str, Any]) -> dict[str, Any]:
    resp = await ctx["api"].get(f"/api/v1/orgs/{ctx['org']}/overview")
    assert resp.status_code == 200, resp.text
    data: dict[str, Any] = resp.json()
    return data


async def test_no_score_before_first_completed_scan(org_ready: dict[str, Any]) -> None:
    ov = await _overview(org_ready)
    assert ov["score"] is None and ov["categories"] == {}
    assert ov["plan"] == [] and ov["actions"] == [] and ov["last_scan"] is None


async def test_overview_ranks_plans_and_scores(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await _scan(org_ready, queued, RealisticCheck(), sessionmaker, dns)
    ov = await _overview(org_ready)

    assert ov["score"]["score"] < 100 and ov["score"]["grade"] in "ABCDF"
    assert set(ov["categories"]) == {"tls", "headers", "email"}
    assert ov["issue_counts"] == {"open": 4}
    assert ov["budget_minutes"] == 120
    actions = {a["key"]: a for a in ov["actions"]}
    assert len(actions) == 4

    # HSTS must wait for the HTTP→HTTPS redirect; the redirect inherits HSTS's urgency.
    hsts, redirect = actions["headers.add_hsts"], actions["tls.redirect_http_to_https"]
    assert hsts["blocked_by"] == ["Send HTTP visitors to HTTPS on example.org"]
    assert not hsts["plannable"]
    assert redirect["unblocks"] == ["Turn on HSTS for example.org"]
    assert redirect["effective_priority"] >= hsts["priority"]

    planned = [p["action"]["key"] for p in ov["plan"]]
    assert "headers.add_hsts" not in planned
    assert "tls.redirect_http_to_https" in planned and len(planned) <= 3
    assert all(p["reason"] for p in ov["plan"])
    assert all(a["why"] for a in ov["actions"])


async def test_issue_detail_has_rendered_remediation_and_risk(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    await _scan(org_ready, queued, RealisticCheck(), sessionmaker, dns)
    api, org = org_ready["api"], org_ready["org"]
    issues = (await api.get(f"/api/v1/orgs/{org}/issues")).json()
    dmarc = next(i for i in issues if i["finding_type"] == "email.dmarc.policy_none")
    detail = (await api.get(f"/api/v1/orgs/{org}/issues/{dmarc['id']}")).json()

    rem = detail["remediation"]
    assert rem["title"] == "Move DMARC for example.org to enforcement"
    assert 'Your DMARC policy is "none"' in rem["why"]
    assert any("p=quarantine" in t["snippet"] for t in rem["technical"])
    assert "{{" not in str(rem)
    assert [f["symbol"] for f in detail["risk"]["factors"]] == ["S", "E", "X", "C", "U"]
    assert 0 < detail["risk"]["score"] <= 100


async def test_triage_and_fixes_move_the_score_honestly(
    org_ready: dict[str, Any],
    queued: list[uuid.UUID],
    dns: FakeResolver,
    sessionmaker: async_sessionmaker[AsyncSession],
) -> None:
    check = RealisticCheck()
    await _scan(org_ready, queued, check, sessionmaker, dns)
    api, org = org_ready["api"], org_ready["org"]
    start = (await _overview(org_ready))["score"]["score"]
    by_type = {i["finding_type"]: i for i in (await api.get(f"/api/v1/orgs/{org}/issues")).json()}

    # Accepting a risk removes it from the to-do list but not from the score.
    xcto = by_type["headers.xcto.missing"]["id"]
    await api.patch(
        f"/api/v1/orgs/{org}/issues/{xcto}", json={"status": "accepted_risk", "reason": "CDN"}
    )
    ov = await _overview(org_ready)
    assert "headers.add_xcto" not in {a["key"] for a in ov["actions"]}
    assert ov["score"]["score"] == start

    # Fixing the redirect (rescan no longer sees it) raises the score and unblocks HSTS.
    check.emit.discard("tls.redirect.missing")
    await _scan(org_ready, queued, check, sessionmaker, dns)
    ov = await _overview(org_ready)
    assert ov["score"]["score"] > start
    assert ov["issue_counts"]["fixed"] == 1
    hsts = next(a for a in ov["actions"] if a["key"] == "headers.add_hsts")
    assert hsts["blocked_by"] == [] and hsts["plannable"]


async def test_overview_of_another_org_is_404(
    org_ready: dict[str, Any], operator_client: httpx.AsyncClient
) -> None:
    api = org_ready["api"]
    theirs = (await api.post("/api/v1/orgs", json={"name": "Other", "slug": "other"})).json()
    await api.post(
        f"/api/v1/orgs/{org_ready['org']}/members",
        json={"email": "staff@fb.org", "password": PASSWORD},
    )
    await api.post("/api/v1/auth/logout")
    await login(operator_client, "staff@fb.org")
    assert (await api.get(f"/api/v1/orgs/{org_ready['org']}/overview")).status_code == 200
    assert (await api.get(f"/api/v1/orgs/{theirs['id']}/overview")).status_code == 404
