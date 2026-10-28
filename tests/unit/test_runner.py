import asyncio
from typing import ClassVar

from civicshield.engine.checks import ALL_CHECKS
from civicshield.engine.checks.base import (
    CheckContext,
    CheckMeta,
    Finding,
    Target,
    TargetKind,
)
from civicshield.engine.fingerprint import fingerprint
from civicshield.engine.net import TargetUnreachableError
from civicshield.engine.runner import plan_targets, run_checks
from civicshield.enums import Category, CheckRunStatus, Confidence, Impact, ScopeKind, Severity
from tests.helpers.net import make_ctx


def _meta(id: str, impact: Impact = Impact.PASSIVE) -> CheckMeta:
    return CheckMeta(
        id=id,
        version="1",
        name=id,
        category=Category.HEADERS,
        impact=impact,
        target_kind=TargetKind.HOST,
        finding_types=frozenset({"x.y"}),
    )


class Boom:
    meta: ClassVar[CheckMeta] = _meta("boom")

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        raise RuntimeError("bug in check")


class Unreachable:
    meta: ClassVar[CheckMeta] = _meta("unreachable")

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        raise TargetUnreachableError("connection refused")


class Slow:
    meta: ClassVar[CheckMeta] = _meta("slow")

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        await asyncio.sleep(5)
        return []


class Active:
    meta: ClassVar[CheckMeta] = _meta("active", Impact.LOW)

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        raise AssertionError("must not run without authorization")


async def test_failures_are_isolated_and_explicit() -> None:
    targets = [Target(TargetKind.HOST, "example.org")]
    outcomes = await run_checks(
        [Boom(), Unreachable(), Slow(), Active()],
        targets,
        make_ctx(),
        max_impact=Impact.PASSIVE,
        check_timeout=0.05,
    )
    by = {o.check.meta.id: o for o in outcomes}
    assert by["boom"].status is CheckRunStatus.ERROR
    assert by["boom"].error == "internal error: RuntimeError"  # no internals leaked
    assert by["unreachable"].status is CheckRunStatus.ERROR
    assert by["slow"].status is CheckRunStatus.TIMEOUT
    assert by["active"].status is CheckRunStatus.SKIPPED


def test_plan_targets() -> None:
    targets = plan_targets(
        [("example.org", ScopeKind.ZONE), ("blog.other.org", ScopeKind.HOST_ONLY)]
    )
    assert targets == [
        Target(TargetKind.ZONE, "example.org"),
        Target(TargetKind.HOST, "example.org"),
        Target(TargetKind.HOST, "www.example.org"),
        Target(TargetKind.HOST, "blog.other.org"),
    ]


def test_fingerprint_ignores_volatile_fields() -> None:
    def f(sev: Severity, days: int) -> Finding:
        return Finding(
            finding_type="tls.cert.expiring_soon",
            title=f"{days} days",
            severity=sev,
            confidence=Confidence.HIGH,
            asset="Example.org",
            remediation_key="r",
            facts={"days_to_expiry": days},
        )

    assert fingerprint("tls", f(Severity.LOW, 20)) == fingerprint("tls", f(Severity.HIGH, 3))


def test_registry_ids_unique_and_finding_types_namespaced() -> None:
    ids = [c.meta.id for c in ALL_CHECKS]
    assert len(ids) == len(set(ids))
    for c in ALL_CHECKS:
        assert all(t.startswith(c.meta.id + ".") for t in c.meta.finding_types), c.meta.id
