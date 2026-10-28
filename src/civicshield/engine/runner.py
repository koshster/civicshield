"""Plan and execute checks for a scan.

Failure isolation is the main job here: one check crashing or timing out must never
abort the scan or, worse, be reported as "no problems found". Every (check, target)
pair produces exactly one CheckOutcome, with an explicit status.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass, field

from civicshield.engine.checks.base import Check, CheckContext, Finding, Target, TargetKind
from civicshield.engine.net import NetError, OutOfScopeError
from civicshield.enums import CheckRunStatus, Impact, ScopeKind
from civicshield.log import get_logger

log = get_logger(__name__)

CHECK_TIMEOUT_SECONDS = 120.0
MAX_CONCURRENT_CHECKS = 4


@dataclass
class CheckOutcome:
    check: Check
    target: Target
    status: CheckRunStatus
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0


def plan_targets(domains: Sequence[tuple[str, ScopeKind]]) -> list[Target]:
    """Turn in-scope domains into concrete targets.

    A zone-verified domain gets a ZONE target (email/DNS checks) plus HOST targets for the
    apex and ``www``. A host-only domain gets just its one HOST target. Subdomain
    discovery (certificate transparency) adds more HOST targets in a later phase.
    """
    targets: list[Target] = []
    for name, kind in domains:
        if kind is ScopeKind.ZONE:
            targets.append(Target(TargetKind.ZONE, name))
            targets.append(Target(TargetKind.HOST, name))
            if not name.startswith("www."):
                targets.append(Target(TargetKind.HOST, f"www.{name}"))
        else:
            targets.append(Target(TargetKind.HOST, name))
    return list(dict.fromkeys(targets))  # de-duplicate, keep order


async def _run_one(
    check: Check, target: Target, ctx: CheckContext, sem: asyncio.Semaphore, check_timeout: float
) -> CheckOutcome:
    async with sem:
        start = time.monotonic()
        try:
            findings = await asyncio.wait_for(check.run(target, ctx), check_timeout)
            status, error = CheckRunStatus.OK, None
        except TimeoutError:
            findings, status, error = (
                [],
                CheckRunStatus.TIMEOUT,
                f"timed out after {check_timeout}s",
            )
        except OutOfScopeError as exc:
            # A check tried to reach something out of scope: a bug worth surfacing loudly.
            log.error("check.out_of_scope", check=check.meta.id, target=target.name, error=str(exc))
            findings, status, error = [], CheckRunStatus.ERROR, str(exc)
        except NetError as exc:
            findings, status, error = [], CheckRunStatus.ERROR, str(exc)
        except Exception as exc:  # isolate check bugs from the scan
            log.exception("check.crashed", check=check.meta.id, target=target.name)
            findings, status = [], CheckRunStatus.ERROR
            error = f"internal error: {type(exc).__name__}"
        duration = int((time.monotonic() - start) * 1000)
        return CheckOutcome(check, target, status, findings, error, duration)


async def run_checks(
    checks: Sequence[Check],
    targets: Sequence[Target],
    ctx: CheckContext,
    max_impact: Impact,
    check_timeout: float = CHECK_TIMEOUT_SECONDS,
) -> list[CheckOutcome]:
    sem = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
    jobs = []
    outcomes: list[CheckOutcome] = []
    for check in checks:
        for target in targets:
            if target.kind is not check.meta.target_kind:
                continue
            if check.meta.impact > max_impact:
                # Not authorized at this impact level: record as skipped, visibly.
                outcomes.append(
                    CheckOutcome(
                        check,
                        target,
                        CheckRunStatus.SKIPPED,
                        error="not covered by the authorization",
                    )
                )
                continue
            jobs.append(_run_one(check, target, ctx, sem, check_timeout))
    outcomes.extend(await asyncio.gather(*jobs))
    return outcomes
