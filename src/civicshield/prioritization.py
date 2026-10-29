"""Risk scoring, action grouping, the weekly plan, and the org score.

Pure functions over issue-like objects: no I/O, so every ranking decision is unit-tested
and reproducible. The design and its trade-offs are in docs/adr/0005-prioritization.md.
In short:

* **Issue risk** (0–100) = 100 × S × E × X × C × U, multiplicative so any factor near
  zero (an unlikely-to-matter finding, a low-confidence guess) sinks the whole score.
* Issues are grouped into **actions** by remediation key and domain, because staff work
  in tasks ("Turn on HSTS"), not findings. An action's value is its issues' risk with
  diminishing returns.
* **priority** = value / √effort: WSJF with a damped effort term, so quick wins come
  first but real severity still dominates.
* **Prerequisites** come from the remediation library. A blocked action can't be planned,
  and its blockers inherit its priority so they get done first.
* The **weekly plan** pins "fix now" items, then fills a volunteer-time budget.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from civicshield.enums import Category, Confidence, Severity
from civicshield.remediation import RemediationEntry, get_entry, render_text

# --- Factor tables ----------------------------------------------------------------------

SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,  # info findings never move the score or enter the plan
    Severity.LOW: 0.2,
    Severity.MEDIUM: 0.45,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}

CONFIDENCE_WEIGHT = {Confidence.HIGH: 1.0, Confidence.MEDIUM: 0.7, Confidence.LOW: 0.4}

# Exploitability: how likely a real attacker, or plain bad luck, turns this into harm at
# a small nonprofit. It answers a different question from severity ("how bad if it
# happens"). Defaults are judgment calls written down so they can be argued with. Every
# finding type must be listed (a unit test checks against the check registry).
EXPLOITABILITY: dict[str, float] = {
    # Not a probability: an expired certificate is already hurting every visitor.
    "tls.cert.expired": 1.0,
    "tls.cert.not_yet_valid": 1.0,
    "tls.cert.expiring_soon": 1.0,  # with the urgency ramp below
    "tls.https.unavailable": 0.6,  # passive sniffing on shared Wi-Fi needs no skill
    "tls.cert.self_signed": 0.8,
    "tls.cert.hostname_mismatch": 0.8,
    "tls.cert.invalid": 0.8,
    "tls.cert.untrusted_chain": 0.6,  # breaks for some clients, not all
    "tls.redirect.missing": 0.5,
    "tls.cipher.null": 0.6,
    "tls.cipher.anonymous": 0.6,
    "tls.cipher.export": 0.5,
    "tls.protocol.ssl3": 0.4,
    "tls.cipher.rc4": 0.3,
    "tls.cert.weak_key": 0.3,
    "tls.cert.weak_signature": 0.3,
    # Legacy TLS/3DES: real but needs a privileged network position and lots of traffic.
    "tls.protocol.tls10": 0.2,
    "tls.protocol.tls11": 0.2,
    "tls.cipher.3des": 0.2,
    "headers.cookie.missing_secure": 0.5,
    "headers.hsts.missing": 0.4,
    "headers.cookie.missing_httponly": 0.4,
    "headers.csp.missing": 0.3,
    "headers.clickjacking.missing": 0.3,
    "headers.cookie.missing_samesite": 0.3,
    "headers.hsts.short_max_age": 0.2,
    "headers.csp.report_only": 0.2,
    "headers.csp.unsafe_inline": 0.2,
    "headers.csp.unsafe_eval": 0.2,
    "headers.csp.wildcard": 0.2,
    "headers.csp.no_script_restriction": 0.2,
    "headers.referrer_policy.unsafe": 0.2,
    "headers.version_disclosure": 0.2,
    "headers.xcto.missing": 0.1,
    "headers.referrer_policy.missing": 0.1,
    "headers.permissions_policy.missing": 0.1,
    # Email spoofing is the #1 nonprofit attack (fake "from the director" gift-card and
    # wire requests) and needs zero skill when the domain doesn't defend itself.
    "email.spf.pass_all": 1.0,
    "email.spf.missing": 0.8,
    "email.dmarc.missing": 0.8,
    "email.dmarc.multiple": 0.8,
    "email.dmarc.invalid": 0.8,
    "email.dmarc.policy_none": 0.8,
    "email.spf.multiple": 0.7,
    "email.spf.syntax_error": 0.7,
    "email.spf.neutral_all": 0.7,
    "email.spf.too_many_lookups": 0.6,
    "email.dmarc.partial_pct": 0.6,
    "email.dmarc.weak_subdomain_policy": 0.6,
    "email.spf.too_many_void_lookups": 0.5,
    "email.spf.include_missing": 0.5,
    "email.dkim.not_found": 0.4,
    "email.dkim.weak_key": 0.3,
    "email.dmarc.no_reporting": 0.3,
    "email.spf.ptr": 0.2,
}
DEFAULT_EXPLOITABILITY = 0.5

# Things that are actively breaking the site for visitors right now. They go to the top
# of the weekly plan regardless of effort or budget.
FIX_NOW_TYPES = {"tls.cert.expired", "tls.cert.not_yet_valid"}
FIX_NOW_EXPIRY_DAYS = 7

# Hostnames that are probably not what donors and volunteers visit.
NON_PRODUCTION_LABELS = {"staging", "stage", "dev", "test", "beta", "old", "demo"}

# Diminishing returns within an action: the 2nd issue counts half, the 3rd a quarter…
# So an action is worth at most 2× its worst issue, and one plugin with 15 low CVEs
# can't outrank everything else.
DECAY = 0.5

# Residual risk at which the score is 100·e⁻¹ ≈ 37. About three fully exploitable
# high-severity issues on the main site. See org_score().
REFERENCE_RISK = 200.0

DEFAULT_WEEKLY_BUDGET_MINUTES = 120
MAX_PLAN_ITEMS = 3
MAX_PLAN_PER_CATEGORY = 2


class IssueLike(Protocol):
    """What prioritization needs from an issue. The ORM ``Issue`` satisfies this."""

    @property
    def finding_type(self) -> str: ...
    @property
    def asset(self) -> str: ...
    @property
    def title(self) -> str: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def confidence(self) -> Confidence: ...
    @property
    def remediation_key(self) -> str: ...
    @property
    def facts(self) -> Mapping[str, Any]: ...


# --- Per-issue risk ---------------------------------------------------------------------


@dataclass(frozen=True)
class Factor:
    symbol: str
    name: str
    value: float
    explanation: str


@dataclass(frozen=True)
class Risk:
    score: float
    factors: tuple[Factor, ...]


def zone_for(asset: str, zones: Iterable[str]) -> str:
    """The verified domain an asset belongs to (longest suffix match), or the asset."""
    asset = asset.lower()
    matches = [z for z in zones if asset == z or asset.endswith("." + z)]
    return max(matches, key=len) if matches else asset


def exposure(asset: str, zone: str) -> tuple[float, str]:
    if asset in (zone, f"www.{zone}"):
        return 1.0, "main site or domain: what donors and volunteers actually use"
    first_label = asset.split(".", 1)[0]
    if first_label in NON_PRODUCTION_LABELS:
        return 0.6, "looks like a non-production host"
    return 0.8, "other public host"


def urgency(issue: IssueLike) -> tuple[float, str]:
    """Deadline items ramp up as the deadline nears: ×1 at 30+ days, up to ×2.5 at 0."""
    if issue.finding_type == "tls.cert.expiring_soon":
        days = issue.facts.get("days_to_expiry")
        if isinstance(days, int):
            ramp = min(max((30 - days) / 30, 0.0), 1.0)
            return 1 + 1.5 * ramp, f"certificate expires in {days} days"
    return 1.0, "no deadline"


def issue_risk(issue: IssueLike, zone: str) -> Risk:
    s = SEVERITY_WEIGHT[issue.severity]
    e = EXPLOITABILITY.get(issue.finding_type, DEFAULT_EXPLOITABILITY)
    x, x_why = exposure(issue.asset.lower(), zone)
    c = CONFIDENCE_WEIGHT[issue.confidence]
    u, u_why = urgency(issue)
    factors = (
        Factor("S", "severity", s, f"{issue.severity.label} severity"),
        Factor("E", "exploitability", e, "how easily this turns into real harm"),
        Factor("X", "exposure", x, x_why),
        Factor("C", "confidence", c, f"{issue.confidence.name.lower()} confidence"),
        Factor("U", "urgency", u, u_why),
    )
    return Risk(min(100.0, 100 * s * e * x * c * u), factors)


def is_fix_now(issue: IssueLike) -> bool:
    if issue.finding_type in FIX_NOW_TYPES:
        return True
    days = issue.facts.get("days_to_expiry")
    return (
        issue.finding_type == "tls.cert.expiring_soon"
        and isinstance(days, int)
        and days <= FIX_NOW_EXPIRY_DAYS
    )


# --- Actions ----------------------------------------------------------------------------


@dataclass
class RankedIssue:
    issue: IssueLike
    risk: Risk


@dataclass
class Action:
    key: str
    zone: str
    entry: RemediationEntry
    issues: list[RankedIssue]  # highest risk first
    risk_reduction: float
    priority: float  # risk_reduction / √effort
    effective_priority: float  # priority, raised to that of anything this unblocks
    fix_now: bool
    # Plannable only if at least one issue is more than a low-confidence guess:
    # a false alarm in "this week" costs more trust than it's worth.
    confident: bool
    blocked_by: list[Action] = field(default_factory=list, repr=False, compare=False)
    unblocks: list[Action] = field(default_factory=list, repr=False, compare=False)

    @property
    def category(self) -> Category:
        return self.entry.category

    @property
    def lead(self) -> RankedIssue:
        return self.issues[0]

    @property
    def title(self) -> str:
        lead = self.lead.issue
        return render_text(self.entry.title, {**lead.facts, "asset": lead.asset, "zone": self.zone})

    @property
    def plannable(self) -> bool:
        return self.confident and not self.blocked_by and self.effective_priority > 0

    def explain(self) -> list[str]:
        """The "why is this ranked here?" text, built from the same numbers that ranked it."""
        n = len(self.issues)
        lines = [
            f"Fixes {n} issue{'s' if n != 1 else ''}; the most serious is "
            f"“{self.lead.issue.title}” (risk {self.lead.risk.score:.0f}/100).",
            f"Effort: about {self.entry.effort_minutes} minutes (level {self.entry.effort}).",
            f"Priority {self.priority:.1f} = risk reduction {self.risk_reduction:.1f} "
            f"÷ √{self.entry.effort}.",
        ]
        if self.fix_now:
            lines.insert(0, "Fix now: this is breaking the site for visitors already.")
        if self.unblocks:
            lines.append(
                "Ranked up because it must be done first for: "
                + ", ".join(a.title for a in self.unblocks)
            )
        if self.blocked_by:
            lines.append("Waiting on: " + ", ".join(a.title for a in self.blocked_by))
        if not self.confident:
            lines.append("Low confidence: worth checking, so it's kept out of the weekly plan.")
        return lines


def _risk_reduction(risks: Sequence[float]) -> float:
    return sum(r * DECAY**i for i, r in enumerate(sorted(risks, reverse=True)))


def build_actions(issues: Iterable[IssueLike], zones: Iterable[str]) -> list[Action]:
    """Group issues into actions and rank them by effective priority (highest first)."""
    zone_list = [z.lower() for z in zones]
    groups: dict[tuple[str, str], list[RankedIssue]] = defaultdict(list)
    for issue in issues:
        zone = zone_for(issue.asset, zone_list)
        groups[(issue.remediation_key, zone)].append(RankedIssue(issue, issue_risk(issue, zone)))

    actions: dict[tuple[str, str], Action] = {}
    for (key, zone), ranked in groups.items():
        ranked.sort(key=lambda r: r.risk.score, reverse=True)
        entry = get_entry(key)
        reduction = _risk_reduction([r.risk.score for r in ranked])
        priority = reduction / math.sqrt(entry.effort)
        actions[(key, zone)] = Action(
            key=key,
            zone=zone,
            entry=entry,
            issues=ranked,
            risk_reduction=reduction,
            priority=priority,
            effective_priority=priority,
            fix_now=any(is_fix_now(r.issue) for r in ranked),
            confident=any(r.issue.confidence > Confidence.LOW for r in ranked),
        )

    # Prerequisites, within the same domain only.
    for (_, zone), action in actions.items():
        for dep in action.entry.requires:
            blocker = actions.get((dep, zone))
            if blocker is not None:
                action.blocked_by.append(blocker)
                blocker.unblocks.append(action)
    # Priority inheritance (as with OS schedulers): a blocker is at least as urgent as
    # what it blocks. Otherwise an info-level "add DMARC reporting" would sit at the
    # bottom forever while holding up "enforce DMARC". Only priority is inherited, not
    # confidence: a low-confidence blocker still stays out of the plan, and the UI shows
    # what's waiting on it. The prerequisite graph is acyclic (unit-tested), so this
    # settles within its depth.
    changed = True
    while changed:
        changed = False
        for action in actions.values():
            for blocker in action.blocked_by:
                if blocker.effective_priority < action.effective_priority:
                    blocker.effective_priority = action.effective_priority
                    changed = True

    return sorted(
        actions.values(),
        key=lambda a: (a.fix_now, a.effective_priority, a.risk_reduction),
        reverse=True,
    )


# --- Weekly plan ------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanItem:
    action: Action
    reason: str


def weekly_plan(
    actions: Sequence[Action],
    budget_minutes: int = DEFAULT_WEEKLY_BUDGET_MINUTES,
    max_items: int = MAX_PLAN_ITEMS,
    max_per_category: int = MAX_PLAN_PER_CATEGORY,
) -> list[PlanItem]:
    """ "Fix these things this week": a greedy fill of the volunteer-time budget.

    1. Fix-now actions always go first, regardless of budget or count.
    2. Then by effective priority, skipping blocked or low-confidence actions, at most
       ``max_per_category`` per category (variety keeps one area from eating the week),
       and only if the action fits the remaining time. The first item is the exception:
       if the most important task takes longer than the budget, the plan names it
       rather than coming back empty.
    """
    plan: list[PlanItem] = []
    per_category: dict[Category, int] = defaultdict(int)
    remaining = budget_minutes
    candidates = [a for a in actions if a.plannable]

    for a in candidates:
        if a.fix_now:
            plan.append(PlanItem(a, "Fix now: it's already affecting visitors."))
            per_category[a.category] += 1
            remaining -= a.entry.effort_minutes

    for a in sorted(candidates, key=lambda a: a.effective_priority, reverse=True):
        if len(plan) >= max(max_items, sum(p.action.fix_now for p in plan)):
            break
        if a.fix_now or per_category[a.category] >= max_per_category:
            continue
        if plan and a.entry.effort_minutes > remaining:
            continue
        if a.unblocks:
            reason = "Do this first: " + ", ".join(u.title for u in a.unblocks) + " depends on it."
        elif not plan:
            reason = "The highest-priority task right now."
        else:
            reason = "High value for the time it takes."
        plan.append(PlanItem(a, reason))
        per_category[a.category] += 1
        remaining -= a.entry.effort_minutes
    return plan


# --- Org score --------------------------------------------------------------------------


@dataclass(frozen=True)
class Score:
    score: int
    grade: str
    residual_risk: float


def grade(score: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= threshold:
            return letter
    return "F"


def _score(residual: float) -> Score:
    # The plan sketched 100·(1 − r/R). That hits 0 for any badly configured site, and
    # then fixing things doesn't move the number, which is demoralizing for exactly the
    # orgs that need it most. exp(−r/R) behaves the same for small r, never goes
    # negative, and every fix visibly raises it.
    s = round(100 * math.exp(-residual / REFERENCE_RISK))
    return Score(s, grade(s), round(residual, 1))


def org_score(
    actions: Sequence[Action], categories: Iterable[Category]
) -> tuple[Score, dict[Category, Score]]:
    """Overall and per-category scores from residual risk (the actions' risk reduction).

    Uses action values, not raw issue sums, so the score follows the same diminishing
    returns as the ranking. Ten missing headers on one server is one problem, not ten.
    """
    by_cat: dict[Category, float] = {c: 0.0 for c in categories}
    for a in actions:
        by_cat[a.category] = by_cat.get(a.category, 0.0) + a.risk_reduction
    return _score(sum(by_cat.values())), {c: _score(r) for c, r in by_cat.items()}
