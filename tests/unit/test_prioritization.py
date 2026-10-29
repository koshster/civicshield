from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from civicshield.engine.checks import ALL_CHECKS
from civicshield.enums import Category, Confidence, Severity
from civicshield.prioritization import (
    DEFAULT_EXPLOITABILITY,
    EXPLOITABILITY,
    Action,
    build_actions,
    grade,
    issue_risk,
    org_score,
    weekly_plan,
    zone_for,
)

ZONE = "example.org"


@dataclass
class FakeIssue:
    finding_type: str
    remediation_key: str
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.HIGH
    asset: str = ZONE
    title: str = "an issue"
    facts: Mapping[str, Any] = field(default_factory=dict)


def hsts(asset: str = ZONE, **kw: Any) -> FakeIssue:
    return FakeIssue("headers.hsts.missing", "headers.add_hsts", asset=asset, **kw)


def redirect(asset: str = ZONE) -> FakeIssue:
    return FakeIssue("tls.redirect.missing", "tls.redirect_http_to_https", asset=asset)


def by_key(actions: list[Action]) -> dict[tuple[str, str], Action]:
    return {(a.key, a.zone): a for a in actions}


# --- risk -------------------------------------------------------------------------------


def test_every_finding_type_has_an_explicit_exploitability() -> None:
    types = {t for c in ALL_CHECKS for t in c.meta.finding_types}
    assert types - EXPLOITABILITY.keys() == set(), "add these to EXPLOITABILITY"
    assert EXPLOITABILITY.keys() - types == set(), "stale EXPLOITABILITY entries"
    assert all(0 < e <= 1 for e in EXPLOITABILITY.values())
    assert 0 < DEFAULT_EXPLOITABILITY <= 1


def test_risk_is_the_product_of_its_factors() -> None:
    risk = issue_risk(hsts(), ZONE)
    assert risk.score == pytest.approx(100 * 0.45 * 0.4 * 1.0 * 1.0 * 1.0)
    assert [f.symbol for f in risk.factors] == ["S", "E", "X", "C", "U"]
    assert risk.score == pytest.approx(100 * math.prod(f.value for f in risk.factors))


def test_info_findings_carry_no_risk() -> None:
    assert issue_risk(hsts(severity=Severity.INFO), ZONE).score == 0


def test_low_confidence_sinks_risk() -> None:
    high = issue_risk(hsts(), ZONE).score
    low = issue_risk(hsts(confidence=Confidence.LOW), ZONE).score
    assert low == pytest.approx(high * 0.4)


@pytest.mark.parametrize(
    ("asset", "x"),
    [(ZONE, 1.0), (f"www.{ZONE}", 1.0), (f"donate.{ZONE}", 0.8), (f"staging.{ZONE}", 0.6)],
)
def test_exposure(asset: str, x: float) -> None:
    factors = {f.symbol: f.value for f in issue_risk(hsts(asset), ZONE).factors}
    assert factors["X"] == x


@pytest.mark.parametrize(("days", "u"), [(45, 1.0), (30, 1.0), (15, 1.75), (0, 2.5), (-3, 2.5)])
def test_expiry_urgency_ramps_up(days: int, u: float) -> None:
    issue = FakeIssue(
        "tls.cert.expiring_soon", "tls.renew_certificate", facts={"days_to_expiry": days}
    )
    factors = {f.symbol: f.value for f in issue_risk(issue, ZONE).factors}
    assert factors["U"] == pytest.approx(u)


def test_risk_is_capped_at_100() -> None:
    issue = FakeIssue(
        "tls.cert.expiring_soon",
        "tls.renew_certificate",
        severity=Severity.CRITICAL,
        facts={"days_to_expiry": 0},
    )
    assert issue_risk(issue, ZONE).score == 100


def test_zone_for_picks_longest_verified_suffix() -> None:
    zones = ["example.org", "shop.example.org"]
    assert zone_for("www.shop.example.org", zones) == "shop.example.org"
    assert zone_for("WWW.example.org", zones) == "example.org"
    assert zone_for("notexample.org", zones) == "notexample.org"


# --- actions ----------------------------------------------------------------------------


def test_same_fix_on_apex_and_www_is_one_action_with_diminishing_returns() -> None:
    [action] = build_actions([hsts(ZONE), hsts(f"www.{ZONE}")], [ZONE])
    r = issue_risk(hsts(), ZONE).score
    assert len(action.issues) == 2
    assert action.risk_reduction == pytest.approx(r + r / 2)
    assert action.priority == pytest.approx(action.risk_reduction / math.sqrt(1))
    assert action.title == f"Turn on HSTS for {ZONE}"


def test_different_domains_are_different_actions() -> None:
    actions = build_actions([hsts("a.org"), hsts("b.org")], ["a.org", "b.org"])
    assert {a.zone for a in actions} == {"a.org", "b.org"}


def test_effort_damps_priority() -> None:
    csp = FakeIssue("headers.csp.missing", "headers.add_csp", severity=Severity.LOW)
    [action] = build_actions([csp], [ZONE])
    assert action.entry.effort == 3
    assert action.priority == pytest.approx(action.risk_reduction / math.sqrt(3))


def test_prerequisite_blocks_and_blocker_inherits_priority() -> None:
    actions = by_key(build_actions([hsts(), redirect()], [ZONE]))
    h, r = actions[("headers.add_hsts", ZONE)], actions[("tls.redirect_http_to_https", ZONE)]
    assert h.blocked_by == [r] and r.unblocks == [h]
    assert r.effective_priority >= h.effective_priority
    assert not h.plannable and r.plannable
    assert any("must be done first" in line for line in r.explain())
    assert any("Waiting on" in line for line in h.explain())


def test_prerequisites_only_apply_within_the_same_domain() -> None:
    actions = by_key(build_actions([hsts("a.org"), redirect("b.org")], ["a.org", "b.org"]))
    assert actions[("headers.add_hsts", "a.org")].blocked_by == []


def test_info_level_blocker_is_pulled_into_the_plan() -> None:
    # "Add DMARC reporting" is info severity (risk 0) but must happen before enforcement.
    no_rua = FakeIssue(
        "email.dmarc.no_reporting", "email.add_dmarc_reporting", severity=Severity.INFO
    )
    p_none = FakeIssue("email.dmarc.policy_none", "email.enforce_dmarc")
    actions = build_actions([no_rua, p_none], [ZONE])
    plan = weekly_plan(actions)
    assert [i.action.key for i in plan] == ["email.add_dmarc_reporting"]
    assert "depends on it" in plan[0].reason


def test_low_confidence_blocker_is_not_planned_and_keeps_blocking() -> None:
    dkim = FakeIssue("email.dkim.not_found", "email.enable_dkim", confidence=Confidence.LOW)
    p_none = FakeIssue("email.dmarc.policy_none", "email.enforce_dmarc")
    actions = by_key(build_actions([dkim, p_none], [ZONE]))
    assert weekly_plan(list(actions.values())) == []
    assert not actions[("email.enable_dkim", ZONE)].plannable
    assert any("Low confidence" in line for line in actions[("email.enable_dkim", ZONE)].explain())


# --- weekly plan ------------------------------------------------------------------------


def test_expired_certificate_is_fix_now_even_over_budget() -> None:
    expired = FakeIssue("tls.cert.expired", "tls.replace_certificate", severity=Severity.HIGH)
    actions = build_actions([hsts(), expired], [ZONE])
    plan = weekly_plan(actions, budget_minutes=0)
    assert plan[0].action.key == "tls.replace_certificate"
    assert plan[0].reason.startswith("Fix now")


@pytest.mark.parametrize(("days", "fix_now"), [(5, True), (7, True), (20, False)])
def test_expiring_soon_becomes_fix_now_inside_a_week(days: int, fix_now: bool) -> None:
    issue = FakeIssue(
        "tls.cert.expiring_soon", "tls.renew_certificate", facts={"days_to_expiry": days}
    )
    [action] = build_actions([issue], [ZONE])
    assert action.fix_now is fix_now


def test_plan_caps_items_and_categories() -> None:
    issues = [
        FakeIssue("headers.xcto.missing", "headers.add_xcto"),
        FakeIssue("headers.clickjacking.missing", "headers.add_frame_protection"),
        FakeIssue("headers.referrer_policy.missing", "headers.add_referrer_policy"),
        FakeIssue("email.dmarc.missing", "email.add_dmarc"),
        FakeIssue("email.spf.missing", "email.add_spf", severity=Severity.HIGH),
    ]
    plan = weekly_plan(build_actions(issues, [ZONE]))
    assert len(plan) == 3
    cats = [i.action.category for i in plan]
    assert cats.count(Category.HEADERS) <= 2 and cats.count(Category.EMAIL) <= 2


def test_plan_respects_budget_but_never_comes_back_empty() -> None:
    csp = FakeIssue("headers.csp.missing", "headers.add_csp", severity=Severity.HIGH)
    xcto = FakeIssue("headers.xcto.missing", "headers.add_xcto", severity=Severity.LOW)
    actions = build_actions([csp, xcto], [ZONE])
    # CSP (240 min) is the top priority but exceeds the 120-minute budget on its own.
    plan = weekly_plan(actions, budget_minutes=120)
    assert [i.action.key for i in plan] == ["headers.add_csp"]
    plan = weekly_plan(actions, budget_minutes=300)
    assert [i.action.key for i in plan] == ["headers.add_csp", "headers.add_xcto"]


def test_low_confidence_only_actions_never_enter_the_plan() -> None:
    issue = hsts(confidence=Confidence.LOW, severity=Severity.HIGH)
    assert weekly_plan(build_actions([issue], [ZONE])) == []


# --- score ------------------------------------------------------------------------------

CATS = (Category.TLS, Category.HEADERS, Category.EMAIL)


def test_no_open_issues_scores_100() -> None:
    overall, per_cat = org_score([], CATS)
    assert (overall.score, overall.grade) == (100, "A")
    assert {c: s.score for c, s in per_cat.items()} == dict.fromkeys(CATS, 100)


def test_info_findings_do_not_move_the_score() -> None:
    info = hsts(severity=Severity.INFO)
    assert org_score(build_actions([info], [ZONE]), CATS)[0].score == 100


def test_score_by_category() -> None:
    overall, per_cat = org_score(build_actions([hsts()], [ZONE]), CATS)
    assert per_cat[Category.HEADERS].score < 100
    assert per_cat[Category.TLS].score == per_cat[Category.EMAIL].score == 100
    assert overall.score == per_cat[Category.HEADERS].score


@pytest.mark.parametrize(
    ("s", "g"), [(100, "A"), (90, "A"), (89, "B"), (70, "C"), (60, "D"), (5, "F")]
)
def test_grade(s: int, g: str) -> None:
    assert grade(s) == g


_TYPES = sorted(EXPLOITABILITY)
_issue = st.builds(
    FakeIssue,
    finding_type=st.sampled_from(_TYPES),
    remediation_key=st.sampled_from(
        ["headers.add_hsts", "email.add_dmarc", "tls.renew_certificate"]
    ),
    severity=st.sampled_from(list(Severity)),
    confidence=st.sampled_from(list(Confidence)),
    asset=st.sampled_from([ZONE, f"www.{ZONE}", f"staging.{ZONE}"]),
    facts=st.fixed_dictionaries({"days_to_expiry": st.integers(-10, 60)}),
)


@given(st.lists(_issue, min_size=1, max_size=12), st.data())
def test_fixing_an_issue_never_lowers_the_score(
    issues: list[FakeIssue], data: st.DataObject
) -> None:
    before = org_score(build_actions(issues, [ZONE]), CATS)[0].score
    fixed = data.draw(st.integers(0, len(issues) - 1))
    remaining = issues[:fixed] + issues[fixed + 1 :]
    after = org_score(build_actions(remaining, [ZONE]), CATS)[0].score
    assert after >= before


@given(st.lists(_issue, max_size=12))
def test_plan_invariants(issues: list[FakeIssue]) -> None:
    actions = build_actions(issues, [ZONE])
    plan = weekly_plan(actions)
    keys = [i.action.key for i in plan]
    assert len(keys) == len(set(keys))
    for item in plan:
        assert item.action.confident and not item.action.blocked_by
    non_urgent = [i for i in plan if not i.action.fix_now]
    assert len(non_urgent) <= 3
