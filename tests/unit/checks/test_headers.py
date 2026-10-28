import httpx
import pytest
import respx

from civicshield.engine.checks.base import CheckContext, Target, TargetKind
from civicshield.engine.checks.headers import SecurityHeadersCheck
from civicshield.engine.checks.headers.check import HeadersObservation, analyze, parse_set_cookie
from civicshield.enums import Confidence, Severity
from tests.helpers.net import IP, make_ctx

GOOD = (
    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
    ("content-security-policy", "default-src 'self'; frame-ancestors 'none'"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    ("permissions-policy", "camera=()"),
    ("server", "nginx"),
    ("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax"),
)


def obs(headers: tuple[tuple[str, str], ...], https: bool = True) -> HeadersObservation:
    return HeadersObservation(url="https://example.org/", status=200, headers=headers, https=https)


def types(findings: list) -> set[str]:  # type: ignore[type-arg]
    return {f.finding_type for f in findings}


def test_well_configured_site_has_no_findings() -> None:
    assert analyze(obs(GOOD), "example.org") == []


def test_bare_site_reports_every_missing_header() -> None:
    found = types(analyze(obs(()), "example.org"))
    assert found == {
        "headers.hsts.missing",
        "headers.csp.missing",
        "headers.clickjacking.missing",
        "headers.xcto.missing",
        "headers.referrer_policy.missing",
        "headers.permissions_policy.missing",
    }


def test_hsts_not_expected_over_plain_http() -> None:
    assert "headers.hsts.missing" not in types(analyze(obs((), https=False), "example.org"))


@pytest.mark.parametrize(
    "value, flagged",
    [
        ("max-age=300", True),
        ("max-age=15552000", False),
        ("max-age=abc", True),
        ('max-age="31536000"', False),
    ],
)
def test_hsts_max_age(value: str, flagged: bool) -> None:
    headers = tuple(h for h in GOOD if h[0] != "strict-transport-security") + (
        ("strict-transport-security", value),
    )
    assert ("headers.hsts.short_max_age" in types(analyze(obs(headers), "x"))) is flagged


def test_x_frame_options_satisfies_clickjacking() -> None:
    found = types(analyze(obs((("x-frame-options", "DENY"),)), "x"))
    assert "headers.clickjacking.missing" not in found


def test_version_disclosure_only_with_version_numbers() -> None:
    f = analyze(obs(GOOD + (("x-powered-by", "PHP/7.2.34"),)), "x")
    assert [x.facts["software"] for x in f] == ["PHP/7.2.34"]
    assert analyze(obs(GOOD + (("x-powered-by", "PHP"),)), "x") == []


def test_cookie_flags_with_session_cookie_escalation() -> None:
    headers = GOOD + (("set-cookie", "PHPSESSID=1; path=/"), ("set-cookie", "_ga=2; Secure"))
    by_key = {(f.finding_type, f.discriminator): f for f in analyze(obs(headers), "x")}
    assert by_key[("headers.cookie.missing_secure", "PHPSESSID")].severity is Severity.MEDIUM
    assert by_key[("headers.cookie.missing_httponly", "PHPSESSID")].severity is Severity.MEDIUM
    ga = by_key[("headers.cookie.missing_httponly", "_ga")]
    assert ga.severity is Severity.INFO and ga.confidence is Confidence.MEDIUM
    assert ("headers.cookie.missing_secure", "_ga") not in by_key


def test_parse_set_cookie() -> None:
    c = parse_set_cookie("a=b=c; Path=/; secure; HTTPONLY; SameSite=Strict")
    assert (c.name, c.secure, c.httponly, c.samesite) == ("a", True, True, "Strict")


@respx.mock
async def test_run_end_to_end_with_mocked_http() -> None:
    respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200, headers=list(GOOD)))
    ctx = make_ctx()
    findings = await SecurityHeadersCheck().run(Target(TargetKind.HOST, "example.org"), ctx)
    assert findings == []


@respx.mock
async def test_falls_back_to_http_when_https_unreachable() -> None:
    respx.get(f"https://{IP}/").mock(side_effect=httpx.ConnectError("refused"))
    respx.get(f"http://{IP}/").mock(return_value=httpx.Response(200))
    findings = await SecurityHeadersCheck().run(Target(TargetKind.HOST, "example.org"), make_ctx())
    assert "headers.hsts.missing" not in types(findings)
    assert "headers.xcto.missing" in types(findings)


def test_ctx_type() -> None:
    assert isinstance(make_ctx(), CheckContext)
