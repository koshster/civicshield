import httpx
import pytest
import respx

from civicshield.engine.checks.base import CheckContext, Target, TargetKind
from civicshield.engine.checks.headers import SecurityHeadersCheck
from civicshield.engine.checks.headers.check import (
    HeadersObservation,
    analyze,
    parse_set_cookie,
    siblings,
)
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


# --- apex ↔ www redirects (real-world false positive from the first smoke test) ---

PAGE = {"headers.csp.missing", "headers.xcto.missing", "headers.referrer_policy.missing"}


def sibling_obs(own: tuple[tuple[str, str], ...]) -> HeadersObservation:
    """example.org 308 → www.example.org, which serves a page with no headers at all."""
    return HeadersObservation(
        url="https://www.example.org/",
        status=200,
        headers=(),
        https=True,
        page_on_sibling="www.example.org",
        own_url="https://example.org/",
        own_status=308,
        own_headers=own,
    )


def test_page_headers_are_not_judged_on_a_host_that_redirects_to_its_sibling() -> None:
    hsts = (("strict-transport-security", "max-age=63072000"),)
    found = types(analyze(sibling_obs(hsts), "example.org"))
    assert not found & PAGE
    assert "headers.clickjacking.missing" not in found
    assert "headers.permissions_policy.missing" not in found
    assert "headers.hsts.missing" not in found


def test_response_level_headers_come_from_the_hosts_own_redirect() -> None:
    own = (("set-cookie", "sid=1"), ("x-powered-by", "PHP/7.4.3"))
    findings = analyze(sibling_obs(own), "example.org")
    found = types(findings)
    # The redirect itself sent no HSTS: www's (absent here) must not be borrowed, and the
    # cookie and version leak are the apex's own.
    assert "headers.hsts.missing" in found
    assert {"headers.cookie.missing_secure", "headers.version_disclosure"} <= found
    hsts = next(f for f in findings if f.finding_type == "headers.hsts.missing")
    assert hsts.evidence[0].data["url"] == "https://example.org/"


def test_header_less_redirect_does_not_borrow_sibling_hsts() -> None:
    o = sibling_obs(())
    o = HeadersObservation(**{**o.__dict__, "headers": GOOD})
    assert "headers.hsts.missing" in types(analyze(o, "example.org"))


def test_siblings() -> None:
    assert siblings("example.org") == {"www.example.org"}
    assert siblings("www.example.org") == {"www.www.example.org", "example.org"}


@respx.mock
async def test_gather_attributes_apex_redirect_to_www() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "example.org":
            return httpx.Response(308, headers={"Location": "https://www.example.org/"})
        return httpx.Response(200)

    respx.get(f"https://{IP}/").mock(side_effect=respond)
    ctx = make_ctx()
    o = await SecurityHeadersCheck().gather(Target(TargetKind.HOST, "example.org"), ctx)
    assert (o.page_on_sibling, o.own_url, o.own_status) == (
        "www.example.org",
        "https://example.org/",
        308,
    )
    found = types(analyze(o, "example.org"))
    assert found == {"headers.hsts.missing"}
    # www itself still gets every page finding.
    www = await SecurityHeadersCheck().run(Target(TargetKind.HOST, "www.example.org"), ctx)
    assert types(www) >= PAGE


@respx.mock
async def test_non_sibling_in_scope_redirect_keeps_page_findings() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "example.org":
            return httpx.Response(301, headers={"Location": "https://blog.example.org/"})
        return httpx.Response(200)

    respx.get(f"https://{IP}/").mock(side_effect=respond)
    ctx = make_ctx({("blog.example.org", "A"): [IP]})
    o = await SecurityHeadersCheck().gather(Target(TargetKind.HOST, "example.org"), ctx)
    assert o.page_on_sibling is None
    assert types(analyze(o, "example.org")) >= PAGE
