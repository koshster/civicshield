"""Security headers and cookie flags on a site's homepage.

Severity reflects a small nonprofit's realistic risk, not a checklist. Missing HSTS
(a downgrade/hijack risk on public Wi-Fi) is MEDIUM. Missing Permissions-Policy is INFO.
A missing CSP is LOW, because a good CSP is hard for a small org to deploy and other fixes
pay off sooner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import ClassVar

from civicshield.engine.checks.base import (
    CheckContext,
    CheckMeta,
    Evidence,
    Finding,
    Reference,
    Target,
    TargetKind,
    cwe,
)
from civicshield.engine.checks.headers.csp import analyze_csp, parse_csp
from civicshield.engine.net import CertificateError, NetError
from civicshield.engine.net.http import FetchResult
from civicshield.enums import Category, Confidence, Impact, Severity

HSTS_MIN_MAX_AGE = 15_552_000  # 180 days, the commonly recommended minimum
_VERSION_IN_HEADER = re.compile(r"\d+(\.\d+)+")
_SESSIONISH = re.compile(
    r"(sess|auth|token|login|wordpress_logged_in|wp-settings|phpsessid)", re.IGNORECASE
)

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


@dataclass(frozen=True)
class HeadersObservation:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]  # lower-cased names, original order, duplicates kept
    https: bool  # the analyzed response came over HTTPS
    tls_verified: bool = True
    redirect_blocked_to: str | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)

    def get(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k == name), None)

    def get_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]


def _observation(result: FetchResult, *, https: bool, verified: bool) -> HeadersObservation:
    return HeadersObservation(
        url=result.url,
        status=result.status,
        headers=tuple((k.lower(), v) for k, v in result.headers.multi_items()),
        https=https,
        tls_verified=verified,
        redirect_blocked_to=result.redirect_blocked_to,
    )


def _parse_hsts(value: str) -> tuple[int | None, bool]:
    max_age: int | None = None
    include_sub = False
    for part in value.split(";"):
        key, _, val = part.strip().partition("=")
        if key.lower() == "max-age":
            try:
                max_age = int(val.strip().strip('"'))
            except ValueError:
                max_age = None
        elif key.lower() == "includesubdomains":
            include_sub = True
    return max_age, include_sub


@dataclass(frozen=True)
class ParsedCookie:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None


def parse_set_cookie(header: str) -> ParsedCookie:
    first, *attrs = header.split(";")
    name = first.split("=", 1)[0].strip()
    flags = {
        a.strip().split("=", 1)[0].lower(): (a.split("=", 1)[1].strip() if "=" in a else "")
        for a in attrs
        if a.strip()
    }
    return ParsedCookie(name, "secure" in flags, "httponly" in flags, flags.get("samesite") or None)


class SecurityHeadersCheck:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="headers",
        version="1.0.0",
        name="Security headers & cookies",
        category=Category.HEADERS,
        impact=Impact.PASSIVE,
        target_kind=TargetKind.HOST,
        description="Fetches the homepage once and inspects browser security headers "
        "and cookie flags.",
        finding_types=frozenset(
            {
                "headers.hsts.missing",
                "headers.hsts.short_max_age",
                "headers.csp.missing",
                "headers.csp.report_only",
                "headers.csp.unsafe_inline",
                "headers.csp.unsafe_eval",
                "headers.csp.wildcard",
                "headers.csp.no_script_restriction",
                "headers.clickjacking.missing",
                "headers.xcto.missing",
                "headers.referrer_policy.missing",
                "headers.referrer_policy.unsafe",
                "headers.permissions_policy.missing",
                "headers.version_disclosure",
                "headers.cookie.missing_secure",
                "headers.cookie.missing_httponly",
                "headers.cookie.missing_samesite",
            }
        ),
    )

    async def gather(self, target: Target, ctx: CheckContext) -> HeadersObservation:
        try:
            r = await ctx.fetch(f"https://{target.name}/")
            return _observation(r, https=True, verified=True)
        except CertificateError:
            # The TLS check reports the certificate itself; here we still want the headers.
            r = await ctx.fetch(f"https://{target.name}/", verify_tls=False)
            return _observation(r, https=True, verified=False)
        except NetError:
            pass
        r = await ctx.fetch(f"http://{target.name}/")  # raises if neither works → check error
        return _observation(r, https=False, verified=False)

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        return analyze(await self.gather(target, ctx), target.name)


def analyze(obs: HeadersObservation, asset: str) -> list[Finding]:
    out: list[Finding] = []
    # Headers on a redirect to another site describe the redirect, not the real page.
    conf = Confidence.MEDIUM if obs.redirect_blocked_to else Confidence.HIGH

    def header_ev(name: str, value: str | None) -> list[Evidence]:
        summary = f"{name}: {value}" if value is not None else f"{name} header not present"
        return [
            Evidence(
                kind="http_header",
                summary=summary,
                data={"url": obs.url, "status": obs.status, "header": name, "value": value},
            )
        ]

    def add(
        ftype: str,
        title: str,
        sev: Severity,
        rkey: str,
        refs: list[Reference],
        header: str,
        value: str | None = None,
        *,
        disc: str = "",
        facts: dict[str, str | int | float | bool | list[str]] | None = None,
        confidence: Confidence | None = None,
    ) -> None:
        out.append(
            Finding(
                finding_type=ftype,
                title=title,
                severity=sev,
                confidence=confidence or conf,
                asset=asset,
                remediation_key=rkey,
                discriminator=disc,
                evidence=header_ev(header, value),
                references=refs,
                facts=facts or {},
            )
        )

    # --- HSTS (only meaningful over HTTPS) -------------------------------------------
    if obs.https:
        hsts = obs.get("strict-transport-security")
        if hsts is None:
            add(
                "headers.hsts.missing",
                "HSTS header missing",
                Severity.MEDIUM,
                "headers.add_hsts",
                [
                    cwe(319),
                    Reference(kind="url", id="MDN HSTS", url=MDN + "Strict-Transport-Security"),
                ],
                "strict-transport-security",
            )
        else:
            max_age, include_sub = _parse_hsts(hsts)
            if max_age is None or max_age < HSTS_MIN_MAX_AGE:
                add(
                    "headers.hsts.short_max_age",
                    "HSTS max-age is too short",
                    Severity.LOW,
                    "headers.add_hsts",
                    [cwe(319)],
                    "strict-transport-security",
                    hsts,
                    facts={
                        "max_age": max_age or 0,
                        "recommended_max_age": HSTS_MIN_MAX_AGE,
                        "include_subdomains": include_sub,
                    },
                )

    # --- CSP -------------------------------------------------------------------------
    csp = obs.get("content-security-policy")
    if csp is None:
        if obs.get("content-security-policy-report-only"):
            add(
                "headers.csp.report_only",
                "CSP is in report-only mode (not enforced)",
                Severity.INFO,
                "headers.add_csp",
                [cwe(693)],
                "content-security-policy-report-only",
                obs.get("content-security-policy-report-only"),
            )
        else:
            add(
                "headers.csp.missing",
                "Content-Security-Policy header missing",
                Severity.LOW,
                "headers.add_csp",
                [cwe(693), cwe(79)],
                "content-security-policy",
            )
    else:
        for weak in analyze_csp(parse_csp(csp)):
            add(
                f"headers.csp.{weak.kind}",
                f"Weak Content-Security-Policy: {weak.detail}",
                Severity.LOW,
                "headers.strengthen_csp",
                [cwe(693), cwe(79)],
                "content-security-policy",
                csp,
            )

    # --- Clickjacking: X-Frame-Options or CSP frame-ancestors ------------------------------
    frame_ancestors = csp is not None and parse_csp(csp).sources("frame-ancestors") is not None
    if obs.get("x-frame-options") is None and not frame_ancestors:
        add(
            "headers.clickjacking.missing",
            "No clickjacking protection",
            Severity.LOW,
            "headers.add_frame_protection",
            [cwe(1021)],
            "x-frame-options",
        )

    # --- X-Content-Type-Options --------------------------------------------------------
    xcto = obs.get("x-content-type-options")
    if xcto is None or xcto.strip().lower() != "nosniff":
        add(
            "headers.xcto.missing",
            "X-Content-Type-Options: nosniff missing",
            Severity.LOW,
            "headers.add_xcto",
            [cwe(693)],
            "x-content-type-options",
            xcto,
        )

    # --- Referrer-Policy --------------------------------------------------------------
    ref = obs.get("referrer-policy")
    if ref is None:
        add(
            "headers.referrer_policy.missing",
            "Referrer-Policy header missing",
            Severity.INFO,
            "headers.add_referrer_policy",
            [cwe(200)],
            "referrer-policy",
        )
    elif ref.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
        add(
            "headers.referrer_policy.unsafe",
            "Referrer-Policy leaks full URLs",
            Severity.LOW,
            "headers.add_referrer_policy",
            [cwe(200)],
            "referrer-policy",
            ref,
        )

    # --- Permissions-Policy --------------------------------------------------------------
    if obs.get("permissions-policy") is None:
        add(
            "headers.permissions_policy.missing",
            "Permissions-Policy header missing",
            Severity.INFO,
            "headers.add_permissions_policy",
            [cwe(693)],
            "permissions-policy",
        )

    # --- Version disclosure (Server, X-Powered-By) ----------------------------------------
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = obs.get(name)
        if value and _VERSION_IN_HEADER.search(value):
            add(
                "headers.version_disclosure",
                f"{name} header reveals software version",
                Severity.LOW,
                "headers.hide_version",
                [cwe(200)],
                name,
                value,
                disc=name,
                facts={"header": name, "software": value[:100]},
            )

    # --- Cookies ----------------------------------------------------------------------
    for raw in obs.get_all("set-cookie"):
        c = parse_set_cookie(raw)
        if not c.name:
            continue
        sessionish = bool(_SESSIONISH.search(c.name))
        cookie_facts: dict[str, str | int | float | bool | list[str]] = {
            "cookie": c.name,
            "looks_like_session": sessionish,
        }
        if obs.https and not c.secure:
            add(
                "headers.cookie.missing_secure",
                f"Cookie '{c.name}' lacks the Secure flag",
                Severity.MEDIUM if sessionish else Severity.LOW,
                "headers.cookie_flags",
                [cwe(614)],
                "set-cookie",
                raw,
                disc=c.name,
                facts=cookie_facts,
            )
        if not c.httponly:
            add(
                "headers.cookie.missing_httponly",
                f"Cookie '{c.name}' lacks the HttpOnly flag",
                Severity.MEDIUM if sessionish else Severity.INFO,
                "headers.cookie_flags",
                [cwe(1004)],
                "set-cookie",
                raw,
                disc=c.name,
                facts=cookie_facts,
                # Analytics cookies are often *meant* to be read by JS: lower confidence.
                confidence=Confidence.HIGH if sessionish else Confidence.MEDIUM,
            )
        if c.samesite is None:
            add(
                "headers.cookie.missing_samesite",
                f"Cookie '{c.name}' has no SameSite attribute",
                Severity.INFO,
                "headers.cookie_flags",
                [cwe(1275)],
                "set-cookie",
                raw,
                disc=c.name,
                facts=cookie_facts,
            )
    return out
