"""Domain ownership verification (DNS TXT record or HTTP file).

Same idea as Google Search Console: we give the org a random token, and they publish it
somewhere only the owner can write. Finding it proves control. The token must be
*unguessable* (192 random bits) but not secret: it is public once published.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel

from civicshield.config import Settings
from civicshield.engine.net import NetError, Scope
from civicshield.engine.net.factory import NetFactory
from civicshield.enums import DomainStatus, ScopeKind, VerificationMethod
from civicshield.models import Domain

DNS_LABEL = "_civicshield-verification"


class VerificationInstructions(BaseModel):
    method: VerificationMethod
    summary: str
    steps: list[str]
    record_name: str | None = None
    record_value: str | None = None
    file_url: str | None = None
    file_contents: str | None = None


def new_token() -> str:
    return secrets.token_urlsafe(24)


def scope_kind_for(method: VerificationMethod) -> ScopeKind:
    # What each method *proves* determines what it authorizes; see engine/net/scope.py.
    return ScopeKind.ZONE if method is VerificationMethod.DNS_TXT else ScopeKind.HOST_ONLY


def expected_value(domain: Domain, settings: Settings) -> str:
    return f"{settings.verification_txt_prefix}{domain.verification_token}"


def instructions(domain: Domain, settings: Settings) -> VerificationInstructions:
    value = expected_value(domain, settings)
    if domain.verification_method is VerificationMethod.DNS_TXT:
        name = f"{DNS_LABEL}.{domain.name}"
        return VerificationInstructions(
            method=domain.verification_method,
            summary="Add one TXT record in your DNS provider (where you manage your domain).",
            steps=[
                "Sign in to the company where you manage your domain's DNS "
                "(for example GoDaddy, Namecheap, Cloudflare, or Squarespace Domains).",
                "Open the DNS settings for your domain and choose 'Add record'.",
                f"Type: TXT. Name/Host: {DNS_LABEL} (some providers want the full name {name}).",
                f"Value: {value}",
                "Save. Changes can take a few minutes to an hour to appear, "
                "then click 'Check verification'.",
            ],
            record_name=name,
            record_value=value,
        )
    url = f"https://{domain.name}{settings.verification_file_path}"
    return VerificationInstructions(
        method=domain.verification_method,
        summary="Upload a small text file to your website.",
        steps=[
            "Create a plain text file named civicshield-verification.txt containing "
            "exactly the value below.",
            "Upload it so it's reachable at the address below (folder: /.well-known/).",
            "Open the address in your browser to confirm, then click 'Check verification'.",
            "Note: this method only covers this exact website address, not other subdomains.",
        ],
        file_url=url,
        file_contents=value,
    )


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    detail: str


async def check_dns_txt(
    domain: Domain, settings: Settings, net_factory: NetFactory
) -> VerificationResult:
    expected = expected_value(domain, settings)
    net = net_factory(Scope.of((domain.name, ScopeKind.ZONE)))
    try:
        answer = await net.dns.query(f"{DNS_LABEL}.{domain.name}", "TXT")
    except NetError as exc:
        return VerificationResult(False, f"DNS lookup failed, try again later ({exc})")
    finally:
        await net.aclose()
    if expected in (r.strip() for r in answer.records):
        return VerificationResult(True, "TXT record found")
    if answer.records:
        return VerificationResult(False, "a TXT record exists but its value doesn't match")
    return VerificationResult(False, f"no TXT record found at {DNS_LABEL}.{domain.name}")


async def check_http_file(
    domain: Domain, settings: Settings, net_factory: NetFactory
) -> VerificationResult:
    expected = expected_value(domain, settings)
    # The scope is only this host, so a redirect elsewhere is never followed and the
    # check fails. Otherwise a site could "verify" by redirecting to someone else's file.
    net = net_factory(Scope.of((domain.name, ScopeKind.HOST_ONLY)))
    try:
        errors: list[str] = []
        # HTTPS first; fall back to HTTP for sites with broken TLS (which we want to help).
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain.name}{settings.verification_file_path}"
            try:
                result = await net.http.fetch(url)
            except NetError as exc:
                errors.append(f"{scheme}: {exc}")
                continue
            first_lines = [line.strip() for line in result.body.splitlines()[:5]]
            if result.status == 200 and expected in first_lines:
                return VerificationResult(True, f"file found at {url}")
            errors.append(f"{scheme}: HTTP {result.status}, token not found")
        return VerificationResult(False, "; ".join(errors))
    finally:
        await net.aclose()


async def verify_domain(
    domain: Domain, settings: Settings, net_factory: NetFactory
) -> VerificationResult:
    """Run the domain's verification method and update its status (caller commits)."""
    check = (
        check_dns_txt
        if domain.verification_method is VerificationMethod.DNS_TXT
        else check_http_file
    )
    result = await check(domain, settings, net_factory)
    now = datetime.now(UTC)
    domain.last_checked_at = now
    if result.ok:
        domain.status = DomainStatus.VERIFIED
        domain.verified_at = now  # time of the most recent *successful* check
        domain.last_check_error = None
    else:
        # A previously verified domain that stops verifying is FAILED (scans paused);
        # one that never verified stays PENDING.
        if domain.status is DomainStatus.VERIFIED:
            domain.status = DomainStatus.FAILED
        domain.last_check_error = result.detail[:1000]
    return result
