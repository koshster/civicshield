"""HTTPS/TLS: certificate health, legacy protocols, weak ciphers, HTTP→HTTPS redirect.

Probe budget per host: 2 certificate handshakes (verified, then unverified only if
needed), 3 legacy-protocol ClientHellos and 5 weak-cipher ClientHellos, plus one HTTP
request. All go through the rate-limited Gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar, Literal

from civicshield.engine.checks.base import (
    CheckContext,
    CheckMeta,
    Evidence,
    Finding,
    Reference,
    Target,
    TargetKind,
    cwe,
    rfc,
)
from civicshield.engine.checks.tls.certinfo import CertSummary, summarize
from civicshield.engine.net import NetError, TargetUnreachableError
from civicshield.engine.net.tls_wire import COMPAT_SUITES, WEAK_SUITE_FAMILIES, TLSVersion
from civicshield.enums import Category, Confidence, Impact, Severity

RedirectState = Literal["https", "no_redirect", "http_unreachable"]

LEGACY_VERSIONS = (TLSVersion.SSL3, TLSVersion.TLS1_0, TLSVersion.TLS1_1)

# OpenSSL X509_V_ERR_* codes → our finding types. Expiry is judged from the dates
# directly (more precise, and works even when another error is reported first).
_SELF_SIGNED = {18, 19}
_UNTRUSTED = {2, 20, 21}
_HOSTNAME = {62}
_DATE_CODES = {9, 10}

_WEAK_CIPHER_SEVERITY = {
    "rc4": Severity.MEDIUM,
    "3des": Severity.LOW,
    "null": Severity.HIGH,
    "export": Severity.HIGH,
    "anonymous": Severity.HIGH,
}

Facts = dict[str, str | int | float | bool | list[str]]


@dataclass(frozen=True)
class TLSObservation:
    host: str
    https_reachable: bool
    cert: CertSummary | None = None
    verified: bool = False
    verify_code: int | None = None
    verify_message: str | None = None
    negotiated_protocol: str | None = None
    legacy_accepted: dict[str, bool] = field(default_factory=dict)  # "TLS 1.0" → accepted
    weak_ciphers_accepted: dict[str, bool] = field(default_factory=dict)  # "rc4" → accepted
    http_redirect: RedirectState = "http_unreachable"
    http_final_url: str | None = None


class TLSCheck:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="tls",
        version="1.0.0",
        name="HTTPS & TLS configuration",
        category=Category.TLS,
        impact=Impact.PASSIVE,
        target_kind=TargetKind.HOST,
        description="Certificate validity/expiry/strength, legacy TLS versions, weak "
        "ciphers, and whether plain HTTP redirects to HTTPS.",
        finding_types=frozenset(
            {
                "tls.https.unavailable",
                "tls.cert.expired",
                "tls.cert.expiring_soon",
                "tls.cert.not_yet_valid",
                "tls.cert.self_signed",
                "tls.cert.untrusted_chain",
                "tls.cert.hostname_mismatch",
                "tls.cert.invalid",
                "tls.cert.weak_key",
                "tls.cert.weak_signature",
                "tls.protocol.ssl3",
                "tls.protocol.tls10",
                "tls.protocol.tls11",
                "tls.cipher.rc4",
                "tls.cipher.3des",
                "tls.cipher.null",
                "tls.cipher.export",
                "tls.cipher.anonymous",
                "tls.redirect.missing",
            }
        ),
    )

    async def gather(self, target: Target, ctx: CheckContext) -> TLSObservation:
        host = target.name
        redirect, final_url = await _http_redirect_state(host, ctx)
        try:
            cert = await ctx.tls.fetch_certificate(host)
        except TargetUnreachableError:
            if redirect == "http_unreachable":
                raise  # neither HTTP nor HTTPS answered → "couldn't check", not "all good"
            return TLSObservation(
                host, https_reachable=False, http_redirect=redirect, http_final_url=final_url
            )

        legacy: dict[str, bool] = {}
        for version in LEGACY_VERSIONS:
            try:
                reply = await ctx.tls.probe(host, version, COMPAT_SUITES)
                legacy[version.label] = reply.accepted
            except NetError:
                continue  # unknown → no claim either way
        weak: dict[str, bool] = {}
        for family, suites in WEAK_SUITE_FAMILIES.items():
            try:
                weak[family] = (await ctx.tls.probe(host, TLSVersion.TLS1_2, suites)).accepted
            except NetError:
                continue
        return TLSObservation(
            host=host,
            https_reachable=True,
            cert=summarize(cert.leaf_der) if cert.leaf_der else None,
            verified=cert.verified,
            verify_code=cert.verify_code,
            verify_message=cert.verify_message,
            negotiated_protocol=cert.protocol,
            legacy_accepted=legacy,
            weak_ciphers_accepted=weak,
            http_redirect=redirect,
            http_final_url=final_url,
        )

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        return analyze(await self.gather(target, ctx), ctx.now())


async def _http_redirect_state(host: str, ctx: CheckContext) -> tuple[RedirectState, str | None]:
    try:
        result = await ctx.fetch(f"http://{host}/")
    except NetError:
        return "http_unreachable", None
    final = result.redirect_blocked_to or result.url
    return ("https" if final.startswith("https://") else "no_redirect"), final


def _cert_evidence(obs: TLSObservation) -> list[Evidence]:
    c = obs.cert
    data: dict[str, object] = {
        "host": obs.host,
        "verified": obs.verified,
        "verify_code": obs.verify_code,
        "verify_message": obs.verify_message,
    }
    if c:
        data |= {
            "subject_cn": c.subject_cn,
            "issuer_cn": c.issuer_cn,
            "sans": list(c.sans),
            "not_before": c.not_before.isoformat(),
            "not_after": c.not_after.isoformat(),
            "key": f"{c.key_type}-{c.key_bits}",
            "signature_hash": c.signature_hash,
        }
    summary = (
        f"certificate for {c.subject_cn or obs.host} issued by {c.issuer_cn}, "
        f"valid until {c.not_after:%Y-%m-%d}"
        if c
        else "no certificate retrieved"
    )
    if obs.verify_message:
        summary += f"; verification failed: {obs.verify_message}"
    return [Evidence(kind="certificate", summary=summary, data=data)]


def analyze(obs: TLSObservation, now: datetime) -> list[Finding]:
    out: list[Finding] = []
    host = obs.host

    def add(
        ftype: str,
        title: str,
        sev: Severity,
        rkey: str,
        refs: list[Reference],
        evidence: list[Evidence],
        *,
        conf: Confidence = Confidence.HIGH,
        facts: Facts | None = None,
    ) -> None:
        out.append(
            Finding(
                finding_type=ftype,
                title=title,
                severity=sev,
                confidence=conf,
                asset=host,
                remediation_key=rkey,
                evidence=evidence,
                references=refs,
                facts=facts or {},
            )
        )

    # --- No HTTPS at all ---------------------------------------------------------------
    if not obs.https_reachable:
        add(
            "tls.https.unavailable",
            "Website is not available over HTTPS",
            Severity.HIGH,
            "tls.enable_https",
            [cwe(319)],
            [
                Evidence(
                    kind="tls_probe",
                    summary=f"could not connect to {host}:443",
                    data={"http_final_url": obs.http_final_url},
                )
            ],
        )
        return out

    # --- Certificate ---------------------------------------------------------------------
    cev = _cert_evidence(obs)
    c = obs.cert
    if c is not None:
        days_left = (c.not_after - now).days
        date_facts: Facts = {
            "not_after": c.not_after.date().isoformat(),
            "days_to_expiry": days_left,
        }
        if now > c.not_after:
            add(
                "tls.cert.expired",
                "TLS certificate has expired",
                Severity.HIGH,
                "tls.renew_certificate",
                [cwe(298)],
                cev,
                facts=date_facts,
            )
        elif now < c.not_before:
            add(
                "tls.cert.not_yet_valid",
                "TLS certificate is not valid yet",
                Severity.HIGH,
                "tls.renew_certificate",
                [cwe(298)],
                cev,
                facts=date_facts,
            )
        elif days_left <= 30:
            sev = (
                Severity.HIGH
                if days_left <= 7
                else Severity.MEDIUM
                if days_left <= 14
                else Severity.LOW
            )
            add(
                "tls.cert.expiring_soon",
                f"TLS certificate expires in {days_left} days",
                sev,
                "tls.renew_certificate",
                [cwe(298)],
                cev,
                facts=date_facts,
            )
        if (c.key_type == "RSA" and c.key_bits < 2048) or c.key_type == "DSA":
            add(
                "tls.cert.weak_key",
                f"Weak certificate key ({c.key_type}-{c.key_bits})",
                Severity.MEDIUM,
                "tls.replace_certificate",
                [cwe(326)],
                cev,
                facts={"key_type": c.key_type, "key_bits": c.key_bits},
            )
        if c.signature_hash in {"md5", "sha1"} and not c.self_issued:
            add(
                "tls.cert.weak_signature",
                f"Certificate signed with obsolete {c.signature_hash.upper()}",
                Severity.MEDIUM,
                "tls.replace_certificate",
                [cwe(327)],
                cev,
                facts={"signature_hash": c.signature_hash},
            )

    if not obs.verified and obs.verify_code not in _DATE_CODES:
        code = obs.verify_code
        if code in _SELF_SIGNED:
            add(
                "tls.cert.self_signed",
                "Certificate is self-signed (browsers will warn)",
                Severity.HIGH,
                "tls.replace_certificate",
                [cwe(295)],
                cev,
            )
        elif code in _HOSTNAME:
            add(
                "tls.cert.hostname_mismatch",
                "Certificate does not match the website's name",
                Severity.HIGH,
                "tls.replace_certificate",
                [cwe(297)],
                cev,
                facts={"names_on_cert": list(c.sans) if c else []},
            )
        elif code in _UNTRUSTED:
            # Either an incomplete chain (server forgot the intermediate) or an unknown
            # CA. We can't distinguish them with Python 3.12's ssl API, hence MEDIUM.
            add(
                "tls.cert.untrusted_chain",
                "Certificate chain is incomplete or from an untrusted issuer",
                Severity.HIGH,
                "tls.fix_certificate_chain",
                [cwe(295)],
                cev,
                conf=Confidence.MEDIUM,
            )
        else:
            add(
                "tls.cert.invalid",
                "TLS certificate failed validation",
                Severity.HIGH,
                "tls.replace_certificate",
                [cwe(295)],
                cev,
                conf=Confidence.MEDIUM,
                facts={"reason": (obs.verify_message or "unknown")[:120]},
            )

    # --- Legacy protocols -----------------------------------------------------------------
    legacy_types = {
        "SSL 3.0": ("tls.protocol.ssl3", Severity.HIGH),
        "TLS 1.0": ("tls.protocol.tls10", Severity.MEDIUM),
        "TLS 1.1": ("tls.protocol.tls11", Severity.MEDIUM),
    }
    for label, accepted in obs.legacy_accepted.items():
        if accepted and label in legacy_types:
            ftype, sev = legacy_types[label]
            add(
                ftype,
                f"Server still accepts {label}",
                sev,
                "tls.disable_legacy_protocols",
                [cwe(327), rfc(8996)],
                [
                    Evidence(
                        kind="tls_probe",
                        summary=f"server answered a {label} ClientHello with a ServerHello",
                        data={"host": host, "version": label},
                    )
                ],
                facts={"protocol": label},
            )

    # --- Weak cipher families -----------------------------------------------------------
    for family, accepted in obs.weak_ciphers_accepted.items():
        if accepted:
            add(
                f"tls.cipher.{family}",
                f"Server accepts {family.upper()} cipher suites",
                _WEAK_CIPHER_SEVERITY[family],
                "tls.disable_weak_ciphers",
                [cwe(327)],
                [
                    Evidence(
                        kind="tls_probe",
                        summary=f"server selected a {family} cipher "
                        "when only those were offered (TLS 1.2)",
                        data={"host": host, "family": family},
                    )
                ],
                facts={"cipher_family": family},
            )

    # --- HTTP → HTTPS ---------------------------------------------------------------------
    if obs.http_redirect == "no_redirect":
        add(
            "tls.redirect.missing",
            "Plain HTTP does not redirect to HTTPS",
            Severity.MEDIUM,
            "tls.redirect_http_to_https",
            [cwe(319)],
            [
                Evidence(
                    kind="http_response",
                    summary=f"http://{host}/ ended at "
                    f"{obs.http_final_url} without switching to HTTPS",
                    data={"final_url": obs.http_final_url},
                )
            ],
        )
    return out
