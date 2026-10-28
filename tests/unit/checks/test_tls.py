from datetime import UTC, datetime, timedelta
from typing import Any, cast

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes

from civicshield.engine.checks.base import Target, TargetKind
from civicshield.engine.checks.tls import TLSCheck
from civicshield.engine.checks.tls.certinfo import CertSummary, summarize
from civicshield.engine.checks.tls.check import TLSObservation, analyze
from civicshield.engine.net import TargetUnreachableError
from civicshield.engine.net.tls import CertFetch, TLSProber
from civicshield.engine.net.tls_wire import ProbeReply, TLSVersion
from civicshield.enums import Confidence, Severity
from tests.helpers.certs import make_cert
from tests.helpers.net import IP, make_ctx

NOW = datetime(2026, 10, 28, tzinfo=UTC)


def cert(
    days_left: int = 90, key_type: str = "EC", bits: int = 256, sig: str = "sha256"
) -> CertSummary:
    return CertSummary(
        "example.org",
        "R11",
        ("example.org",),
        NOW - timedelta(days=30),
        NOW + timedelta(days=days_left),
        key_type,
        bits,
        sig,
        False,
    )


def obs(**kw: Any) -> TLSObservation:
    base: dict[str, Any] = dict(
        host="example.org",
        https_reachable=True,
        cert=cert(),
        verified=True,
        http_redirect="https",
        legacy_accepted={"SSL 3.0": False, "TLS 1.0": False, "TLS 1.1": False},
        weak_ciphers_accepted={"rc4": False, "3des": False},
    )
    return TLSObservation(**(base | kw))


def types(findings: list[Any]) -> set[str]:
    return {f.finding_type for f in findings}


def test_healthy_site_has_no_findings() -> None:
    assert analyze(obs(), NOW) == []


@pytest.mark.parametrize(
    "days, severity",
    [
        (31, None),
        (30, Severity.LOW),
        (14, Severity.MEDIUM),
        (7, Severity.HIGH),
        (0, Severity.HIGH),
    ],
)
def test_expiry_thresholds(days: int, severity: Severity | None) -> None:
    found = [
        f for f in analyze(obs(cert=cert(days)), NOW) if f.finding_type == "tls.cert.expiring_soon"
    ]
    assert (found[0].severity if found else None) == severity
    if found:
        assert found[0].facts["days_to_expiry"] == days


def test_expired_reported_once_even_with_verify_code() -> None:
    f = analyze(
        obs(
            cert=cert(-3), verified=False, verify_code=10, verify_message="certificate has expired"
        ),
        NOW,
    )
    assert types(f) == {"tls.cert.expired"}


@pytest.mark.parametrize(
    "code, ftype",
    [
        (18, "tls.cert.self_signed"),
        (19, "tls.cert.self_signed"),
        (62, "tls.cert.hostname_mismatch"),
        (20, "tls.cert.untrusted_chain"),
        (99, "tls.cert.invalid"),
    ],
)
def test_verification_failures(code: int, ftype: str) -> None:
    assert types(analyze(obs(verified=False, verify_code=code), NOW)) == {ftype}


def test_untrusted_chain_is_medium_confidence() -> None:
    (f,) = analyze(obs(verified=False, verify_code=20), NOW)
    assert f.confidence is Confidence.MEDIUM


def test_weak_key_and_signature() -> None:
    found = types(analyze(obs(cert=cert(key_type="RSA", bits=1024, sig="sha1")), NOW))
    assert found == {"tls.cert.weak_key", "tls.cert.weak_signature"}


def test_legacy_protocols_and_ciphers() -> None:
    f = analyze(
        obs(
            legacy_accepted={"TLS 1.0": True, "TLS 1.1": True},
            weak_ciphers_accepted={"3des": True, "export": True},
        ),
        NOW,
    )
    by = {x.finding_type: x.severity for x in f}
    assert by == {
        "tls.protocol.tls10": Severity.MEDIUM,
        "tls.protocol.tls11": Severity.MEDIUM,
        "tls.cipher.3des": Severity.LOW,
        "tls.cipher.export": Severity.HIGH,
    }


def test_no_https_and_missing_redirect() -> None:
    assert types(
        analyze(obs(https_reachable=False, cert=None, http_redirect="no_redirect"), NOW)
    ) == {"tls.https.unavailable"}
    assert types(analyze(obs(http_redirect="no_redirect"), NOW)) == {"tls.redirect.missing"}


def test_summarize_real_certificate() -> None:
    bundle = make_cert(["example.org", "www.example.org"], rsa_bits=2048, hash_alg=hashes.SHA256())
    s = summarize(bundle.der)
    assert s.sans == ("example.org", "www.example.org")
    assert (s.key_type, s.key_bits, s.signature_hash) == ("RSA", 2048, "sha256")
    assert s.self_issued


# --- gather(): stub prober, mocked HTTP ------------------------------------------------
class StubProber:
    def __init__(self, cert_fetch: CertFetch | None, accepts: set[int]) -> None:
        self.cert_fetch = cert_fetch
        self.accepts = accepts
        self.probes: list[TLSVersion] = []

    async def fetch_certificate(self, host: str, port: int = 443) -> CertFetch:
        if self.cert_fetch is None:
            raise TargetUnreachableError("refused")
        return self.cert_fetch

    async def probe(
        self, host: str, version: TLSVersion, suites: tuple[int, ...], port: int = 443
    ) -> ProbeReply:
        self.probes.append(version)
        return ProbeReply(version in self.accepts and 0x000A not in suites)


@respx.mock
async def test_gather_end_to_end_with_stubs() -> None:
    respx.get(f"http://{IP}/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://example.org/"})
    )
    respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200))
    der = make_cert(["example.org"], not_after=datetime.now(UTC) + timedelta(days=5)).der
    ctx = make_ctx()
    ctx.tls = cast(
        TLSProber,
        StubProber(
            CertFetch(der, True, None, None, "TLSv1.3", "x"),
            accepts={TLSVersion.TLS1_0, TLSVersion.TLS1_2},
        ),
    )
    findings = await TLSCheck().run(Target(TargetKind.HOST, "example.org"), ctx)
    found = types(findings)
    assert "tls.cert.expiring_soon" in found and "tls.protocol.tls10" in found
    assert "tls.redirect.missing" not in found
    assert "tls.cipher.rc4" in found  # stub accepts any TLS 1.2 offer without 3DES


@respx.mock
async def test_gather_raises_when_nothing_answers() -> None:
    respx.get(f"http://{IP}/").mock(side_effect=httpx.ConnectError("refused"))
    ctx = make_ctx()
    ctx.tls = cast(TLSProber, StubProber(None, set()))
    with pytest.raises(TargetUnreachableError):
        await TLSCheck().run(Target(TargetKind.HOST, "example.org"), ctx)
