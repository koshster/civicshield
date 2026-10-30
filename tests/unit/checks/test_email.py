import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hypothesis import given
from hypothesis import strategies as st

from civicshield.engine.checks.base import Target, TargetKind
from civicshield.engine.checks.email import EmailSecurityCheck
from civicshield.engine.checks.email.dkim import candidate_selectors, detect_providers, parse_dkim
from civicshield.engine.checks.email.dmarc import parse_dmarc
from civicshield.engine.checks.email.spf import evaluate_tree, parse_spf
from civicshield.engine.net.dns import FakeResolver
from civicshield.enums import Confidence, Severity
from tests.helpers.net import make_ctx

D = "example.org"


def dkim_record(bits: int) -> str:
    key = rsa.generate_private_key(65537, bits).public_key()
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


GOOD_DKIM = dkim_record(2048)


async def run(records: dict[tuple[str, str], list[str]]) -> dict[str, Any]:
    findings = await EmailSecurityCheck().run(Target(TargetKind.ZONE, D), make_ctx(records))
    return {f.finding_type: f for f in findings}


def good() -> dict[tuple[str, str], list[str]]:
    return {
        (D, "MX"): ["1 aspmx.l.google.com"],
        (D, "TXT"): ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"],
        ("_spf.google.com", "TXT"): ["v=spf1 ip4:203.0.113.0/24 ~all"],
        (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.org"],
        (f"google._domainkey.{D}", "TXT"): [GOOD_DKIM],
    }


# --- end to end through FakeResolver ----------------------------------------------------
async def test_well_configured_domain_is_clean() -> None:
    assert await run(good()) == {}


async def test_nothing_configured() -> None:
    f = await run({(D, "MX"): ["10 mail.example.org"]})
    assert set(f) == {"email.spf.missing", "email.dmarc.missing", "email.dkim.not_found"}
    assert f["email.spf.missing"].severity is Severity.HIGH
    assert f["email.dkim.not_found"].confidence is Confidence.LOW


async def test_non_mail_domain_gets_lockdown_advice_and_no_dkim_finding() -> None:
    f = await run({(D, "A"): ["93.184.216.34"]})
    assert f["email.spf.missing"].remediation_key == "email.lock_down_no_mail"
    assert f["email.spf.missing"].severity is Severity.MEDIUM
    assert "email.dkim.not_found" not in f
    # One coherent task: DMARC must not say "start at p=none" while SPF says lock down.
    assert f["email.dmarc.missing"].remediation_key == "email.lock_down_no_mail"


async def test_dmarc_missing_on_a_sending_domain_gets_normal_dmarc_advice() -> None:
    f = await run({(D, "TXT"): ["v=spf1 include:_spf.google.com -all"]})
    assert f["email.dmarc.missing"].remediation_key == "email.add_dmarc"
    f = await run({(D, "MX"): ["10 mail.example.org"]})
    assert f["email.dmarc.missing"].remediation_key == "email.add_dmarc"


async def test_spf_all_qualifiers() -> None:
    rec = good()
    rec[(D, "TXT")] = ["v=spf1 include:_spf.google.com +all"]
    assert (await run(rec))["email.spf.pass_all"].severity is Severity.CRITICAL
    rec[(D, "TXT")] = ["v=spf1 include:_spf.google.com"]
    assert "email.spf.neutral_all" in await run(rec)
    rec[(D, "TXT")] = ["v=spf1 include:_spf.google.com ~all"]
    assert await run(rec) == {}


async def test_multiple_spf_records() -> None:
    rec = good()
    rec[(D, "TXT")] = ["v=spf1 -all", "v=spf1 include:_spf.google.com -all"]
    assert "email.spf.multiple" in await run(rec)


async def test_spf_lookup_limit_counts_nested_includes() -> None:
    rec = good()
    includes = " ".join(f"include:s{i}.example.net" for i in range(4))
    rec[(D, "TXT")] = [f"v=spf1 {includes} -all"]
    for i in range(4):  # each include itself does 2 more lookups → 4 + 4*2 = 12
        rec[(f"s{i}.example.net", "TXT")] = ["v=spf1 a mx -all"]
    f = await run(rec)
    assert f["email.spf.too_many_lookups"].facts["lookups"] == 12


async def test_spf_missing_include_and_void_lookups() -> None:
    rec = good()
    rec[(D, "TXT")] = [
        "v=spf1 include:gone1.example.net include:gone2.example.net include:gone3.example.net -all"
    ]
    f = await run(rec)
    assert f["email.spf.too_many_void_lookups"].facts["void_lookups"] == 3
    assert "email.spf.include_missing" in f


async def test_dmarc_variants() -> None:
    rec = good()
    rec[(f"_dmarc.{D}", "TXT")] = ["v=DMARC1; p=none; rua=mailto:a@example.org"]
    assert set(await run(rec)) == {"email.dmarc.policy_none"}
    rec[(f"_dmarc.{D}", "TXT")] = ["v=DMARC1; p=quarantine; pct=25; sp=none"]
    assert set(await run(rec)) == {
        "email.dmarc.partial_pct",
        "email.dmarc.weak_subdomain_policy",
        "email.dmarc.no_reporting",
    }
    rec[(f"_dmarc.{D}", "TXT")] = ["v=DMARC1; p=bogus"]
    assert set(await run(rec)) == {"email.dmarc.invalid"}


async def test_weak_dkim_key() -> None:
    rec = good()
    rec[(f"google._domainkey.{D}", "TXT")] = [dkim_record(1024)]
    f = await run(rec)
    assert f["email.dkim.weak_key"].severity is Severity.LOW
    assert f["email.dkim.weak_key"].facts["key_bits"] == 1024


async def test_microsoft_selectors_inferred_from_mx() -> None:
    rec = good()
    rec[(D, "MX")] = ["0 example-org.mail.protection.outlook.com"]
    rec[(D, "TXT")] = ["v=spf1 include:spf.protection.outlook.com -all"]
    rec[("spf.protection.outlook.com", "TXT")] = ["v=spf1 ip4:40.92.0.0/15 -all"]
    del rec[(f"google._domainkey.{D}", "TXT")]
    rec[(f"selector1._domainkey.{D}", "TXT")] = [GOOD_DKIM]
    f = await run(rec)
    assert "email.dkim.not_found" not in f


# --- parser units -------------------------------------------------------------------------
def test_spf_parser() -> None:
    r = parse_spf("v=spf1 a/24 mx ip4:192.0.2.0/24 ?include:x.org redirect=y.org exp=z.org -all")
    assert [(t.qualifier, t.mechanism) for t in r.terms] == [
        ("+", "a"),
        ("+", "mx"),
        ("+", "ip4"),
        ("?", "include"),
        ("-", "all"),
    ]
    assert r.redirect == "y.org" and r.errors == ()
    assert parse_spf("v=spf1 bogus:x -all").errors == ("unknown mechanism 'bogus:x'",)


async def test_spf_include_loop_detected() -> None:
    dns = FakeResolver(
        {
            ("a.org", "TXT"): ["v=spf1 include:b.org -all"],
            ("b.org", "TXT"): ["v=spf1 include:a.org -all"],
        }
    )
    tree = await evaluate_tree(dns, parse_spf("v=spf1 include:a.org -all"))
    assert any("loop" in e for e in tree.errors)


@pytest.mark.parametrize(
    "raw, valid, policy, pct",
    [
        ("v=DMARC1; p=reject", True, "reject", 100),
        ("v=DMARC1;p=quarantine;pct=50", True, "quarantine", 50),
        ("p=reject; v=DMARC1", False, "reject", 100),
        ("v=DMARC1; rua=mailto:x@y", False, None, 100),
    ],
)
def test_dmarc_parser(raw: str, valid: bool, policy: str | None, pct: int) -> None:
    rec = parse_dmarc(raw)
    assert (rec.valid, rec.policy, rec.pct) == (valid, policy, pct)


def test_dkim_parser_revoked_and_garbage() -> None:
    revoked = parse_dkim("s", "v=DKIM1; p=")
    assert revoked and revoked.revoked
    garbage = parse_dkim("s", "v=DKIM1; p=!!notbase64")
    assert garbage and garbage.bits is None
    assert parse_dkim("s", "not a dkim record") is None


def test_provider_detection() -> None:
    providers = detect_providers(["aspmx.l.google.com"], ["servers.mcsv.net"])
    assert providers == ["Google Workspace", "Mailchimp"]
    assert candidate_selectors(providers)[:4] == ["google", "k1", "k2", "k3"]


@given(st.text(max_size=200))
def test_parsers_never_crash(raw: str) -> None:
    parse_spf("v=spf1 " + raw)
    parse_dmarc(raw)
    parse_dkim("s", raw)
