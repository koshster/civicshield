"""Email authentication: can someone send email pretending to be this organization?

For a nonprofit this is often the single most important check. Without an enforced DMARC
policy, an attacker can email donors "from" the executive director with new bank details.
The check is entirely DNS lookups through our own resolver; it sends nothing to the
org's servers.
"""

from __future__ import annotations

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
    rfc,
)
from civicshield.engine.checks.email.dkim import (
    DKIMKey,
    candidate_selectors,
    detect_providers,
    parse_dkim,
)
from civicshield.engine.checks.email.dmarc import DMARCRecord, is_dmarc, parse_dmarc
from civicshield.engine.checks.email.spf import (
    MAX_DNS_LOOKUPS,
    MAX_VOID_LOOKUPS,
    SPFRecord,
    SPFTreeResult,
    evaluate_tree,
    is_spf,
    parse_spf,
)
from civicshield.engine.net import NetError
from civicshield.enums import Category, Confidence, Impact, Severity

Facts = dict[str, str | int | float | bool | list[str]]


@dataclass(frozen=True)
class EmailObservation:
    domain: str
    mx_hosts: list[str]
    spf_records: list[str]
    spf_tree: SPFTreeResult | None
    dmarc_records: list[str]
    dkim_keys: list[DKIMKey]
    selectors_tried: list[str]
    providers: list[str] = field(default_factory=list)


class EmailSecurityCheck:
    meta: ClassVar[CheckMeta] = CheckMeta(
        id="email",
        version="1.0.0",
        name="Email spoofing protection (SPF, DKIM, DMARC)",
        category=Category.EMAIL,
        impact=Impact.PASSIVE,
        target_kind=TargetKind.ZONE,
        description="Reads MX, SPF, DMARC and DKIM records to judge whether others can "
        "send email that appears to come from this domain.",
        finding_types=frozenset(
            {
                "email.spf.missing",
                "email.spf.multiple",
                "email.spf.syntax_error",
                "email.spf.pass_all",
                "email.spf.neutral_all",
                "email.spf.too_many_lookups",
                "email.spf.too_many_void_lookups",
                "email.spf.include_missing",
                "email.spf.ptr",
                "email.dmarc.missing",
                "email.dmarc.multiple",
                "email.dmarc.invalid",
                "email.dmarc.policy_none",
                "email.dmarc.partial_pct",
                "email.dmarc.weak_subdomain_policy",
                "email.dmarc.no_reporting",
                "email.dkim.not_found",
                "email.dkim.weak_key",
            }
        ),
    )

    async def gather(self, target: Target, ctx: CheckContext) -> EmailObservation:
        domain = target.name
        mx = await ctx.dns.query(domain, "MX")
        # "0 ." is a null MX (RFC 7505): the domain explicitly receives no mail.
        mx_hosts = [
            r.split(" ", 1)[1]
            for r in mx.records
            if " " in r and r.split(" ", 1)[1] not in {"", "."}
        ]
        txt = await ctx.dns.query(domain, "TXT")
        spf_records = [r for r in txt.records if is_spf(r)]
        tree = (
            await evaluate_tree(ctx.dns, parse_spf(spf_records[0]))
            if len(spf_records) == 1
            else None
        )
        dmarc_answer = await ctx.dns.query(f"_dmarc.{domain}", "TXT")
        dmarc_records = [r for r in dmarc_answer.records if is_dmarc(r)]

        providers = detect_providers(mx_hosts, tree.includes if tree else [])
        selectors = candidate_selectors(providers)
        keys: list[DKIMKey] = []
        for sel in selectors:
            try:
                answer = await ctx.dns.query(f"{sel}._domainkey.{domain}", "TXT")
            except NetError:
                continue
            for rec in answer.records:
                key = parse_dkim(sel, rec)
                if key:
                    keys.append(key)
        return EmailObservation(
            domain, mx_hosts, spf_records, tree, dmarc_records, keys, selectors, providers
        )

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]:
        return analyze(await self.gather(target, ctx))


def analyze(obs: EmailObservation) -> list[Finding]:
    out: list[Finding] = []
    d = obs.domain
    receives_mail = bool(obs.mx_hosts)
    base_facts: Facts = {"has_mx": receives_mail, "email_providers": obs.providers}

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
        disc: str = "",
    ) -> None:
        out.append(
            Finding(
                finding_type=ftype,
                title=title,
                severity=sev,
                confidence=conf,
                asset=d,
                remediation_key=rkey,
                evidence=evidence,
                references=refs,
                facts=base_facts | (facts or {}),
                discriminator=disc,
            )
        )

    def dns_ev(name: str, rtype: str, records: list[str]) -> list[Evidence]:
        summary = (
            (f"{rtype} {name}: " + " | ".join(records))
            if records
            else (f"no {rtype} record at {name}")
        )
        return [
            Evidence(
                kind="dns_record",
                summary=summary[:500],
                data={"name": name, "type": rtype, "records": records},
            )
        ]

    # --- SPF --------------------------------------------------------------------------
    spf_ev = dns_ev(d, "TXT", obs.spf_records)
    spf_refs = [rfc(7208), cwe(290)]
    if not obs.spf_records:
        # A domain that sends no mail should still publish "v=spf1 -all" so it can't be
        # spoofed; that's a different (easier) fix, picked by the remediation key.
        add(
            "email.spf.missing",
            "No SPF record",
            Severity.HIGH if receives_mail else Severity.MEDIUM,
            "email.add_spf" if receives_mail else "email.lock_down_no_mail",
            spf_refs,
            spf_ev,
        )
    elif len(obs.spf_records) > 1:
        add(
            "email.spf.multiple",
            "Multiple SPF records (SPF is broken)",
            Severity.HIGH,
            "email.merge_spf",
            [rfc(7208, "3.2")],
            spf_ev,
            facts={"record_count": len(obs.spf_records)},
        )
    else:
        spf: SPFRecord = parse_spf(obs.spf_records[0])
        if spf.errors:
            add(
                "email.spf.syntax_error",
                "SPF record has syntax errors",
                Severity.HIGH,
                "email.fix_spf_syntax",
                spf_refs,
                spf_ev,
                facts={"errors": list(spf.errors)[:5]},
            )
        q = spf.all_qualifier
        if q == "+":
            add(
                "email.spf.pass_all",
                "SPF allows anyone to send as this domain (+all)",
                Severity.CRITICAL,
                "email.fix_spf_all",
                spf_refs,
                spf_ev,
                facts={"all_qualifier": "+all"},
            )
        elif q == "?" or (q is None and spf.redirect is None):
            add(
                "email.spf.neutral_all",
                "SPF does not reject unauthorized senders",
                Severity.MEDIUM,
                "email.fix_spf_all",
                spf_refs,
                spf_ev,
                facts={"all_qualifier": f"{q}all" if q else "none"},
            )
        tree = obs.spf_tree
        if tree:
            if tree.lookups > MAX_DNS_LOOKUPS:
                add(
                    "email.spf.too_many_lookups",
                    f"SPF needs {tree.lookups} DNS lookups (limit {MAX_DNS_LOOKUPS})",
                    Severity.HIGH,
                    "email.flatten_spf",
                    [rfc(7208, "4.6.4")],
                    spf_ev,
                    facts={
                        "lookups": tree.lookups,
                        "limit": MAX_DNS_LOOKUPS,
                        "includes": tree.includes[:15],
                    },
                )
            if tree.void_lookups > MAX_VOID_LOOKUPS:
                add(
                    "email.spf.too_many_void_lookups",
                    "SPF references domains that don't exist",
                    Severity.MEDIUM,
                    "email.fix_spf_includes",
                    [rfc(7208, "4.6.4")],
                    spf_ev,
                    facts={"void_lookups": tree.void_lookups},
                )
            for missing in tree.missing_includes:
                add(
                    "email.spf.include_missing",
                    f"SPF include '{missing}' has no valid SPF record",
                    Severity.MEDIUM,
                    "email.fix_spf_includes",
                    spf_refs,
                    spf_ev,
                    disc=missing,
                    facts={"include": missing},
                )
            if tree.uses_ptr:
                add(
                    "email.spf.ptr",
                    "SPF uses the deprecated 'ptr' mechanism",
                    Severity.LOW,
                    "email.fix_spf_syntax",
                    [rfc(7208, "5.5")],
                    spf_ev,
                )

    # --- DMARC --------------------------------------------------------------------------
    dmarc_name = f"_dmarc.{d}"
    dmarc_ev = dns_ev(dmarc_name, "TXT", obs.dmarc_records)
    dmarc_refs = [rfc(7489), cwe(290)]
    if not obs.dmarc_records:
        add(
            "email.dmarc.missing",
            "No DMARC policy: others can send email as this domain",
            Severity.HIGH,
            "email.add_dmarc",
            dmarc_refs,
            dmarc_ev,
        )
    elif len(obs.dmarc_records) > 1:
        add(
            "email.dmarc.multiple",
            "Multiple DMARC records (receivers ignore DMARC)",
            Severity.HIGH,
            "email.fix_dmarc",
            dmarc_refs,
            dmarc_ev,
        )
    else:
        dm: DMARCRecord = parse_dmarc(obs.dmarc_records[0])
        if not dm.valid:
            add(
                "email.dmarc.invalid",
                "DMARC record is invalid",
                Severity.HIGH,
                "email.fix_dmarc",
                dmarc_refs,
                dmarc_ev,
                facts={"error": dm.error or ""},
            )
        else:
            pol_facts: Facts = {
                "policy": dm.policy or "",
                "pct": dm.pct,
                "subdomain_policy": dm.subdomain_policy or "",
            }
            if dm.policy == "none":
                add(
                    "email.dmarc.policy_none",
                    "DMARC is monitor-only (p=none): spoofed email is still delivered",
                    Severity.MEDIUM,
                    "email.enforce_dmarc",
                    dmarc_refs,
                    dmarc_ev,
                    facts=pol_facts,
                )
            else:
                if dm.pct < 100:
                    add(
                        "email.dmarc.partial_pct",
                        f"DMARC policy applies to only {dm.pct}% of email",
                        Severity.LOW,
                        "email.enforce_dmarc",
                        dmarc_refs,
                        dmarc_ev,
                        facts=pol_facts,
                    )
                if dm.subdomain_policy == "none":
                    add(
                        "email.dmarc.weak_subdomain_policy",
                        "Subdomains are not protected by DMARC (sp=none)",
                        Severity.LOW,
                        "email.enforce_dmarc",
                        dmarc_refs,
                        dmarc_ev,
                        facts=pol_facts,
                    )
            if not dm.rua:
                add(
                    "email.dmarc.no_reporting",
                    "DMARC has no reporting address (rua)",
                    Severity.INFO,
                    "email.add_dmarc_reporting",
                    dmarc_refs,
                    dmarc_ev,
                )

    # --- DKIM ---------------------------------------------------------------------------
    # A domain "sends mail" if it receives mail or its SPF authorizes any sender at all
    # ("v=spf1 -all" alone means "this domain never sends", so DKIM isn't expected).
    spf_authorizes_senders = len(obs.spf_records) == 1 and any(
        t.mechanism != "all" for t in parse_spf(obs.spf_records[0]).terms
    )
    sends_mail = receives_mail or spf_authorizes_senders
    live_keys = [k for k in obs.dkim_keys if not k.revoked]
    if sends_mail and not live_keys:
        add(
            "email.dkim.not_found",
            "No DKIM signing key found",
            Severity.MEDIUM,
            "email.enable_dkim",
            [rfc(6376)],
            [
                Evidence(
                    kind="dns_record",
                    summary="no DKIM key at common or provider-specific "
                    f"selectors ({', '.join(obs.selectors_tried)})",
                    data={"selectors_tried": obs.selectors_tried},
                )
            ],
            # We can only guess selector names, so "not found" ≠ "doesn't exist".
            conf=Confidence.LOW,
            facts={"selectors_tried": obs.selectors_tried},
        )
    for key in live_keys:
        if key.key_type == "rsa" and key.bits is not None and key.bits < 2048:
            add(
                "email.dkim.weak_key",
                f"DKIM key '{key.selector}' is only {key.bits}-bit",
                Severity.HIGH if key.bits < 1024 else Severity.LOW,
                "email.rotate_dkim_key",
                [rfc(8301), cwe(326)],
                [
                    Evidence(
                        kind="dns_record",
                        summary=f"{key.selector}._domainkey.{d}: RSA-{key.bits}",
                        data={"selector": key.selector, "bits": key.bits},
                    )
                ],
                disc=key.selector,
                facts={"selector": key.selector, "key_bits": key.bits},
            )
    return out
