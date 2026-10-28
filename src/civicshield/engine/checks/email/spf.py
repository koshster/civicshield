"""SPF (RFC 7208) parsing and DNS-lookup-limit evaluation.

The most common *silent* SPF failure at small orgs: every new service (Mailchimp,
Salesforce, a donation CRM) asks you to add ``include:`` to your SPF record. Each
include costs DNS lookups, including nested ones inside the include, and RFC 7208 §4.6.4
caps the total at 10. Go over and receivers treat SPF as a permanent error: the record
silently stops protecting you. Nobody notices until mail is spoofed or starts bouncing.

So we don't just parse the top-level record; we walk the include/redirect tree and count.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from civicshield.engine.net import NetError
from civicshield.engine.net.dns import Resolver

MAX_DNS_LOOKUPS = 10  # RFC 7208 §4.6.4
MAX_VOID_LOOKUPS = 2  # RFC 7208 §4.6.4
_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
_MODIFIER = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.IGNORECASE)


@dataclass(frozen=True)
class SPFTerm:
    qualifier: str  # "+", "-", "~", "?"
    mechanism: str
    value: str


@dataclass(frozen=True)
class SPFRecord:
    raw: str
    terms: tuple[SPFTerm, ...]
    redirect: str | None
    errors: tuple[str, ...]

    @property
    def all_qualifier(self) -> str | None:
        return next((t.qualifier for t in self.terms if t.mechanism == "all"), None)


def is_spf(txt: str) -> bool:
    # "v=spf1" must be followed by a space or end of record ("v=spf10" isn't SPF).
    return txt.lower() == "v=spf1" or txt.lower().startswith("v=spf1 ")


def parse_spf(raw: str) -> SPFRecord:
    terms: list[SPFTerm] = []
    errors: list[str] = []
    redirect: str | None = None
    for token in raw.split()[1:]:
        mod = _MODIFIER.match(token)
        if mod and mod.group(1).lower() not in _MECHANISMS:
            if mod.group(1).lower() == "redirect":
                redirect = mod.group(2)
            continue  # exp= and unknown modifiers are allowed and ignored
        qualifier = "+"
        if token[0] in "+-~?":
            qualifier, token = token[0], token[1:]
        name, _, value = token.partition(":")
        if "/" in name and not value:  # e.g. "a/24" or "mx/24": a CIDR suffix, no domain
            name = name.split("/")[0]
        name = name.lower()
        if name not in _MECHANISMS:
            errors.append(f"unknown mechanism '{token}'")
            continue
        if name in {"include", "exists", "ip4", "ip6"} and not value:
            errors.append(f"'{name}' requires a value")
            continue
        terms.append(SPFTerm(qualifier, name, value))
    return SPFRecord(raw, tuple(terms), redirect, tuple(errors))


@dataclass
class SPFTreeResult:
    lookups: int = 0
    void_lookups: int = 0
    missing_includes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)  # every domain visited
    uses_ptr: bool = False


async def fetch_spf(resolver: Resolver, domain: str) -> tuple[list[str], bool]:
    """Return (spf_records, is_void). A void lookup is NXDOMAIN or no TXT at all."""
    answer = await resolver.query(domain, "TXT")
    return [r for r in answer.records if is_spf(r)], not answer.exists


async def evaluate_tree(resolver: Resolver, root: SPFRecord) -> SPFTreeResult:
    result = SPFTreeResult()
    seen: set[str] = set()

    async def walk(record: SPFRecord, depth: int) -> None:
        if depth > MAX_DNS_LOOKUPS or result.lookups > MAX_DNS_LOOKUPS:
            return  # already over the limit; no need to keep querying
        result.errors.extend(record.errors)
        children: list[str] = []
        for term in record.terms:
            if term.mechanism in _LOOKUP_MECHANISMS:
                result.lookups += 1
            if term.mechanism == "ptr":
                result.uses_ptr = True
            if term.mechanism == "include":
                children.append(term.value)
        if record.redirect and record.all_qualifier is None:  # redirect ignored if "all" present
            result.lookups += 1
            children.append(record.redirect)
        for child in children:
            name = child.lower().rstrip(".")
            if "%" in name:
                continue  # SPF macros expand per-message; can't evaluate statically
            if name in seen:
                result.errors.append(f"include loop via {name}")
                continue
            seen.add(name)
            result.includes.append(name)
            try:
                records, void = await fetch_spf(resolver, name)
            except NetError as exc:
                result.errors.append(f"lookup of {name} failed: {exc}")
                continue
            if void:
                result.void_lookups += 1
            if len(records) != 1:
                result.missing_includes.append(name)
                continue
            await walk(parse_spf(records[0]), depth + 1)

    await walk(root, 0)
    return result
