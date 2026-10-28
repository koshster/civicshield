"""DNS lookups for checks and for SSRF validation.

DNS queries go to *our* recursive resolver, not to the target's servers, so they aren't
scope-restricted: the email check legitimately reads third-party records such as
``spf.protection.outlook.com`` when following SPF ``include:`` chains. What scope
restricts is *connections to hosts* (HTTP, TLS), which live in http.py and tls.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from civicshield.engine.net.errors import DNSLookupError

DNSStatus = Literal["ok", "nxdomain", "nodata"]


@dataclass(frozen=True)
class DNSAnswer:
    status: DNSStatus
    records: tuple[str, ...] = field(default_factory=tuple)

    @property
    def exists(self) -> bool:
        return self.status == "ok" and bool(self.records)


class Resolver(Protocol):
    """Interface checks depend on. Tests pass a FakeResolver with canned answers."""

    async def query(self, name: str, rdtype: str) -> DNSAnswer: ...


def _rdata_to_text(rdata: dns.rdata.Rdata, rdtype: str) -> str:
    if rdtype == "TXT":
        # Long TXT records (SPF, DKIM keys) are split into several ≤255-byte strings on
        # the wire. Per RFC 7208 §3.3 they must be concatenated with no separator.
        # Getting this wrong is a classic SPF/DKIM parsing bug.
        return b"".join(rdata.strings).decode("utf-8", errors="replace")  # type: ignore[attr-defined]
    if rdtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"  # type: ignore[attr-defined]
    return rdata.to_text().rstrip(".")


class DNSResolver:
    """Production resolver built on dnspython's async resolver."""

    def __init__(self, nameservers: Sequence[str] = (), timeout: float = 5.0) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout
        self.query_count = 0

    async def query(self, name: str, rdtype: str) -> DNSAnswer:
        self.query_count += 1
        try:
            answer = await self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DNSAnswer("nxdomain")
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise DNSLookupError(f"{rdtype} lookup for {name} failed: {exc}") from exc
        if answer.rrset is None:
            return DNSAnswer("nodata")
        return DNSAnswer("ok", tuple(_rdata_to_text(r, rdtype) for r in answer.rrset))


class FakeResolver:
    """In-memory resolver for tests: ``FakeResolver({("example.org", "TXT"): ["v=spf1 -all"]})``.

    Names absent from the table are NXDOMAIN. A name that exists for another type
    returns NODATA, matching real DNS semantics.
    """

    def __init__(
        self, records: dict[tuple[str, str], list[str]], failing: set[tuple[str, str]] | None = None
    ) -> None:
        self.records = {(n.lower().rstrip("."), t.upper()): v for (n, t), v in records.items()}
        self.failing = failing or set()
        self.queries: list[tuple[str, str]] = []

    async def query(self, name: str, rdtype: str) -> DNSAnswer:
        key = (name.lower().rstrip("."), rdtype.upper())
        self.queries.append(key)
        if key in self.failing:
            raise DNSLookupError(f"simulated failure for {key}")
        if key in self.records:
            values = self.records[key]
            return DNSAnswer("ok", tuple(values)) if values else DNSAnswer("nodata")
        if any(n == key[0] for n, _ in self.records):
            return DNSAnswer("nodata")
        return DNSAnswer("nxdomain")
