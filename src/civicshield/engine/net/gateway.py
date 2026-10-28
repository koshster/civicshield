"""Resolve-and-validate: the step every outbound connection goes through.

``Gateway.connect_target(host)`` performs, in order:
1. scope check: is ``host`` inside a verified, authorized domain?
2. DNS resolution (A + AAAA) through our resolver
3. SSRF check on *every* returned address: one bad address blocks the host, because we
   can't know which address a real client would pick
4. per-host rate limiting
and returns the pinned IP that the caller must connect to.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from civicshield.engine.net.dns import Resolver
from civicshield.engine.net.errors import BlockedAddressError, TargetUnreachableError
from civicshield.engine.net.ratelimit import HostRateLimiter
from civicshield.engine.net.scope import Scope
from civicshield.engine.net.ssrf import IPAddress, IPNetwork, is_allowed_address


@dataclass
class Gateway:
    scope: Scope
    resolver: Resolver
    limiter: HostRateLimiter
    allowed_private: Sequence[IPNetwork] = ()
    # Traffic accounting: connections per host, persisted into Scan.stats.
    connections: Counter[str] = field(default_factory=Counter)
    _cache: dict[str, IPAddress] = field(default_factory=dict)

    async def resolve_pinned(self, host: str) -> tuple[str, IPAddress]:
        """Return (normalized_host, validated_ip) or raise. Cached per scan.

        Caching is also a security property: within one scan, a host always maps to the
        address we validated, even if its DNS answer changes mid-scan.
        """
        host = self.scope.require(host)
        if host in self._cache:
            return host, self._cache[host]

        addresses: list[IPAddress] = []
        for rdtype in ("A", "AAAA"):
            answer = await self.resolver.query(host, rdtype)
            for rec in answer.records:
                try:
                    addresses.append(ipaddress.ip_address(rec))
                except ValueError:
                    continue  # CNAME targets show up in some resolvers' text output
        if not addresses:
            raise TargetUnreachableError(f"{host} has no A/AAAA records")
        bad = [str(ip) for ip in addresses if not is_allowed_address(ip, self.allowed_private)]
        if bad:
            raise BlockedAddressError(
                f"{host} resolves to non-public address(es) {', '.join(bad)}; refusing to connect"
            )
        # Prefer IPv4: many small-org hosts publish AAAA records that don't actually work.
        ip = next((a for a in addresses if a.version == 4), addresses[0])
        self._cache[host] = ip
        return host, ip

    async def connect_target(self, host: str) -> tuple[str, IPAddress]:
        host, ip = await self.resolve_pinned(host)
        await self.limiter.acquire(host)
        self.connections[host] += 1
        return host, ip
