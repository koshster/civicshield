"""Assemble the network stack for one scan (or one verification attempt)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from civicshield.config import Settings
from civicshield.engine.net.dns import DNSResolver, Resolver
from civicshield.engine.net.gateway import Gateway
from civicshield.engine.net.http import ScopedHttpClient, build_ssl_context
from civicshield.engine.net.ratelimit import HostRateLimiter
from civicshield.engine.net.scope import Scope
from civicshield.engine.net.tls import TLSProber


@dataclass
class NetBundle:
    gateway: Gateway
    dns: Resolver
    http: ScopedHttpClient
    tls: TLSProber

    async def aclose(self) -> None:
        await self.http.aclose()

    def stats(self) -> dict[str, int]:
        return dict(self.gateway.connections)


def build_net(scope: Scope, settings: Settings, resolver: Resolver | None = None) -> NetBundle:
    resolver = resolver or DNSResolver(settings.dns_nameservers)
    gateway = Gateway(
        scope=scope,
        resolver=resolver,
        limiter=HostRateLimiter(settings.scanner_requests_per_second, settings.scanner_burst),
        allowed_private=settings.private_networks,  # empty unless env=lab (enforced in config)
    )
    ssl_ctx = build_ssl_context(settings.extra_ca_bundle)
    http = ScopedHttpClient(
        gateway,
        user_agent=settings.scanner_user_agent,
        timeout=settings.scanner_timeout_seconds,
        max_redirects=settings.scanner_max_redirects,
        ssl_context=ssl_ctx,
    )
    tls = TLSProber(gateway, ssl_ctx, settings.scanner_timeout_seconds)
    return NetBundle(gateway, resolver, http, tls)


NetFactory = Callable[[Scope], NetBundle]
