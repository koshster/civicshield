"""Build a CheckContext wired to fake DNS and (respx-mocked) HTTP."""

from __future__ import annotations

import ipaddress

from civicshield.config import Settings
from civicshield.engine.checks.base import CheckContext
from civicshield.engine.net import Scope
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.factory import build_net
from civicshield.enums import ScopeKind

IP = "93.184.216.34"


def make_ctx(
    records: dict[tuple[str, str], list[str]] | None = None,
    zone: str = "example.org",
    allow_loopback: bool = False,
) -> CheckContext:
    base = {(zone, "A"): [IP], (f"www.{zone}", "A"): [IP]}
    resolver = FakeResolver({**base, **(records or {})})
    settings = Settings(
        scanner_requests_per_second=1000, scanner_burst=1000, scanner_timeout_seconds=3
    )
    net = build_net(Scope.of((zone, ScopeKind.ZONE)), settings, resolver=resolver)
    if allow_loopback:
        net.gateway.allowed_private = [ipaddress.ip_network("127.0.0.0/8")]
    return CheckContext(http=net.http, dns=net.dns, tls=net.tls)
