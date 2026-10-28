import ipaddress

import pytest

from civicshield.engine.net import BlockedAddressError, OutOfScopeError, Scope
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.gateway import Gateway
from civicshield.engine.net.ratelimit import HostRateLimiter
from civicshield.engine.net.ssrf import is_allowed_address, is_public_address
from civicshield.enums import ScopeKind

ZONE = Scope.of(("example.org", ScopeKind.ZONE), ("www.other.org", ScopeKind.HOST_ONLY))


@pytest.mark.parametrize(
    "host",
    [
        "example.org",
        "www.example.org",
        "a.b.example.org",
        "EXAMPLE.ORG.",
        "www.other.org",
    ],
)
def test_in_scope(host: str) -> None:
    assert ZONE.contains(host)


@pytest.mark.parametrize(
    "host",
    [
        "evil-example.org",  # suffix match without dot boundary
        "example.org.evil.com",  # scope name as a prefix
        "other.org",  # host_only does not include the apex…
        "api.www.other.org",  # …or children
        "",
        "..",
        "exa mple.org",
    ],
)
def test_out_of_scope(host: str) -> None:
    assert not ZONE.contains(host)


def test_idn_normalized() -> None:
    scope = Scope.of(("bücher.example", ScopeKind.ZONE))
    assert scope.contains("xn--bcher-kva.example")
    assert scope.contains("www.BÜCHER.example")


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "192.0.2.1",
    ],
)
def test_non_public_addresses_blocked(ip: str) -> None:
    assert not is_public_address(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(ip: str) -> None:
    assert is_public_address(ipaddress.ip_address(ip))


def test_lab_allowlist() -> None:
    lab = [ipaddress.ip_network("172.30.0.0/16")]
    assert is_allowed_address(ipaddress.ip_address("172.30.0.5"), lab)
    assert not is_allowed_address(ipaddress.ip_address("172.31.0.5"), lab)
    assert not is_allowed_address(ipaddress.ip_address("127.0.0.1"), lab)


def _gateway(records: dict[tuple[str, str], list[str]]) -> Gateway:
    return Gateway(ZONE, FakeResolver(records), HostRateLimiter(100, 100))


async def test_gateway_blocks_out_of_scope_without_dns_lookup() -> None:
    gw = _gateway({})
    with pytest.raises(OutOfScopeError):
        await gw.connect_target("attacker.com")
    assert gw.resolver.queries == []  # type: ignore[attr-defined]


async def test_gateway_blocks_dns_rebinding_to_metadata_ip() -> None:
    gw = _gateway({("www.example.org", "A"): ["169.254.169.254"]})
    with pytest.raises(BlockedAddressError):
        await gw.connect_target("www.example.org")


async def test_gateway_blocks_if_any_address_private() -> None:
    gw = _gateway({("example.org", "A"): ["93.184.216.34"], ("example.org", "AAAA"): ["::1"]})
    with pytest.raises(BlockedAddressError):
        await gw.connect_target("example.org")


async def test_gateway_pins_ip_for_the_whole_scan() -> None:
    gw = _gateway({("example.org", "A"): ["93.184.216.34"]})
    _, first = await gw.connect_target("example.org")
    # DNS changes mid-scan (rebinding attempt) → we keep using the validated address.
    gw.resolver.records[("example.org", "A")] = ["127.0.0.1"]  # type: ignore[attr-defined]
    _, second = await gw.connect_target("example.org")
    assert first == second == ipaddress.ip_address("93.184.216.34")
    assert gw.connections["example.org"] == 2
