"""TLS prober tests against real local sockets (127.0.0.1, allow-listed like the lab)."""

import asyncio
import ipaddress
import ssl
import struct
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest

from civicshield.engine.net import Scope
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.gateway import Gateway
from civicshield.engine.net.ratelimit import HostRateLimiter
from civicshield.engine.net.tls import TLSProber
from civicshield.engine.net.tls_wire import (
    COMPAT_SUITES,
    TLSVersion,
    build_client_hello,
    parse_server_reply,
)
from civicshield.enums import ScopeKind
from tests.helpers.certs import make_cert

HOST = "tls.example.test"


def _prober(extra_ca: str = "") -> TLSProber:
    gw = Gateway(
        Scope.of(("example.test", ScopeKind.ZONE)),
        FakeResolver({(HOST, "A"): ["127.0.0.1"]}),
        HostRateLimiter(100, 100),
        allowed_private=[ipaddress.ip_network("127.0.0.0/8")],
    )
    ctx = ssl.create_default_context()
    if extra_ca:
        ctx.load_verify_locations(extra_ca)
    return TLSProber(gw, ctx, timeout=3)


def server_hello(version: int, suite: int) -> bytes:
    body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00" + struct.pack("!HB", suite, 0)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 0x16, version, len(hs)) + hs


# --- pure wire-format tests -----------------------------------------------------------
def test_client_hello_structure() -> None:
    hello = build_client_hello(HOST, TLSVersion.TLS1_0, (0x002F, 0x0035))
    assert hello[0] == 0x16  # handshake record
    assert struct.unpack("!H", hello[1:3])[0] == 0x0301  # record version
    assert struct.unpack("!H", hello[3:5])[0] == len(hello) - 5
    assert hello[5] == 0x01  # ClientHello
    assert struct.unpack("!H", hello[9:11])[0] == 0x0301  # client_version
    assert HOST.encode() in hello  # SNI present
    suites_len = struct.unpack("!H", hello[44:46])[0]
    assert struct.unpack("!2H", hello[46 : 46 + suites_len]) == (0x002F, 0x0035)


def test_parse_server_hello_and_alert() -> None:
    reply = parse_server_reply(server_hello(0x0303, 0xC02F))
    assert reply.accepted and reply.version == 0x0303 and reply.cipher_suite == 0xC02F
    alert = parse_server_reply(bytes([0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46]))
    assert not alert.accepted and alert.alert == 70  # protocol_version alert
    assert not parse_server_reply(b"").accepted
    assert not parse_server_reply(b"HTTP/1.1 400 Bad Request\r\n").accepted


# --- socket-level tests -------------------------------------------------------------
Handler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


@pytest.fixture
async def raw_server() -> AsyncIterator[Callable[[Handler], Awaitable[int]]]:
    servers: list[asyncio.Server] = []

    async def start(handler: Handler) -> int:
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        servers.append(server)
        return int(server.sockets[0].getsockname()[1])

    yield start
    for s in servers:
        s.close()
        await s.wait_closed()


async def test_probe_detects_accepted_and_rejected_versions(raw_server) -> None:  # type: ignore[no-untyped-def]
    async def tls10_only(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(4096)
        offered = struct.unpack("!H", data[9:11])[0]
        if offered == 0x0301:
            writer.write(server_hello(0x0301, 0x002F))
        else:
            writer.write(bytes([0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46]))
        await writer.drain()
        writer.close()

    port = await raw_server(tls10_only)
    prober = _prober()
    assert (await prober.probe(HOST, TLSVersion.TLS1_0, COMPAT_SUITES, port=port)).accepted
    rejected = await prober.probe(HOST, TLSVersion.TLS1_1, COMPAT_SUITES, port=port)
    assert not rejected.accepted and rejected.alert == 70


async def test_probe_treats_version_downgrade_as_rejection(raw_server) -> None:  # type: ignore[no-untyped-def]
    async def answers_12(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        writer.write(server_hello(0x0303, 0xC02F))
        await writer.drain()
        writer.close()

    port = await raw_server(answers_12)
    reply = await _prober().probe(HOST, TLSVersion.TLS1_0, COMPAT_SUITES, port=port)
    assert not reply.accepted


async def test_probe_handles_silent_close(raw_server) -> None:  # type: ignore[no-untyped-def]
    async def closes(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(4096)
        writer.close()

    port = await raw_server(closes)
    assert not (await _prober().probe(HOST, TLSVersion.TLS1_0, COMPAT_SUITES, port=port)).accepted


async def _tls_server(
    tmp_path: Path, bundle_names: list[str], ca: bool
) -> tuple[int, str, asyncio.Server]:
    root = make_cert(["Test Root CA"], is_ca=True) if ca else None
    leaf = make_cert(bundle_names, issuer=root)
    cert_path, key_path = leaf.write(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
    ca_path = ""
    if root:
        ca_path, _ = root.write(tmp_path, "ca")
    return int(server.sockets[0].getsockname()[1]), str(ca_path), server


async def test_fetch_certificate_trusted(tmp_path: Path) -> None:
    port, ca_path, server = await _tls_server(tmp_path, [HOST], ca=True)
    async with server:
        result = await _prober(ca_path).fetch_certificate(HOST, port)
    assert result.verified and result.leaf_der and result.protocol == "TLSv1.3"


async def test_fetch_certificate_self_signed_still_returns_cert(tmp_path: Path) -> None:
    port, _, server = await _tls_server(tmp_path, [HOST], ca=False)
    async with server:
        result = await _prober().fetch_certificate(HOST, port)
    assert not result.verified
    assert result.verify_code == 18  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
    assert result.leaf_der is not None


async def test_fetch_certificate_hostname_mismatch(tmp_path: Path) -> None:
    port, ca_path, server = await _tls_server(tmp_path, ["other.example.test"], ca=True)
    async with server:
        result = await _prober(ca_path).fetch_certificate(HOST, port)
    assert not result.verified and result.verify_code == 62  # X509_V_ERR_HOSTNAME_MISMATCH
