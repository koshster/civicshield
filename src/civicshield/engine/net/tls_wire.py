"""Minimal TLS ClientHello builder and ServerHello parser (pure functions, no I/O).

Why hand-roll this instead of using Python's ``ssl``? Modern OpenSSL builds refuse to
*offer* TLS 1.0/1.1 or weak ciphers, so with ``ssl`` a failed handshake could mean "the
server refused" or "our own library refused". We can't tell those apart. By writing the
first handshake message ourselves we control exactly what's offered, and the server's
reply (ServerHello vs. alert) tells us unambiguously what it accepts.

We only ever send a ClientHello and read the first reply; we never complete a handshake.
That makes the probe about as low-impact as a TLS interaction can be.

Wire format reference: RFC 5246 §7.4.1.2 (ClientHello), §7.4.1.3 (ServerHello),
RFC 6066 §3 (SNI).
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntEnum


class TLSVersion(IntEnum):
    SSL3 = 0x0300
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303

    @property
    def label(self) -> str:
        return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2"}[
            self.value
        ]


# A broad, compatible offer used when probing *protocol versions*: CBC suites work on
# TLS 1.0+, GCM/ChaCha only on 1.2 (servers ignore suites they can't use).
COMPAT_SUITES: tuple[int, ...] = (
    0xC02F,
    0xC030,
    0xC02B,
    0xC02C,
    0xCCA8,
    0xCCA9,  # ECDHE + AEAD (TLS 1.2)
    0xC013,
    0xC014,
    0xC009,
    0xC00A,  # ECDHE + AES-CBC
    0x009C,
    0x009D,
    0x002F,
    0x0035,  # RSA key exchange + AES
    0x0033,
    0x0039,  # DHE + AES-CBC
)

# Weak suite families probed one family at a time at TLS 1.2. If the server picks one,
# it's willing to use that weak cipher with *some* client.
WEAK_SUITE_FAMILIES: dict[str, tuple[int, ...]] = {
    "rc4": (0x0005, 0x0004, 0xC011, 0xC007),
    "3des": (0x000A, 0xC012, 0xC008, 0x0016),
    "null": (0x0001, 0x0002, 0x003B, 0xC010, 0xC006),
    "export": (0x0003, 0x0006, 0x0008, 0x000E, 0x0014),
    "anonymous": (0x0018, 0x001B, 0x0034, 0x003A, 0xC018, 0xC019),
}

_HANDSHAKE = 0x16
_ALERT = 0x15
_CLIENT_HELLO = 0x01
_SERVER_HELLO = 0x02


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def build_client_hello(
    server_name: str, version: TLSVersion, cipher_suites: tuple[int, ...]
) -> bytes:
    sni_name = server_name.encode("ascii")
    sni = struct.pack("!HBH", len(sni_name) + 3, 0, len(sni_name)) + sni_name
    groups = struct.pack("!H3H", 6, 0x001D, 0x0017, 0x0018)  # x25519, P-256, P-384
    sig_algs_list = (0x0401, 0x0403, 0x0804, 0x0501, 0x0503, 0x0601, 0x0201, 0x0203)
    sig_algs = struct.pack(f"!H{len(sig_algs_list)}H", 2 * len(sig_algs_list), *sig_algs_list)
    extensions = b"".join(
        [
            _ext(0x0000, sni),  # server_name: needed for virtual hosting
            _ext(0x000A, groups),  # supported_groups
            _ext(0x000B, b"\x01\x00"),  # ec_point_formats: uncompressed
            _ext(0x000D, sig_algs),  # signature_algorithms (ignored before 1.2)
            _ext(0xFF01, b"\x00"),  # renegotiation_info (RFC 5746)
        ]
    )
    suites = struct.pack(f"!{len(cipher_suites)}H", *cipher_suites)
    body = (
        struct.pack("!H", version)
        + os.urandom(32)  # client random
        + b"\x00"  # empty session id
        + struct.pack("!H", len(suites))
        + suites
        + b"\x01\x00"  # compression: null only
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = struct.pack("!B", _CLIENT_HELLO) + len(body).to_bytes(3, "big") + body
    # Record-layer version: TLS 1.0 for maximum compatibility, as real clients do.
    record_version = min(version, TLSVersion.TLS1_0)
    return struct.pack("!BHH", _HANDSHAKE, record_version, len(handshake)) + handshake


@dataclass(frozen=True)
class ProbeReply:
    accepted: bool
    version: int | None = None
    cipher_suite: int | None = None
    alert: int | None = None  # TLS alert description code when rejected
    detail: str = ""


def parse_server_reply(data: bytes) -> ProbeReply:
    """Interpret the first bytes the server sent back after our ClientHello."""
    if len(data) < 5:
        return ProbeReply(False, detail="connection closed without a TLS response")
    content_type, _rec_version, length = struct.unpack("!BHH", data[:5])
    payload = data[5 : 5 + length]
    if content_type == _ALERT:
        alert = payload[1] if len(payload) >= 2 else None
        return ProbeReply(False, alert=alert, detail=f"alert {alert}")
    if content_type != _HANDSHAKE or len(payload) < 4 or payload[0] != _SERVER_HELLO:
        return ProbeReply(False, detail="unexpected response (not a TLS ServerHello)")
    body = payload[4:]
    if len(body) < 2 + 32 + 1:
        return ProbeReply(False, detail="truncated ServerHello")
    (server_version,) = struct.unpack("!H", body[:2])
    sid_len = body[34]
    offset = 35 + sid_len
    if len(body) < offset + 2:
        return ProbeReply(False, detail="truncated ServerHello")
    (suite,) = struct.unpack("!H", body[offset : offset + 2])
    return ProbeReply(True, version=server_version, cipher_suite=suite)


def record_length(header: bytes) -> int:
    """Length of the record payload, given its 5-byte header."""
    return int(struct.unpack("!H", header[3:5])[0])
