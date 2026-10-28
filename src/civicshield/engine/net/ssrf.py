"""Server-side request forgery (SSRF) protection.

Threat: someone verifies a domain they own, then points its DNS at ``127.0.0.1``,
``169.254.169.254`` (cloud metadata service) or ``10.x`` (our Postgres/Redis). The
scanner would then attack our own infrastructure on their behalf. Scope checks can't
stop this, because the *hostname* is legitimately in scope; only the *address* is evil.

Defense: resolve the name ourselves, reject any non-public address, then connect to that
exact validated IP (see http.py). If we validated and then let the HTTP library resolve
the name again, a malicious DNS server could answer with a public IP the first time and a
private one the second ("DNS rebinding"). Pinning the IP closes that window.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def is_public_address(ip: IPAddress) -> bool:
    # IPv4-mapped IPv6 (::ffff:127.0.0.1) must be judged as the IPv4 address it wraps.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # is_global is False for private, loopback, link-local, CGNAT (100.64/10),
    # documentation, benchmarking and other IANA special-purpose ranges.
    return ip.is_global and not ip.is_multicast


def is_allowed_address(ip: IPAddress, allowed_private: Sequence[IPNetwork] = ()) -> bool:
    """Public addresses are allowed; private ones only if explicitly allow-listed (lab)."""
    if is_public_address(ip):
        return True
    return any(ip in net for net in allowed_private if ip.version == net.version)
