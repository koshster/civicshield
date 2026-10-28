"""The scanner's only gateway to the network.

Checks never import httpx/socket/ssl/dnspython (ruff bans it inside ``engine/checks``).
They receive these objects through ``CheckContext`` instead, so every byte the scanner
sends passes through scope enforcement, SSRF protection, rate limiting and accounting.
"""

from civicshield.engine.net.errors import (
    BlockedAddressError,
    CertificateError,
    DNSLookupError,
    NetError,
    OutOfScopeError,
    TargetUnreachableError,
)
from civicshield.engine.net.scope import Scope, normalize_hostname

__all__ = [
    "BlockedAddressError",
    "CertificateError",
    "DNSLookupError",
    "NetError",
    "OutOfScopeError",
    "Scope",
    "TargetUnreachableError",
    "normalize_hostname",
]
