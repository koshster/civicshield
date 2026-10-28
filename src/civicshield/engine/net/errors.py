from __future__ import annotations


class NetError(Exception):
    """Base class for scanner network errors (all are "couldn't check", never "all clear")."""


class OutOfScopeError(NetError):
    """The host is not covered by any verified domain/authorization. Never contacted."""


class BlockedAddressError(NetError):
    """The host resolved to a private/reserved address (SSRF / DNS rebinding defense)."""


class DNSLookupError(NetError):
    """DNS timeout or SERVFAIL. Distinct from NXDOMAIN, which is a valid answer."""


class TargetUnreachableError(NetError):
    """Connection refused, reset, or timed out."""


class CertificateError(NetError):
    """TLS certificate failed verification (expired, wrong host, untrusted chain...)."""
