"""Scope: which hostnames the scanner may connect to.

Built from the org's *verified* domains that are covered by an *active* authorization.
The rules mirror what each verification method actually proves:

* DNS TXT on ``example.org`` proves control of the DNS zone → ``example.org`` and every
  subdomain (``www.example.org``, ``donate.example.org``) are in scope.
* An HTTP file on ``www.example.org`` proves control of that one web server → only
  ``www.example.org``; not the apex, not siblings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from civicshield.engine.net.errors import OutOfScopeError
from civicshield.enums import ScopeKind

# Letters, digits, hyphen; underscore allowed for service labels like "_dmarc".
_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_hostname(host: str) -> str:
    """Lowercase, strip a trailing dot, convert Unicode (IDN) names to punycode.

    Normalizing before comparison prevents bypasses like ``EXAMPLE.org.`` or a Unicode
    lookalike being treated as different from (or the same as) the verified name.
    """
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError("empty hostname")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid hostname: {host!r}") from exc
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.match(lbl) for lbl in labels):
        raise ValueError(f"invalid hostname: {host!r}")
    return host


@dataclass(frozen=True)
class ScopeEntry:
    domain: str
    kind: ScopeKind

    def covers(self, host: str) -> bool:
        if self.kind is ScopeKind.HOST_ONLY:
            return host == self.domain
        # The leading dot matters: "evil-example.org".endswith("example.org") is True,
        # but it must not be treated as a subdomain of example.org.
        return host == self.domain or host.endswith("." + self.domain)


@dataclass(frozen=True)
class Scope:
    entries: tuple[ScopeEntry, ...] = field(default_factory=tuple)

    @classmethod
    def of(cls, *entries: tuple[str, ScopeKind]) -> Scope:
        return cls(tuple(ScopeEntry(normalize_hostname(d), k) for d, k in entries))

    def contains(self, host: str) -> bool:
        try:
            h = normalize_hostname(host)
        except ValueError:
            return False
        return any(e.covers(h) for e in self.entries)

    def require(self, host: str) -> str:
        """Return the normalized host, or raise OutOfScopeError."""
        if not self.contains(host):
            raise OutOfScopeError(f"{host} is outside the authorized scope")
        return normalize_hostname(host)
