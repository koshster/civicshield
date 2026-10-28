"""The versioned authorization text an organization agrees to before any scan.

Changing the wording means adding a new version, never editing an old one: stored
authorizations reference a version and its SHA-256, so we can always show exactly what
someone agreed to.

NOTE: This is a starting template, not legal advice. Have it reviewed (e.g. by a law
school clinic) before scanning sites for anyone other than yourself.
"""

from __future__ import annotations

import hashlib

CURRENT_VERSION = "2026-10-v1"

_TEXTS: dict[str, str] = {
    "2026-10-v1": """\
Authorization for security scanning by CivicShield

I confirm that I am authorized to act on behalf of the organization named in this
record, and that the organization owns or controls the domains listed.

I authorize the CivicShield operator to perform automated security checks against
those domains (and, where DNS ownership was verified, their subdomains), limited to:
  - passive checks: reading DNS records, TLS certificates and configuration, HTTP
    response headers and publicly accessible pages, and public certificate
    transparency logs; and
  - low-impact checks, only if selected below: a small number of requests to
    well-known paths (for example /.git/HEAD) to detect accidentally exposed files.

CivicShield will NOT attempt to exploit vulnerabilities, guess or test passwords,
submit forms, or generate load intended to disrupt service. Requests are rate-limited
and identify themselves as CivicShield.

This authorization lasts until the expiry date shown, or until revoked. It can be
revoked at any time, which stops all further scanning immediately.
""",
}


def get_text(version: str = CURRENT_VERSION) -> str:
    return _TEXTS[version]


def text_sha256(version: str = CURRENT_VERSION) -> str:
    return hashlib.sha256(get_text(version).encode()).hexdigest()
