"""Check registry.

An explicit list, not import-time discovery or entry points: easy to read, easy to
debug, and the order is deterministic. Adding a check = write the module, add it here.
"""

from __future__ import annotations

from civicshield.engine.checks.base import Check
from civicshield.engine.checks.email import EmailSecurityCheck
from civicshield.engine.checks.headers import SecurityHeadersCheck
from civicshield.engine.checks.tls import TLSCheck

ALL_CHECKS: tuple[Check, ...] = (TLSCheck(), SecurityHeadersCheck(), EmailSecurityCheck())


def get_check(check_id: str) -> Check:
    for c in ALL_CHECKS:
        if c.meta.id == check_id:
            return c
    raise KeyError(check_id)
