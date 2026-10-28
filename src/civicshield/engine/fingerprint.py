"""Stable identity for a finding across scans.

The fingerprint deliberately excludes severity, evidence and timestamps: those change
from scan to scan (a cert's days-to-expiry ticks down) while it's still the *same*
problem. If they were included, every rescan would look like "1 fixed, 1 new".
"""

from __future__ import annotations

import hashlib

from civicshield.engine.checks.base import Finding


def fingerprint(check_id: str, finding: Finding) -> str:
    raw = "|".join([check_id, finding.finding_type, finding.asset.lower(), finding.discriminator])
    return hashlib.sha256(raw.encode()).hexdigest()
