"""The lab's cases, in one place: hostnames, IPs, and which nginx target serves them.

Imported by ca/generate.py (certificate SANs), dns/render.py (zone file) and
eval/harness.py (which domains to verify and scan). Keeping it in one module means the
three can't drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass

SUBNET = "172.30.0.0/24"  # the lab's internal Docker network (no internet route)
DNS_IP = "172.30.0.10"
PARENT = "lab.civicshield.test"  # .test is reserved by RFC 2606: can never be a real domain


@dataclass(frozen=True)
class Target:
    """One nginx container."""

    name: str
    ip: str


TARGETS = {
    t.name: t
    for t in (
        Target("hardened", "172.30.0.20"),
        Target("bad-headers", "172.30.0.21"),
        Target("weak-tls", "172.30.0.22"),
        Target("expired-cert", "172.30.0.23"),
        Target("self-signed", "172.30.0.24"),
        Target("redirector", "172.30.0.25"),
        Target("outside", "172.30.0.26"),
        Target("apex-redirect", "172.30.0.27"),
    )
}


@dataclass(frozen=True)
class Zone:
    """One domain the lab org registers, verifies and authorizes.

    ``email`` holds the zone's TXT records at the apex and at ``_dmarc``. The default is
    the correct setup for a domain that sends no mail, so web cases don't produce email
    findings by accident.
    """

    label: str
    target: str
    spf: str | None = "v=spf1 -all"
    dmarc: str | None = None  # None → the clean default below

    @property
    def name(self) -> str:
        return f"{self.label}.{PARENT}"

    @property
    def dmarc_record(self) -> str | None:
        if self.dmarc == "":
            return None
        return self.dmarc or f"v=DMARC1; p=reject; rua=mailto:dmarc@{self.name}"

    @property
    def hosts(self) -> tuple[str, str]:
        return (self.name, f"www.{self.name}")


ZONES = (
    # Web cases: the email side is clean by default.
    Zone("hardened", "hardened"),
    Zone("bad-headers", "bad-headers"),
    Zone("weak-tls", "weak-tls"),
    Zone("expired-cert", "expired-cert"),
    Zone("self-signed", "self-signed"),
    Zone("apex-redirect", "apex-redirect"),
    # Email cases: web side served by the hardened target.
    Zone("spf-missing", "hardened", spf=None),
    Zone("spf-pass-all", "hardened", spf="v=spf1 +all"),
    Zone("dmarc-missing", "hardened", dmarc=""),
    Zone(
        "dmarc-none",
        "hardened",
        dmarc="v=DMARC1; p=none; rua=mailto:dmarc@dmarc-none.lab.civicshield.test",
    ),
    # Scope case: every request is redirected to OUTSIDE, which is never authorized.
    Zone("redirector", "redirector"),
)

# Not registered with the org, so it's out of scope. Its access log must stay empty.
OUTSIDE_HOST = "outside.notours.test"
