"""Render the lab's DNS zone files from lab/cases.py.

    uv run python lab/dns/render.py                 # initial zones (no verification records)
    render_zones(out_dir, {"x.lab...": "civicshield-verification=..."})   # from the harness

The eval harness re-renders the zone with the verification TXT values the API hands out,
exactly as an org's IT person would paste them into their DNS provider. CoreDNS reloads the
file when the SOA serial changes.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lab.cases import DNS_IP, OUTSIDE_HOST, PARENT, TARGETS, ZONES

VERIFICATION_LABEL = "_civicshield-verification"  # mirrors authz.verification.DNS_LABEL


def _soa(origin: str, serial: int) -> list[str]:
    return [
        f"$ORIGIN {origin}.",
        "$TTL 5",
        f"@ IN SOA ns.{origin}. hostmaster.{origin}. {serial} 60 60 600 5",
        f"@ IN NS ns.{origin}.",
        f"ns IN A {DNS_IP}",
    ]


def _txt(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def lab_zone(verification: dict[str, str], serial: int) -> str:
    lines = _soa(PARENT, serial)
    for zone in ZONES:
        rel = zone.name.removesuffix(f".{PARENT}")
        ip = TARGETS[zone.target].ip
        lines += [f"{rel} IN A {ip}", f"www.{rel} IN A {ip}"]
        if zone.spf:
            lines.append(f"{rel} IN TXT {_txt(zone.spf)}")
        if zone.dmarc_record:
            lines.append(f"_dmarc.{rel} IN TXT {_txt(zone.dmarc_record)}")
        if zone.name in verification:
            lines.append(f"{VERIFICATION_LABEL}.{rel} IN TXT {_txt(verification[zone.name])}")
    return "\n".join(lines) + "\n"


def outside_zone(serial: int) -> str:
    origin = OUTSIDE_HOST.split(".", 1)[1]
    label = OUTSIDE_HOST.split(".", 1)[0]
    return "\n".join([*_soa(origin, serial), f"{label} IN A {TARGETS['outside'].ip}"]) + "\n"


def render_zones(out_dir: Path, verification: dict[str, str] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    serial = int(time.time())
    (out_dir / f"db.{PARENT}").write_text(lab_zone(verification or {}, serial))
    (out_dir / f"db.{OUTSIDE_HOST.split('.', 1)[1]}").write_text(outside_zone(serial))


if __name__ == "__main__":
    out = Path(__file__).resolve().parent / "zones"
    render_zones(out)
    print(f"wrote zone files to {out}")
