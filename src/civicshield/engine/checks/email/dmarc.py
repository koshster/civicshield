"""DMARC (RFC 7489) record parsing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DMARCRecord:
    raw: str
    tags: dict[str, str]
    valid: bool
    error: str | None = None

    @property
    def policy(self) -> str | None:
        return self.tags.get("p", "").lower() or None

    @property
    def subdomain_policy(self) -> str | None:
        return self.tags.get("sp", "").lower() or self.policy  # sp defaults to p

    @property
    def pct(self) -> int:
        try:
            return max(0, min(100, int(self.tags.get("pct", "100"))))
        except ValueError:
            return 100

    @property
    def rua(self) -> list[str]:
        return [u.strip() for u in self.tags.get("rua", "").split(",") if u.strip()]


def is_dmarc(txt: str) -> bool:
    return txt.replace(" ", "").lower().startswith("v=dmarc1")


def parse_dmarc(raw: str) -> DMARCRecord:
    tags: dict[str, str] = {}
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    for part in parts:
        key, sep, value = part.partition("=")
        if sep:
            tags.setdefault(key.strip().lower(), value.strip())
    # RFC 7489 §6.3: v must be the first tag and p must follow it.
    if not parts or parts[0].replace(" ", "").lower() != "v=dmarc1":
        return DMARCRecord(raw, tags, False, "record must start with v=DMARC1")
    if tags.get("p", "").lower() not in {"none", "quarantine", "reject"}:
        return DMARCRecord(raw, tags, False, "missing or invalid p= policy tag")
    return DMARCRecord(raw, tags, True)
