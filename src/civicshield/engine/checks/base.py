"""The check plugin interface.

A check is a small class with:
* ``meta``: static metadata (id, version, category, impact level, target kind, the
  finding types it may emit), and
* ``run(target, ctx)``: an async method returning a list of ``Finding``s.

Convention inside each check (not enforced by the interface, but followed by all core
checks): ``run`` = ``gather`` (I/O through ``ctx``) + ``analyze`` (a *pure* function from
an observation dataclass to findings). Most tests then target ``analyze`` with
hand-built observations: fast, exhaustive, and free of network mocks.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, Field

from civicshield.engine.net.dns import Resolver
from civicshield.engine.net.http import FetchResult, ScopedHttpClient
from civicshield.engine.net.tls import TLSProber
from civicshield.enums import Category, Confidence, Impact, Severity


class TargetKind(StrEnum):
    HOST = "host"  # a web host: "www.example.org"
    ZONE = "zone"  # a DNS zone apex: "example.org" (email checks)


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    name: str


@dataclass(frozen=True)
class CheckMeta:
    id: str
    version: str  # bump when detection logic changes; stored on every CheckRun
    name: str
    category: Category
    impact: Impact
    target_kind: TargetKind
    finding_types: frozenset[str]
    description: str = ""


class Reference(BaseModel):
    kind: str  # "cwe" | "cve" | "rfc" | "url"
    id: str
    url: str | None = None


class Evidence(BaseModel):
    """What we observed, in enough detail for a technical person to confirm it."""

    kind: str  # "http_header" | "dns_record" | "certificate" | "tls_probe" | "http_response"
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    finding_type: str  # e.g. "email.dmarc.policy_none"
    title: str
    severity: Severity
    confidence: Confidence
    asset: str  # host or zone the finding is about
    remediation_key: str  # key into the curated remediation library
    discriminator: str = ""  # distinguishes several findings of one type on one asset
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    # Normalized, validated values that reports may cite (days_to_expiry, policy, ...).
    # Never raw page content: see docs/PLAN.md §2.10 on prompt injection.
    facts: dict[str, str | int | float | bool | list[str]] = Field(default_factory=dict)


@dataclass
class CheckContext:
    """Everything a check may use. There's deliberately no other way to reach the network."""

    http: ScopedHttpClient
    dns: Resolver
    tls: TLSProber
    now: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))
    # Per-scan memo so several checks share one fetch of the same URL.
    _fetch_cache: dict[tuple[str, bool], FetchResult] = field(default_factory=dict)

    async def fetch(self, url: str, *, verify_tls: bool = True) -> FetchResult:
        key = (url, verify_tls)
        if key not in self._fetch_cache:
            self._fetch_cache[key] = await self.http.fetch(url, verify_tls=verify_tls)
        return self._fetch_cache[key]


class Check(Protocol):
    meta: ClassVar[CheckMeta]

    async def run(self, target: Target, ctx: CheckContext) -> list[Finding]: ...


def cwe(n: int) -> Reference:
    return Reference(
        kind="cwe", id=f"CWE-{n}", url=f"https://cwe.mitre.org/data/definitions/{n}.html"
    )


def rfc(n: int, section: str = "") -> Reference:
    anchor = f"#section-{section}" if section else ""
    return Reference(
        kind="rfc",
        id=f"RFC {n}{' §' + section if section else ''}",
        url=f"https://www.rfc-editor.org/rfc/rfc{n}{anchor}",
    )
