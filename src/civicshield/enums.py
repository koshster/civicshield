"""Enumerations shared by the database models, the scan engine and the API.

They're stored as plain strings in the database (``native_enum=False``), so adding a value
needs no migration that alters a Postgres ENUM type.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Role(StrEnum):
    ORG_STAFF = "org_staff"  # can view their org, sign authorization, see verification steps


class VerificationMethod(StrEnum):
    DNS_TXT = "dns_txt"  # proves control of the DNS zone → apex + subdomains in scope
    HTTP_FILE = "http_file"  # proves control of one web host → only that host in scope


class DomainStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"  # was verified, re-check failed → scanning paused


class ScopeKind(StrEnum):
    ZONE = "zone"
    HOST_ONLY = "host_only"


class Impact(IntEnum):
    """How intrusive a check is. Ordered, so "allowed if check.impact <= authorized"."""

    PASSIVE = 1  # what any visitor or resolver sees: DNS, TLS handshake, homepage headers
    LOW = 2  # a few targeted GETs to well-known paths (e.g. /.git/HEAD)
    ACTIVE = 3  # opt-in only; nothing in the MVP uses this


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"  # authorization or verification check failed at scan start


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    VERIFY_FIX = "verify_fix"
    EVAL = "eval"


class CheckRunStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class IssueStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class Category(StrEnum):
    TLS = "tls"
    HEADERS = "headers"
    EMAIL = "email"
    SOFTWARE = "software"
    EXPOSURE = "exposure"
    SUBDOMAINS = "subdomains"
