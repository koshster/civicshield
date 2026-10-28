from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Enum, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from civicshield.db.base import Base, Timestamped, UUIDPk
from civicshield.enums import (
    CheckRunStatus,
    Confidence,
    IssueStatus,
    ScanStatus,
    ScanTrigger,
    Severity,
)


class Scan(UUIDPk, Timestamped, Base):
    __tablename__ = "scans"

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, native_enum=False, length=32), default=ScanStatus.QUEUED, index=True
    )
    trigger: Mapped[ScanTrigger] = mapped_column(Enum(ScanTrigger, native_enum=False, length=32))
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("authorizations.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    error: Mapped[str | None] = mapped_column(Text)
    engine_version: Mapped[str] = mapped_column(String(32), default="")
    # Summary counters, e.g. requests made per host. This is the "how much traffic
    # did we send" record, kept per scan instead of one audit row per request.
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict)

    check_runs: Mapped[list[CheckRun]] = relationship(back_populates="scan")


class CheckRun(UUIDPk, Base):
    """One check executed against one target within a scan.

    Stored separately from findings because "the check failed to run" must never look
    like "the check found nothing." The UI shows these as "couldn't check."
    """

    __tablename__ = "check_runs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    check_id: Mapped[str] = mapped_column(String(64))
    check_version: Mapped[str] = mapped_column(String(16))
    target: Mapped[str] = mapped_column(String(253))
    status: Mapped[CheckRunStatus] = mapped_column(
        Enum(CheckRunStatus, native_enum=False, length=32)
    )
    duration_ms: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="check_runs")


class Issue(UUIDPk, Base):
    """A long-lived problem, identified across scans by a stable fingerprint.

    The Issue/Observation split makes scan-to-scan diffing simple set arithmetic:
    fingerprints seen now but not before are *new*, seen before but not now are *resolved*,
    and previously fixed ones that reappear are *regressed*.
    """

    __tablename__ = "issues"
    __table_args__ = (UniqueConstraint("org_id", "fingerprint"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    check_id: Mapped[str] = mapped_column(String(64))
    finding_type: Mapped[str] = mapped_column(String(128))
    asset: Mapped[str] = mapped_column(String(253))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[Severity]
    confidence: Mapped[Confidence]
    remediation_key: Mapped[str] = mapped_column(String(128))
    status: Mapped[IssueStatus] = mapped_column(
        Enum(IssueStatus, native_enum=False, length=32), default=IssueStatus.OPEN
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    facts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    first_seen_at: Mapped[datetime]
    last_seen_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None]
    regressed_count: Mapped[int] = mapped_column(default=0)


class Observation(UUIDPk, Timestamped, Base):
    """Immutable record that a check saw an issue during a specific scan, with evidence."""

    __tablename__ = "observations"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    issue_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("issues.id", ondelete="CASCADE"), index=True
    )
    severity: Mapped[Severity]
    confidence: Mapped[Confidence]
    evidence: Mapped[list[Any]] = mapped_column(default=list)
    facts: Mapped[dict[str, Any]] = mapped_column(default=dict)
    references: Mapped[list[Any]] = mapped_column(default=list)
