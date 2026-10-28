from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, Enum, ForeignKey, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from civicshield.db.base import Base, Timestamped, UUIDPk
from civicshield.enums import DomainStatus, Impact, ScopeKind, VerificationMethod

authorization_domains = Table(
    "authorization_domains",
    Base.metadata,
    Column(
        "authorization_id", ForeignKey("authorizations.id", ondelete="CASCADE"), primary_key=True
    ),
    Column("domain_id", ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True),
)


class Domain(UUIDPk, Timestamped, Base):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    # Lower-case, IDNA (punycode) form, no trailing dot: "example.org"
    name: Mapped[str] = mapped_column(String(253))
    verification_method: Mapped[VerificationMethod] = mapped_column(
        Enum(VerificationMethod, native_enum=False, length=32)
    )
    # Stored in plaintext on purpose: the token is published in public DNS or on the
    # website, so it's not a secret. What it proves is "whoever controls this
    # domain put this exact random value there," and that requires it to be unguessable,
    # not hidden.
    verification_token: Mapped[str] = mapped_column(String(64))
    status: Mapped[DomainStatus] = mapped_column(
        Enum(DomainStatus, native_enum=False, length=32), default=DomainStatus.PENDING
    )
    scope_kind: Mapped[ScopeKind] = mapped_column(Enum(ScopeKind, native_enum=False, length=32))
    verified_at: Mapped[datetime | None]
    last_checked_at: Mapped[datetime | None]
    last_check_error: Mapped[str | None] = mapped_column(Text)


class Authorization(UUIDPk, Timestamped, Base):
    """A written, attributable permission to scan specific domains.

    Domain verification proves *technical control*; this record proves *organizational
    consent* from a named person. A scan needs both. Rows are never edited: changing
    scope means revoking this one and recording a new one, which keeps a clean history
    of who allowed what, and when.
    """

    __tablename__ = "authorizations"

    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    signer_name: Mapped[str] = mapped_column(String(200))
    signer_title: Mapped[str] = mapped_column(String(200))
    signer_email: Mapped[str] = mapped_column(String(320))
    # The exact authorization text the signer agreed to is versioned in code
    # (authz/authorization_text.py); we store the version and a hash of the text.
    text_version: Mapped[str] = mapped_column(String(32))
    text_sha256: Mapped[str] = mapped_column(String(64))
    max_impact: Mapped[Impact] = mapped_column(default=Impact.PASSIVE)
    granted_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    recorded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    source_ip: Mapped[str | None] = mapped_column(String(45))

    domains: Mapped[list[Domain]] = relationship(secondary=authorization_domains)
