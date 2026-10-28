from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from civicshield.db.base import Base, Timestamped, UUIDPk
from civicshield.enums import Role


class Organization(UUIDPk, Timestamped, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="organization")


class User(UUIDPk, Timestamped, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True)
    # argon2id hash in PHC string format ($argon2id$v=19$m=...,t=...,p=...$salt$hash), which
    # embeds its own parameters so they can be raised later without a migration.
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(200), default="")
    # The single deployment operator (you). Operators can see and manage every org.
    is_operator: Mapped[bool] = mapped_column(default=False)
    is_active: Mapped[bool] = mapped_column(default=True)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user")


class Membership(Timestamped, Base):
    __tablename__ = "memberships"
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=32))

    user: Mapped[User] = relationship(back_populates="memberships")
    organization: Mapped[Organization] = relationship(back_populates="memberships")


class UserSession(Base):
    """Server-side session.

    The browser holds a random token in an HttpOnly cookie; the database stores only
    ``sha256(token)``. A database leak therefore doesn't hand out live sessions, and
    logging out (deleting the row) revokes access immediately, unlike a stateless JWT.
    """

    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime]
    expires_at: Mapped[datetime]

    user: Mapped[User] = relationship()
