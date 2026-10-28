"""Declarative base and portable column types.

Models use generic SQLAlchemy types (``Uuid``, ``JSON``) with Postgres-specific variants,
so the same models run on PostgreSQL in production/CI and on in-memory SQLite for fast
unit tests. Anything Postgres-only (e.g. row-level security) lives in migrations.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, ClassVar

from sqlalchemy import JSON, DateTime, Integer, MetaData, TypeDecorator, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from civicshield.enums import Confidence, Impact, Severity

# Deterministic constraint names make Alembic autogenerate diffs stable and readable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

JSONType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware datetime that always comes back as UTC.

    SQLite drops tzinfo; Postgres returns it. Normalizing here means application code can
    always compare against ``datetime.now(UTC)`` without naive/aware TypeErrors.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("naive datetime passed to UTCDateTime; use datetime.now(UTC)")
        return value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class IntEnumType[E: IntEnum](TypeDecorator[E]):
    """Store an IntEnum as its integer value.

    SQLAlchemy's default Enum type stores the member *name* ("HIGH"), which sorts
    alphabetically. Storing the integer lets ``ORDER BY severity DESC`` mean
    "most severe first".
    """

    impl = Integer
    cache_ok = True

    def __init__(self, enum_cls: type[E]) -> None:
        super().__init__()
        self.enum_cls = enum_cls

    def process_bind_param(self, value: E | None, dialect: Dialect) -> int | None:
        return None if value is None else int(value)

    def process_result_value(self, value: int | None, dialect: Dialect) -> E | None:
        return None if value is None else self.enum_cls(value)


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: ClassVar[dict[Any, Any]] = {
        datetime: UTCDateTime(),
        uuid.UUID: Uuid(),
        dict[str, Any]: JSONType,
        list[Any]: JSONType,
        Severity: IntEnumType(Severity),
        Confidence: IntEnumType(Confidence),
        Impact: IntEnumType(Impact),
    }


class UUIDPk:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
