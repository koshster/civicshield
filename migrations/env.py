"""Alembic environment.

The app uses the async driver (asyncpg); Alembic runs synchronously, so we swap the
driver to psycopg for migrations. Same database, different client library.
"""

from __future__ import annotations

from logging.config import fileConfig
from typing import Any

from alembic import context
from sqlalchemy import create_engine, pool
from sqlalchemy.types import TypeDecorator

import civicshield.models  # noqa: F401  (registers all tables on Base.metadata)
from civicshield.config import get_settings
from civicshield.db.base import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def render_item(type_: str, obj: Any, autogen_context: Any) -> str | bool:
    """Render custom TypeDecorators as their underlying SQL type.

    Migrations are a frozen history; they must not import application classes that may
    later be renamed or changed. UTCDateTime → DateTime(timezone=True), IntEnumType → Integer.
    """
    if type_ == "type" and isinstance(obj, TypeDecorator):
        impl = obj.impl if not isinstance(obj.impl, type) else obj.impl()
        return f"sa.{impl!r}"
    return False


def sync_url() -> str:
    url = config.attributes.get("database_url") or get_settings().database_url
    return str(url).replace("+asyncpg", "+psycopg").replace("+aiosqlite", "")


def run_migrations_offline() -> None:
    context.configure(url=sync_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(sync_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_item=render_item,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
