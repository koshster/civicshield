"""Shared fixtures.

Database tests run on in-memory SQLite by default (fast, no Docker needed). When
CIVICSHIELD_TEST_DATABASE_URL points at Postgres (as in CI), the same tests run there
instead, which catches dialect differences without maintaining two test suites.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

import civicshield.models  # noqa: F401
from civicshield.db.base import Base

TEST_DB_URL = os.environ.get("CIVICSHIELD_TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    if TEST_DB_URL.startswith("sqlite"):
        # StaticPool keeps one connection so the in-memory DB survives across sessions.
        eng = create_async_engine(
            TEST_DB_URL, poolclass=StaticPool, connect_args={"check_same_thread": False}
        )

        @event.listens_for(eng.sync_engine, "connect")
        def _fk_on(dbapi_conn, _record):  # type: ignore[no-untyped-def]
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    else:
        eng = create_async_engine(TEST_DB_URL)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest.fixture
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
async def db(sessionmaker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with sessionmaker() as session:
        yield session
