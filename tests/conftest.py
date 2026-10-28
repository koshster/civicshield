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
from civicshield.config import Settings
from civicshield.db.base import Base

# Tests must not depend on a developer's local .env (e.g. COOKIE_SECURE=false for
# http://localhost would silently change auth behavior under test). Only real
# environment variables and per-test monkeypatching apply.
Settings.model_config["env_file"] = None

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


# --- API fixtures -------------------------------------------------------------------
import httpx  # noqa: E402

from civicshield.api.app import create_app  # noqa: E402
from civicshield.api.routes.auth import login_limiter  # noqa: E402
from civicshield.auth.passwords import hash_password  # noqa: E402
from civicshield.db.session import get_db  # noqa: E402
from civicshield.models import User  # noqa: E402

OPERATOR_EMAIL = "operator@example.org"
PASSWORD = "correct horse battery staple"


@pytest.fixture
async def client(
    sessionmaker: async_sessionmaker[AsyncSession],
) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app()

    async def _db() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    login_limiter._events.clear()
    # https:// so the Secure session cookie is sent back, as in a real browser.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://testserver"
    ) as c:
        yield c


@pytest.fixture
async def operator(db: AsyncSession) -> User:
    user = User(email=OPERATOR_EMAIL, password_hash=hash_password(PASSWORD), is_operator=True)
    db.add(user)
    await db.commit()
    return user


async def login(client: httpx.AsyncClient, email: str, password: str = PASSWORD) -> str:
    """Log in and configure the client to send the CSRF header. Returns the CSRF token."""
    resp = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    csrf: str = resp.json()["csrf_token"]
    client.headers["X-CSRF-Token"] = csrf
    return csrf


@pytest.fixture
async def operator_client(client: httpx.AsyncClient, operator: User) -> httpx.AsyncClient:
    await login(client, operator.email)
    return client
