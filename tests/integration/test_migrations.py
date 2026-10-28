"""Run the real Alembic migrations against Postgres and check DB-level guarantees."""

import os
import subprocess

import pytest
from sqlalchemy import create_engine, text

pytestmark = pytest.mark.integration

URL = os.environ.get("CIVICSHIELD_TEST_DATABASE_URL", "")


@pytest.fixture
def migrated() -> str:
    if not URL.startswith("postgresql"):
        pytest.skip("needs CIVICSHIELD_TEST_DATABASE_URL pointing at Postgres")
    env = {**os.environ, "CIVICSHIELD_DATABASE_URL": URL}
    subprocess.run(["alembic", "downgrade", "base"], check=True, env=env, capture_output=True)
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env, capture_output=True)
    yield URL.replace("+asyncpg", "+psycopg")
    subprocess.run(["alembic", "downgrade", "base"], check=True, env=env, capture_output=True)


def test_models_match_migrations(migrated: str) -> None:
    env = {**os.environ, "CIVICSHIELD_DATABASE_URL": URL}
    result = subprocess.run(["alembic", "check"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_audit_log_is_append_only(migrated: str) -> None:
    engine = create_engine(migrated)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (created_at, actor_label, action, target_type, target_id,"
                " details, prev_hash, hash) VALUES (now(), 'test', 'a', 't', '1', '{}', '0', 'h')"
            )
        )
    with pytest.raises(Exception, match="append-only"), engine.begin() as conn:
        conn.execute(text("UPDATE audit_events SET action = 'tampered'"))
    with pytest.raises(Exception, match="append-only"), engine.begin() as conn:
        conn.execute(text("DELETE FROM audit_events"))
    engine.dispose()
