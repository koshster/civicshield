import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.audit import verify_chain
from civicshield.auth.passwords import hash_password, verify_password
from civicshield.models import User
from tests.conftest import PASSWORD, login


def test_password_hash_roundtrip_and_min_length() -> None:
    h = hash_password(PASSWORD)
    assert h.startswith("$argon2id$")
    assert verify_password(h, PASSWORD)
    assert not verify_password(h, PASSWORD + "x")
    assert not verify_password(None, PASSWORD)
    with pytest.raises(ValueError):
        hash_password("short")


async def test_login_sets_hardened_cookie(client: httpx.AsyncClient, operator: User) -> None:
    resp = await client.post(
        "/api/v1/auth/login", json={"email": operator.email, "password": PASSWORD}
    )
    assert resp.status_code == 200
    cookie = resp.headers["set-cookie"].lower()
    for attr in ("httponly", "secure", "samesite=strict", "path=/api"):
        assert attr in cookie
    assert resp.json()["user"]["is_operator"] is True
    assert "password_hash" not in resp.text


async def test_wrong_password_and_unknown_user_look_identical(
    client: httpx.AsyncClient, operator: User
) -> None:
    a = await client.post(
        "/api/v1/auth/login", json={"email": operator.email, "password": "wrong-password!"}
    )
    b = await client.post(
        "/api/v1/auth/login", json={"email": "nobody@example.org", "password": "wrong-password!"}
    )
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


async def test_login_rate_limited(client: httpx.AsyncClient, operator: User) -> None:
    for _ in range(10):
        await client.post(
            "/api/v1/auth/login", json={"email": operator.email, "password": "wrong-password!"}
        )
    resp = await client.post(
        "/api/v1/auth/login", json={"email": operator.email, "password": PASSWORD}
    )
    assert resp.status_code == 429


async def test_state_change_requires_csrf(client: httpx.AsyncClient, operator: User) -> None:
    await login(client, operator.email)
    del client.headers["X-CSRF-Token"]
    resp = await client.post("/api/v1/orgs", json={"name": "Org", "slug": "org"})
    assert resp.status_code == 403
    client.headers["X-CSRF-Token"] = "forged"
    resp = await client.post("/api/v1/orgs", json={"name": "Org", "slug": "org"})
    assert resp.status_code == 403


async def test_logout_revokes_session(client: httpx.AsyncClient, operator: User) -> None:
    await login(client, operator.email)
    assert (await client.get("/api/v1/auth/me")).status_code == 200
    assert (await client.post("/api/v1/auth/logout")).status_code == 204
    assert (await client.get("/api/v1/auth/me")).status_code == 401


async def test_login_is_audited_with_intact_chain(
    client: httpx.AsyncClient, operator: User, db: AsyncSession
) -> None:
    await login(client, operator.email)
    await login(client, operator.email)
    assert await verify_chain(db) is None
