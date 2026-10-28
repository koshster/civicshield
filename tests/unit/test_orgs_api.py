import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.models import User
from tests.conftest import PASSWORD, login


async def _create_org(client: httpx.AsyncClient, slug: str) -> str:
    resp = await client.post("/api/v1/orgs", json={"name": slug.title(), "slug": slug})
    assert resp.status_code == 201, resp.text
    org_id: str = resp.json()["id"]
    return org_id


async def test_operator_creates_org_and_member(operator_client: httpx.AsyncClient) -> None:
    org_id = await _create_org(operator_client, "food-bank")
    resp = await operator_client.post(
        f"/api/v1/orgs/{org_id}/members",
        json={"email": "Staff@FoodBank.org", "full_name": "Sam", "password": PASSWORD},
    )
    assert resp.status_code == 201
    assert resp.json()["user"]["email"] == "staff@foodbank.org"
    dup = await operator_client.post("/api/v1/orgs", json={"name": "Dup", "slug": "food-bank"})
    assert dup.status_code == 409


async def test_invalid_slug_rejected(operator_client: httpx.AsyncClient) -> None:
    resp = await operator_client.post("/api/v1/orgs", json={"name": "Bad", "slug": "Bad Slug!"})
    assert resp.status_code == 422


async def test_staff_only_see_their_org(
    operator_client: httpx.AsyncClient, operator: User, db: AsyncSession
) -> None:
    mine = await _create_org(operator_client, "mine")
    theirs = await _create_org(operator_client, "theirs")
    await operator_client.post(
        f"/api/v1/orgs/{mine}/members", json={"email": "staff@mine.org", "password": PASSWORD}
    )
    await operator_client.post("/api/v1/auth/logout")

    await login(operator_client, "staff@mine.org")
    listed = (await operator_client.get("/api/v1/orgs")).json()
    assert [o["id"] for o in listed] == [mine]
    assert (await operator_client.get(f"/api/v1/orgs/{mine}")).status_code == 200
    # Another org's id → 404, indistinguishable from a nonexistent org.
    assert (await operator_client.get(f"/api/v1/orgs/{theirs}")).status_code == 404
    # Staff can't create orgs or add members.
    assert (
        await operator_client.post("/api/v1/orgs", json={"name": "n", "slug": "n"})
    ).status_code == 403
    assert (
        await operator_client.post(
            f"/api/v1/orgs/{mine}/members", json={"email": "x@y.org", "password": PASSWORD}
        )
    ).status_code == 403


async def test_unauthenticated_rejected(client: httpx.AsyncClient) -> None:
    assert (await client.get("/api/v1/orgs")).status_code == 401
