import httpx


async def test_healthz(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
