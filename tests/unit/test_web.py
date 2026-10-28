"""Security headers on CivicShield's own responses, and SPA serving."""

from pathlib import Path

import httpx
import pytest

from civicshield.api.app import create_app
from civicshield.config import get_settings


async def test_api_responses_carry_security_headers(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/healthz")
    h = resp.headers
    assert "script-src 'self'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY"
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    assert h["strict-transport-security"].startswith("max-age=")


async def test_civicshield_passes_its_own_header_check(client: httpx.AsyncClient) -> None:
    """Dogfooding: run our headers analyzer against our own response."""
    from civicshield.engine.checks.headers.check import HeadersObservation, analyze

    resp = await client.get("/api/healthz")
    obs = HeadersObservation(
        url=str(resp.url),
        status=resp.status_code,
        headers=tuple((k.lower(), v) for k, v in resp.headers.multi_items()),
        https=True,
    )
    found = {f.finding_type for f in analyze(obs, "testserver")}
    # style-src 'unsafe-inline' is a deliberate, documented trade-off; nothing else may fire.
    assert found <= {"headers.csp.unsafe_inline"}, found


@pytest.fixture
def spa_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> httpx.AsyncClient:
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text("<!doctype html><title>CivicShield</title>")
    (tmp_path / "assets" / "app-123.js").write_text("console.log(1)")
    (tmp_path.parent / "secret.txt").write_text("nope")
    monkeypatch.setenv("CIVICSHIELD_FRONTEND_DIST", str(tmp_path))
    get_settings.cache_clear()
    app = create_app()
    get_settings.cache_clear()
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://t")


async def test_spa_serves_index_for_client_routes(spa_client: httpx.AsyncClient) -> None:
    async with spa_client as c:
        for path in ("/", "/orgs/123/issues"):
            resp = await c.get(path)
            assert resp.status_code == 200
            assert "CivicShield" in resp.text
            assert resp.headers["x-frame-options"] == "DENY"


async def test_spa_serves_assets_with_long_cache(spa_client: httpx.AsyncClient) -> None:
    async with spa_client as c:
        resp = await c.get("/assets/app-123.js")
        assert resp.text == "console.log(1)"
        assert "immutable" in resp.headers["cache-control"]


async def test_spa_blocks_traversal_and_keeps_api_404(spa_client: httpx.AsyncClient) -> None:
    async with spa_client as c:
        resp = await c.get("/..%2fsecret.txt")
        assert "nope" not in resp.text
        assert (await c.get("/api/v1/nope")).status_code == 404
        assert (await c.get("/api/healthz")).json()["status"] == "ok"
