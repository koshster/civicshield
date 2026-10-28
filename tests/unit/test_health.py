from fastapi.testclient import TestClient

from civicshield.api.app import create_app


def test_healthz() -> None:
    client = TestClient(create_app())
    resp = client.get("/api/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
