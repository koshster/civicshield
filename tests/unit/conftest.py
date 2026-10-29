"""Fixtures for tests that drive the scan pipeline through the API."""

from __future__ import annotations

import uuid
from typing import Any

import httpx
import pytest

from civicshield.api.deps import get_enqueuer, get_net_factory
from civicshield.authz.authorization_text import CURRENT_VERSION, text_sha256
from civicshield.config import get_settings
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.factory import build_net


def net_factory(dns: FakeResolver) -> Any:
    return lambda scope: build_net(scope, get_settings(), resolver=dns)


@pytest.fixture
def dns() -> FakeResolver:
    return FakeResolver(
        {("example.org", "A"): ["93.184.216.34"], ("www.example.org", "A"): ["93.184.216.34"]}
    )


@pytest.fixture
def queued() -> list[uuid.UUID]:
    return []


@pytest.fixture
async def org_ready(
    operator_client: httpx.AsyncClient, dns: FakeResolver, queued: list[uuid.UUID]
) -> dict[str, Any]:
    """An org with a verified, authorized domain, plus API overrides for net/enqueue."""
    app = operator_client._transport.app  # type: ignore[attr-defined]
    app.dependency_overrides[get_net_factory] = lambda: net_factory(dns)
    app.dependency_overrides[get_enqueuer] = lambda: queued.append
    api = operator_client
    org = (await api.post("/api/v1/orgs", json={"name": "Food Bank", "slug": "fb"})).json()
    d = (await api.post(f"/api/v1/orgs/{org['id']}/domains", json={"name": "example.org"})).json()
    dns.records[("_civicshield-verification.example.org", "TXT")] = [
        d["instructions"]["record_value"]
    ]
    await api.post(f"/api/v1/orgs/{org['id']}/domains/{d['id']}/verify")
    auth = (
        await api.post(
            f"/api/v1/orgs/{org['id']}/authorizations",
            json={
                "signer_name": "Pat",
                "signer_title": "Director",
                "signer_email": "pat@example.org",
                "domain_ids": [d["id"]],
                "text_version": CURRENT_VERSION,
                "text_sha256": text_sha256(),
                "agree": True,
            },
        )
    ).json()
    return {"api": api, "org": org["id"], "auth": auth["id"]}


def _factory(dns: FakeResolver) -> Any:
    return lambda scope: build_net(scope, get_settings(), resolver=dns)
