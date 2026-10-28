from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.api.deps import get_net_factory
from civicshield.authz.authorization_text import CURRENT_VERSION, text_sha256
from civicshield.authz.scope_builder import NotAuthorizedError, resolve_permission
from civicshield.config import get_settings
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.factory import build_net
from civicshield.models import Domain, User
from tests.conftest import PASSWORD, login

IP = "93.184.216.34"


@pytest.fixture
def dns() -> FakeResolver:
    return FakeResolver({("example.org", "A"): [IP], ("www.example.org", "A"): [IP]})


@pytest.fixture
async def api(operator_client: httpx.AsyncClient, dns: FakeResolver) -> httpx.AsyncClient:
    app = operator_client._transport.app  # type: ignore[attr-defined]
    app.dependency_overrides[get_net_factory] = lambda: (
        lambda scope: build_net(scope, get_settings(), resolver=dns)
    )
    return operator_client


async def _org(api: httpx.AsyncClient) -> str:
    resp = await api.post("/api/v1/orgs", json={"name": "Food Bank", "slug": "food-bank"})
    org_id: str = resp.json()["id"]
    return org_id


async def test_add_domain_returns_dns_instructions(api: httpx.AsyncClient) -> None:
    org = await _org(api)
    resp = await api.post(f"/api/v1/orgs/{org}/domains", json={"name": "https://Example.ORG/"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "example.org"
    assert body["status"] == "pending" and body["scope_kind"] == "zone"
    instr = body["instructions"]
    assert instr["record_name"] == "_civicshield-verification.example.org"
    assert instr["record_value"].startswith("civicshield-verification=")


async def test_dns_txt_verification_flow(api: httpx.AsyncClient, dns: FakeResolver) -> None:
    org = await _org(api)
    d = (await api.post(f"/api/v1/orgs/{org}/domains", json={"name": "example.org"})).json()

    failed = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert failed["status"] == "pending" and "no TXT record" in failed["last_check_error"]

    dns.records[("_civicshield-verification.example.org", "TXT")] = ["unrelated"]
    wrong = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert "doesn't match" in wrong["last_check_error"]

    dns.records[("_civicshield-verification.example.org", "TXT")] = [
        d["instructions"]["record_value"]
    ]
    ok = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert ok["status"] == "verified" and ok["verified_at"]

    # Record removed later → previously verified domain becomes FAILED (scanning pauses).
    del dns.records[("_civicshield-verification.example.org", "TXT")]
    lost = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert lost["status"] == "failed"


@respx.mock
async def test_http_file_verification_is_host_only(api: httpx.AsyncClient) -> None:
    org = await _org(api)
    d = (
        await api.post(
            f"/api/v1/orgs/{org}/domains",
            json={"name": "www.example.org", "verification_method": "http_file"},
        )
    ).json()
    assert d["scope_kind"] == "host_only"
    path = "/.well-known/civicshield-verification.txt"
    route = respx.get(f"https://{IP}{path}").mock(
        return_value=httpx.Response(200, text=d["instructions"]["file_contents"] + "\n")
    )
    ok = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert ok["status"] == "verified"
    assert route.calls.last.request.headers["host"] == "www.example.org"


@respx.mock
async def test_http_file_redirect_offsite_does_not_verify(api: httpx.AsyncClient) -> None:
    org = await _org(api)
    d = (
        await api.post(
            f"/api/v1/orgs/{org}/domains",
            json={"name": "www.example.org", "verification_method": "http_file"},
        )
    ).json()
    path = "/.well-known/civicshield-verification.txt"
    for scheme in ("https", "http"):
        respx.get(f"{scheme}://{IP}{path}").mock(
            return_value=httpx.Response(
                302, headers={"Location": f"https://attacker.example.com{path}"}
            )
        )
    resp = (await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")).json()
    assert resp["status"] == "pending"


async def _verified_domain(api: httpx.AsyncClient, dns: FakeResolver, org: str) -> str:
    d = (await api.post(f"/api/v1/orgs/{org}/domains", json={"name": "example.org"})).json()
    dns.records[("_civicshield-verification.example.org", "TXT")] = [
        d["instructions"]["record_value"]
    ]
    await api.post(f"/api/v1/orgs/{org}/domains/{d['id']}/verify")
    domain_id: str = d["id"]
    return domain_id


def _auth_body(domain_id: str, **overrides: object) -> dict[str, object]:
    return {
        "signer_name": "Pat Lee",
        "signer_title": "Executive Director",
        "signer_email": "pat@example.org",
        "domain_ids": [domain_id],
        "text_version": CURRENT_VERSION,
        "text_sha256": text_sha256(),
        "agree": True,
        **overrides,
    }


async def test_authorization_requires_verified_domain_and_current_text(
    api: httpx.AsyncClient, dns: FakeResolver
) -> None:
    org = await _org(api)
    pending = (await api.post(f"/api/v1/orgs/{org}/domains", json={"name": "other.org"})).json()
    resp = await api.post(f"/api/v1/orgs/{org}/authorizations", json=_auth_body(pending["id"]))
    assert resp.status_code == 422

    verified = await _verified_domain(api, dns, org)
    stale = await api.post(
        f"/api/v1/orgs/{org}/authorizations", json=_auth_body(verified, text_sha256="0" * 64)
    )
    assert stale.status_code == 409
    no_agree = await api.post(
        f"/api/v1/orgs/{org}/authorizations", json=_auth_body(verified, agree=False)
    )
    assert no_agree.status_code == 422

    ok = await api.post(f"/api/v1/orgs/{org}/authorizations", json=_auth_body(verified))
    assert ok.status_code == 201
    assert ok.json()["domain_names"] == ["example.org"]


async def test_scope_requires_authorization_and_fresh_verification(
    api: httpx.AsyncClient, dns: FakeResolver, db: AsyncSession
) -> None:
    import uuid

    org = await _org(api)
    domain_id = await _verified_domain(api, dns, org)
    with pytest.raises(NotAuthorizedError, match="authorization"):
        await resolve_permission(db, uuid.UUID(org), 30)

    auth = (await api.post(f"/api/v1/orgs/{org}/authorizations", json=_auth_body(domain_id))).json()
    perm = await resolve_permission(db, uuid.UUID(org), 30)
    assert perm.scope.contains("www.example.org")
    assert not perm.scope.contains("example.com")

    # Stale verification → not scannable.
    domain = (await db.execute(select(Domain))).scalar_one()
    domain.verified_at = datetime.now(UTC) - timedelta(days=31)
    await db.commit()
    with pytest.raises(NotAuthorizedError, match="stale"):
        await resolve_permission(db, uuid.UUID(org), 30)

    # Revoked → not scannable, even with fresh verification.
    domain.verified_at = datetime.now(UTC)
    await db.commit()
    await api.post(f"/api/v1/orgs/{org}/authorizations/{auth['id']}/revoke")
    db.expire_all()
    with pytest.raises(NotAuthorizedError):
        await resolve_permission(db, uuid.UUID(org), 30)


async def test_staff_can_verify_and_revoke_but_not_add_domains(
    api: httpx.AsyncClient, dns: FakeResolver, operator: User
) -> None:
    org = await _org(api)
    domain_id = await _verified_domain(api, dns, org)
    await api.post(
        f"/api/v1/orgs/{org}/members", json={"email": "staff@example.org", "password": PASSWORD}
    )
    await api.post("/api/v1/auth/logout")
    await login(api, "staff@example.org")
    assert (
        await api.post(f"/api/v1/orgs/{org}/domains", json={"name": "x.org"})
    ).status_code == 403
    assert (await api.post(f"/api/v1/orgs/{org}/domains/{domain_id}/verify")).status_code == 200
    auth = await api.post(f"/api/v1/orgs/{org}/authorizations", json=_auth_body(domain_id))
    assert auth.status_code == 201
    revoke = await api.post(f"/api/v1/orgs/{org}/authorizations/{auth.json()['id']}/revoke")
    assert revoke.json()["revoked_at"] is not None
