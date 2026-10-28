import httpx
import pytest
import respx

from civicshield.engine.net import BlockedAddressError, OutOfScopeError, Scope
from civicshield.engine.net.dns import FakeResolver
from civicshield.engine.net.gateway import Gateway
from civicshield.engine.net.http import MAX_BODY_BYTES, ScopedHttpClient, build_ssl_context
from civicshield.engine.net.ratelimit import HostRateLimiter
from civicshield.enums import ScopeKind

IP = "93.184.216.34"


@pytest.fixture
async def client() -> ScopedHttpClient:
    resolver = FakeResolver(
        {
            ("example.org", "A"): [IP],
            ("www.example.org", "A"): [IP],
            ("internal.example.org", "A"): ["10.0.0.5"],
        }
    )
    gw = Gateway(Scope.of(("example.org", ScopeKind.ZONE)), resolver, HostRateLimiter(100, 100))
    return ScopedHttpClient(
        gw,
        user_agent="CivicShield-test",
        timeout=5,
        max_redirects=3,
        ssl_context=build_ssl_context(),
    )


@respx.mock
async def test_request_goes_to_pinned_ip_with_original_host(client: ScopedHttpClient) -> None:
    route = respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200, text="hi"))
    result = await client.fetch("https://www.example.org/")
    sent = route.calls.last.request
    assert sent.headers["host"] == "www.example.org"
    assert sent.headers["user-agent"] == "CivicShield-test"
    assert sent.extensions["sni_hostname"] == "www.example.org"
    assert result.status == 200 and result.body == "hi"
    assert result.url == "https://www.example.org/"


@respx.mock
async def test_follows_in_scope_redirects_and_records_chain(client: ScopedHttpClient) -> None:
    respx.get(f"http://{IP}/").mock(
        return_value=httpx.Response(301, headers={"Location": "https://www.example.org/"})
    )
    respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200))
    result = await client.fetch("http://example.org/")
    assert [(h.status, h.location) for h in result.redirects] == [(301, "https://www.example.org/")]
    assert result.url == "https://www.example.org/"


@respx.mock
async def test_out_of_scope_redirect_recorded_not_followed(client: ScopedHttpClient) -> None:
    respx.get(f"https://{IP}/donate").mock(
        return_value=httpx.Response(302, headers={"Location": "https://payments.example.com/x"})
    )
    result = await client.fetch("https://example.org/donate")
    assert result.status == 302
    assert result.redirect_blocked_to == "https://payments.example.com/x"
    assert len(respx.calls) == 1


@respx.mock
async def test_redirect_to_private_address_blocked(client: ScopedHttpClient) -> None:
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://internal.example.org/"})
    )
    with pytest.raises(BlockedAddressError):
        await client.fetch("https://example.org/")


async def test_out_of_scope_url_never_requested(client: ScopedHttpClient) -> None:
    with respx.mock(assert_all_called=False) as mock:
        with pytest.raises(OutOfScopeError):
            await client.fetch("https://google.com/")
        assert len(mock.calls) == 0


@respx.mock
async def test_body_is_capped(client: ScopedHttpClient) -> None:
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(200, content=b"a" * (MAX_BODY_BYTES * 2))
    )
    result = await client.fetch("https://example.org/")
    assert len(result.body) == MAX_BODY_BYTES


@respx.mock
async def test_multiple_set_cookie_headers_preserved(client: ScopedHttpClient) -> None:
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(
            200, headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2; Secure")]
        )
    )
    result = await client.fetch("https://example.org/")
    assert result.headers.get_list("set-cookie") == ["a=1", "b=2; Secure"]
