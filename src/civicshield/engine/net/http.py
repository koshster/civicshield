"""Scoped HTTP client.

Wraps httpx so that every request (including each redirect hop) is scope-checked,
SSRF-validated, IP-pinned and rate-limited by the Gateway.

IP pinning with working TLS: we send the request to ``https://<validated-ip>/path`` but set
the ``Host`` header to the real name and pass ``sni_hostname`` to httpcore, so the server
sees a normal request and certificate validation still checks the real hostname.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from civicshield.engine.net.errors import CertificateError, NetError, TargetUnreachableError
from civicshield.engine.net.gateway import Gateway

MAX_BODY_BYTES = 2 * 1024 * 1024  # enough for any homepage; protects worker memory


@dataclass(frozen=True)
class RedirectHop:
    url: str
    status: int
    location: str
    # The redirecting response's own headers. A host that only redirects (apex → www)
    # still sets HSTS and cookies on that response, and checks must judge it on those.
    headers: httpx.Headers = field(default_factory=httpx.Headers)


@dataclass(frozen=True)
class FetchResult:
    url: str  # final URL after redirects
    status: int
    headers: httpx.Headers  # multi-valued (several Set-Cookie headers survive)
    body: str
    redirects: tuple[RedirectHop, ...] = field(default_factory=tuple)
    # Set when a redirect pointed outside scope; we stop and return the 3xx response.
    redirect_blocked_to: str | None = None
    tls_verified: bool = True


def build_ssl_context(extra_ca_bundle: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if extra_ca_bundle:
        ctx.load_verify_locations(extra_ca_bundle)
    return ctx


class ScopedHttpClient:
    def __init__(
        self,
        gateway: Gateway,
        *,
        user_agent: str,
        timeout: float,
        max_redirects: int,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self.gateway = gateway
        self.max_redirects = max_redirects
        self._verified = httpx.AsyncClient(
            verify=ssl_context,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )
        # Used only when a check explicitly asks to look past a broken certificate
        # (e.g. to still read security headers). Never used for anything sensitive.
        self._unverified = httpx.AsyncClient(
            verify=False,  # noqa: S501 - deliberate, see comment above
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )

    async def aclose(self) -> None:
        await self._verified.aclose()
        await self._unverified.aclose()

    async def _send_once(
        self, url: str, *, method: str, verify_tls: bool
    ) -> tuple[httpx.Response, bytes]:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise NetError(f"unsupported URL: {url}")
        host, ip = await self.gateway.connect_target(parts.hostname)
        ip_host = f"[{ip}]" if ip.version == 6 else str(ip)
        netloc = f"{ip_host}:{parts.port}" if parts.port else ip_host
        pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
        host_header = f"{host}:{parts.port}" if parts.port else host
        client = self._verified if verify_tls else self._unverified
        request = client.build_request(
            method, pinned, headers={"Host": host_header}, extensions={"sni_hostname": host}
        )
        try:
            response = await client.send(request, stream=True)
            try:
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        break
            finally:
                await response.aclose()
        except httpx.TimeoutException as exc:
            raise TargetUnreachableError(f"timeout fetching {url}") from exc
        except httpx.ConnectError as exc:
            # Certificate failures surface as ConnectError wrapping ssl.SSLCertVerificationError.
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                raise CertificateError(str(exc)) from exc
            raise TargetUnreachableError(f"cannot connect to {url}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise TargetUnreachableError(f"HTTP error fetching {url}: {exc}") from exc
        return response, body[:MAX_BODY_BYTES]

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        verify_tls: bool = True,
    ) -> FetchResult:
        hops: list[RedirectHop] = []
        current = url
        for _ in range(self.max_redirects + 1):
            response, body = await self._send_once(current, method=method, verify_tls=verify_tls)
            location = response.headers.get("location")
            if not (follow_redirects and response.is_redirect and location):
                break
            nxt = urljoin(current, location)
            hops.append(RedirectHop(current, response.status_code, nxt, response.headers))
            next_host = urlsplit(nxt).hostname or ""
            if not self.gateway.scope.contains(next_host):
                # Redirecting off-site (e.g. to a donation platform) is normal; we record
                # where it goes but never follow it, since that host isn't authorized.
                return self._result(
                    current, response, body, hops, blocked=nxt, verify_tls=verify_tls
                )
            current = nxt
        else:
            raise TargetUnreachableError(f"too many redirects from {url}")
        return self._result(current, response, body, hops, blocked=None, verify_tls=verify_tls)

    @staticmethod
    def _result(
        url: str,
        response: httpx.Response,
        body: bytes,
        hops: list[RedirectHop],
        blocked: str | None,
        verify_tls: bool,
    ) -> FetchResult:
        return FetchResult(
            url=url,
            status=response.status_code,
            headers=response.headers,
            body=body.decode(response.charset_encoding or "utf-8", errors="replace"),
            redirects=tuple(hops),
            redirect_blocked_to=blocked,
            tls_verified=verify_tls,
        )


__all__ = [
    "CertificateError",
    "FetchResult",
    "RedirectHop",
    "ScopedHttpClient",
    "build_ssl_context",
]
