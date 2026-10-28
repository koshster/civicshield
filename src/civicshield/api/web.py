"""Browser-facing hardening: security headers on every response, and SPA serving.

CivicShield tells nonprofits to set these headers, so it sets them on itself. The CSP is
strict because the frontend is built to need nothing else: no inline scripts, no
third-party origins, no eval. Inline *styles* are allowed only because React's ``style``
prop emits them; they can't execute code.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


def security_headers(hsts: bool) -> dict[str, str]:
    headers = {
        "Content-Security-Policy": CSP,
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    if hsts:  # only when served over HTTPS, otherwise browsers ignore it anyway
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return headers


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, *, hsts: bool) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._headers = security_headers(hsts)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in self._headers.items():
            response.headers.setdefault(name, value)
        if request.url.path.startswith("/api/"):
            # API responses carry org data: never let a shared cache keep them.
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def mount_spa(app: FastAPI, dist: Path) -> None:
    """Serve the built SPA: real files if they exist, otherwise index.html (client routing).

    Paths are resolved and checked to stay inside ``dist`` so ``/../../etc/passwd`` style
    traversal can't escape. Unknown ``/api/...`` paths stay 404s instead of returning HTML.
    """
    root = dist.resolve()
    index = root / "index.html"
    if not index.is_file():
        raise RuntimeError(f"frontend_dist {root} has no index.html; run `npm run build`")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        if path == "api" or path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = (root / path).resolve()
        if path and candidate.is_relative_to(root) and candidate.is_file():
            # Vite fingerprints asset names, so they can be cached forever.
            cache = "public, max-age=31536000, immutable" if path.startswith("assets/") else None
            return FileResponse(candidate, headers={"Cache-Control": cache} if cache else None)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
