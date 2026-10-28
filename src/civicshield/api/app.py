"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI

from civicshield import __version__
from civicshield.api.routes import auth, authorizations, domains, orgs, scans
from civicshield.config import get_settings
from civicshield.log import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    app = FastAPI(
        title="CivicShield",
        version=__version__,
        # Interactive docs are handy in dev but advertise the full attack surface in prod.
        docs_url="/api/docs" if settings.env != "prod" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.env != "prod" else None,
    )

    @app.get("/api/healthz", tags=["meta"])
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    for router in (auth.router, orgs.router, domains.router, authorizations.router, scans.router):
        app.include_router(router, prefix="/api/v1")

    return app
