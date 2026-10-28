"""Request dependencies: authentication, CSRF, and org-level access control."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.auth.sessions import CSRF_HEADER, SESSION_COOKIE, csrf_matches, resolve_session
from civicshield.config import get_settings
from civicshield.db.session import get_db
from civicshield.engine.net.factory import NetFactory, build_net
from civicshield.models import Organization, User, UserSession
from civicshield.scanning import Enqueue

DB = Annotated[AsyncSession, Depends(get_db)]

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def current_session(request: Request, db: DB) -> UserSession:
    session = await resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    if request.method not in SAFE_METHODS and not csrf_matches(
        session.csrf_token, request.headers.get(CSRF_HEADER)
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    return session


async def current_user(session: Annotated[UserSession, Depends(current_session)]) -> User:
    return session.user


CurrentUser = Annotated[User, Depends(current_user)]


async def require_operator(user: CurrentUser) -> User:
    if not user.is_operator:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "operator only")
    return user


Operator = Annotated[User, Depends(require_operator)]


async def org_for_user(org_id: uuid.UUID, user: CurrentUser, db: DB) -> Organization:
    """Load an org the current user may access, or 404.

    Every org-scoped route goes through this single function, so tenant isolation lives in
    one place. We return 404 (not 403) for orgs the user can't see so that probing ids
    doesn't reveal which orgs exist.
    """
    org = await db.get(Organization, org_id)
    if org is None or not (user.is_operator or any(m.org_id == org_id for m in user.memberships)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return org


OrgAccess = Annotated[Organization, Depends(org_for_user)]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def get_net_factory() -> NetFactory:
    """The network stack factory. Tests override this with fake DNS/HTTP."""
    settings = get_settings()
    return lambda scope: build_net(scope, settings)


Net = Annotated[NetFactory, Depends(get_net_factory)]


def get_enqueuer() -> Enqueue:
    """How queued scans reach the worker. Tests override this to capture scan ids."""
    from civicshield.worker.celery_app import enqueue_scan  # lazy: avoids Celery at import

    return enqueue_scan


Enqueuer = Annotated[Enqueue, Depends(get_enqueuer)]
