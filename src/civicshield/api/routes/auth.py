from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from civicshield.api.deps import DB, CurrentUser, client_ip, current_session
from civicshield.api.ratelimit import SlidingWindowLimiter
from civicshield.api.schemas import LoginRequest, SessionOut, UserOut
from civicshield.audit import Actor, record
from civicshield.auth.passwords import hash_password, needs_rehash, verify_password
from civicshield.auth.sessions import SESSION_COOKIE, create_session, destroy_session
from civicshield.config import get_settings
from civicshield.models import User, UserSession

router = APIRouter(prefix="/auth", tags=["auth"])

# 10 attempts per 15 minutes per (IP, email). Keyed on both so one attacker can't lock
# out a real user from elsewhere, and one IP can't spray many accounts quickly.
login_limiter = SlidingWindowLimiter(max_events=10, window_seconds=15 * 60)


@router.post("/login", response_model=SessionOut)
async def login(body: LoginRequest, request: Request, response: Response, db: DB) -> SessionOut:
    email = body.email.lower()
    key = f"{client_ip(request)}|{email}"
    if not login_limiter.hit(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts")

    user = (
        await db.execute(
            select(User)
            .where(func.lower(User.email) == email)
            .options(selectinload(User.memberships))
        )
    ).scalar_one_or_none()
    # Always run verify_password, even for unknown users (constant-ish timing).
    ok = verify_password(user.password_hash if user else None, body.password)
    if user is None or not ok or not user.is_active:
        # One generic message: don't reveal whether the email exists.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")

    login_limiter.reset(key)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    settings = get_settings()
    token, csrf = await create_session(db, user, timedelta(hours=settings.session_ttl_hours))
    await record(
        db,
        actor=Actor.user(user),
        action="auth.login",
        target_type="user",
        target_id=user.id,
        details={"ip": client_ip(request)},
    )
    await db.commit()

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_hours * 3600,
        httponly=True,  # unreadable from JavaScript → XSS can't steal it
        secure=settings.cookie_secure,  # only sent over HTTPS
        samesite="strict",  # not sent on cross-site requests → CSRF defense
        path="/api",
    )
    return SessionOut(user=UserOut.model_validate(user), csrf_token=csrf)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: DB,
    _session: Annotated[UserSession, Depends(current_session)],
) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        await destroy_session(db, token)
        await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/api")


@router.get("/me", response_model=SessionOut)
async def me(
    session: Annotated[UserSession, Depends(current_session)], user: CurrentUser
) -> SessionOut:
    # Returning the CSRF token here lets the SPA recover it after a page reload, since we
    # deliberately keep it in memory instead of localStorage.
    return SessionOut(user=UserOut.model_validate(user), csrf_token=session.csrf_token)
