"""Server-side sessions and CSRF tokens.

Flow:
1. Login creates a random 256-bit session token. The browser gets it in an HttpOnly,
   Secure, SameSite=Strict cookie, so JavaScript (and therefore XSS) can't read it.
   The DB stores only sha256(token).
2. The response body also returns a separate CSRF token. The React app keeps it in
   memory and sends it as the ``X-CSRF-Token`` header on every state-changing request.
3. SameSite=Strict already stops modern browsers from attaching the cookie to
   cross-site requests. The CSRF header is a second, independent layer for cases
   SameSite doesn't cover (older browsers, attacks from a sibling subdomain): an
   attacker can make the browser *send* the cookie but can't *read* the CSRF token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from civicshield.models import User, UserSession

SESSION_COOKIE = "cs_session"
CSRF_HEADER = "X-CSRF-Token"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_session(db: AsyncSession, user: User, ttl: timedelta) -> tuple[str, str]:
    """Return (session_token, csrf_token). Only the hash of the session token is stored."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    db.add(
        UserSession(
            token_hash=_hash_token(token),
            user_id=user.id,
            csrf_token=csrf,
            created_at=now,
            expires_at=now + ttl,
        )
    )
    await db.flush()
    return token, csrf


async def resolve_session(db: AsyncSession, token: str | None) -> UserSession | None:
    if not token:
        return None
    session = (
        await db.execute(
            select(UserSession)
            .where(UserSession.token_hash == _hash_token(token))
            .options(selectinload(UserSession.user).selectinload(User.memberships))
        )
    ).scalar_one_or_none()
    if session is None or session.expires_at <= datetime.now(UTC) or not session.user.is_active:
        return None
    return session


async def destroy_session(db: AsyncSession, token: str) -> None:
    await db.execute(delete(UserSession).where(UserSession.token_hash == _hash_token(token)))


def csrf_matches(expected: str, provided: str | None) -> bool:
    # compare_digest runs in constant time, so response timing doesn't leak how many
    # leading characters of a guessed token were correct.
    return provided is not None and hmac.compare_digest(expected, provided)
