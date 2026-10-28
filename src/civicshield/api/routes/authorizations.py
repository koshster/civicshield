from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from civicshield.api.deps import DB, CurrentUser, OrgAccess, client_ip
from civicshield.api.schemas import AuthorizationCreate, AuthorizationOut, AuthorizationText
from civicshield.audit import Actor, record
from civicshield.authz import authorization_text as atext
from civicshield.enums import DomainStatus
from civicshield.models import Authorization, Domain

router = APIRouter(tags=["authorization"])


def _out(a: Authorization) -> AuthorizationOut:
    return AuthorizationOut.model_validate(
        {
            **{k: getattr(a, k) for k in AuthorizationOut.model_fields if k != "domain_names"},
            "domain_names": sorted(d.name for d in a.domains),
        }
    )


@router.get("/authorization-text", response_model=AuthorizationText)
async def current_text() -> AuthorizationText:
    return AuthorizationText(
        version=atext.CURRENT_VERSION, text=atext.get_text(), sha256=atext.text_sha256()
    )


@router.get("/orgs/{org_id}/authorizations", response_model=list[AuthorizationOut])
async def list_authorizations(org: OrgAccess, db: DB) -> list[AuthorizationOut]:
    rows = await db.execute(
        select(Authorization)
        .where(Authorization.org_id == org.id)
        .options(selectinload(Authorization.domains))
        .order_by(Authorization.granted_at.desc())
    )
    return [_out(a) for a in rows.scalars()]


@router.post(
    "/orgs/{org_id}/authorizations",
    response_model=AuthorizationOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_authorization(
    body: AuthorizationCreate, org: OrgAccess, user: CurrentUser, request: Request, db: DB
) -> AuthorizationOut:
    if not body.agree:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "you must agree to the text")
    if body.text_version != atext.CURRENT_VERSION or body.text_sha256 != atext.text_sha256():
        raise HTTPException(
            status.HTTP_409_CONFLICT, "authorization text has changed; reload and review it again"
        )
    domains = list(
        (
            await db.execute(
                select(Domain).where(Domain.id.in_(body.domain_ids), Domain.org_id == org.id)
            )
        ).scalars()
    )
    if len(domains) != len(set(body.domain_ids)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "domain not found")
    unverified = [d.name for d in domains if d.status is not DomainStatus.VERIFIED]
    if unverified:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"verify ownership first: {', '.join(unverified)}",
        )
    now = datetime.now(UTC)
    auth = Authorization(
        org_id=org.id,
        signer_name=body.signer_name,
        signer_title=body.signer_title,
        signer_email=body.signer_email.lower(),
        text_version=body.text_version,
        text_sha256=body.text_sha256,
        max_impact=body.max_impact,
        granted_at=now,
        expires_at=now + timedelta(days=body.valid_days),
        recorded_by_user_id=user.id,
        source_ip=client_ip(request),
        domains=domains,
    )
    db.add(auth)
    await db.flush()
    await record(
        db,
        actor=Actor.user(user),
        action="authorization.granted",
        target_type="authorization",
        target_id=auth.id,
        org_id=org.id,
        details={
            "signer": auth.signer_email,
            "domains": [d.name for d in domains],
            "max_impact": auth.max_impact.name,
            "text_version": auth.text_version,
            "expires_at": auth.expires_at.isoformat(),
        },
    )
    await db.commit()
    return _out(auth)


@router.post("/orgs/{org_id}/authorizations/{auth_id}/revoke", response_model=AuthorizationOut)
async def revoke_authorization(
    auth_id: uuid.UUID, org: OrgAccess, user: CurrentUser, db: DB
) -> AuthorizationOut:
    """Revoking is open to org staff too: the org must always be able to say stop."""
    auth = (
        await db.execute(
            select(Authorization)
            .where(Authorization.id == auth_id, Authorization.org_id == org.id)
            .options(selectinload(Authorization.domains))
        )
    ).scalar_one_or_none()
    if auth is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "authorization not found")
    if auth.revoked_at is None:
        auth.revoked_at = datetime.now(UTC)
        await record(
            db,
            actor=Actor.user(user),
            action="authorization.revoked",
            target_type="authorization",
            target_id=auth.id,
            org_id=org.id,
        )
        await db.commit()
    return _out(auth)
