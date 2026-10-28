from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from civicshield.api.deps import DB, CurrentUser, Net, Operator, OrgAccess
from civicshield.api.schemas import DomainCreate, DomainDetail, DomainOut
from civicshield.audit import Actor, record
from civicshield.authz.verification import instructions, new_token, scope_kind_for, verify_domain
from civicshield.config import get_settings
from civicshield.engine.net import normalize_hostname
from civicshield.models import Domain, Organization

router = APIRouter(prefix="/orgs/{org_id}/domains", tags=["domains"])


async def _get_domain(db: DB, org: Organization, domain_id: uuid.UUID) -> Domain:
    # Filtering by org_id as well as id: a valid domain id from another org is a 404.
    domain = (
        await db.execute(select(Domain).where(Domain.id == domain_id, Domain.org_id == org.id))
    ).scalar_one_or_none()
    if domain is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "domain not found")
    return domain


def _detail(domain: Domain) -> DomainDetail:
    return DomainDetail.model_validate(
        {
            **DomainOut.model_validate(domain).model_dump(),
            "instructions": instructions(domain, get_settings()),
        }
    )


@router.get("", response_model=list[DomainOut])
async def list_domains(org: OrgAccess, db: DB) -> list[Domain]:
    rows = await db.execute(select(Domain).where(Domain.org_id == org.id).order_by(Domain.name))
    return list(rows.scalars())


@router.post("", response_model=DomainDetail, status_code=status.HTTP_201_CREATED)
async def add_domain(
    body: DomainCreate, org: OrgAccess, operator: Operator, db: DB
) -> DomainDetail:
    try:
        name = normalize_hostname(
            body.name.removeprefix("https://").removeprefix("http://").split("/")[0]
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if "." not in name:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "enter a full domain name")
    domain = Domain(
        org_id=org.id,
        name=name,
        verification_method=body.verification_method,
        verification_token=new_token(),
        scope_kind=scope_kind_for(body.verification_method),
    )
    db.add(domain)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "domain already added") from exc
    await record(
        db,
        actor=Actor.user(operator),
        action="domain.added",
        target_type="domain",
        target_id=domain.id,
        org_id=org.id,
        details={"name": name, "method": body.verification_method.value},
    )
    await db.commit()
    return _detail(domain)


@router.get("/{domain_id}", response_model=DomainDetail)
async def get_domain(domain_id: uuid.UUID, org: OrgAccess, db: DB) -> DomainDetail:
    return _detail(await _get_domain(db, org, domain_id))


@router.post("/{domain_id}/verify", response_model=DomainDetail)
async def verify(
    domain_id: uuid.UUID, org: OrgAccess, user: CurrentUser, db: DB, net: Net
) -> DomainDetail:
    """Check the TXT record / file now. Staff can trigger this after publishing it."""
    domain = await _get_domain(db, org, domain_id)
    result = await verify_domain(domain, get_settings(), net)
    await record(
        db,
        actor=Actor.user(user),
        action="domain.verified" if result.ok else "domain.verification_failed",
        target_type="domain",
        target_id=domain.id,
        org_id=org.id,
        details={"name": domain.name, "detail": result.detail},
    )
    await db.commit()
    return _detail(domain)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(domain_id: uuid.UUID, org: OrgAccess, operator: Operator, db: DB) -> None:
    domain = await _get_domain(db, org, domain_id)
    await record(
        db,
        actor=Actor.user(operator),
        action="domain.deleted",
        target_type="domain",
        target_id=domain.id,
        org_id=org.id,
        details={"name": domain.name},
    )
    await db.delete(domain)
    await db.commit()
