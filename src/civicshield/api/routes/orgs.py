from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from civicshield.api.deps import DB, CurrentUser, Operator, OrgAccess
from civicshield.api.schemas import MemberCreate, MemberOut, OrgCreate, OrgOut, UserOut
from civicshield.audit import Actor, record
from civicshield.auth.passwords import hash_password
from civicshield.models import Membership, Organization, User

router = APIRouter(prefix="/orgs", tags=["organizations"])


@router.get("", response_model=list[OrgOut])
async def list_orgs(user: CurrentUser, db: DB) -> list[Organization]:
    query = select(Organization).order_by(Organization.name)
    if not user.is_operator:
        query = query.where(Organization.id.in_([m.org_id for m in user.memberships]))
    return list((await db.execute(query)).scalars())


@router.post("", response_model=OrgOut, status_code=status.HTTP_201_CREATED)
async def create_org(body: OrgCreate, operator: Operator, db: DB) -> Organization:
    org = Organization(name=body.name, slug=body.slug)
    db.add(org)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "slug already in use") from exc
    await record(
        db,
        actor=Actor.user(operator),
        action="org.created",
        target_type="organization",
        target_id=org.id,
        org_id=org.id,
        details={"name": org.name},
    )
    await db.commit()
    return org


@router.get("/{org_id}", response_model=OrgOut)
async def get_org(org: OrgAccess) -> Organization:
    return org


@router.get("/{org_id}/members", response_model=list[MemberOut])
async def list_members(org: OrgAccess, db: DB) -> list[MemberOut]:
    rows = (
        await db.execute(
            select(Membership)
            .where(Membership.org_id == org.id)
            .options(selectinload(Membership.user))
        )
    ).scalars()
    return [MemberOut(user=UserOut.model_validate(m.user), role=m.role) for m in rows]


@router.post("/{org_id}/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
async def add_member(body: MemberCreate, org: OrgAccess, operator: Operator, db: DB) -> MemberOut:
    """Operator creates a staff account for someone at the organization."""
    email = body.email.lower()
    user = (
        await db.execute(select(User).where(func.lower(User.email) == email))
    ).scalar_one_or_none()
    if user is None:
        user = User(
            email=email, full_name=body.full_name, password_hash=hash_password(body.password)
        )
        db.add(user)
        await db.flush()
    if await db.get(Membership, (user.id, org.id)):
        raise HTTPException(status.HTTP_409_CONFLICT, "already a member")
    db.add(Membership(user_id=user.id, org_id=org.id, role=body.role))
    await record(
        db,
        actor=Actor.user(operator),
        action="org.member_added",
        target_type="user",
        target_id=user.id,
        org_id=org.id,
        details={"email": email, "role": body.role.value},
    )
    await db.commit()
    return MemberOut(user=UserOut.model_validate(user), role=body.role)
