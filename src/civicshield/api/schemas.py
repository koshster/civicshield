"""Pydantic request/response models for the JSON API.

Responses are explicit schemas rather than ORM objects, so a new column (say, a
password hash) can never leak into an API response just because it was added to a model.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field

from civicshield.enums import (
    CheckRunStatus,
    Confidence,
    DomainStatus,
    Impact,
    IssueStatus,
    Role,
    ScanStatus,
    ScanTrigger,
    ScopeKind,
    Severity,
    VerificationMethod,
)

_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _slug(v: str) -> str:
    if not _SLUG.match(v):
        raise ValueError("slug must be lowercase letters, digits and single hyphens")
    return v


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth -------------------------------------------------------------------------
class LoginRequest(BaseModel):
    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=1024)]


class UserOut(ORM):
    id: uuid.UUID
    email: str
    full_name: str
    is_operator: bool


class SessionOut(BaseModel):
    user: UserOut
    csrf_token: str


# --- orgs -------------------------------------------------------------------------
class OrgCreate(BaseModel):
    name: Annotated[str, Field(min_length=2, max_length=200)]
    slug: Annotated[str, Field(min_length=2, max_length=80), AfterValidator(_slug)]


class OrgOut(ORM):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class MemberCreate(BaseModel):
    email: EmailStr
    full_name: Annotated[str, Field(max_length=200)] = ""
    password: Annotated[str, Field(min_length=12, max_length=1024)]
    role: Role = Role.ORG_STAFF


class MemberOut(BaseModel):
    user: UserOut
    role: Role


# --- domains & authorization ---------------------------------------------------------
class DomainCreate(BaseModel):
    name: Annotated[str, Field(min_length=3, max_length=253)]
    verification_method: VerificationMethod = VerificationMethod.DNS_TXT


class DomainOut(ORM):
    id: uuid.UUID
    name: str
    verification_method: VerificationMethod
    status: DomainStatus
    scope_kind: ScopeKind
    verified_at: datetime | None
    last_checked_at: datetime | None
    last_check_error: str | None


class VerificationInstructions(BaseModel):
    method: VerificationMethod
    summary: str
    steps: list[str]
    record_name: str | None = None
    record_value: str | None = None
    file_url: str | None = None
    file_contents: str | None = None


class DomainDetail(DomainOut):
    instructions: VerificationInstructions


class AuthorizationText(BaseModel):
    version: str
    text: str
    sha256: str


class AuthorizationCreate(BaseModel):
    signer_name: Annotated[str, Field(min_length=2, max_length=200)]
    signer_title: Annotated[str, Field(min_length=2, max_length=200)]
    signer_email: EmailStr
    domain_ids: Annotated[list[uuid.UUID], Field(min_length=1)]
    text_version: str
    # The signer must echo the hash of the exact text they were shown. This proves the
    # client displayed the current text, not a stale or altered copy.
    text_sha256: str
    max_impact: Impact = Impact.PASSIVE
    valid_days: Annotated[int, Field(ge=1, le=366)] = 365
    agree: bool


class AuthorizationOut(ORM):
    id: uuid.UUID
    signer_name: str
    signer_title: str
    signer_email: str
    text_version: str
    max_impact: Impact
    granted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    domain_names: list[str]


# --- scans ------------------------------------------------------------------------
class ScanOut(ORM):
    id: uuid.UUID
    status: ScanStatus
    trigger: ScanTrigger
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    stats: dict[str, Any]


class CheckRunOut(ORM):
    check_id: str
    check_version: str
    target: str
    status: CheckRunStatus
    duration_ms: int
    error: str | None


class ScanDetail(ScanOut):
    check_runs: list[CheckRunOut]
    new_issue_ids: list[uuid.UUID] = []
    resolved_issue_ids: list[uuid.UUID] = []


class IssueOut(ORM):
    id: uuid.UUID
    check_id: str
    finding_type: str
    asset: str
    title: str
    severity: Severity
    confidence: Confidence
    status: IssueStatus
    remediation_key: str
    facts: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None


class ObservationOut(ORM):
    scan_id: uuid.UUID
    created_at: datetime
    evidence: list[Any]
    references: list[Any]


class IssueDetail(IssueOut):
    observations: list[ObservationOut]


class AuditEventOut(ORM):
    id: int
    created_at: datetime
    actor_label: str
    action: str
    target_type: str
    target_id: str
    details: dict[str, Any]
