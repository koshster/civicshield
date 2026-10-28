from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.enums import Confidence, ScopeKind, Severity, VerificationMethod
from civicshield.models import Domain, Issue, Organization


async def test_issue_roundtrip_preserves_enums_and_utc(db: AsyncSession) -> None:
    org = Organization(name="Food Bank", slug="food-bank")
    db.add(org)
    await db.flush()
    now = datetime.now(UTC)
    db.add(
        Issue(
            org_id=org.id,
            fingerprint="f" * 64,
            check_id="tls",
            finding_type="tls.cert.expired",
            asset="example.org",
            title="Expired cert",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            remediation_key="tls.renew_cert",
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    await db.commit()

    issue = (await db.execute(select(Issue))).scalar_one()
    assert issue.severity is Severity.HIGH
    assert issue.first_seen_at.tzinfo is not None
    assert issue.first_seen_at > now - timedelta(seconds=5)


async def test_severity_sorts_numerically(db: AsyncSession) -> None:
    org = Organization(name="o", slug="o")
    db.add(org)
    await db.flush()
    now = datetime.now(UTC)
    for i, sev in enumerate([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]):
        db.add(
            Issue(
                org_id=org.id,
                fingerprint=str(i),
                check_id="c",
                finding_type="t",
                asset="a",
                title="t",
                severity=sev,
                confidence=Confidence.HIGH,
                remediation_key="r",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    await db.commit()
    rows = (await db.execute(select(Issue.severity).order_by(Issue.severity.desc()))).scalars()
    assert list(rows) == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


async def test_naive_datetime_rejected(db: AsyncSession) -> None:
    org = Organization(name="o", slug="o2")
    db.add(org)
    await db.flush()
    db.add(
        Domain(
            org_id=org.id,
            name="example.org",
            verification_token="t",
            verification_method=VerificationMethod.DNS_TXT,
            scope_kind=ScopeKind.ZONE,
            verified_at=datetime.now(),
        )
    )
    with pytest.raises(Exception, match="naive datetime"):
        await db.commit()
