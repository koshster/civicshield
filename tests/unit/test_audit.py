from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from civicshield.audit import GENESIS_HASH, Actor, record, verify_chain
from civicshield.models import AuditEvent


async def test_chain_links_and_detects_tampering(db: AsyncSession) -> None:
    actor = Actor.system("test")
    first = await record(db, actor=actor, action="a.one", target_type="t", target_id="1")
    second = await record(
        db, actor=actor, action="a.two", target_type="t", target_id="2", details={"n": 1}
    )
    await db.commit()
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert await verify_chain(db) is None

    # Simulate an attacker editing history (SQLite has no append-only trigger).
    await db.execute(
        update(AuditEvent).where(AuditEvent.id == first.id).values(details={"edited": True})
    )
    await db.commit()
    db.expire_all()
    assert await verify_chain(db) == first.id
