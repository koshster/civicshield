# ADR 0004: A hash-chained, append-only audit log

**Status:** accepted, 2026-10-28

## Context

Every scan, authorization, verification and status change must leave a record. For a
security tool the log is also evidence ("we had written permission for exactly these
domains at that time"), so it needs to be tamper-evident, not just present.

## Decision

- Each `AuditEvent` stores `hash = sha256(prev_hash || canonical_json(event))`. Editing
  or deleting any row breaks every later hash. `civicshield verify-audit` recomputes the
  chain and reports the first bad event.
- A Postgres trigger rejects `UPDATE` and `DELETE` on the table outright.
- Writers take a transaction-scoped advisory lock, so two concurrent events can't both
  chain off the same predecessor.
- Events have no foreign keys: an audit record must outlive the org, user or scan it
  describes.
- Details are structured and never include secrets (verification tokens, passwords,
  session tokens). The log processor redacts them as a second line of defense.

## Consequences

A database superuser can still rewrite the whole chain. Anchoring the head hash
externally (for example, periodically emailed to the org) is a phase-5 item. The eval
harness asserts that the chain verifies after a full lab run.
