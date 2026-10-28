# ADR 0002: Celery + Redis for scan jobs, with an idempotent claim and a sweeper

**Status:** accepted, 2026-10-28. Supersedes the Procrastinate recommendation in PLAN §2.3.

## Context

Scans take tens of seconds to minutes and must run outside the request cycle. The plan
originally recommended a Postgres-backed queue (Procrastinate), because enqueueing in the
same transaction as the `Scan` row makes "row exists but no job" impossible. The project
owner chose the more widely used option, Celery + Redis. Two well-known consequences
have to be handled explicitly.

## Decision

1. **Commit, then enqueue.** The API commits the `Scan(status=queued)` row and only then
   sends the task. A worker can never receive an id that doesn't exist yet.
2. **The dual-write gap is closed by a sweeper.** If the process dies between commit and
   enqueue, the scan sits in `queued` with no task. A beat task every 5 minutes
   re-enqueues scans queued for more than 10 minutes, and fails scans stuck in `running`
   for more than an hour.
3. **At-least-once delivery is made safe by an idempotent claim.** With `acks_late`, a
   task can run twice (for example, after a worker crash). `execute_scan` starts with
   `UPDATE scans SET status='running' WHERE id=:id AND status='queued'`. Only the
   execution that changes a row proceeds; duplicates exit immediately. The sweeper relies
   on this too, since re-enqueueing a scan whose original task does still exist is
   harmless.
4. **Authorization is re-checked at run time, not just at queue time.** Domain ownership
   is re-verified and the authorization re-resolved when the worker starts. A revocation
   while queued produces a `blocked` scan with an audit entry.

## Consequences

- Industry-standard tooling that most reviewers already know.
- Redis is one more service to run. It's acceptable in Docker Compose.
- The sweeper and the claim are both covered by unit tests (`tests/unit/test_scanning.py`).
