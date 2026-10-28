# CLAUDE.md

Guidance for AI assistants and contributors working in this repo. Read `README.md` for
what CivicShield is, and `docs/PLAN.md` + `docs/adr/` for why it's built this way.

## Non-negotiables (don't weaken these, even "temporarily")

- **No scan without verified ownership + recorded written authorization.**
  `authz/scope_builder.resolve_permission` is the only source of scan scope, and it is
  re-checked inside the worker at run time.
- **Checks never touch the network directly.** Use `ctx.http`, `ctx.dns` and `ctx.tls`
  only. Ruff TID251 bans `httpx`, `socket`, `ssl` and `dns.resolver` under
  `engine/checks/`. Don't add `noqa` to get around it. If a check needs a new
  capability, add it to `engine/net/` behind `Scope.require` + `Gateway`.
- **Passive/low-impact by default.** A new check declares its `Impact`. Nothing does
  exploitation, brute force, credential testing or DoS, and no PR should add that.
- **Every scan-affecting action writes an audit event** via `audit.record()`. The audit
  table is append-only (DB trigger), so never "fix" history.
- **Private IPs are reachable only when `env=lab`.** Don't relax `engine/net/ssrf.py` or
  the config validator.
- **Nothing sensitive in logs or audit details:** no passwords, session or verification
  tokens, or cookies. `log.redact_processor` is a backstop, not a license.
- **Org isolation:** routes get the org via the `OrgAccess` dependency. Filter every
  query by `org.id` from it, never from the request body. Return 404, not 403, for other
  orgs' resources.

## Commands

```bash
uv sync
uv run pytest                                   # SQLite, fast
CIVICSHIELD_TEST_DATABASE_URL=postgresql+asyncpg://civicshield:civicshield@localhost:5432/civicshield_test uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy   # mypy is strict
uv run alembic revision --autogenerate -m "..." # then review it; run `uv run alembic check`
./lab/run.sh                                    # lab eval (Docker); updates eval/results/
cd frontend && npm run build                    # tsc + vite
```

Use `set -o pipefail` when piping test output (`pytest | tail` hides failures otherwise).

## Code conventions

- Python 3.12, SQLAlchemy 2.x async, Pydantic v2, strict mypy, ruff (incl. bandit `S`).
- **Checks** = `meta` + `run()`, split into `gather()` (I/O through ctx) and a **pure**
  `analyze(observation) -> list[Finding]`. Test `analyze` exhaustively with hand-built
  observations; test `gather` lightly with `tests/helpers/net.make_ctx`.
- A finding's `finding_type` and `discriminator` feed its fingerprint, so **renaming
  either one resets issue history.** Add new types to `meta.finding_types`. `facts` hold
  only normalized values, never raw page content (that would allow prompt injection into
  later LLM reports).
- Bump a check's `meta.version` when its detection logic changes.
- Severity reflects a small nonprofit's realistic risk, and confidence is separate.
  Explain non-obvious calls in a comment.
- DB types: use `UTCDateTime` (rejects naive datetimes), `JSONType` and `IntEnumType`
  from `db/base.py`, so models work on both Postgres and SQLite.
- Comments explain *why* (threat, trade-off, RFC section), not what.
- New lab case → add it to `lab/cases.py` + `lab/ground_truth.yaml` (a unit test checks
  that the two agree and that every expected type exists).

## Layout

- `api/`: FastAPI app factory (`create_app`), routes, `deps.py` (session, CSRF,
  `OrgAccess`, net factory, enqueuer), `web.py` (security headers, SPA serving)
- `authz/`: verification (DNS TXT → zone scope, file → host scope), authorization text,
  permission resolution
- `engine/net/`: scope, SSRF guard, gateway (IP pinning), HTTP client, DNS, TLS prober
  plus raw ClientHello wire code
- `engine/checks/`: `tls/`, `headers/`, `email/`, and `base.py` (the interface)
- `scanning.py`: request → claim → execute → persist/diff, plus the sweeper
- `worker/celery_app.py`: Celery tasks and beat schedule
- `frontend/`: React + TS, served same-origin by the API in production
- `lab/`, `eval/`: isolated eval lab and harness (go through the real API path)

## Commits

Small, focused commits with conventional prefixes (`feat(scope):`, `fix(...)`, `test:`,
`docs:`, `ci:`). Run lint, types and tests before committing.
