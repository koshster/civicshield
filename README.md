# CivicShield

[![CI](https://github.com/koshster/civicshield/actions/workflows/ci.yml/badge.svg)](https://github.com/koshster/civicshield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**An open-source security scanner and monitor for small nonprofits, built so that it is
safe to point at the internet.**

Small nonprofits run donation pages, volunteer sign-ups and email lists with no security
staff. Their real risks are mundane: an expired certificate that breaks donations, email
that anyone can spoof in the director's name, a site that leaks session cookies on café
Wi-Fi. Commercial scanners are built for security teams. CivicShield finds these issues,
ranks them by what actually matters to a small org, and explains each fix in plain
language.

Because a scanner is also an attack tool in the wrong hands, CivicShield is built around
one rule: **it will not scan anything until ownership is proven and someone has signed
for it.**

## Safety model

| Guarantee | How it's enforced |
|---|---|
| No scan without verified ownership | DNS TXT record or a `.well-known` file, like Google Search Console. Re-verified at the start of **every** scan. |
| No scan without written authorization | A named signer agrees to a versioned authorization text. The signer, domains, text hash, time and expiry are stored immutably. Revocable by org staff at any time. |
| Never touches anything out of scope | Every network call goes through one scoped layer: scope check → resolve → reject private IPs → pin the IP (defeats DNS rebinding) → re-check every redirect hop. Checks **cannot** import `httpx`/`socket`/`ssl`, because a lint rule fails CI if they try ([ADR 0001](docs/adr/0001-network-capability-layer.md)). |
| Low impact by default | Checks declare an impact level (passive / low / active). Anything above the org's authorized level is skipped. Per-host rate limit of 2 req/s. No exploitation, brute force, credential testing or DoS, ever. |
| Everything is audited | Hash-chained, append-only audit log. A Postgres trigger blocks `UPDATE`/`DELETE`, and `civicshield verify-audit` detects tampering ([ADR 0004](docs/adr/0004-hash-chained-audit-log.md)). |
| CivicShield is itself secure | argon2id passwords, server-side sessions (only token hashes stored), HttpOnly/Secure/SameSite=Strict cookies + CSRF header, strict CSP on its own UI, per-org data isolation (cross-org access returns 404), and secrets redacted from logs. |

## Architecture

```mermaid
flowchart LR
    subgraph Browser
        UI[React + TS dashboard]
    end
    subgraph CivicShield
        API[FastAPI API<br/>auth · orgs · domains<br/>authorizations · scans]
        W[Celery worker<br/>execute_scan]
        B[Celery beat<br/>sweeper · weekly rescans]
        DB[(Postgres<br/>+ audit chain)]
        R[(Redis)]
        subgraph Engine
            RUN[Runner<br/>timeouts · isolation]
            CK[Checks<br/>TLS · headers · email]
            NET[Scoped network layer<br/>scope · SSRF · IP pinning · rate limit]
        end
    end
    T[(Verified org domains)]

    UI -- same origin, cookie + CSRF --> API
    API --> DB
    API -- enqueue after commit --> R --> W
    B --> R
    W --> RUN --> CK --> NET --> T
    W --> DB
```

A scan: the operator requests it → the API checks for a valid authorization and commits
a `queued` scan → the worker atomically claims it (safe under Celery's at-least-once
delivery) → re-verifies ownership and authorization → runs checks inside the verified
scope → diffs findings into issues (new / regressed / resolved) → writes an audit event.
Details: [ADR 0002](docs/adr/0002-celery-with-sweeper.md) and [docs/PLAN.md](docs/PLAN.md).

## Checks

| Check | What it looks for |
|---|---|
| **TLS** | Expired or soon-to-expire certificates, self-signed or untrusted chains, hostname mismatch, weak keys and signatures, TLS 1.0/1.1 and SSL 3 (via a raw ClientHello prober, independent of local OpenSSL), RC4/3DES/NULL/EXPORT/anonymous ciphers, missing HTTP→HTTPS redirect |
| **Security headers** | HSTS, CSP (parsed, so `'unsafe-inline'` is neutralized by nonces and wildcards by `'strict-dynamic'`), clickjacking protection, nosniff, Referrer-Policy, Permissions-Policy, version disclosure, and cookie flags (escalated for session-like cookies) |
| **Email** | SPF (full include-tree evaluation: 10-lookup limit, void lookups, loops, `+all`), DMARC (policy, pct, subdomain policy, reporting), DKIM (provider-aware selector discovery, key strength) |

Every finding carries evidence, references (CWE/RFC), a severity and a **confidence**,
and has a stable fingerprint, so an issue is tracked over time instead of being
re-reported each scan. An issue is only marked fixed when the same check ran
successfully on the same asset and didn't find it. "We couldn't look" is never treated
as "it's gone".

## From findings to "fix these 3 things this week"

Findings are grouped into **tasks** ("Turn on HSTS" fixes it on both `example.org` and
`www`) and ranked so a volunteer with two hours knows where to start
([ADR 0005](docs/adr/0005-prioritization.md)):

- **Risk** per issue = 100 × severity × exploitability × exposure × confidence ×
  urgency. It's multiplicative, so a probable false positive can't outrank a confirmed
  problem, and certificate expiry ramps up as the date nears.
- **Priority** = risk reduction ÷ √effort (WSJF with a damped effort term): quick wins
  first, but real severity still dominates.
- **Prerequisites:** HSTS waits for working HTTPS, and DMARC enforcement waits for
  SPF, DKIM and reporting. Blockers inherit the priority of what they unblock.
- **Weekly plan:** expired certificates are pinned to the top, then a 2-hour budget is
  filled, with at most 3 tasks and never a low-confidence guess.
- **Score** 0–100 with a letter grade, overall and per category. Accepting a risk
  doesn't raise it. Property tests guarantee that fixing an issue never lowers it.

Each task comes from a curated [remediation library](src/civicshield/remediation/library.yaml):
a plain-language "why", steps for staff, copy-paste snippets for the tech helper
(nginx, Apache, Cloudflare, Google Workspace, Microsoft 365), a verify command, and a
**"copy as email for your tech helper"** button. Every number has a "Why this rank?"
breakdown in the UI.

## Evaluation

An isolated Docker lab (`internal: true` network, no internet route) holds deliberately
misconfigured targets plus a hardened negative control. The harness drives the
**real API end to end**: it adds domains, publishes the verification TXT records in the
lab DNS, verifies, signs the authorization and scans. It then scores the issues against
[ground truth](lab/ground_truth.yaml). See [lab/README.md](lab/README.md).

| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| email | 4 | 0 | 0 | 1.00 | 1.00 |
| headers | 20 | 0 | 0 | 1.00 | 1.00 |
| tls | 8 | 0 | 0 | 1.00 | 1.00 |
| **overall** | 32 | 0 | 0 | 1.00 | 1.00 |

Requests reaching the out-of-scope host (reachable only via an in-scope redirect): **0**.
Audit chain intact: **yes**. **Fix → rescan:** the harness then fixes one case at the
lab DNS (DMARC `p=none` → `p=reject`) and rescans. Exactly that issue is marked fixed,
nothing else changes, and residual risk drops (579.5 → 543.5). CI fails if any of these
regress.

*Honest caveat:* the lab is small and was written alongside the checks, so this shows
"no regressions on known cases", not real-world accuracy.

## Quickstart

Requires Docker.

```bash
cp .env.example .env                    # dev defaults; set a real SECRET_KEY for anything else
docker compose up -d --build            # postgres, redis, migrations, api, worker, beat
docker compose run --rm api civicshield create-operator
open http://localhost:8000              # log in as the operator
```

Then, in the dashboard:

1. **Create an organization** and **add a domain** you control.
2. Follow the **verification instructions** (add the TXT record, or upload the file), then
   click *Verify*.
3. On **Authorization**, have the person responsible read and sign the authorization for
   the verified domains.
4. **Start a scan.** The overview shows the score, a "fix these this week" plan and
   every open task. Each issue page has evidence, plain-language fix steps and
   copy-paste snippets for whoever makes the change.

Everything is bound to `127.0.0.1`. Put a TLS-terminating reverse proxy in front for any
real deployment, and set `CIVICSHIELD_ENV=prod`, `CIVICSHIELD_COOKIE_SECURE=true` and a
random 32+ character `CIVICSHIELD_SECRET_KEY`.

## Development

```bash
uv sync                                  # Python 3.12 deps (incl. dev tools)
docker compose up -d postgres redis
uv run pytest                            # unit tests on SQLite (fast)
CIVICSHIELD_TEST_DATABASE_URL=postgresql+asyncpg://civicshield:civicshield@localhost:5432/civicshield_test \
  uv run pytest                          # same suite on Postgres + migration tests
uv run ruff check . && uv run ruff format --check . && uv run mypy
./lab/run.sh                             # full lab evaluation (Docker)

cd frontend && npm ci && npm run dev     # dashboard on :5173, proxies /api to :8000
```

```
src/civicshield/
  api/          FastAPI app, routes, deps (auth, CSRF, org access), security headers
  authz/        domain verification, authorization text, permission resolution
  engine/net/   the scoped network layer: scope, SSRF guard, gateway, HTTP, DNS, TLS prober
  engine/checks/ TLS, headers, email checks (gather + pure analyze)
  engine/       runner and fingerprinting
  remediation/  curated fix guidance (library.yaml) and its renderer
  prioritization.py  risk, action grouping, weekly plan, org score
  scanning.py   scan lifecycle: request, claim, execute, diff, sweeper
  worker/       Celery app and tasks
  audit/        hash-chained audit log
frontend/       React + TypeScript dashboard
lab/  eval/     isolated evaluation lab and scoring harness
docs/           PLAN.md (design + roadmap), adr/
```

## Roadmap

The MVP (phase 1) is complete. Next up: passive WordPress fingerprinting matched against
vulnerability feeds (CISA KEV, EPSS), opt-in low-impact exposure checks, an "I fixed
this" button that re-runs one check on one asset, platform-aware fix steps (Squarespace,
WordPress.com), subdomain discovery via certificate transparency, change alerts for
continuous monitoring, and an optional, guardrailed LLM layer for plain-language reports.
See [docs/PLAN.md §3](docs/PLAN.md).

## License

[MIT](LICENSE). Please read [SECURITY.md](SECURITY.md) before using it.
