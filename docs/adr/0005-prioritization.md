# ADR 0005: Rank fix actions with a transparent, multiplicative risk model

**Status:** accepted, 2026-10-28

## Context

A small nonprofit has a volunteer with maybe two hours a week. A list of 40 findings
sorted by severity doesn't tell them what to do: ten missing headers on one server are
one task, an expired certificate matters more than its "high" label suggests, and some
fixes are unsafe until others are done. The ranking also has to be explainable, because
staff won't act on a number they can't question.

## Decision

Implemented in `src/civicshield/prioritization.py` (pure functions, no I/O), with fix
guidance from the curated library in `src/civicshield/remediation/library.yaml`.

**Issue risk** (0–100) = 100 × **S**everity × **E**xploitability × e**X**posure ×
**C**onfidence × **U**rgency.

- Multiplicative, so any factor near zero sinks the result. An additive model lets a
  "critical but probably a false positive" outrank a confirmed high.
- Exploitability is an explicit table per finding type, separate from severity ("how
  likely" vs "how bad"). A test makes sure every finding type in the check registry is
  listed, so a new check can't silently fall back to a default.
- Urgency ramps from ×1 to ×2.5 over the last 30 days before a certificate expires.

**Actions.** Issues are grouped by remediation key and verified domain. An action's value
is its issues' risk with diminishing returns: each further issue counts half the
previous one, so an action is worth at most 2× its worst issue.

**Priority** = value / √effort, where effort is 1–4 from the library. This is WSJF
(Weighted Shortest Job First) with the effort term square-root-damped. Pure value/effort
lets a trivial info-level fix beat a critical one that takes an hour.

**Prerequisites** are declared in the library (`requires`) and enforced within a domain.
HSTS waits on HTTPS, the redirect and a valid certificate, because HSTS on a broken
setup locks returning visitors out with no click-through. DMARC enforcement waits on
SPF, DKIM and reporting being in place, because enforcing early sends the org's own mail
to spam. A blocker **inherits the priority** of what it blocks, as in OS priority
inheritance, so an info-level "add DMARC reporting" doesn't sit at the bottom while
holding up enforcement. It does **not** inherit confidence: a low-confidence blocker stays
out of the plan, and the UI shows what's waiting on it.

**Weekly plan.** Fix-now items (expired or not-yet-valid certificate, or one expiring
within 7 days) go first regardless of budget. The rest is a greedy fill by priority of
a time budget (default 120 min), with at most 3 items and at most 2 per category.
Low-confidence or blocked actions are never planned. If the top task alone exceeds the
budget, the plan still names it rather than coming back empty.

**Org score** = 100 · exp(−residual / 200) with letter grades, overall and per
category, where residual is the sum of action values over open **and accepted-risk**
issues. Accepting a risk is a decision, not a fix, so it doesn't raise the score.
False positives don't count. The plan had sketched 100 · (1 − residual/R), but that hits
zero for any badly configured site, and then fixing things no longer moves it. That's
demoralizing for exactly the orgs that need it most. The exponential behaves the same
for small residuals and every fix moves it.

## Consequences

- Every number in the UI can be explained from the factors. The API returns them and
  the UI shows them under "Why this rank?".
- Properties are tested with Hypothesis: fixing an issue never lowers the score (this
  holds because the decayed sum over sorted risks is monotone), and plans never contain
  blocked or low-confidence actions. The lab harness checks it end to end: fix one DNS
  record, rescan, and require that exactly that issue resolves and residual risk drops.
- The weights are judgment calls. They're written down in one table so they can be
  argued with, and phase 3 plans to validate the ranking against independent rankings
  by practitioners (Kendall's τ).
- The score is computed on read, so it can't drift from the issues. A trend chart
  needs per-scan snapshots, a later addition.
- The score aggregates every domain an org has, so an org with many broken domains sits
  near the bottom (the lab org scores 6). Per-domain scores may be worth adding when real
  orgs with several domains use it.
