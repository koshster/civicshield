# ADR 0001: All scanner network access goes through one scoped capability layer

**Status:** accepted, 2026-10-28

## Context

The most important promise CivicShield makes is that it never touches anything outside
the domains an organization has verified and authorized. Checks are written by different
people over time. If any check can call `httpx.get()` or open a socket, the promise depends
on every author remembering the rules, on every code path, forever.

Two attacks matter in particular:

- **SSRF / DNS rebinding.** A verified domain can be re-pointed at `127.0.0.1`, a cloud
  metadata address or an internal network, and the scanner then attacks itself or its
  host.
- **Redirect escape.** An in-scope page redirects to a third party, and a naive client
  follows it.

## Decision

Checks get a `CheckContext` holding three objects: `http`, `dns` and `tls`. These are
the *only* way to reach the network, and each one is built for one scan's `Scope`:

- `Scope.require(host)` runs before any resolution. DNS-verified domains cover their
  subdomains; file-verified domains cover exactly one host (see ADR 0003).
- `Gateway.resolve_pinned` resolves A/AAAA, rejects any non-public address (including
  IPv4-mapped IPv6), and pins the validated IP for the rest of the scan. Later
  connections reuse it, so a rebinding DNS answer between "check" and "use" has no
  effect. The HTTP client connects to the pinned IP but keeps the original `Host` header
  and SNI.
- Every redirect hop is re-checked against scope. An out-of-scope hop is recorded in the
  result (`redirect_blocked_to`) and never requested.
- A per-host token bucket enforces politeness (default 2 req/s, burst 5).

The rule is **enforced by lint, not by convention.** Ruff's `banned-api` rule (TID251)
forbids `httpx`, `socket`, `ssl` and `dns.resolver` inside `src/civicshield/engine/checks/`.
A check that tries to bypass the layer fails CI.

## Consequences

- Checks are easy to test: hand them a context with a `FakeResolver` and mocked
  transports. Most check logic lives in pure `analyze()` functions with no I/O at all.
- The lab eval asserts the property end to end: an in-scope host redirects to an
  unauthorized one, and that host's access log must stay empty.
- Private ranges can be allowed only when `CIVICSHIELD_ENV=lab`, and config validation
  rejects them anywhere else.
- Cost: low-level probes (the raw TLS ClientHello prober) had to be written against the
  gateway's pinned connections instead of reusing off-the-shelf tools like `sslyze`.
  That's more code, but it's also independent of the local OpenSSL build, which
  usually can't even offer TLS 1.0 anymore.
