# ADR 0003: What a verification method proves defines what it authorizes

**Status:** accepted, 2026-10-28

## Context

Ownership is verified like Google Search Console does it: a DNS TXT record or an
uploaded file. These prove different things.

- Publishing a TXT record at `_civicshield-verification.example.org` requires control of
  the **DNS zone**, which implies control of every name in it.
- Serving `/.well-known/civicshield-verification.txt` from `www.example.org` proves
  control of **that one web host**. Shared hosting, a subdirectory CMS or a misconfigured
  proxy could let someone place a file on a host they don't otherwise own.

## Decision

- DNS TXT → `ScopeKind.ZONE`: the apex and all subdomains, with a dot-boundary match so
  `example.org` never covers `badexample.org`.
- HTTP file → `ScopeKind.HOST_ONLY`: exactly that hostname.
- The file check fetches with a scope of only that host, so a redirect to another site
  can't satisfy verification.
- Verification must be fresh (default 30 days). It is re-checked at the start of every
  scan, and a previously verified domain that fails becomes `failed`, which pauses scans.
- Email checks (SPF/DMARC/DKIM) need zone-level DNS data, so they run only on ZONE
  targets.

## Consequences

Small orgs that can't edit DNS can still use the file method, and get web checks on that
host only. The UI explains the difference when an operator picks a method.
