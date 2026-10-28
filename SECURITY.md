# Security policy

## Reporting a vulnerability in CivicShield

Please **don't open a public issue**. Use GitHub's private vulnerability reporting
(Security → Report a vulnerability) on this repository. You'll get an acknowledgement
within 7 days. Please allow 90 days for a fix before public disclosure.

In scope: anything that would let someone scan without verified ownership and written
authorization, reach hosts outside the authorized scope (SSRF, redirect or DNS-rebinding
bypasses), read another organization's data, tamper with the audit log undetected, or
recover credentials or tokens.

## Using CivicShield responsibly

CivicShield is a defensive tool for organizations assessing **their own** websites:

- It refuses to scan a domain until ownership is verified and a named person has
  recorded written authorization for it.
- Default checks are passive or low-impact: reading headers, TLS configuration, DNS
  records and public pages.
- It never attempts exploitation, brute-forcing, credential testing or denial of service,
  and contributions adding such capabilities will not be accepted.

Scanning systems you don't own or have permission to test may be illegal where you live.
