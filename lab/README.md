# Evaluation lab

An isolated Docker network of deliberately misconfigured web and mail-DNS targets, plus
a hardened negative control, used to measure CivicShield's precision and recall.

```bash
./lab/run.sh      # generates certs + DNS zones, builds the image, runs eval, tears down
```

Results land in `eval/results/latest.{md,json}`. The harness exits non-zero if precision
or recall drops below `eval/baseline.json`, if the out-of-scope host receives any request,
or if the audit hash chain doesn't verify.

## Isolation

- Every container is only on `labnet`, declared `internal: true`: Docker creates no
  default route, so nothing in the lab can reach the internet (and vice versa). You can
  check: `ip route` inside a target shows only `172.30.0.0/24`.
- No ports are published to the host.
- `.test` is reserved by RFC 2606, so no lab name can collide with a real domain.
- The scanner allows private IPs only because it runs with `CIVICSHIELD_ENV=lab` and
  `CIVICSHIELD_ALLOWED_PRIVATE_CIDRS=172.30.0.0/24`. Config validation rejects that
  setting in every other environment.
- The lab CA is generated fresh on each run into `lab/ca/out/` (gitignored) and is
  trusted only by the lab scanner.

## How a run works

The harness goes through the **same path as production**. It logs in through the real
API, creates an org and adds the domains. It then publishes the verification TXT values
the API hands out into the lab DNS (CoreDNS reloads the zone), verifies ownership,
records a written authorization, and requests a scan. Only the Celery hop is replaced by
calling `execute_scan` directly.

## Cases

| Zone | Target | Tests |
|---|---|---|
| `hardened` | hardened | negative control: must produce **zero** findings |
| `bad-headers` | bad-headers | missing HSTS/CSP/XFO/nosniff/Referrer/Permissions, version leak, flagless session cookie |
| `weak-tls` | weak-tls | TLS 1.0 and 1.1 enabled |
| `expired-cert` | expired-cert | certificate expired 30 days ago |
| `self-signed` | self-signed | self-signed certificate |
| `apex-redirect` | apex-redirect | apex 308s to `www`, which lacks page headers: those findings must appear on `www` only |
| `spf-missing`, `spf-pass-all`, `dmarc-missing`, `dmarc-none` | hardened | one email misconfiguration each |
| `redirector` | redirector | redirects to `outside.notours.test`, which is never authorized: must get 0 requests |

Hostnames, IPs and DNS records all come from `lab/cases.py`. Expected findings are in
`lab/ground_truth.yaml`.

## Reading the numbers honestly

The lab is small and was written alongside the checks, so a perfect score means "no
regressions on known cases", not "accurate on the real internet". The value is the gate:
every new check adds lab cases, and every change must keep the hardened control clean.
Real-world false-positive rates are tracked separately, from triage outcomes.
