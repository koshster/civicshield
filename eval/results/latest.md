| Category | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| email | 4 | 0 | 0 | 1.00 | 1.00 |
| headers | 25 | 0 | 0 | 1.00 | 1.00 |
| tls | 8 | 0 | 0 | 1.00 | 1.00 |
| **overall** | 37 | 0 | 0 | 1.00 | 1.00 |

**False positives:** none

**False negatives:** none

**Scan status:** completed in 19s

**Check runs:** {"ok": 55}

**Requests reaching out-of-scope outside.notours.test:** 0

**Audit chain intact:** True

**Fix → rescan:** `email.dmarc.policy_none` on dmarc-none.lab.civicshield.test marked fixed; score 5 (F) → 6 (F), residual risk 593.5 → 557.5; other open issues unchanged: True

**Weekly plan after the first scan:** Renew the HTTPS certificate for expired-cert.lab.civicshield.test (Fix now: it's already affecting visitors.); Make the SPF record for spf-pass-all.lab.civicshield.test reject unknown senders (High value for the time it takes.); Install a valid, trusted certificate for self-signed.lab.civicshield.test (High value for the time it takes.)
