"""Run the evaluation inside the lab (see lab/docker-compose.lab.yml and lab/run.sh).

The harness drives CivicShield exactly as an operator would, through the real HTTP API
(in-process via ASGI): log in → create org → add domains → publish the verification TXT
records in the lab DNS → verify → record a written authorization → request a scan. Only
the Celery hop is replaced: the queued scan id is captured and ``execute_scan`` runs here.

So the eval measures detection quality *and* exercises ownership verification, scope
enforcement, and the audit trail. Then it closes the loop the product promises: it fixes
one case in the lab DNS (DMARC p=none → p=reject), rescans, and requires that the issue
is marked fixed, nothing else changed, and the org score went up. It finishes by
checking that the out-of-scope host got zero requests, then writes
eval/results/latest.{md,json} and compares against eval/baseline.json (exit code 1 on
regression).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import dns.asyncresolver
import dns.exception
import httpx
from lab.cases import OUTSIDE_HOST, ZONES, Zone
from lab.dns.render import render_zones

from civicshield.api.app import create_app
from civicshield.api.deps import get_enqueuer
from civicshield.audit import verify_chain
from civicshield.auth.passwords import hash_password
from civicshield.config import get_settings
from civicshield.db.session import get_sessionmaker
from civicshield.models import User
from civicshield.scanning import execute_scan
from eval.scoring import load_ground_truth, score, to_markdown

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab"
RESULTS = ROOT / "eval" / "results"
EMAIL, PASSWORD = "operator@lab.example", "lab-operator-password-not-secret"
# The remediation demo: this case's issue gets fixed between the two scans.
FIX_ZONE, FIX_TYPE = "dmarc-none", "email.dmarc.policy_none"


async def _wait_for_txt(name: str, needle: str, nameservers: list[str]) -> None:
    """Wait until the lab DNS serves the edited record (CoreDNS reloads every 2s)."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = nameservers
    for _ in range(30):
        try:
            answer = await resolver.resolve(name, "TXT")
            if any(needle in b"".join(r.strings).decode() for r in answer):
                return
        except dns.exception.DNSException:
            pass
        await asyncio.sleep(1)
    raise SystemExit(f"lab DNS never served the fixed record for {name}")


async def _create_operator() -> None:
    async with get_sessionmaker()() as db:
        db.add(
            User(
                email=EMAIL,
                full_name="Lab Operator",
                password_hash=hash_password(PASSWORD),
                is_operator=True,
            )
        )
        await db.commit()


async def _ok(resp: httpx.Response) -> Any:
    if resp.is_error:
        raise SystemExit(
            f"{resp.request.method} {resp.request.url.path} → {resp.status_code}: {resp.text}"
        )
    return resp.json() if resp.content else None


async def run() -> int:
    settings = get_settings()
    await _create_operator()
    queued: list[uuid.UUID] = []
    app = create_app()
    app.dependency_overrides[get_enqueuer] = lambda: queued.append

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://civicshield.lab") as api:
        me = await _ok(
            await api.post("/api/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
        )
        api.headers["X-CSRF-Token"] = me["csrf_token"]
        org = await _ok(
            await api.post("/api/v1/orgs", json={"name": "Lab Nonprofit", "slug": "lab"})
        )
        base = f"/api/v1/orgs/{org['id']}"

        # 1. Register domains and publish their verification records in the lab DNS.
        domains = [
            await _ok(await api.post(f"{base}/domains", json={"name": z.name})) for z in ZONES
        ]
        verification = {d["name"]: d["instructions"]["record_value"] for d in domains}
        render_zones(LAB / "dns" / "zones", verification)

        # 2. Verify (CoreDNS reloads within a few seconds, so retry briefly).
        pending = {d["id"] for d in domains}
        for _ in range(15):
            for did in list(pending):
                d = await _ok(await api.post(f"{base}/domains/{did}/verify"))
                if d["status"] == "verified":
                    pending.discard(did)
            if not pending:
                break
            await asyncio.sleep(2)
        if pending:
            raise SystemExit(f"{len(pending)} lab domains failed verification")

        # 3. Written authorization over exactly these domains.
        text = await _ok(await api.get("/api/v1/authorization-text"))
        await _ok(
            await api.post(
                f"{base}/authorizations",
                json={
                    "signer_name": "Lab Director",
                    "signer_title": "Executive Director",
                    "signer_email": "director@example.org",
                    "domain_ids": [d["id"] for d in domains],
                    "text_version": text["version"],
                    "text_sha256": text["sha256"],
                    "agree": True,
                    "max_impact": 2,
                    "valid_days": 1,
                },
            )
        )

        # 4. Scan (the API queues it; we play the worker).
        scan = await _ok(await api.post(f"{base}/scans"))
        started = datetime.now(UTC)
        status = await execute_scan(queued.pop(), get_sessionmaker(), settings)
        elapsed = (datetime.now(UTC) - started).total_seconds()
        detail = await _ok(await api.get(f"{base}/scans/{scan['id']}"))
        issues = await _ok(await api.get(f"{base}/issues?status=open"))
        before = await _ok(await api.get(f"{base}/overview"))

        # 5. Remediation loop: fix one case at the "DNS provider", rescan, compare.
        fixed_zone = next(z for z in ZONES if z.label == FIX_ZONE)
        zones: tuple[Zone, ...] = tuple(
            dataclasses.replace(z, dmarc=None) if z is fixed_zone else z for z in ZONES
        )
        render_zones(LAB / "dns" / "zones", verification, zones)
        await _wait_for_txt(f"_dmarc.{fixed_zone.name}", "p=reject", settings.dns_nameservers)
        await _ok(await api.post(f"{base}/scans"))
        await execute_scan(queued.pop(), get_sessionmaker(), settings)
        after = await _ok(await api.get(f"{base}/overview"))
        fixed = await _ok(await api.get(f"{base}/issues?status=fixed"))
        reopened = await _ok(await api.get(f"{base}/issues?status=open"))

    # 6. Score + safety assertions.
    found = [(i["finding_type"], i["asset"]) for i in issues]
    report = score(load_ground_truth(LAB / "ground_truth.yaml"), found)
    outside_log = LAB / "logs" / "outside-access.log"
    outside_hits = len(outside_log.read_text().splitlines()) if outside_log.exists() else -1
    async with get_sessionmaker()() as db:
        chain_ok = await verify_chain(db) is None
    errors = [r for r in detail["check_runs"] if r["status"] != "ok"]
    fixed_keys = {(i["finding_type"], i["asset"]) for i in fixed}
    open_before = {(i["finding_type"], i["asset"]) for i in issues}
    open_after = {(i["finding_type"], i["asset"]) for i in reopened}
    target = (FIX_TYPE, fixed_zone.name)
    loop_ok = (
        fixed_keys == {target}
        and open_after == open_before - {target}
        # Residual risk must strictly drop; the rounded 0-100 score must not fall.
        and after["score"]["residual_risk"] < before["score"]["residual_risk"]
        and after["score"]["score"] >= before["score"]["score"]
    )
    plan = [f"{p['action']['title']} ({p['reason']})" for p in before["plan"]]

    extra = {
        "Scan status": f"{status} in {elapsed:.0f}s",
        "Check runs": json.dumps(detail["stats"].get("check_runs", {})),
        f"Requests reaching out-of-scope {OUTSIDE_HOST}": str(outside_hits),
        "Audit chain intact": str(chain_ok),
        "Fix → rescan": (
            f"`{FIX_TYPE}` on {fixed_zone.name} "
            f"{'marked fixed' if target in fixed_keys else 'NOT marked fixed'}; "
            f"score {before['score']['score']} ({before['score']['grade']}) → "
            f"{after['score']['score']} ({after['score']['grade']}), residual risk "
            f"{before['score']['residual_risk']} → {after['score']['residual_risk']}; "
            f"other open issues unchanged: {open_after == open_before - {target}}"
        ),
        "Weekly plan after the first scan": "; ".join(plan) or "empty",
    }
    md = to_markdown(report, extra=extra)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "latest.md").write_text(md)
    summary: dict[str, Any] = {
        "precision": round(report.overall.precision, 4),
        "recall": round(report.overall.recall, 4),
        "tp": report.overall.tp,
        "fp": report.overall.fp,
        "fn": report.overall.fn,
        "out_of_scope_requests": outside_hits,
        "audit_chain_ok": chain_ok,
        "remediation_loop_ok": loop_ok,
        "score_before": before["score"]["score"],
        "score_after": after["score"]["score"],
        "check_run_errors": [f"{r['check_id']}@{r['target']}: {r['error']}" for r in errors],
    }
    (RESULTS / "latest.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(md)
    for e in summary["check_run_errors"]:
        print("check error:", e)

    # 6. Gate: safety properties are absolute; quality must not regress below baseline.
    failures = []
    if outside_hits != 0:
        failures.append(f"out-of-scope host received {outside_hits} requests")
    if not chain_ok:
        failures.append("audit chain broken")
    if not loop_ok:
        failures.append("fix → rescan didn't resolve exactly the fixed issue and lower the risk")
    baseline = json.loads((ROOT / "eval" / "baseline.json").read_text())
    for metric in ("precision", "recall"):
        if summary[metric] < baseline[metric]:
            failures.append(f"{metric} {summary[metric]} < baseline {baseline[metric]}")
    for f in failures:
        print("FAIL:", f, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
