"""Drive a scan batch on the probe: plan, submit, poll, collect.

The probe can never reach back here, so this is strictly outbound: submit
drops a job on the VM and returns at once, the worker scans in the
background, and collect pulls the JSONL it wrote. Results land in the local
spool (data/netwatch/spool/<scan_id>.jsonl) for ingest to load - decoupling
"got the bytes back" from "wrote them to DuckDB", so a busy write lock never
costs a scan.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from ..probe import vm_proxy
from ..sources import budget
from ..util import data_dir
from . import watchlist

log = logging.getLogger(__name__)

# One worker scans a job's targets serially, so a job is sized to stay well
# inside the collect timeout rather than to fill the day.
JOB_CHUNK = 40
POLL_INTERVAL = 10.0
POLL_TIMEOUT = 1800.0


def spool_dir() -> Path:
    d = data_dir() / "netwatch" / "spool"
    d.mkdir(parents=True, exist_ok=True)
    return d


def plan(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group a watchlist into jobs: one profile per job, chunked. The tier
    is the profile, so hot targets scan light and full targets get the port
    sweep."""
    by_profile: dict[str, list[dict[str, Any]]] = {}
    for t in targets:
        by_profile.setdefault(t["tier"], []).append(
            {"value": t["value"], "ports": t.get("ports") or [],
             "actor": t.get("actor")})
    jobs = []
    for profile, entries in by_profile.items():
        for i in range(0, len(entries), JOB_CHUNK):
            jobs.append({"job_id": f"{profile}-{uuid.uuid4().hex[:12]}",
                         "profile": profile, "vantage": "probe",
                         "targets": entries[i:i + JOB_CHUNK]})
    return jobs


def _collect(job_id: str) -> list[dict[str, Any]]:
    """Poll one job to completion, then pull and spool its records."""
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        status = vm_proxy.netwatch_status(job_id)
        if status.get("state") == "done":
            break
        time.sleep(POLL_INTERVAL)
    else:
        log.warning("netwatch job %s did not finish within %ss", job_id, POLL_TIMEOUT)
    pulled = vm_proxy.netwatch_collect(job_id, purge=True)
    records = pulled.get("records") or []
    out = spool_dir() / f"{job_id}.jsonl"
    with out.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    return records


def run(*, tiers: set[str] | None = None,
        clusters: list[str] | None = None) -> dict[str, Any]:
    """Scan every watchlist target in the given tiers through the probe and
    spool the results. Returns a summary; ingest() loads the spool."""
    tiers = tiers or {"hot", "full"}
    targets = watchlist.for_tiers(tiers, clusters=clusters)
    if not targets:
        return {"targets": 0, "jobs": 0, "records": 0, "spooled": []}

    try:
        budget.spend("netwatch", len(targets))
    except budget.BudgetExhausted as e:
        log.warning("netwatch budget: %s", e)
        return {"skipped": str(e), "targets": len(targets), "jobs": 0, "records": 0}

    jobs = plan(targets)
    spooled, total = [], 0
    for job in jobs:
        try:
            ack = vm_proxy.netwatch_submit(job)
        except vm_proxy.VMProxyError as e:
            log.warning("netwatch submit failed for %s: %s", job["job_id"], e)
            continue
        if ack.get("error"):
            log.warning("netwatch submit rejected %s: %s", job["job_id"], ack["error"])
            continue
        records = _collect(job["job_id"])
        spooled.append(job["job_id"])
        total += len(records)
    return {"targets": len(targets), "jobs": len(jobs),
            "records": total, "spooled": spooled}
