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
from ..util import state_subdir
from . import queue, watchlist

log = logging.getLogger(__name__)

# A job is sized so that one slow chunk does not hold back the results of
# the rest: each job is collected as soon as it finishes.
JOB_CHUNK = 40
POLL_INTERVAL = 10.0
POLL_TIMEOUT = 1800.0
MAX_POLL_FAILURES = 3


def spool_dir() -> Path:
    return state_subdir("netwatch", "spool")


def plan(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group a watchlist into jobs: one profile per job, chunked. The tier
    is the profile, so hot targets scan light and full targets get the port
    sweep."""
    by_profile: dict[str, list[dict[str, Any]]] = {}
    for t in targets:
        by_profile.setdefault(t["tier"], []).append(
            {"value": t["value"], "ports": t.get("ports") or [],
             "actor": t.get("actor")})
    # Imported here: ingest imports this module for spool_dir.
    from .ingest import control_target
    control = control_target()
    jobs = []
    for profile, entries in by_profile.items():
        entries = [e for e in entries if not control or e["value"] != control[0]]
        for i in range(0, len(entries), JOB_CHUNK):
            chunk = entries[i:i + JOB_CHUNK]
            if control:
                # First, so a job cut short still carries its control scan.
                chunk = [{"value": control[0], "ports": sorted(control[1]),
                          "actor": None}] + chunk
            jobs.append({"job_id": f"{profile}-{uuid.uuid4().hex[:12]}",
                         "profile": profile, "vantage": "probe",
                         "targets": chunk})
    return jobs


def outstanding_path() -> Path:
    return state_subdir("netwatch") / "outstanding.json"


def _load_outstanding() -> list[dict[str, Any]]:
    try:
        data = json.loads(outstanding_path().read_text())
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as e:
        log.warning("unreadable %s: %s", outstanding_path(), e)
        return []
    if not isinstance(data, list):
        return []
    return [j for j in data if isinstance(j, dict) and j.get("job_id")]


def _save_outstanding(jobs: list[dict[str, Any]]) -> None:
    path = outstanding_path()
    if not jobs:
        path.unlink(missing_ok=True)
        return
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(jobs))
    tmp.replace(path)


def _spool(job_id: str) -> int:
    """Pull a finished job's records into the local spool and clear it off
    the probe. Written under a temporary name first, so ingest never loads
    half a file."""
    pulled = vm_proxy.netwatch_collect(job_id, purge=True)
    records = pulled.get("records") or []
    out = spool_dir() / f"{job_id}.jsonl"
    tmp = out.with_suffix(".part")
    with tmp.open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    tmp.replace(out)
    return len(records)


def _gather(pending: list[dict[str, Any]], *, wait: float
            ) -> tuple[list[str], int, list[dict[str, Any]]]:
    """Poll `pending` jobs together for up to `wait` seconds, spooling each
    as it finishes. Returns (spooled ids, record count, jobs still running).

    A job the probe no longer knows is dropped. One still running at the
    deadline is handed back untouched, so its results stay whole on the
    probe for the next run to collect.
    """
    spooled: list[str] = []
    total = 0
    pending = list(pending)
    deadline = time.monotonic() + wait
    failures = 0
    while pending:
        still: list[dict[str, Any]] = []
        for i, job in enumerate(pending):
            job_id = job["job_id"]
            try:
                state = vm_proxy.netwatch_status(job_id).get("state")
                if state == "done":
                    total += _spool(job_id)
                    spooled.append(job_id)
                    continue
            except vm_proxy.VMProxyError as e:
                failures += 1
                log.warning("netwatch poll failed for %s: %s", job_id, e)
                still.extend(pending[i:])
                break
            failures = 0
            if state == "unknown":
                log.warning("netwatch job %s is unknown to the probe; dropped", job_id)
                continue
            still.append(job)
        pending = still
        if (not pending or failures >= MAX_POLL_FAILURES
                or time.monotonic() + POLL_INTERVAL > deadline):
            break
        time.sleep(POLL_INTERVAL)
    return spooled, total, pending


def run(*, tiers: set[str] | None = None,
        clusters: list[str] | None = None) -> dict[str, Any]:
    """Scan every watchlist target in the given tiers through the probe and
    spool the results. Returns a summary; ingest() loads the spool.

    Every job is submitted first and then all are polled together. A job
    that outlasts the run is recorded in outstanding.json and collected at
    the start of the next run; its targets are not submitted again until it
    has been.
    """
    tiers = tiers or {"hot", "full"}
    # Jobs a previous run left on the probe: collect what has finished.
    spooled, total, late = _gather(_load_outstanding(), wait=0)
    _save_outstanding(late)
    busy = {(j.get("profile"), v) for j in late for v in j.get("values") or []}

    targets = [t for t in watchlist.for_tiers(tiers, clusters=clusters)
               if (t["tier"], t["value"]) not in busy]
    # Candidate discovery (CT, neighbourhood) drops extra targets on the
    # queue; take the ones this run's tiers cover and merge by value so a
    # queued host already on the watchlist does not scan twice.
    seen = {t["value"] for t in targets}
    queued = [t for t in queue.drain(tiers=tiers) if t["value"] not in seen]
    targets += queued
    summary: dict[str, Any] = {"targets": len(targets), "queued": len(queued),
                               "jobs": 0, "records": total, "spooled": spooled,
                               "outstanding": [j["job_id"] for j in late]}
    if not targets:
        return summary

    try:
        budget.spend("netwatch", len(targets))
    except budget.BudgetExhausted as e:
        log.warning("netwatch budget: %s", e)
        # Draining is destructive, so a refused run hands its targets back.
        queue.enqueue(queued, source="requeue")
        return {**summary, "skipped": str(e)}

    by_value = {t["value"]: t for t in queued}
    jobs = plan(targets)
    submitted = []
    for job in jobs:
        try:
            error = vm_proxy.netwatch_submit(job).get("error")
        except vm_proxy.VMProxyError as e:
            error = str(e)
        if error:
            log.warning("netwatch submit failed for %s: %s", job["job_id"], error)
            queue.enqueue([by_value[t["value"]] for t in job["targets"]
                           if t["value"] in by_value], source="requeue")
            continue
        submitted.append({"job_id": job["job_id"], "profile": job["profile"],
                          "values": [t["value"] for t in job["targets"]]})
    # Recorded before the wait, so a run killed while polling loses nothing.
    _save_outstanding(late + submitted)
    done, records, unfinished = _gather(submitted, wait=POLL_TIMEOUT)
    for job in unfinished:
        log.warning("netwatch job %s did not finish within %ss; left for the "
                    "next run", job["job_id"], POLL_TIMEOUT)
    _save_outstanding(late + unfinished)
    return {**summary, "jobs": len(submitted), "records": total + records,
            "spooled": spooled + done,
            "outstanding": [j["job_id"] for j in late + unfinished]}
