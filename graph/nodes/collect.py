"""Stage A as graph nodes: deterministic, no model involved.

Ported from scripts/daily_tracking.py, which ran this as a straight
sequence. The one structural change is `sweep`: the old loop swept eight
clusters strictly one after another, each internally parallel across its
own observables but never across clusters. Here the clusters fan out.

Everything else keeps the old shape deliberately, including the rule that
a failed phase is recorded and the run continues - the exit code is
nonzero only when the digest itself cannot be written, so cron mail stays
meaningful.

There is no model in this subgraph. It is here so that the diagram covers
the whole pipeline rather than just the judgement half, which is the
thing that was hardest to see at runtime.
"""
from __future__ import annotations

import logging
import os
from datetime import date
from typing import Any

from langgraph.types import Send

from cti import core, store
from cti.tracking import analytics, digest, enrich, ingest

log = logging.getLogger("graph.collect")


# What the sweep needs from the environment. The probe settings gate it: with
# them missing, every lookup goes to a default address that is not this lab's
# probe VM, fails, and is recorded as "unknown" - and pivot_cluster writes
# that status back over the cluster's real one. The keys only degrade it.
PROBE_ENV = ("CTI_PROBE_HOST", "CTI_PROBE_USER", "CTI_PROBE_SSH_KEY",
             "CTI_PROBE_KNOWN_HOSTS")
KEY_ENV = ("WEBAMON_API_KEY", "HONEYLABS_API_KEY")


def preflight(env=None) -> tuple[str, list[str]]:
    """("ok" | "warning: ..." | "blocked: ...", the missing variable names).

    Added after the first scheduled run (2026-09-19) collected nothing. The
    crontab lines this project printed omitted `. $HOME/.bashrc &&`, which the
    old crontab had and which is where every key and probe setting lives, so
    cron ran with none of them. The sweep "succeeded" for 7 of 8 clusters,
    wrote zero observations (406 the day before), and overwrote 82 observables'
    statuses with "unknown". Nothing in the digest said so: a lookup that
    cannot reach its source fails into an error dict, which the sweep treats
    as a result.
    """
    env = os.environ if env is None else env
    probe_missing = [v for v in PROBE_ENV if not env.get(v)]
    key_missing = [v for v in KEY_ENV if not env.get(v)]
    hint = "is cron sourcing ~/.bashrc?"
    if probe_missing:
        return (f"blocked: sweep skipped, missing {', '.join(probe_missing)} - "
                f"every lookup would fail and overwrite real statuses with "
                f"'unknown' ({hint})", probe_missing + key_missing)
    if key_missing:
        return (f"warning: missing {', '.join(key_missing)} - those sources "
                f"will be skipped ({hint})", key_missing)
    return "ok", []


def _day(state: dict) -> date:
    """State carries the day as an ISO string so one state type serves
    both subgraphs; the store wants a date."""
    value = state.get("day")
    return date.fromisoformat(value) if isinstance(value, str) else (value or date.today())


def _phase(sections: dict, name: str, fn, *args, **kwargs):
    """Record the outcome and keep going. A single dead source must not
    cost the whole day's collection."""
    try:
        result = fn(*args, **kwargs)
        sections.setdefault("status", {})[name] = "ok"
        return result
    except Exception as e:                      # noqa: BLE001 - see docstring
        log.exception("phase %s failed", name)
        sections.setdefault("status", {})[name] = f"failed: {e}"
        return None


def ingest_inbox(state: dict) -> dict:
    sections: dict[str, Any] = {}

    def _ingest():
        with store.connect() as con:
            return ingest.ingest_inbox(con)

    def _register():
        with store.connect() as con:
            return ingest.register_new_clusters(con)

    sections["ingest"] = _phase(sections, "ingest", _ingest) or {}
    sections["register"] = _phase(sections, "register", _register) or {}
    verdict, missing = preflight()
    sections.setdefault("status", {})["preflight"] = verdict
    if verdict != "ok":
        log.error("preflight: %s", verdict)
    return {"sections": sections, "clusters": core.list_clusters()}


def fan_out_clusters(state: dict) -> list[Send]:
    """One `sweep` invocation per cluster, dispatched together.

    This is the biggest throughput change in Stage A. Each cluster's
    sweep is minutes of probe-VM round-trips that do not touch any other
    cluster's data, and they were serialized only because a for-loop is
    the obvious way to write it.

    `skip_enrich` stops the fan-out entirely, not just the enrichment
    phase. Its help text promises "no network calls", and the sweep is
    where most of the network calls are - the first port of this kept only
    the enrichment half of that guard, so --skip-enrich still spent
    minutes probing.
    """
    if state.get("skip_enrich"):
        return ["enrich_and_write"]
    if _sweep_blocked(state):
        return ["enrich_and_write"]
    sends = [Send("sweep", {"cluster": slug, "day": state.get("day")})
             for slug in state.get("clusters") or []]
    # A conditional fan-out that returns nothing does not "skip the fan-out"
    # - it strands the rest of the graph, because the edges downstream hang
    # off the node that never ran. With --skip-enrich, or with no clusters
    # registered yet, that silently produced no digest at all and reported
    # success. Route past the sweep instead of returning an empty list.
    return sends or ["enrich_and_write"]


# Above this share of "unknown" lifecycle statuses, a sweep is treated as
# having failed rather than as reporting on the infrastructure. Yesterday's
# real distribution had 1 unknown in 148; the failed run had 82 of 82.
UNKNOWN_ALARM = 0.5


def _unknown_share(results: list[dict]) -> tuple[int, int]:
    unknown = checked = 0
    for r in results:
        if not r.get("ok"):
            continue
        for cat in ("domains", "ips"):
            for row in (r.get("result") or {}).get(cat) or []:
                checked += 1
                unknown += row.get("status") == "unknown"
    return unknown, checked


def _sweep_blocked(state: dict) -> bool:
    status = ((state.get("sections") or {}).get("status") or {}).get("preflight", "")
    return str(status).startswith("blocked")


def sweep(payload: dict) -> dict:
    """One cluster's enrichment sweep.

    The network phase holds no DB connection, but the sweep is NOT
    write-free: core.pivot_cluster records enrichment history itself at the
    end. An earlier version of this docstring said all writes happen in
    write_batch, which was wrong, and the design leaned on it. Concurrent
    writers are safe because the store serialises read-write connections
    (cti/store/connection.py), not because sweeps don't write.
    """
    slug = payload["cluster"]
    try:
        result = core.pivot_cluster(slug)
        return {"sweep_results": [{
            "cluster": slug, "ok": True, "result": result,
            # pivot_cluster's history write is best-effort and reports its
            # failure as a note rather than raising. It has to be lifted out
            # here or it vanishes: the sweep "succeeded", the cluster JSON is
            # current, and the DuckDB history that change detection depends
            # on quietly is not.
            "history_note": (result or {}).get("history_note"),
        }]}
    except Exception as e:                      # noqa: BLE001
        log.exception("sweep failed for %s", slug)
        return {"sweep_results": [{"cluster": slug, "ok": False, "error": str(e)}]}


def enrich_and_write(state: dict) -> dict:
    """The network enrichment phase, then the single write batch.

    The split is load-bearing and predates this rewrite: build the
    worklist, do the network work holding no connection, then take one
    connection and write everything. DuckDB is process-exclusive for
    read-write, so holding it across minutes of HTTP would block the MCP
    server the analyst is using.
    """
    sections = dict(state.get("sections") or {})
    results = state.get("sweep_results") or []
    errors = {r["cluster"]: r["error"] for r in results if not r["ok"]}
    history_errors = {r["cluster"]: r["history_note"] for r in results
                      if r["ok"] and r.get("history_note")}
    sections["pivot_sweep"] = {
        "clusters_swept": sum(1 for r in results if r["ok"]),
        "errors": errors,
        "history_errors": history_errors,
    }
    # The digest only renders phases whose status is not "ok". The sweep
    # used to set no status at all, so a cluster that failed (fox-tempest,
    # 2026-09-19) sat in pivot_sweep.errors while the phase block read
    # all-ok - visible only to someone who opened the JSON.
    unknown, checked = _unknown_share(results)
    sections["pivot_sweep"]["unknown"] = {"unknown": unknown, "checked": checked}
    problems = len(errors) + len(history_errors)
    if _sweep_blocked(state):
        status = "blocked by preflight - see the preflight line above"
    elif checked and unknown / checked >= UNKNOWN_ALARM:
        status = (f"{unknown} of {checked} observables came back 'unknown' - "
                  f"that is a source outage or a bad environment, not "
                  f"infrastructure going dark; the cluster statuses were "
                  f"overwritten")
    elif problems:
        status = (f"{len(errors)} cluster(s) failed, {len(history_errors)} without "
                  f"recorded history: {', '.join(sorted({*errors, *history_errors}))}")
    else:
        status = "ok"
    sections.setdefault("status", {})["pivot_sweep"] = status

    if state.get("skip_enrich"):
        # Annotate, don't replace: replacing threw away the errors computed
        # a few lines up. It only looked right because skipping normally
        # means there were no sweep results to lose.
        sections["pivot_sweep"]["skipped"] = "skip_enrich"
        sections["enrich"] = {"skipped": True}
        return {"sections": sections}

    def _enrich():
        with store.connect() as con:
            worklist, rdap_due = enrich.build_worklist(con)
        log.info("enriching %d IPs (%d due registry lookup)",
                 len(worklist), len(rdap_due))
        # The paced network loop, deliberately outside any connection so
        # the MCP server the analyst is using isn't locked out meanwhile.
        results, notes = enrich.enrich_ips(worklist, rdap_due)
        sections["enrich_notes"] = notes
        with store.connect() as con:
            return enrich.apply_results(con, results, _day(state))

    sections["enrich"] = _phase(sections, "enrich", _enrich) or {}
    return {"sections": sections}


def run_analytics(state: dict) -> dict:
    sections = dict(state.get("sections") or {})
    def _analytics():
        with store.connect() as con:
            return analytics.run_all(con)

    sections.update(_phase(sections, "analytics", _analytics) or {})
    return {"sections": sections}


def write_digest(state: dict) -> dict:
    """The digest file, plus its contents loaded into state so the
    analyze subgraph can read it without touching the disk again."""
    import json

    path = digest.write(_day(state), state.get("sections") or {})
    return {"digest_path": str(path),
            "digest_md": path.read_text(),
            "digest_json": json.loads(path.with_suffix(".json").read_text())}
