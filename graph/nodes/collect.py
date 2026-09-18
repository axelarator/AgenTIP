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
from datetime import date
from typing import Any

from langgraph.types import Send

from cti import core, store
from cti.tracking import analytics, digest, enrich, ingest

log = logging.getLogger("graph.collect")


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
    sends = [Send("sweep", {"cluster": slug, "day": state.get("day")})
             for slug in state.get("clusters") or []]
    # A conditional fan-out that returns nothing does not "skip the fan-out"
    # - it strands the rest of the graph, because the edges downstream hang
    # off the node that never ran. With --skip-enrich, or with no clusters
    # registered yet, that silently produced no digest at all and reported
    # success. Route past the sweep instead of returning an empty list.
    return sends or ["enrich_and_write"]


def sweep(payload: dict) -> dict:
    """One cluster's enrichment sweep. Runs with no DB connection held -
    the writes happen in write_batch."""
    slug = payload["cluster"]
    try:
        result = core.pivot_cluster(slug)
        return {"sweep_results": [{"cluster": slug, "ok": True, "result": result}]}
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
    sections["pivot_sweep"] = {
        "clusters_swept": sum(1 for r in results if r["ok"]),
        "errors": {r["cluster"]: r["error"] for r in results if not r["ok"]},
    }

    if state.get("skip_enrich"):
        sections["pivot_sweep"] = {"clusters_swept": 0, "errors": {},
                                   "skipped": "skip_enrich"}
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
