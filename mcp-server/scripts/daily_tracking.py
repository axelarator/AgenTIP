#!/usr/bin/env python3
"""Stage A of the daily actor-tracking loop - pure Python, zero agent
tokens. Run from cron (see setup.sh output) or manually:

    mcp-server/.venv/bin/python mcp-server/scripts/daily_tracking.py
    ... --seed          # one-time: import actors/IPs from the cluster store
    ... --date 2026-08-20   # backfill xref/analytics for a past day
    ... --skip-enrich   # no network calls (fast local re-run)
    ... --dry-run       # report what would be enriched, write nothing

Sequence: init schema -> ingest inbox -> register new clusters (any
data/clusters/*.json not yet tracked) -> pivot sweep (RDAP/RIPEstat/
Shodan/ThreatFox lifecycle+port check for every cluster, via
core.pivot_cluster) -> enrich (worklist, then the paced network loop
with NO db connection held, then one write batch) -> Zeek xref ->
analytics -> digest. Every phase failure is recorded in the digest and
the run continues; the exit code is nonzero only if the digest itself
cannot be written, so cron mail stays meaningful.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti_tools.tracking import analytics, digest, enrich, ingest, store  # noqa: E402
from cti_tools.tracking.opensearch_xref import run_daily_xref  # noqa: E402

log = logging.getLogger("daily_tracking")

RETENTION_DAYS = 180


def _prune_old_files(*dirs: Path) -> None:
    cutoff = time.time() - RETENTION_DAYS * 86400
    for d in dirs:
        if not d.is_dir():
            continue
        for path in d.iterdir():
            try:
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--date", type=date.fromisoformat, default=date.today())
    parser.add_argument("--seed", action="store_true",
                        help="import actors/IPs from the JSON cluster store")
    parser.add_argument("--skip-enrich", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # One httpx INFO line per MCP call would swamp the cron log.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    day: date = args.date
    sections: dict = {"status": {}}

    def phase(name: str, fn):
        try:
            result = fn()
            sections["status"][name] = "ok"
            return result
        except Exception as e:  # keep going; the digest records the failure
            log.exception("phase %s failed", name)
            sections["status"][name] = f"FAILED: {e}"
            return None

    if args.dry_run:
        with store.connect() as con:
            worklist, rdap_due = enrich.build_worklist(con)
        print(f"would enrich {len(worklist)} IPs "
              f"({len(rdap_due)} due a registry lookup): {worklist[:20]}"
              + (" ..." if len(worklist) > 20 else ""))
        return 0

    if args.seed:
        def _seed():
            with store.connect() as con:
                return ingest.seed_from_clusters(con)
        result = phase("seed", _seed)
        log.info("seed: %s", result)

    def _ingest():
        with store.connect() as con:
            return ingest.ingest_inbox(con)
    sections["ingest"] = phase("ingest", _ingest)

    def _register():
        with store.connect() as con:
            return ingest.register_new_clusters(con)
    sections["register"] = phase("register", _register)

    if not args.skip_enrich:
        def _pivot_sweep():
            from cti_tools import core  # deferred: pulls in the whole cluster stack
            errors: dict[str, str] = {}
            swept = 0
            for slug in core.list_clusters():
                try:
                    core.pivot_cluster(slug)
                except Exception as e:  # one bad cluster shouldn't sink the sweep
                    errors[slug] = str(e)
                else:
                    swept += 1
            return {"clusters_swept": swept, "errors": errors}
        sections["pivot_sweep"] = phase("pivot_sweep", _pivot_sweep)

        def _enrich():
            with store.connect() as con:
                worklist, rdap_due = enrich.build_worklist(con)
            log.info("enriching %d IPs (%d due registry lookup)",
                     len(worklist), len(rdap_due))
            # Slow paced network loop - deliberately outside any
            # connection so the MCP server isn't locked out meanwhile.
            results, notes = enrich.enrich_ips(worklist, rdap_due)
            sections["enrich_notes"] = notes
            with store.connect() as con:
                return enrich.apply_results(con, results, day)
        sections["enrich"] = phase("enrich", _enrich)

    def _xref():
        # Cross-reference *yesterday's* logs relative to the run date:
        # the 6:15 run sees a complete day of traffic for day-1.
        with store.connect() as con:
            return run_daily_xref(con, day - timedelta(days=1))
    sections["zeek"] = phase("zeek_xref", _xref)

    def _analytics():
        with store.connect() as con:
            results = analytics.run_all(con)
            results["zeek_matches"] = [
                dict(zip(("day", "indicator_value", "actor", "direction",
                          "hit_count", "ports"), row))
                for row in con.execute(
                    """SELECT day, indicator_value, actor, direction,
                              hit_count, ports
                       FROM zeek_matches WHERE day >= ?
                       ORDER BY hit_count DESC""",
                    [day - timedelta(days=1)]).fetchall()]
            return results
    analytics_result = phase("analytics", _analytics) or {}
    sections.update(analytics_result)

    try:
        path = digest.write(day, sections)
    except Exception:
        log.exception("digest write failed")
        return 1
    log.info("digest written: %s", path)

    _prune_old_files(digest.digest_dir(),
                     digest.digest_dir().parent / "logs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
