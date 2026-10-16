"""CLI for the pipeline.

    python -m graph draw                      # write the diagrams
    python -m graph analyze --date 2026-09-18 # Stage B over an existing digest
    python -m graph analyze --date ... --dry-run   # no writes
    python -m graph collect --date 2026-09-18 # Stage A
    python -m graph daily   --date 2026-09-18 # both
    python -m graph trace   --date 2026-09-18 # summarize a recorded run
    python -m graph netwatch                  # scan the watchlist + ingest
    python -m graph netwatch --ingest-only    # just load what's spooled
    python -m graph netwatch --discover       # queue neighbourhood sweep targets
    python -m graph netwatch --certstream-seconds 120  # a bounded CT batch
    python -m graph netwatch --flowcarp       # label unnamed services via FlowCarp
    python -m graph netwatch --win116         # also fetch due hosts as a Windows client
    python -m graph netwatch --ingest-only --win116   # only the Windows-client pass
    python -m graph hunt 'tls.jarm:<hash> AND NOT net.asn:13335'   # key:value hunt
    python -m graph hunt 'net.port:8443 during:[2026-03-01,2026-04-30]' --json
    python -m graph hunt --pairs update-trellix.com            # what is it most like
    python -m graph hunt --pairs kakatown.com update-trellix.com   # what two share, when

Hunt syntax is documented in cti/store/hunt_query.py.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import date
from pathlib import Path

from cti.tracking import digest as digest_mod

from .build import build_analyze, build_collect, build_daily
from .trace import run_files, run_traced, summarize
from .viz import write_all

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_digest(day: str) -> dict:
    md = digest_mod.digest_dir() / f"{day}.md"
    js = digest_mod.digest_dir() / f"{day}.json"
    if not js.exists():
        raise SystemExit(f"no digest for {day} at {js} - run `collect` first")
    return {"digest_md": md.read_text() if md.exists() else "",
            "digest_json": json.loads(js.read_text())}


async def _run(which: str, day: str, *, dry_run: bool, skip_enrich: bool,
               force_expand: bool = False) -> int:
    state: dict = {"day": day, "dry_run": dry_run, "skip_enrich": skip_enrich,
                   "force_expand": force_expand}
    if which == "analyze":
        state.update(_load_digest(day))
        compiled = build_analyze()
    elif which == "collect":
        compiled = build_collect()
    else:
        compiled = build_daily()

    final, trace_path = await run_traced(compiled, state, day=day, stage=which)

    narrative = final.get("narrative")
    if narrative:
        out = digest_mod.narrative_dir() / f"{day}.md"
        if dry_run:
            print(f"--- narrative (dry run, not written to {out}) ---\n{narrative}")
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(narrative)
            print(f"narrative written: {out}")

    print(f"trace written: {trace_path}")
    for error in final.get("errors") or []:
        print(f"  error: {error}", file=sys.stderr)
    return 0


def _hunt(args) -> int:
    from cti import store
    from cti.store import hunt_query

    if not args.query:
        raise SystemExit("hunt needs a query, or --pairs and one or two indicators")
    try:
        if args.explain and not args.pairs:
            print(json.dumps(hunt_query.explain(" ".join(args.query)), indent=1))
            return 0
        with store.connect_retry(read_only=True) as con:
            if args.pairs:
                if len(args.query) > 2:
                    raise SystemExit("--pairs takes one indicator, or two to compare")
                out = hunt_query.pairs(con, args.query[0],
                                       args.query[1] if len(args.query) == 2 else None,
                                       limit=args.limit)
            else:
                out = hunt_query.run(con, " ".join(args.query), limit=args.limit)
    except hunt_query.QueryError as e:
        raise SystemExit(f"query error: {e}")
    if args.json:
        print(json.dumps(out, indent=1, default=str))
        return 0

    def members(ms):
        return ", ".join(f"{m['cluster']}:{m['role']}" + (f"/{m['band']}" if m.get("band") else "")
                         for m in ms) or "-"

    if args.pairs and "other" in out:
        print(f"{out['indicator']} <-> {out['other']}: {out['band']} {out['score']:.2f}")
        for e in out["evidence"]:
            gap = "overlap" if e["gap_days"] == 0 else (
                "undated" if e["gap_days"] is None else f"{e['gap_days']:.0f}d apart")
            print(f"  {e['weight']:.3f}  {e['class']:11s} {e['type']}={e['value']}  "
                  f"({gap}{'; ' + e['note'] if e.get('note') else ''})")
    elif args.pairs:
        print(f"{out['indicator']}: {out['shared_values']} shared values")
        for r in out["related"]:
            print(f"  {r['band']:9s} {r['score']:.2f}  {r['other']:40s} "
                  f"{', '.join(list(r['artefacts'])[:3]):40s} [{members(r['memberships'])}]")
    else:
        window = out["window"]
        span = (f" in [{window['from'] or '...'}, {window['to'] or '...'}]"
                if window["from"] or window["to"] else "")
        print(f"{out['total']} match(es){span}; showing {out['returned']}")
        for r in out["results"]:
            print(f"  {r['indicator']:45s} [{members(r['memberships'])}]")
            for m in r["matched"][:4]:
                print(f"      {m['type']}={str(m['value'])[:64]}  {m['from'][:10]}..{m['to'][:10]}"
                      f"  {m['source']}{'/' + m['vantage'] if m.get('vantage') else ''}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="graph", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command",
                    choices=["draw", "analyze", "collect", "daily", "trace", "netwatch",
                             "hunt"])
    ap.add_argument("query", nargs="*",
                    help="hunt: the key:value query (quote it), or with --pairs one or "
                         "two indicators")
    ap.add_argument("--pairs", action="store_true",
                    help="hunt: show what an indicator shares, with whom and when")
    ap.add_argument("--limit", type=int, default=50, help="hunt: maximum results")
    ap.add_argument("--json", action="store_true", help="hunt: print JSON")
    ap.add_argument("--explain", action="store_true", help="hunt: print the compiled SQL")
    ap.add_argument("--date", default=date.today().isoformat())
    ap.add_argument("--tiers", default="hot,full",
                    help="netwatch: which watchlist tiers to scan (comma-separated)")
    ap.add_argument("--ingest-only", action="store_true",
                    help="netwatch: skip scanning, just ingest the spool")
    ap.add_argument("--discover", action="store_true",
                    help="netwatch: queue neighbourhood sweep targets, then scan")
    ap.add_argument("--certstream-seconds", type=float, default=0.0,
                    help="netwatch: consume the CT stream for N seconds and queue "
                         "hits before scanning (needs certstream-server-go running)")
    ap.add_argument("--flowcarp", action="store_true",
                    help="netwatch: after ingest, label unnamed services with "
                         "FlowCarp over their Arkime pcap (needs the flowcarp "
                         "binary and CTI_ARKIME_*)")
    ap.add_argument("--win116", action="store_true",
                    help="netwatch: after ingest, fetch the hosts win116 is due to see "
                         "as a Windows client (needs CTI_WIN_HOST / CTI_WIN_USER)")
    ap.add_argument("--dry-run", action="store_true",
                    help="analyze without saving correlations or the narrative")
    ap.add_argument("--skip-enrich", action="store_true",
                    help="collect without the network phase")
    ap.add_argument("--expand", action="store_true",
                    help="run the weekly coverage expansion today, whatever the weekday "
                         "(CTI_EXPAND_WEEKDAY, default Monday)")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "docs",
                    help="where `draw` writes")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_intermixed_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.command == "draw":
        for name, path in write_all(args.out).items():
            print(f"{name:14s} {path}")
        return 0

    if args.command == "netwatch":
        from cti.netwatch import ingest, jobs
        if args.discover:
            from cti.netwatch.candidates import neighbourhood
            print(f"neighbourhood: {neighbourhood.enqueue()}")
        if args.certstream_seconds > 0:
            from cti.netwatch.candidates import ct
            print(f"certstream: {asyncio.run(ct.stream(seconds=args.certstream_seconds))}")
        scan = None
        if not args.ingest_only:
            scan = jobs.run(tiers={t.strip() for t in args.tiers.split(",") if t.strip()})
            print(f"scan: {scan}")
        print(f"ingest: {ingest.ingest()}")
        if args.flowcarp:
            from cti.netwatch import flowcarp
            # Scope to this run's scans when we just scanned; a standalone
            # --ingest-only --flowcarp pass labels the most recent snapshots.
            scan_ids = scan.get("spooled") if scan else None
            print(f"flowcarp: {flowcarp.label_services(scan_ids=scan_ids)}")
        if args.win116:
            from cti.netwatch import win116
            print(f"win116: {win116.run()}")
        return 0

    if args.command == "hunt":
        return _hunt(args)

    if args.command == "trace":
        files = run_files(args.date)
        if not files:
            raise SystemExit(f"no trace for {args.date} under data/runs/")
        for stage, path in files:
            summary = summarize(path)
            print(f"{stage:8s} total {summary['total_s']}s  "
                  f"slowest: {summary['slowest']}")
            for n in summary["nodes"]:
                print(f"  {n['node']:26s} {n['elapsed_s']:>8.2f}s")
        return 0

    return asyncio.run(_run(args.command, args.date,
                            dry_run=args.dry_run, skip_enrich=args.skip_enrich,
                            force_expand=args.expand))


if __name__ == "__main__":
    raise SystemExit(main())
