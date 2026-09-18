"""CLI for the pipeline.

    python -m graph draw                      # write the diagrams
    python -m graph analyze --date 2026-09-18 # Stage B over an existing digest
    python -m graph analyze --date ... --dry-run   # no writes
    python -m graph collect --date 2026-09-18 # Stage A
    python -m graph daily   --date 2026-09-18 # both
    python -m graph trace   --date 2026-09-18 # summarize a recorded run
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
from .trace import runs_dir, summarize
from .trace import run_traced
from .viz import write_all

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_digest(day: str) -> dict:
    md = digest_mod.digest_dir() / f"{day}.md"
    js = digest_mod.digest_dir() / f"{day}.json"
    if not js.exists():
        raise SystemExit(f"no digest for {day} at {js} - run `collect` first")
    return {"digest_md": md.read_text() if md.exists() else "",
            "digest_json": json.loads(js.read_text())}


async def _run(which: str, day: str, *, dry_run: bool, skip_enrich: bool) -> int:
    state: dict = {"day": day, "dry_run": dry_run, "skip_enrich": skip_enrich}
    if which == "analyze":
        state.update(_load_digest(day))
        compiled = build_analyze()
    elif which == "collect":
        compiled = build_collect()
    else:
        compiled = build_daily()

    final, trace_path = await run_traced(compiled, state, day=day)

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


def main() -> int:
    ap = argparse.ArgumentParser(prog="graph", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["draw", "analyze", "collect", "daily", "trace"])
    ap.add_argument("--date", default=date.today().isoformat())
    ap.add_argument("--dry-run", action="store_true",
                    help="analyze without saving correlations or the narrative")
    ap.add_argument("--skip-enrich", action="store_true",
                    help="collect without the network phase")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "docs",
                    help="where `draw` writes")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.command == "draw":
        for name, path in write_all(args.out).items():
            print(f"{name:14s} {path}")
        return 0

    if args.command == "trace":
        path = runs_dir() / f"{args.date}.jsonl"
        summary = summarize(path)
        if not summary["nodes"]:
            raise SystemExit(f"no trace at {path}")
        print(f"run {summary['day']}  total {summary['total_s']}s  "
              f"slowest: {summary['slowest']}")
        for n in summary["nodes"]:
            print(f"  {n['node']:22s} {n['elapsed_s']:>8.2f}s")
        return 0

    return asyncio.run(_run(args.command, args.date,
                            dry_run=args.dry_run, skip_enrich=args.skip_enrich))


if __name__ == "__main__":
    raise SystemExit(main())
