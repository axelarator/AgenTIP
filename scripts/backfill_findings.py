#!/usr/bin/env python3
"""Replay findings out of run traces into the findings table.

    python scripts/backfill_findings.py [--dry-run]

Findings have always been produced; until now only the ones carrying a
correlation_type were persisted, and the rest lived in
`data/runs/<date>.*.jsonl` - a debug artifact. This recovers them.

Nothing new is computed. The indicator values in those traces are already
complete, which is the whole reason the portal can show full hashes on a
day the narrative abbreviated them.

One caveat the trace format imposes: `graph/trace.py` caps lists at 40
elements and strings at 2000 chars. A 64-character hash is unaffected, but
a finding naming more than 40 indicators would arrive short. That applies
to this historical backfill only - new runs write through persist().
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.store import connect, record_findings  # noqa: E402
from graph.trace import run_days, run_files  # noqa: E402


def findings_in(day: str) -> list[dict]:
    """Every distinct finding recorded for a day.

    Traces hold each finding TWICE - once on the per-family node
    (`analyze:cert_tls`) and again on the `analyze` subgraph rollup, which
    carries the merged state. Verified on 2026-09-21, where the bare
    `analyze` node repeated all four. Taking only namespaced nodes drops
    the rollup; the dedupe below is the backstop for any other shape.
    """
    seen: set[tuple] = set()
    out: list[dict] = []
    for _stage, path in run_files(day):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            node = row.get("node") or ""
            if row.get("event") != "node" or ":" not in node:
                continue
            output = row.get("output")
            if not isinstance(output, dict):
                continue
            for finding in output.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                key = (finding.get("family"), finding.get("headline"),
                       tuple(finding.get("indicators") or []))
                if key in seen:
                    continue
                seen.add(key)
                out.append(finding)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    total_new = 0
    for day in sorted(run_days()):
        found = findings_in(day)
        if not found:
            continue
        saved = sum(1 for f in found if f.get("correlation_type"))
        if args.dry_run:
            print(f"{day}: {len(found)} finding(s), {saved} with a correlation_type")
            for f in found:
                print(f"    [{f.get('family')}] {f.get('headline')[:78]}")
            continue
        with connect(read_only=False) as con:
            new = record_findings(con, day=date.fromisoformat(day), findings=found)
        total_new += new
        print(f"{day}: {len(found)} finding(s), {new} new, {saved} with a correlation_type")

    if not args.dry_run:
        print(f"\n{total_new} finding(s) recovered from run traces")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
