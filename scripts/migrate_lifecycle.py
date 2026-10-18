#!/usr/bin/env python3
"""One-time migration onto the indicator lifecycle.

    python scripts/migrate_lifecycle.py            # report only
    python scripts/migrate_lifecycle.py --apply    # write the cluster files

Three things, all from data already on disk - nothing is probed:

1. `last_live` and `lifecycle` on every domain and IP. `last_live` is the
   newest observation that showed the host doing something: a certificate,
   an HTTP response, or (domains only) a non-empty resolution. With none,
   the lifecycle clock runs from first_seen, the same rule the daily sweep
   applies from now on.
2. Certificate hashes. The sweep appended a dated "seen <date>" source on
   every run (one jadeprox hash has 56); those collapse to one undated
   source per domain. Of the hashes filed for a domain, only the one it
   serves today stays current; the rest are marked superseded and retired.
3. JA4L. One reading per target:port is kept, the newest.
"""
from __future__ import annotations

import re

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cti import core  # noqa: E402
from cti.store.connection import db_path  # noqa: E402
from cti.util import now_iso  # noqa: E402

LIVE_SQL = """
SELECT indicator_value, max(observed_at) AS last_live
FROM observations_wide
WHERE (source IN ('observe_tls', 'tls_live') AND tls_sha256 IS NOT NULL)
   OR (source IN ('observe_http', 'http_live') AND http_status IS NOT NULL)
   OR (source IN ('dns_resolve', 'observe_dns') AND indicator_type = 'domain'
       AND resolved_ip IS NOT NULL AND CAST(resolved_ip AS VARCHAR) NOT IN ('[]', ''))
GROUP BY indicator_value
"""


# Inlined from the retired probe_pending_fingerprints.py (2026-10-17).
_AGAINST = re.compile(r"handshake against (\S+:\d+)")


def ja4l_target(entry: dict) -> str | None:
    """The target:port a JA4L entry was measured against - from its
    `measured_for` field, or read out of the source text on entries filed
    before that field existed."""
    if entry.get("measured_for"):
        return entry["measured_for"]
    for source in entry.get("sources") or []:
        m = _AGAINST.search(source)
        if m:
            return m.group(1)
    return None


def last_live_index(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    con = duckdb.connect(str(path), read_only=True)
    try:
        rows = con.execute(LIVE_SQL).fetchall()
    finally:
        con.close()
    # The store keeps naive UTC; the cluster files keep +00:00.
    return {value.lower(): ts.replace(microsecond=0).isoformat() + "+00:00"
            for value, ts in rows if ts is not None}


def migrate_observables(data: dict, live: dict[str, str], now: str) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for cat in ("domains", "ips"):
        for o in data["observables"][cat]:
            seen = live.get(o["value"].lower())
            if seen is None and cat == "domains" and o.get("status") == "active":
                seen = o.get("status_checked")
            if seen and seen > (o.get("last_live") or ""):
                o["last_live"] = seen
            if "lifecycle" not in o:
                core._age_lifecycle(o, now, live=False)
            counts[core.lifecycle_of(o)] += 1
    return dict(counts)


def migrate_cert_hashes(data: dict, now: str) -> dict[str, int]:
    served = {o["value"]: (o.get("cert") or {}).get("sha256")
              for o in data["observables"]["domains"]}
    collapsed = superseded = 0
    by_domain: dict[str, list[dict]] = defaultdict(list)
    for h in data["observables"]["hashes"]:
        if h.get("hash_kind") != "certificate":
            continue
        before = len(h["sources"])
        kept, grabs = [], []
        for src in h["sources"]:
            if src.startswith("live TLS grab for "):
                domain = src[len("live TLS grab for "):].split(",", 1)[0]
                undated = f"live TLS grab for {domain}"
                if undated not in grabs:
                    grabs.append(undated)
            elif src not in kept:
                kept.append(src)
        h["sources"] = kept + grabs
        collapsed += before - len(h["sources"])
        h.setdefault("last_live", h.get("last_seen"))
        if h.get("cert_for"):
            by_domain[h["cert_for"]].append(h)
    for domain, hashes in by_domain.items():
        current = served.get(domain)
        if not current:
            continue
        current_value = f"cert-sha256:{current}"
        if not any(h["value"] == current_value for h in hashes):
            continue
        for h in hashes:
            if h["value"] != current_value and h.get("lifecycle") != "retired":
                h["lifecycle"] = "retired"
                h["lifecycle_since"] = now
                h["superseded_by"] = current_value
                superseded += 1
    return {"sources_collapsed": collapsed, "hashes_superseded": superseded}


def migrate_ja4l(data: dict) -> int:
    newest: dict[str, dict] = {}
    untargeted = []
    for o in data["observables"].get("ja4l", []):
        target = ja4l_target(o)
        if target is None:
            untargeted.append(o)
            continue
        o["measured_for"] = target
        if target not in newest or (o.get("last_seen") or "") > (newest[target].get("last_seen") or ""):
            newest[target] = o
    before = len(data["observables"].get("ja4l", []))
    data["observables"]["ja4l"] = untargeted + list(newest.values())
    return before - len(data["observables"]["ja4l"])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apply", action="store_true", help="write the cluster files")
    ap.add_argument("--db", type=Path, default=None, help="tracking DuckDB (default: the live one)")
    args = ap.parse_args()

    live = last_live_index(args.db or db_path())
    now = now_iso()
    with core._data_lock():
        for slug in core.list_clusters():
            data = core.load_cluster(slug)
            states = migrate_observables(data, live, now)
            certs = migrate_cert_hashes(data, now)
            ja4l = migrate_ja4l(data)
            print(f"{slug:24s} lifecycle={states} certs={certs} ja4l_dropped={ja4l}")
            if args.apply:
                data.setdefault("denylist", [])
                core.save_cluster(data)
    if not args.apply:
        print("\nreport only - rerun with --apply to write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
