"""Rebuild selector_spans from what the store already holds.

Three sources, most precise first:

1. netwatch - service_snapshots keeps every scan's record, so each scan is
   re-derived through the same `observe.selectors_from` the live ingest
   uses, and the spans come out exactly as a live run would have built them.
2. mnemonic passive DNS - the observation rows keep every record with its
   own first/last. `net.historical_ip` was stamped with the day we asked;
   here it gets the record's window, and the `selectors` fold is corrected
   to match.
3. everything else - rows recorded before spans existed have only one
   first/last pair. Each becomes one span over that window. That is the
   least precise of the three and is labelled as such in the summary: it
   asserts continuous presence it never observed. New observations refine
   it from here on.

Dry run by default. `--apply` backs the database file up first, then
replaces the spans table's contents (idempotent: run it twice, get the same
table).

    .venv/bin/python scripts/backfill_spans.py           # what would change
    .venv/bin/python scripts/backfill_spans.py --apply
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti import store  # noqa: E402
from cti.netwatch.ingest import _observe_result  # noqa: E402
from cti.sources import observe as observe_source  # noqa: E402
from cti.store import cdn as cdn_ranges  # noqa: E402
from cti.store import spans  # noqa: E402
from cti.store.selectors import SET_VALUED, normalize  # noqa: E402


def _netwatch(con) -> list[tuple]:
    out = []
    grouped: dict[tuple[str, str], list[dict]] = {}
    for scan_id, target, record, ja4s in con.execute(
            "SELECT scan_id, target, record, ja4s FROM service_snapshots "
            "ORDER BY scanned_at").fetchall():
        rec = json.loads(record) if isinstance(record, str) else (record or {})
        if ja4s:
            rec["_ja4s"] = ja4s
        grouped.setdefault((scan_id, target), []).append(rec)
    for (_scan, target), records in grouped.items():
        passive = {r["port"]: {"ja4s": r["_ja4s"]} for r in records
                   if r.get("_ja4s") and r.get("port")}
        result = _observe_result(records, passive)
        if not (result["http"] or result["tls"] or result["ports"]):
            continue
        kind = "ip" if records[0].get("ip") == target else "domain"
        when = spans.to_ts(records[0].get("ts"))
        vantage = records[0].get("vantage") or "probe"
        for stype, value in observe_source.selectors_from(result, target=target, kind=kind):
            values = [value] if stype in SET_VALUED or not isinstance(
                value, (list, tuple, set)) else list(value)
            for one in values:
                norm = normalize(stype, one)
                if norm is not None:
                    out.append((stype, norm, target, "netwatch", vantage, when, when))
    return out


def _pdns(con) -> list[tuple]:
    out = []
    for indicator, payload in con.execute(
            "SELECT indicator_value, payload->'$.pdns_records' FROM observations "
            "WHERE source = 'mnemonic_pdns' AND indicator_type = 'domain'").fetchall():
        for rec in json.loads(payload or "[]"):
            if rec.get("rrtype") not in ("a", "aaaa"):
                continue
            answer = rec.get("answer")
            if not answer or cdn_ranges.is_cdn(answer):
                continue
            start, end = spans.to_ts(rec.get("first_seen")), spans.to_ts(rec.get("last_seen"))
            if start is None:
                continue
            out.append(("net.historical_ip", normalize("net.historical_ip", answer),
                        indicator, "mnemonic_pdns", None, start, end or start))
    return out


def _legacy(con, covered: set[tuple[str, str, str]]) -> list[tuple]:
    out = []
    for stype, value, indicator, source, first, last in con.execute(
            "SELECT selector_type, selector_value, indicator_value, source, "
            "first_seen, last_seen FROM selectors").fetchall():
        if (stype, value, indicator) in covered or first is None:
            continue
        out.append((stype, value, indicator, source or "unknown", None, first, last or first))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    with store.connect(read_only=not args.apply) as con:
        precise = _netwatch(con) + _pdns(con)
        covered = {(t, v, i) for t, v, i, *_ in precise}
        legacy = _legacy(con, covered)
        summary = Counter(source for _t, _v, _i, source, *_ in precise)
        print(f"precise observations: {len(precise)} "
              f"({', '.join(f'{k} {v}' for k, v in summary.most_common())})")
        print(f"legacy single-window rows: {len(legacy)} (one span each, least precise)")

        latest: dict[tuple[str, str, str], datetime] = {}
        for t, v, i, source, _vantage, _start, end in precise:
            if source == "mnemonic_pdns":
                latest[(t, v, i)] = max(end, latest.get((t, v, i), end))
        stale = sum(1 for (t, v, i), end in latest.items() if con.execute(
            "SELECT 1 FROM selectors WHERE selector_type = ? AND selector_value = ? "
            "AND indicator_value = ? AND last_seen > ?", [t, v, i, end]).fetchone())
        print(f"net.historical_ip rows ({len(latest)} distinct) dated later than their "
              f"own pDNS window, to be re-dated: {stale}")

        if not args.apply:
            print("dry run - nothing written. Re-run with --apply.")
            return 0

        db = store.db_path()
        backup = db.with_name(f"{db.name}.bak-{datetime.now():%Y%m%d-%H%M%S}-pre-spans")
        con.execute("CHECKPOINT")
        shutil.copy2(db, backup)
        print(f"backed up to {backup}")

        con.execute("DELETE FROM selector_spans")
        # A precise observation whose fold row is missing (pDNS records the
        # live path filtered differently) gets one, so no span is orphaned.
        for stype, value, indicator, source, _vantage, start, end in precise:
            con.execute(
                "INSERT INTO selectors (selector_type, selector_value, indicator_value, "
                "source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT DO NOTHING", [stype, value, indicator, source, start, end])
        for stype, value, indicator, source, vantage, start, end in precise + legacy:
            spans.record(con, selector_type=stype, selector_value=value,
                         indicator_value=indicator, source=source, start=start,
                         end=end, vantage=vantage)
        # The fold follows its spans, so first/last stop claiming a date
        # nothing observed.
        con.execute("""
            UPDATE selectors SET first_seen = f.s, last_seen = f.e
            FROM (SELECT selector_type, selector_value, indicator_value,
                         min(start_at) AS s, max(end_at) AS e
                  FROM selector_spans GROUP BY 1, 2, 3) f
            WHERE selectors.selector_type = f.selector_type
              AND selectors.selector_value = f.selector_value
              AND selectors.indicator_value = f.indicator_value""")
        n = con.execute("SELECT count(*) FROM selector_spans").fetchone()[0]
        print(f"wrote {n} spans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
