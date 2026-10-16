"""When an indicator carried a selector value, as intervals.

`selectors` holds one row per (type, value, indicator) with a single
first/last_seen, and that fold loses the one fact that decides whether a
shared value is a lead: whether the two holders had it AT THE SAME TIME.
kakatown.com sat on 192.252.186.62 from 2019-08 to 2020-08; the JadeProx
vendor trio arrived there in 2026-04. As one first/last pair per indicator,
"both resolved there" read as a link. As intervals it is a 5.7-year gap.

A span is one unbroken stretch of observations from one source. A new
observation extends the span it lands inside or next to; one that lands
past the gap tolerance opens a new span, so a value that went away and came
back is two facts, not one long one.

Passive sources (passive DNS, Validin, scan indexes) hand over their own
first/last window. Those are recorded as given rather than stamped with the
time we happened to ask, which is what `history._log_passive` used to do -
every historical address got today's date, the opposite of history.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import duckdb

from ..util import rows

SCHEMA = """
CREATE SEQUENCE IF NOT EXISTS selector_spans_seq;
CREATE TABLE IF NOT EXISTS selector_spans (
    id              BIGINT PRIMARY KEY DEFAULT nextval('selector_spans_seq'),
    selector_type   TEXT NOT NULL,
    selector_value  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    source          TEXT NOT NULL,
    vantage         TEXT,
    start_at        TIMESTAMP NOT NULL,
    end_at          TIMESTAMP NOT NULL,
    observations    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS span_lookup ON selector_spans (selector_type, selector_value);
CREATE INDEX IF NOT EXISTS span_indicator ON selector_spans (indicator_value);
"""

# How far apart two observations from one source may be and still be one
# span. Scan-derived selectors are re-observed daily (hourly for the hot
# tier), so three days tolerates a missed run or two without merging a real
# absence. Passive sources report their own windows: those merge only when
# the windows actually touch.
SCAN_GAP = timedelta(days=3)
PASSIVE_GAP = timedelta(0)

# Sources whose timestamps are somebody else's observation window rather
# than the moment we looked.
PASSIVE_SOURCES = frozenset({"mnemonic_pdns", "validin", "validin_dns",
                             "validin_cert", "webamon", "internetdb"})


def gap_for(source: str | None) -> timedelta:
    return PASSIVE_GAP if (source or "") in PASSIVE_SOURCES else SCAN_GAP


def to_ts(value: Any) -> datetime | None:
    """A naive-UTC datetime from whatever a caller holds.

    DuckDB TIMESTAMP is naive, and the store writes UTC throughout. Epoch
    integers are accepted because Validin and mnemonic both hand them over
    (seconds and milliseconds respectively; a value past year 3000 in
    seconds is taken to be milliseconds).
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 32_503_680_000 else value
        dt = datetime.fromtimestamp(seconds, timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def record(con: duckdb.DuckDBPyConnection, *, selector_type: str,
           selector_value: str, indicator_value: str, source: str | None,
           start: Any, end: Any = None, vantage: str | None = None) -> int:
    """Fold one observation window into the spans. Returns the span id.

    `selector_value` must already be normalized - this is called from
    `selectors.record`, which owns normalization. Every span the new window
    touches (within the source's gap) is merged into one, so out-of-order
    writes - a backfill landing after live data - still converge.
    """
    source = source or "unknown"
    start_dt = to_ts(start)
    end_dt = to_ts(end) or start_dt
    if start_dt is None:
        raise ValueError("a span needs a start time")
    if end_dt < start_dt:
        start_dt, end_dt = end_dt, start_dt
    gap = gap_for(source)

    touching = con.execute(
        """SELECT id, start_at, end_at, observations FROM selector_spans
           WHERE selector_type = ? AND selector_value = ? AND indicator_value = ?
             AND source = ? AND coalesce(vantage, '') = coalesce(?, '')
             AND start_at <= ? AND end_at >= ?
           ORDER BY start_at""",
        [selector_type, selector_value, indicator_value, source, vantage,
         end_dt + gap, start_dt - gap]).fetchall()

    if not touching:
        return con.execute(
            """INSERT INTO selector_spans (selector_type, selector_value,
                   indicator_value, source, vantage, start_at, end_at, observations)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1) RETURNING id""",
            [selector_type, selector_value, indicator_value, source, vantage,
             start_dt, end_dt]).fetchone()[0]

    keep, *extra = touching
    new_start = min([start_dt] + [r[1] for r in touching])
    new_end = max([end_dt] + [r[2] for r in touching])
    count = sum(r[3] for r in touching) + 1
    con.execute("UPDATE selector_spans SET start_at = ?, end_at = ?, observations = ? "
                "WHERE id = ?", [new_start, new_end, count, keep[0]])
    if extra:
        con.execute(f"DELETE FROM selector_spans WHERE id IN "
                    f"({', '.join('?' for _ in extra)})", [r[0] for r in extra])
    return keep[0]


def spans_for(con: duckdb.DuckDBPyConnection, *, indicator_value: str | None = None,
              selector_type: str | None = None, selector_value: str | None = None
              ) -> list[dict[str, Any]]:
    clauses, params = [], []
    for column, value in (("indicator_value", indicator_value),
                          ("selector_type", selector_type),
                          ("selector_value", selector_value)):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return rows(con, f"SELECT * FROM selector_spans {where} "
                     f"ORDER BY selector_type, selector_value, indicator_value, start_at",
                params)


def gap_days(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> float:
    """Days between two intervals; 0.0 when they overlap or touch."""
    (a0, a1), (b0, b1) = a, b
    if a0 <= b1 and b0 <= a1:
        return 0.0
    gap = (b0 - a1) if b0 > a1 else (a0 - b1)
    return gap.total_seconds() / 86400


def closest_gap(mine: list[tuple[datetime, datetime]],
                theirs: list[tuple[datetime, datetime]]) -> float | None:
    """The smallest gap between any of one holder's spans and any of
    another's. None when either side has no spans."""
    if not mine or not theirs:
        return None
    return min(gap_days(a, b) for a in mine for b in theirs)
