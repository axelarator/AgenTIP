"""Read paths: the MCP-facing query surface and the dashboard's views.

Ported from the old tracking/store.py. The SQL now reads
`observations_wide` (the compatibility view over the narrow table) so
every query is textually what it was, and the retired-provider columns
the tracked-observables CTE still referenced - shodan_ports,
vt_file_hashes - are gone from it. They were never written after the
provider swap, so they contributed nothing but confusion.
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta
from typing import Any

import duckdb

from ..errors import TrackingBusy
from ..util import rows as _rows
from .connection import connect_retry
from .writes import CORRELATION_TYPES, insert_correlation

# Row/byte caps for anything that flows back into an agent context.
QUERY_MAX_ROWS = 200
QUERY_MAX_BYTES = 20_000


def _cell(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return value


def run_readonly_query(sql: str, max_rows: int = QUERY_MAX_ROWS) -> dict[str, Any]:
    """Run an arbitrary SELECT against the tracking DB, read-only.

    Read-only enforcement is DuckDB's own read_only flag (writes
    raise), not SQL parsing. Output is capped at max_rows and
    QUERY_MAX_BYTES serialized so agent contexts can't be flooded.
    """
    try:
        with connect_retry(read_only=True) as con:
            cur = con.execute(sql)
            columns = [d[0] for d in cur.description]
            raw = cur.fetchmany(max_rows + 1)
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    except duckdb.Error as e:
        return {"error": str(e)}
    truncated = len(raw) > max_rows
    rows = [[_cell(v) for v in row] for row in raw[:max_rows]]
    kept, size = [], 2
    for row in rows:
        size += len(json.dumps(row, default=str)) + 2
        if size > QUERY_MAX_BYTES:
            truncated = True
            break
        kept.append(row)
    result: dict[str, Any] = {"columns": columns, "rows": kept,
                              "truncated": truncated}
    if truncated:
        result["note"] = (f"output capped at {len(kept)} rows / "
                          f"{QUERY_MAX_BYTES} bytes; add filters or aggregate")
    return result


def save_correlation(actor: str, correlation_type: str, indicators: list[str],
                     narrative: str, confidence: str = "medium",
                     suggested_opensearch_query: str | None = None) -> dict[str, Any]:
    """MCP-facing write path; returns an error dict instead of raising
    when the daily job holds the write lock."""
    if correlation_type not in CORRELATION_TYPES:
        return {"error": f"correlation_type must be one of "
                         f"{sorted(CORRELATION_TYPES)}"}
    if confidence not in ("high", "medium", "low"):
        return {"error": "confidence must be high, medium, or low"}
    if not indicators or not narrative.strip():
        return {"error": "indicators and narrative are both required"}
    now = datetime.now()
    try:
        with connect_retry(read_only=False) as con:
            insert_correlation(con, actor=actor, correlation_type=correlation_type,
                               indicators=indicators, narrative=narrative,
                               confidence=confidence,
                               suggested_opensearch_query=suggested_opensearch_query)
            con.execute(
                """UPDATE actors SET last_observed =
                       greatest(coalesce(last_observed, ?), ?)
                   WHERE actor_name = ?""", [now, now, actor])
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    return {"saved": True, "actor": actor, "correlation_type": correlation_type,
            "indicator_count": len(indicators)}


def actor_summary(actor: str) -> dict[str, Any]:
    """Canned aggregate for one actor - cheaper in agent tokens than
    composing the equivalent four queries through query_duckdb."""
    try:
        with connect_retry(read_only=True) as con:
            row = con.execute(
                """SELECT first_observed, last_observed, known_asns,
                          known_ports, cluster_slug, notes, tracked
                   FROM actors WHERE actor_name = ?""", [actor]).fetchone()
            if row is None:
                known = [r[0] for r in con.execute(
                    "SELECT actor_name FROM actors ORDER BY actor_name").fetchall()]
                return {"error": f"unknown actor {actor!r}", "known_actors": known}
            obs = con.execute(
                """SELECT count(*), count(DISTINCT indicator_value),
                          min(observed_at), max(observed_at)
                   FROM observations_wide WHERE actor = ?""", [actor]).fetchone()
            top_ports = con.execute(
                """SELECT port, count(*) AS n FROM (
                       SELECT unnest(cast(hl_ports AS INTEGER[])) AS port
                       FROM observations_wide
                       WHERE actor = ? AND hl_ports IS NOT NULL)
                   GROUP BY port ORDER BY n DESC, port LIMIT 10""",
                [actor]).fetchall()
            changes = con.execute(
                """SELECT detected_at, indicator_value, old_asn, new_asn,
                          change_type, confidence
                   FROM asn_changes WHERE actor = ?
                   ORDER BY detected_at DESC LIMIT 10""", [actor]).fetchall()
            zeek = con.execute(
                """SELECT day, indicator_value, direction, hit_count
                   FROM zeek_matches WHERE actor = ?
                   ORDER BY day DESC LIMIT 10""", [actor]).fetchall()
            corr = con.execute(
                "SELECT count(*) FROM correlations WHERE actor = ?",
                [actor]).fetchone()
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    return {
        "actor": actor,
        "tracked": row[6],
        "cluster_slug": row[4],
        "notes": row[5],
        "first_observed": _cell(row[0]),
        "last_observed": _cell(row[1]),
        "known_asns": json.loads(row[2] or "[]"),
        "known_ports": json.loads(row[3] or "[]"),
        "observations": {"total": obs[0], "unique_ips": obs[1],
                         "first": _cell(obs[2]), "last": _cell(obs[3])},
        "top_ports": [{"port": p, "observations": n} for p, n in top_ports],
        "recent_asn_changes": [
            {"detected_at": _cell(d), "ip": ip, "old_asn": o, "new_asn": n,
             "change_type": t, "confidence": c}
            for d, ip, o, n, t, c in changes],
        "recent_zeek_matches": [
            {"day": _cell(d), "ip": ip, "direction": dr, "hits": h}
            for d, ip, dr, h in zeek],
        "correlation_count": corr[0],
    }


_TRACKED_OBSERVABLES_SQL = """
WITH tracked_ips AS (
    SELECT DISTINCT o.indicator_value
    FROM observations_wide o
    JOIN actors a ON a.actor_name = o.actor
    WHERE a.tracked = TRUE
),
latest_actor AS (
    SELECT indicator_value, actor FROM (
        SELECT indicator_value, actor,
               row_number() OVER (PARTITION BY indicator_value
                                  ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE actor IS NOT NULL
    ) WHERE rn = 1
),
latest_hl AS (
    SELECT indicator_value, observed_at AS hl_observed_at, hl_events,
           hl_last_seen, hl_ports, hl_tags, hl_threat_level
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE source = 'honeylabs'
    ) WHERE rn = 1
),
latest_asn AS (
    -- Current ASN/netname from whichever source last reported one -
    -- RDAP is authoritative when present (see enrich.apply_results:
    -- new_asn = reg.get("asn") or hl_asn), but honeylabs' own asn/
    -- as_org is the only thing available for a quiet/absent IP RDAP
    -- was never re-checked for. Deliberately NOT scoped to
    -- source='honeylabs' - see latest_hl above, which stays
    -- honeylabs-only for the "active" freshness signal.
    SELECT indicator_value, asn, netname, country_code FROM (
        SELECT indicator_value, asn, netname, country_code,
               row_number() OVER (PARTITION BY indicator_value
                                  ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE asn IS NOT NULL
    ) WHERE rn = 1
),
latest_asn_change AS (
    -- change_type='first_seen' fires on an indicator's first-ever
    -- enrichment (enrich.apply_results: baseline is None), not an
    -- actual infrastructure pivot - excluded so "moved" means the ASN
    -- genuinely changed, not "we checked it for the first time today".
    SELECT indicator_value, detected_at AS asn_change_at, old_asn, new_asn,
           old_netname, new_netname, change_type, confidence
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY detected_at DESC) AS rn
        FROM asn_changes WHERE change_type != 'first_seen'
    ) WHERE rn = 1
),
latest_zeek AS (
    SELECT indicator_value, day AS zeek_day, direction AS zeek_direction,
           hit_count AS zeek_hit_count, last_ts AS zeek_last_ts
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
               ORDER BY day DESC, last_ts DESC NULLS LAST) AS rn
        FROM zeek_matches
    ) WHERE rn = 1
),
-- Ports used to come from this CTE's Shodan rows. Shodan InternetDB was
-- retired and nothing has written a 'shodan' observation since, so the
-- dashboard was showing port data that only got older. Ports now come
-- from the on-demand nmap scan, which is where they actually live.
latest_nmap AS (
    SELECT indicator_value, observed_at AS nmap_observed_at, nmap_ports
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE source = 'nmap'
    ) WHERE rn = 1
),
latest_threatfox AS (
    SELECT indicator_value, observed_at AS threatfox_observed_at,
           threatfox_matches
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE source = 'threatfox'
    ) WHERE rn = 1
)
SELECT t.indicator_value, la.actor,
       h.hl_observed_at, h.hl_events, h.hl_last_seen, h.hl_ports, h.hl_tags,
       h.hl_threat_level, na.asn, na.netname, na.country_code,
       c.asn_change_at, c.old_asn, c.new_asn, c.old_netname, c.new_netname,
       c.change_type, c.confidence AS asn_change_confidence,
       z.zeek_day, z.zeek_direction, z.zeek_hit_count, z.zeek_last_ts,
       s.nmap_observed_at, s.nmap_ports,
       tf.threatfox_observed_at, tf.threatfox_matches
FROM tracked_ips t
LEFT JOIN latest_actor la ON la.indicator_value = t.indicator_value
LEFT JOIN latest_hl h ON h.indicator_value = t.indicator_value
LEFT JOIN latest_asn na ON na.indicator_value = t.indicator_value
LEFT JOIN latest_asn_change c ON c.indicator_value = t.indicator_value
LEFT JOIN latest_zeek z ON z.indicator_value = t.indicator_value
LEFT JOIN latest_nmap s ON s.indicator_value = t.indicator_value
LEFT JOIN latest_threatfox tf ON tf.indicator_value = t.indicator_value
ORDER BY t.indicator_value
"""


def _tracking_status(now: datetime, row: dict[str, Any]) -> str:
    """Derived dashboard status for one indicator, in precedence order:
    in-network (touched our own traffic recently) beats active
    (HoneyLabs sensors saw it recently) beats moved (its ASN just
    changed) beats quiet/absent (no recent signal - the latter is a
    real observed-absence row, not a missing one) beats never-enriched
    (no honeylabs observation exists at all).

    Freshness uses hl_last_seen - HoneyLabs' own last-seen timestamp
    for the IP - not hl_events_7d: the HoneyLabs MCP switch normalizes
    hl_events_7d to NULL on every new row (the MCP ioc_lookup_tool
    exposes only a cumulative total, no rolling 7-day count), so that
    field is dead going forward. hl_last_seen also means the right
    thing - "a sensor actually saw this IP within N days" - where
    observed_at only means "we happened to check on this date"."""
    zeek_recent = False
    if row["zeek_last_ts"] is not None:
        zeek_recent = (now - row["zeek_last_ts"]) <= timedelta(days=1)
    elif row["zeek_day"] is not None:
        zeek_recent = (now.date() - row["zeek_day"]) <= timedelta(days=1)
    if zeek_recent:
        return "in-network"
    if row["hl_last_seen"] is not None and (now - row["hl_last_seen"]) <= timedelta(days=7):
        return "active"
    if row["asn_change_at"] is not None and (now - row["asn_change_at"]) <= timedelta(days=30):
        return "moved"
    if row["hl_observed_at"] is not None:
        return "quiet" if row["hl_events"] else "absent"
    return "never-enriched"


def tracked_observables() -> dict[str, Any]:
    """Dashboard-facing snapshot: every indicator in scope for tracking
    (mirrors enrich.build_worklist's own definition - any observation
    row carries an actor whose actors.tracked is true) with its latest
    honeylabs observation, ASN change, and Zeek match, plus a derived
    status. Not wired as an MCP tool: output is unbounded (unlike
    run_readonly_query/actor_summary, which are sized for agent
    context) and the status labels are dashboard presentation, not a
    generic query result."""
    now = datetime.now()
    try:
        with connect_retry(read_only=True) as con:
            rows = _rows(con, _TRACKED_OBSERVABLES_SQL)
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    for r in rows:
        # Status first, while timestamps are still real datetime/date
        # objects fresh off the connection - _cell() below turns them
        # into ISO strings for JSON, which _tracking_status can't diff.
        r["status"] = _tracking_status(now, r)
        for k in ("hl_observed_at", "hl_last_seen", "asn_change_at", "zeek_day", "zeek_last_ts",
                 "nmap_observed_at", "threatfox_observed_at"):
            r[k] = _cell(r[k])
        for k in ("hl_ports", "hl_tags", "nmap_ports", "threatfox_matches"):
            r[k] = json.loads(r[k]) if r[k] is not None else []
    return {"observables": rows, "count": len(rows)}


def observable_history(ip: str) -> dict[str, Any]:
    """Full time series for one indicator - every observation, ASN
    change, and Zeek match on record, oldest first. No row cap (unlike
    run_readonly_query): one indicator's history is bounded by how long
    it's been tracked, at most ~1 row/day from the daily cron. An IP
    with no rows at all still returns 200 with empty lists and
    "never-enriched" - a tracked-but-unenriched IP is a legitimate
    state, and this doesn't require the IP to already be in the
    "tracked" scope tracked_observables() uses."""
    try:
        with connect_retry(read_only=True) as con:
            observations = _rows(con,
                """SELECT observed_at, source, source_url, actor, campaign,
                          hl_events, hl_events_7d, hl_first_seen, hl_last_seen,
                          hl_ports, hl_tags, hl_threat_level,
                          nmap_ports, threatfox_matches,
                          asn, netname, country_code, abuse_contact, metadata
                   FROM observations_wide WHERE indicator_value = ?
                   ORDER BY observed_at ASC""", [ip])
            asn_changes = _rows(con,
                """SELECT detected_at, old_asn, old_netname, new_asn,
                          new_netname, change_type, confidence
                   FROM asn_changes WHERE indicator_value = ?
                   ORDER BY detected_at ASC""", [ip])
            zeek_matches = _rows(con,
                """SELECT day, direction, hit_count, ports, first_ts, last_ts
                   FROM zeek_matches WHERE indicator_value = ?
                   ORDER BY day ASC""", [ip])
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}

    now = datetime.now()
    # Status first, from raw datetime/date objects, before the loops
    # below stringify everything below for JSON (see the same ordering
    # note in tracked_observables()).
    latest_hl = next((o for o in reversed(observations) if o["source"] == "honeylabs"), None)
    # Exclude 'first_seen' rows for the same reason tracked_observables()'s
    # SQL does: they fire on an indicator's first-ever enrichment, not an
    # actual pivot, and shouldn't make "moved" fire on a fresh IP.
    latest_change = next((c for c in reversed(asn_changes) if c["change_type"] != "first_seen"), None)
    latest_zeek = zeek_matches[-1] if zeek_matches else None
    status = _tracking_status(now, {
        "hl_observed_at": latest_hl["observed_at"] if latest_hl else None,
        "hl_events": latest_hl["hl_events"] if latest_hl else None,
        "hl_last_seen": latest_hl["hl_last_seen"] if latest_hl else None,
        "asn_change_at": latest_change["detected_at"] if latest_change else None,
        "zeek_day": latest_zeek["day"] if latest_zeek else None,
        "zeek_last_ts": latest_zeek["last_ts"] if latest_zeek else None,
    })

    for o in observations:
        for k in ("observed_at", "hl_first_seen", "hl_last_seen"):
            o[k] = _cell(o[k])
        for k in ("hl_ports", "hl_tags", "nmap_ports", "threatfox_matches"):
            o[k] = json.loads(o[k]) if o[k] is not None else []
        o["metadata"] = json.loads(o["metadata"]) if o["metadata"] is not None else {}
    for c in asn_changes:
        c["detected_at"] = _cell(c["detected_at"])
    for z in zeek_matches:
        for k in ("day", "first_ts", "last_ts"):
            z[k] = _cell(z[k])
        z["ports"] = json.loads(z["ports"]) if z["ports"] is not None else []

    return {"ip": ip, "status": status, "observations": observations,
            "asn_changes": asn_changes, "zeek_matches": zeek_matches}
