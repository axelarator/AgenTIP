"""Pre-built analytics over the tracking DB.

Each query lives in a named module constant so the actor-tracking
skill can cite it verbatim, and each function returns a list of plain
dicts sized for the daily digest (callers cap rows before rendering).
"""
from __future__ import annotations

import json
from typing import Any

import duckdb

RECENT_ACTOR_ACTIVITY = """
SELECT actor,
       count(DISTINCT indicator_value) AS unique_ips,
       max(observed_at) AS last_activity,
       count(*) AS total_observations
FROM observations
WHERE actor IS NOT NULL
  AND observed_at >= current_date - INTERVAL (? ) DAY
GROUP BY actor
ORDER BY last_activity DESC
"""

ASN_PIVOTS = """
SELECT detected_at, actor, indicator_value,
       old_asn, new_asn, old_netname, new_netname, confidence,
       count(*) OVER (PARTITION BY actor, detected_at) AS pivot_count
FROM asn_changes
WHERE change_type = 'asn_change'
  AND detected_at >= current_date - INTERVAL (?) DAY
ORDER BY detected_at DESC, pivot_count DESC
"""

PORT_PATTERN_SUMMARY = """
SELECT actor, port,
       count(DISTINCT indicator_value) AS ip_count,
       max(observed_at) AS last_seen
FROM (
    SELECT actor, indicator_value, observed_at,
           unnest(cast(hl_ports AS INTEGER[])) AS port
    FROM observations
    WHERE hl_ports IS NOT NULL AND actor IS NOT NULL
)
GROUP BY actor, port
ORDER BY actor, ip_count DESC, port
"""

NEW_IPS_IN_KNOWN_ASNS = """
WITH actor_asns AS (
    SELECT actor_name, unnest(cast(known_asns AS INTEGER[])) AS asn
    FROM actors WHERE tracked
)
SELECT o.observed_at, o.indicator_value, o.asn,
       a.actor_name AS matches_actor, o.actor AS attributed_to
FROM observations o
JOIN actor_asns a ON a.asn = o.asn
WHERE o.observed_at >= current_date - INTERVAL (?) DAY
  AND (o.actor IS NULL OR o.actor <> a.actor_name)
ORDER BY o.observed_at DESC
"""

TEMPORAL_CLUSTERS = """
WITH weekly AS (
    SELECT actor,
           date_trunc('week', observed_at) AS week,
           count(DISTINCT indicator_value) AS ips
    FROM observations
    WHERE actor IS NOT NULL
      AND observed_at >= current_date - INTERVAL (?) DAY
    GROUP BY actor, week
),
stats AS (
    SELECT actor, median(ips) AS median_ips, count(*) AS weeks_active
    FROM weekly GROUP BY actor
)
SELECT w.actor, w.week, w.ips, s.median_ips, s.weeks_active
FROM weekly w
JOIN stats s USING (actor)
WHERE s.weeks_active >= 2 AND w.ips > 2 * s.median_ips
ORDER BY w.week DESC, w.ips DESC
"""


def _rows(con: duckdb.DuckDBPyConnection, sql: str,
          params: list[Any] | None = None) -> list[dict[str, Any]]:
    cur = con.execute(sql, params or [])
    columns = [d[0] for d in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


def recent_actor_activity(con, days: int = 30) -> list[dict[str, Any]]:
    return _rows(con, RECENT_ACTOR_ACTIVITY, [days])


def asn_pivots(con, days: int = 7) -> list[dict[str, Any]]:
    return _rows(con, ASN_PIVOTS, [days])


def port_pattern_summary(con, actor: str | None = None) -> list[dict[str, Any]]:
    rows = _rows(con, PORT_PATTERN_SUMMARY)
    return [r for r in rows if actor is None or r["actor"] == actor]


def new_ips_in_known_asns(con, days: int = 1) -> list[dict[str, Any]]:
    return _rows(con, NEW_IPS_IN_KNOWN_ASNS, [days])


def temporal_clusters(con, weeks: int = 8) -> list[dict[str, Any]]:
    return _rows(con, TEMPORAL_CLUSTERS, [weeks * 7])


def run_all(con) -> dict[str, list[dict[str, Any]]]:
    return {
        "recent_actor_activity": recent_actor_activity(con),
        "asn_pivots": asn_pivots(con),
        "port_patterns": port_pattern_summary(con),
        "new_ips_in_known_asns": new_ips_in_known_asns(con),
        "temporal_clusters": temporal_clusters(con),
    }
