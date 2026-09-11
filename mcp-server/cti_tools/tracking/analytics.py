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

ATTRIBUTE_CHANGES = """
SELECT detected_at, indicator_value, actor, attribute, change_type,
       old_value, new_value, confidence
FROM attribute_changes
WHERE detected_at >= current_date - INTERVAL (?) DAY
  AND change_type <> 'first_seen'
ORDER BY detected_at DESC
"""

OPEN_DIRECTORIES = """
SELECT indicator_value, actor, url, path, size, first_seen
FROM opendir_files
WHERE first_seen >= current_date - INTERVAL (?) DAY
  AND (is_dir IS NULL OR is_dir = FALSE)
ORDER BY first_seen DESC, indicator_value, path
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

# Large multi-tenant clouds where ASN co-occurrence isn't a correlation
# signal - see silver-fox.json/jadeprox.json diamond notes ("generic
# multi-tenant AWS/Aliyun... not treated as a correlation"). A stable
# enough judgment call about hosting providers in general (not
# per-actor data) that a code constant beats a DB table.
SHARED_HOSTING_ASNS = (16509, 45102, 13335)  # AWS, Alibaba Cloud, Cloudflare

# Genuinely new leads: an unattributed IP, first observed ever inside
# the window, sitting on an ASN a tracked actor is known for. Daily
# re-enrichment re-inserts a dated row for already-tracked indicators,
# so this requires the indicator's first-ever observation (not just
# today's row) to fall in the window - otherwise routine rechecks of
# old, already-attributed infrastructure masquerade as "new".
NEW_INDICATORS_IN_KNOWN_ASNS = """
WITH actor_asns AS (
    SELECT actor_name, unnest(cast(known_asns AS INTEGER[])) AS asn
    FROM actors WHERE tracked
),
window_obs AS (
    SELECT o.observed_at, o.indicator_value, o.asn, o.actor,
           a.actor_name AS matches_actor
    FROM observations o
    JOIN actor_asns a ON a.asn = o.asn
    WHERE o.observed_at >= current_date - INTERVAL (?) DAY
),
first_seen AS (
    SELECT indicator_value, min(observed_at) AS first_seen
    FROM observations GROUP BY indicator_value
)
SELECT w.observed_at, w.indicator_value, w.asn, w.matches_actor,
       fs.first_seen
FROM window_obs w
JOIN first_seen fs ON fs.indicator_value = w.indicator_value
WHERE w.actor IS NULL
  AND fs.first_seen >= current_date - INTERVAL (?) DAY
ORDER BY w.observed_at DESC
"""

# Already-attributed indicators whose ASN also appears in a DIFFERENT
# tracked actor's known_asns - a cross-actor infrastructure-overlap
# lead, never a "new IP". Excludes large shared-hosting ASNs by
# default: two unrelated actors both touching AWS/Alibaba/Cloudflare
# is expected noise, not a link (this is the exact over-firing pattern
# that produced the 2026-08-27 Silver Fox/JadeProx false lead).
CROSS_ACTOR_ASN_OVERLAP = """
WITH actor_asns AS (
    SELECT actor_name, unnest(cast(known_asns AS INTEGER[])) AS asn
    FROM actors WHERE tracked
),
first_seen AS (
    SELECT indicator_value, min(observed_at) AS first_seen
    FROM observations GROUP BY indicator_value
)
SELECT o.observed_at, o.indicator_value, o.asn, a.actor_name AS matches_actor,
       o.actor AS attributed_to, fs.first_seen
FROM observations o
JOIN actor_asns a ON a.asn = o.asn
JOIN first_seen fs ON fs.indicator_value = o.indicator_value
WHERE o.observed_at >= current_date - INTERVAL (?) DAY
  AND o.actor IS NOT NULL
  AND o.actor <> a.actor_name
  AND o.asn NOT IN ({shared_asns})
ORDER BY o.observed_at DESC
""".format(shared_asns=", ".join(str(a) for a in SHARED_HOSTING_ASNS))

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


def attribute_changes(con, days: int = 1) -> list[dict[str, Any]]:
    return _rows(con, ATTRIBUTE_CHANGES, [days])


def new_indicators_in_known_asns(con, days: int = 1) -> list[dict[str, Any]]:
    return _rows(con, NEW_INDICATORS_IN_KNOWN_ASNS, [days, days])


def cross_actor_asn_overlap(con, days: int = 1) -> list[dict[str, Any]]:
    return _rows(con, CROSS_ACTOR_ASN_OVERLAP, [days])


def temporal_clusters(con, weeks: int = 8) -> list[dict[str, Any]]:
    return _rows(con, TEMPORAL_CLUSTERS, [weeks * 7])


def open_directories(con, days: int = 1) -> list[dict[str, Any]]:
    """Files first seen in an open directory during an on-demand active
    scan within the window - the file-level detail behind the digest's
    open-directory section (the attribute_changes 'opendir_files' row only
    carries the added paths)."""
    return _rows(con, OPEN_DIRECTORIES, [days])


def run_all(con) -> dict[str, list[dict[str, Any]]]:
    return {
        "recent_actor_activity": recent_actor_activity(con),
        "asn_pivots": asn_pivots(con),
        "attribute_changes": attribute_changes(con),
        "port_patterns": port_pattern_summary(con),
        "new_indicators_in_known_asns": new_indicators_in_known_asns(con),
        "cross_actor_asn_overlap": cross_actor_asn_overlap(con),
        "temporal_clusters": temporal_clusters(con),
        "open_directories": open_directories(con),
    }
