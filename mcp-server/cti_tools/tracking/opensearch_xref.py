"""Daily cross-reference of tracked-actor IPs against the lab's Zeek
logs in OpenSearch.

Pre-computes aggregate matches into the zeek_matches table so the
Stage B agent reads a handful of rows instead of querying OpenSearch
itself - that keeps query_opensearch off the MCP surface entirely.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

import duckdb

from ..opensearch_client import OpenSearchClient, OpenSearchError
from . import store

log = logging.getLogger(__name__)

_CHUNK = 512
# The lab's zeek-* mapping (checked live 2026-08-21) stores src_ip /
# dst_ip / log_file as text with a .keyword subfield; terms filters and
# aggregations both use .keyword for exact matching.
_DIRECTIONS = {"src": "src_ip.keyword", "dst": "dst_ip.keyword"}


def _day_bounds_epoch(day: date) -> tuple[float, float]:
    # Index timestamps are numeric epoch seconds (UTC); build the
    # [day, day+1) window in the same unit.
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


def _tracked_ips(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    rows = con.execute(
        """SELECT DISTINCT o.indicator_value, o.actor
           FROM observations o
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND o.actor IS NOT NULL""").fetchall()
    return {ip: actor for ip, actor in rows}


def run_daily_xref(con: duckdb.DuckDBPyConnection, day: date,
                   client: OpenSearchClient | None = None) -> dict[str, Any]:
    """Aggregate yesterday's Zeek hits per tracked IP and direction into
    zeek_matches. OpenSearch being unreachable is a skip, not a crash."""
    ip_actor = _tracked_ips(con)
    if not ip_actor:
        return {"matches": 0, "ips_checked": 0}
    client = client or OpenSearchClient()
    lo, hi = _day_bounds_epoch(day)
    ips = sorted(ip_actor)
    matches = 0
    try:
        for i in range(0, len(ips), _CHUNK):
            chunk = ips[i:i + _CHUNK]
            for direction, field in _DIRECTIONS.items():
                query = {"bool": {"filter": [
                    {"terms": {field: chunk}},
                    {"range": {"ts": {"gte": lo, "lt": hi}}},
                ]}}
                aggs = {"per_ip": {
                    "terms": {"field": field, "size": len(chunk)},
                    "aggs": {
                        "ports": {"terms": {"field": "dst_port", "size": 10}},
                        "first_ts": {"min": {"field": "ts"}},
                        "last_ts": {"max": {"field": "ts"}},
                        "log_files": {"terms": {"field": "log_file.keyword", "size": 5}},
                    },
                }}
                payload = client.search(query, size=0, aggs=aggs)
                buckets = (payload.get("aggregations", {})
                           .get("per_ip", {}).get("buckets", []))
                for bucket in buckets:
                    ip = str(bucket["key"])
                    store.upsert_zeek_match(
                        con, day=day, indicator_value=ip, direction=direction,
                        hit_count=int(bucket["doc_count"]),
                        actor=ip_actor.get(ip),
                        ports=[int(b["key"]) for b
                               in bucket.get("ports", {}).get("buckets", [])],
                        first_ts=_epoch_to_dt(bucket.get("first_ts", {}).get("value")),
                        last_ts=_epoch_to_dt(bucket.get("last_ts", {}).get("value")),
                        log_files=[str(b["key"]) for b
                                   in bucket.get("log_files", {}).get("buckets", [])])
                    matches += 1
    except OpenSearchError as e:
        log.warning("Zeek xref unavailable: %s", e)
        return {"skipped": str(e), "matches": matches, "ips_checked": len(ips)}
    return {"matches": matches, "ips_checked": len(ips)}


def _epoch_to_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
