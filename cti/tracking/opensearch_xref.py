"""Cross-reference of one day's tracked-actor IPs against the lab's Zeek
logs (Wazuh archives by default; see cti/sources/opensearch.py). Run on
request with `python -m graph xref --date`; the daily pipeline does not
run it and the digest never carries its results.

Pre-computes aggregate matches into the zeek_matches table so an agent
reads a handful of rows through query_duckdb instead of querying
OpenSearch itself - that keeps query_opensearch off the MCP surface
entirely.
"""
from __future__ import annotations

import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any

import duckdb

from ..sources.opensearch import OpenSearchClient, OpenSearchError
from .. import store

log = logging.getLogger(__name__)

_CHUNK = 512
# Logical field names; the client maps them to whichever backend holds the
# Zeek logs (exact-match fields in both, so terms filters and aggregations
# agree).
_DIRECTIONS = {"src": "src_ip", "dst": "dst_ip"}


def _day_bounds_epoch(day: date) -> tuple[float, float]:
    # Index timestamps are numeric epoch seconds (UTC); build the
    # [day, day+1) window in the same unit.
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


def _tracked_ips(con: duckdb.DuckDBPyConnection) -> dict[str, str]:
    rows = con.execute(
        """SELECT DISTINCT o.indicator_value, o.actor
           FROM observations_wide o
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND o.actor IS NOT NULL""").fetchall()
    return {ip: actor for ip, actor in rows}


def lab_vantages() -> list[str]:
    """The lab machines that connect to tracked infrastructure on purpose:
    the probe VM and the Windows client. A session from one of them to a
    tracked address is us looking at it, not it appearing in our network.
    Until this exclusion existed, the only match ever recorded was our own
    probe scanning a tracked address."""
    names = ("CTI_PROBE_ZEEK_IP", "CTI_PROBE_HOST", "CTI_WIN_ZEEK_IP", "CTI_WIN_HOST")
    return sorted({v.strip() for v in (os.environ.get(n) or "" for n in names) if v.strip()})


def collect(ip_actor: dict[str, str], day: date,
            client: OpenSearchClient) -> tuple[list[dict[str, Any]], str | None]:
    """Ask the sensor which tracked addresses it saw on `day`. Network
    only: touches no database, so the caller holds no connection while it
    runs. Returns (matches, error); matches found before an error are kept.
    """
    lo, hi = _day_bounds_epoch(day)
    ips = sorted(ip_actor)
    ours = lab_vantages()
    found: list[dict[str, Any]] = []
    try:
        for i in range(0, len(ips), _CHUNK):
            chunk = ips[i:i + _CHUNK]
            for direction, logical in _DIRECTIONS.items():
                field = client.field(logical)
                ts = client.field("ts")
                query: dict[str, Any] = {"bool": {"filter": [
                    {"terms": {field: chunk}},
                    client.ts_range(gte=lo, lt=hi),
                ]}}
                if ours:
                    query["bool"]["must_not"] = [
                        {"terms": {client.field("src_ip"): ours}}]
                aggs = {"per_ip": {
                    "terms": {"field": field, "size": len(chunk)},
                    "aggs": {
                        "ports": {"terms": {"field": client.field("dst_port"), "size": 10}},
                        "first_ts": {"min": {"field": ts}},
                        "last_ts": {"max": {"field": ts}},
                        "log_files": {"terms": {"field": client.field("log_file"), "size": 5}},
                    },
                }}
                payload = client.search(query, size=0, aggs=aggs)
                buckets = (payload.get("aggregations", {})
                           .get("per_ip", {}).get("buckets", []))
                for bucket in buckets:
                    ip = str(bucket["key"])
                    found.append(dict(
                        day=day, indicator_value=ip, direction=direction,
                        hit_count=int(bucket["doc_count"]),
                        actor=ip_actor.get(ip),
                        ports=[int(b["key"]) for b
                               in bucket.get("ports", {}).get("buckets", [])],
                        first_ts=_epoch_to_dt(client.agg_epoch(
                            bucket.get("first_ts", {}).get("value"))),
                        last_ts=_epoch_to_dt(client.agg_epoch(
                            bucket.get("last_ts", {}).get("value"))),
                        log_files=[str(b["key"]) for b
                                   in bucket.get("log_files", {}).get("buckets", [])]))
    except OpenSearchError as e:
        log.warning("Zeek xref unavailable: %s", e)
        return found, str(e)
    return found, None


def _summary(found: list[dict[str, Any]], error: str | None, checked: int) -> dict[str, Any]:
    out: dict[str, Any] = {"matches": len(found), "ips_checked": checked}
    if error:
        out["skipped"] = error
    return out


def run_daily_xref(con: duckdb.DuckDBPyConnection, day: date,
                   client: OpenSearchClient | None = None) -> dict[str, Any]:
    """Cross-reference on a connection the caller already holds. Prefer
    `run`, which does not keep the database open while the sensor answers."""
    ip_actor = _tracked_ips(con)
    if not ip_actor:
        return {"matches": 0, "ips_checked": 0}
    found, error = collect(ip_actor, day, client or OpenSearchClient())
    for match in found:
        store.upsert_zeek_match(con, **match)
    return _summary(found, error, len(ip_actor))


def run(day: date, client: OpenSearchClient | None = None) -> dict[str, Any]:
    """Which tracked addresses appeared in the lab's own traffic on `day`.

    Manual by design: the sensor only has something to say after the lab
    has generated traffic (a probe session, a detonation), so running it
    daily would mostly find nothing. `python -m graph xref --date <day>`
    calls this. Reads the tracked addresses, closes the database, queries
    the sensor, then reopens to record what it found.
    """
    with store.connect_read() as con:
        ip_actor = _tracked_ips(con)
    if not ip_actor:
        return {"matches": 0, "ips_checked": 0}
    found, error = collect(ip_actor, day, client or OpenSearchClient())
    if found:
        with store.connect_retry(read_only=False) as con:
            for match in found:
                store.upsert_zeek_match(con, **match)
    return _summary(found, error, len(ip_actor))


def _epoch_to_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
