"""Write paths other than observations and attribute changes.

Ported from the old tracking/store.py. Two behavioural fixes, both
called out at their call sites:

* upsert_opendir_files no longer issues a SELECT per file (it was two
  round-trips per entry, so a 2000-file listing meant 4000 statements).
* every JSON-valued argument goes through one encoder instead of the
  module-private _json.
"""
from __future__ import annotations

import json
from typing import Any

import duckdb

from ..errors import TrackingBusy
from .connection import connect_retry

CORRELATION_TYPES = {"asn_pivot", "port_pattern", "temporal_cluster",
                     "new_infrastructure", "shared_fingerprint", "zeek_hit"}


def _json(value: Any) -> str | None:
    """A caller may pass an already-serialized string; pass it through
    rather than double-encoding it."""
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)


def latest_asn_for(con: duckdb.DuckDBPyConnection, ip: str,
                   before) -> dict[str, Any] | None:
    """Most recent prior observation of `ip` that carried an ASN,
    strictly before `before` - the baseline for change detection."""
    row = con.execute(
        """SELECT observed_at, asn, netname, source FROM observations_wide
           WHERE indicator_value = ? AND asn IS NOT NULL AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [ip, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "asn": row[1], "netname": row[2],
            "source": row[3]}


def record_asn_change(con: duckdb.DuckDBPyConnection, *, detected_at,
                      indicator_value: str, change_type: str, confidence: str,
                      actor: str | None = None,
                      old_asn: int | None = None, old_netname: str | None = None,
                      new_asn: int | None = None, new_netname: str | None = None) -> None:
    con.execute(
        """INSERT INTO asn_changes (detected_at, indicator_value, actor,
               old_asn, old_netname, new_asn, new_netname, change_type, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (indicator_value, detected_at) DO UPDATE SET
               actor = excluded.actor, old_asn = excluded.old_asn,
               old_netname = excluded.old_netname, new_asn = excluded.new_asn,
               new_netname = excluded.new_netname,
               change_type = excluded.change_type,
               confidence = excluded.confidence""",
        [detected_at, indicator_value, actor, old_asn, old_netname,
         new_asn, new_netname, change_type, confidence])


def record_active_scan(con: duckdb.DuckDBPyConnection, *, ran_at, indicator_value: str,
                       tools: Any, summary: Any, actor: str | None = None,
                       zeek_first_ts=None, zeek_last_ts=None) -> None:
    con.execute(
        """INSERT INTO active_scans (ran_at, indicator_value, actor, tools, summary,
               zeek_first_ts, zeek_last_ts)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [ran_at, indicator_value, actor, _json(tools), _json(summary),
         zeek_first_ts, zeek_last_ts])


def upsert_actor(con: duckdb.DuckDBPyConnection, name: str, seen_at, *,
                 asns: list[int] | None = None, ports: list[int] | None = None,
                 cluster_slug: str | None = None) -> None:
    """Create the actor or widen its first/last window; known ASNs and
    ports are unioned in and kept sorted so diffs stay stable."""
    existing = con.execute(
        """SELECT first_observed, last_observed, known_asns, known_ports,
                  cluster_slug FROM actors WHERE actor_name = ?""",
        [name]).fetchone()
    if existing is None:
        con.execute(
            """INSERT INTO actors (actor_name, first_observed, last_observed,
                   known_asns, known_ports, cluster_slug)
               VALUES (?, ?, ?, ?, ?, ?)""",
            [name, seen_at, seen_at, _json(sorted(set(asns or []))),
             _json(sorted(set(ports or []))), cluster_slug])
        return
    first, last, known_asns, known_ports, existing_slug = existing
    merged_asns = sorted(set(json.loads(known_asns or "[]")) | set(asns or []))
    merged_ports = sorted(set(json.loads(known_ports or "[]")) | set(ports or []))
    con.execute(
        """UPDATE actors SET
               first_observed = least(coalesce(first_observed, ?), ?),
               last_observed  = greatest(coalesce(last_observed, ?), ?),
               known_asns = ?, known_ports = ?,
               cluster_slug = coalesce(cluster_slug, ?)
           WHERE actor_name = ?""",
        [seen_at, seen_at, seen_at, seen_at, _json(merged_asns),
         _json(merged_ports), cluster_slug, name])


def record_findings(con: duckdb.DuckDBPyConnection, *, day, findings: list[dict],
                    ) -> int:
    """Persist a day's findings. Returns how many rows were new.

    Every finding, not only the ones carrying a correlation_type. On
    2026-09-21 that distinction was 1 of 5 - the other four existed nowhere
    but a debug trace, and the leads worth clicking are usually among the
    ones not worth filing as durable correlations.

    Idempotent on (day, family, headline) so re-running a day's analysis
    updates rather than duplicates.
    """
    written = 0
    for f in findings:
        headline = (f.get("headline") or "").strip()
        if not headline:
            continue
        existed = con.execute(
            "SELECT 1 FROM findings WHERE day = ? AND family = ? AND headline = ?",
            [day, f.get("family"), headline]).fetchone()
        con.execute(
            """INSERT INTO findings (day, family, actor, headline, detail,
                   indicators, correlation_type, confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (day, family, headline) DO UPDATE SET
                   actor = excluded.actor,
                   detail = excluded.detail,
                   indicators = excluded.indicators,
                   correlation_type = excluded.correlation_type,
                   confidence = excluded.confidence""",
            [day, f.get("family"), f.get("actor"), headline, f.get("detail"),
             json.dumps(f.get("indicators") or []), f.get("correlation_type"),
             f.get("confidence")])
        written += not existed
    return written


def insert_correlation(con: duckdb.DuckDBPyConnection, *, actor: str,
                       correlation_type: str, indicators: list[str],
                       narrative: str, confidence: str = "medium",
                       suggested_opensearch_query: str | None = None,
                       created_by: str = "agent") -> None:
    con.execute(
        """INSERT INTO correlations (actor, correlation_type, indicators,
               confidence, narrative, suggested_opensearch_query, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        [actor, correlation_type, _json(list(indicators)), confidence,
         narrative, suggested_opensearch_query, created_by])


def upsert_zeek_match(con: duckdb.DuckDBPyConnection, *, day, indicator_value: str,
                      direction: str, hit_count: int, actor: str | None = None,
                      ports: list[int] | None = None, first_ts=None, last_ts=None,
                      log_files: list[str] | None = None) -> None:
    con.execute(
        """INSERT INTO zeek_matches (day, indicator_value, actor, direction,
               hit_count, ports, first_ts, last_ts, log_files)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (day, indicator_value, direction) DO UPDATE SET
               actor = excluded.actor, hit_count = excluded.hit_count,
               ports = excluded.ports, first_ts = excluded.first_ts,
               last_ts = excluded.last_ts, log_files = excluded.log_files""",
        [day, indicator_value, actor, direction, hit_count, _json(ports),
         first_ts, last_ts, _json(log_files)])



def upsert_opendir_files(con: duckdb.DuckDBPyConnection, *, indicator_value: str,
                         url: str, files: list[dict[str, Any]], observed_at,
                         actor: str | None = None) -> list[dict[str, Any]]:
    """Record the files seen in one open-directory listing, returning the
    subset that are new - the day-over-day diff the digest flags.
    Re-seeing a known path just bumps last_seen.

    The old version issued a SELECT and an INSERT per file, so a listing
    at the crawler's 2000-file ceiling meant 4000 round-trips. Now the
    known paths are read once and the rows are inserted in one statement.
    """
    rows = []
    for f in files:
        path = f.get("href") or f.get("path") or f.get("name")
        if not path:
            continue
        rows.append((path, f.get("name"), f.get("is_dir"), f.get("size"), f.get("mtime")))
    if not rows:
        return []

    paths = [r[0] for r in rows]
    placeholders = ", ".join("?" for _ in paths)
    known = {r[0] for r in con.execute(
        f"""SELECT path FROM opendir_files
            WHERE indicator_value = ? AND url = ? AND path IN ({placeholders})""",
        [indicator_value, url, *paths]).fetchall()}

    con.executemany(
        """INSERT INTO opendir_files (indicator_value, url, path, is_dir, size,
               mtime, actor, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (indicator_value, url, path) DO UPDATE SET
               last_seen = excluded.last_seen, size = excluded.size,
               mtime = excluded.mtime""",
        [[indicator_value, url, path, is_dir, size, mtime, actor, observed_at, observed_at]
         for path, _name, is_dir, size, mtime in rows])

    return [{"path": path, "name": name, "size": size, "is_dir": is_dir}
            for path, name, is_dir, size, _mtime in rows if path not in known]


def upsert_opendir_samples(con: duckdb.DuckDBPyConnection, *, indicator_value: str,
                           url: str, results: list[dict[str, Any]], analyzed_at,
                           actor: str | None = None) -> int:
    """Record analysis verdicts from the probe VM's sandbox container.

    `results` holds JSON verdicts only - sha256, magic/MIME, YARA hits,
    a strings sample. No sample bytes ever cross the SSH channel, so
    there is deliberately nothing here to write to disk as a file.
    """
    if not results:
        return 0
    con.executemany(
        """INSERT INTO opendir_samples (indicator_value, url, path, sha256, size,
               magic, mime, yara_hits, strings_sample, extracted, verdict,
               actor, analyzed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (indicator_value, url, path) DO UPDATE SET
               sha256 = excluded.sha256, size = excluded.size,
               magic = excluded.magic, mime = excluded.mime,
               yara_hits = excluded.yara_hits,
               strings_sample = excluded.strings_sample,
               extracted = excluded.extracted, verdict = excluded.verdict,
               analyzed_at = excluded.analyzed_at""",
        [[indicator_value, url, r.get("path"), r.get("sha256"), r.get("size"),
          r.get("magic"), r.get("mime"), _json(r.get("yara_hits")),
          _json(r.get("strings_sample")), _json(r.get("extracted")),
          r.get("verdict"), actor, analyzed_at] for r in results])
    return len(results)
