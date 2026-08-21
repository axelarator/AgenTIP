"""DuckDB schema, connections, and all write paths for actor tracking.

Concurrency model: DuckDB's file lock is process-exclusive for
read-write, so every connection here is short-lived (open, work,
close) and the slow parts of the daily pipeline (network enrichment)
run with no connection held. The MCP-facing helpers open read-only
where possible and wrap connect in a small retry so a tool call that
races the daily job degrades to an "in use, retry shortly" error dict
instead of an exception.
"""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterator

import duckdb

# Data lives in <repo>/data/tracking/, next to data/clusters/. Override
# with CTI_DUCKDB_PATH for tests; read lazily so a monkeypatched env
# var takes effect per-test.
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _db_path() -> Path:
    return Path(os.environ.get("CTI_DUCKDB_PATH",
                               _REPO_ROOT / "data" / "tracking" / "tracking.duckdb"))


SCHEMA = """
CREATE SEQUENCE IF NOT EXISTS observations_seq;
CREATE TABLE IF NOT EXISTS observations (
    id              BIGINT PRIMARY KEY DEFAULT nextval('observations_seq'),
    observed_at     TIMESTAMP NOT NULL,
    indicator_type  TEXT NOT NULL DEFAULT 'ipv4',
    indicator_value TEXT NOT NULL,
    actor           TEXT,
    campaign        TEXT,
    source          TEXT NOT NULL,
    source_url      TEXT,
    hl_events       BIGINT,
    hl_events_7d    BIGINT,
    hl_first_seen   TIMESTAMP,
    hl_last_seen    TIMESTAMP,
    hl_ports        JSON,
    hl_tags         JSON,
    hl_threat_level TEXT,
    asn             INTEGER,
    netname         TEXT,
    country_code    TEXT,
    abuse_contact   TEXT,
    metadata        JSON,
    UNIQUE (observed_at, indicator_value, source)
);
CREATE INDEX IF NOT EXISTS obs_ip_time ON observations (indicator_value, observed_at);
CREATE INDEX IF NOT EXISTS obs_actor   ON observations (actor, observed_at);

CREATE SEQUENCE IF NOT EXISTS asn_changes_seq;
CREATE TABLE IF NOT EXISTS asn_changes (
    id BIGINT PRIMARY KEY DEFAULT nextval('asn_changes_seq'),
    detected_at TIMESTAMP NOT NULL,
    indicator_value TEXT NOT NULL,
    actor TEXT,
    old_asn INTEGER, old_netname TEXT,
    new_asn INTEGER, new_netname TEXT,
    change_type TEXT NOT NULL,
    confidence TEXT NOT NULL,
    UNIQUE (indicator_value, detected_at)
);

CREATE TABLE IF NOT EXISTS actors (
    actor_name TEXT PRIMARY KEY,
    first_observed TIMESTAMP,
    last_observed TIMESTAMP,
    known_asns JSON DEFAULT '[]',
    known_ports JSON DEFAULT '[]',
    cluster_slug TEXT,
    notes TEXT DEFAULT '',
    tracked BOOLEAN DEFAULT TRUE
);

CREATE SEQUENCE IF NOT EXISTS correlations_seq;
CREATE TABLE IF NOT EXISTS correlations (
    id BIGINT PRIMARY KEY DEFAULT nextval('correlations_seq'),
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    actor TEXT NOT NULL,
    correlation_type TEXT NOT NULL,
    indicators JSON NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'medium',
    narrative TEXT NOT NULL,
    suggested_opensearch_query TEXT,
    created_by TEXT NOT NULL DEFAULT 'agent'
);

CREATE TABLE IF NOT EXISTS zeek_matches (
    day DATE NOT NULL,
    indicator_value TEXT NOT NULL,
    actor TEXT,
    direction TEXT NOT NULL,
    hit_count BIGINT NOT NULL,
    ports JSON,
    first_ts TIMESTAMP,
    last_ts TIMESTAMP,
    log_files JSON,
    UNIQUE (day, indicator_value, direction)
);
"""

# Row/byte caps for anything that flows back into an agent context.
QUERY_MAX_ROWS = 200
QUERY_MAX_BYTES = 20_000

CORRELATION_TYPES = {"asn_pivot", "port_pattern", "temporal_cluster",
                     "new_infrastructure", "zeek_hit"}


class TrackingBusy(Exception):
    """The DuckDB file is locked by another process (daily job likely)."""


@contextmanager
def connect(read_only: bool = False) -> Iterator[duckdb.DuckDBPyConnection]:
    """Short-lived connection; rw connections initialize the schema."""
    path = _db_path()
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(path), read_only=read_only)
    try:
        if not read_only:
            init_schema(con)
        yield con
    finally:
        con.close()


@contextmanager
def _connect_retry(read_only: bool, attempts: int = 4,
                   backoff: float = 0.5) -> Iterator[duckdb.DuckDBPyConnection]:
    """connect() with backoff on the process-exclusive file lock.

    Only the connect itself is retried - never the caller's body, so a
    mid-transaction failure can't replay non-idempotent writes. Raises
    TrackingBusy after the last attempt; MCP wrappers turn that into an
    error dict rather than letting it propagate.
    """
    path = _db_path()
    if not read_only:
        path.parent.mkdir(parents=True, exist_ok=True)
    elif not path.exists():
        # A missing file can't be lock contention - fail fast instead
        # of sleeping through the whole backoff schedule.
        raise duckdb.IOException(f"tracking DB not initialized ({path})")
    delay = backoff
    con = None
    for attempt in range(attempts):
        try:
            con = duckdb.connect(str(path), read_only=read_only)
            break
        except duckdb.IOException as e:
            if attempt == attempts - 1:
                raise TrackingBusy(str(e)) from e
            time.sleep(delay)
            delay *= 2
    try:
        if not read_only:
            init_schema(con)
        yield con
    finally:
        con.close()


def init_schema(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(SCHEMA)


def _json(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)


_OBS_COLUMNS = (
    "observed_at", "indicator_type", "indicator_value", "actor", "campaign",
    "source", "source_url", "hl_events", "hl_events_7d", "hl_first_seen",
    "hl_last_seen", "hl_ports", "hl_tags", "hl_threat_level",
    "asn", "netname", "country_code", "abuse_contact", "metadata",
)
_OBS_JSON_COLUMNS = {"hl_ports", "hl_tags", "metadata"}


def upsert_observation(con: duckdb.DuckDBPyConnection, *, observed_at,
                       indicator_value: str, source: str, **fields: Any) -> None:
    """Insert one observation row; a same-day re-run for the same
    (observed_at, indicator_value, source) updates in place."""
    unknown = set(fields) - set(_OBS_COLUMNS)
    if unknown:
        raise ValueError(f"unknown observation fields: {sorted(unknown)}")
    row = {"observed_at": observed_at, "indicator_value": indicator_value,
           "source": source, **fields}
    for col in _OBS_JSON_COLUMNS:
        if col in row:
            row[col] = _json(row[col])
    row.setdefault("indicator_type", "ipv4")
    cols = [c for c in _OBS_COLUMNS if c in row]
    updates = [c for c in cols
               if c not in ("observed_at", "indicator_value", "source")]
    sql = (f"INSERT INTO observations ({', '.join(cols)}) "
           f"VALUES ({', '.join('?' for _ in cols)}) "
           f"ON CONFLICT (observed_at, indicator_value, source) DO UPDATE SET "
           + ", ".join(f"{c} = excluded.{c}" for c in updates))
    con.execute(sql, [row[c] for c in cols])


def latest_asn_for(con: duckdb.DuckDBPyConnection, ip: str,
                   before) -> dict[str, Any] | None:
    """Most recent prior observation of `ip` that carried an ASN,
    strictly before `before` - the baseline for change detection."""
    row = con.execute(
        """SELECT observed_at, asn, netname, source FROM observations
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
        with _connect_retry(read_only=True) as con:
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
        with _connect_retry(read_only=False) as con:
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
        with _connect_retry(read_only=True) as con:
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
                   FROM observations WHERE actor = ?""", [actor]).fetchone()
            top_ports = con.execute(
                """SELECT port, count(*) AS n FROM (
                       SELECT unnest(cast(hl_ports AS INTEGER[])) AS port
                       FROM observations
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
