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
from datetime import date, datetime, timedelta
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
    shodan_ports    JSON,
    shodan_tags     JSON,
    threatfox_matches JSON,
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

-- Day-over-day port/certificate diffs from pivot_cluster's daily Shodan/
-- Cert Spotter sweep - the same detected-change pattern as asn_changes,
-- generalized. Deliberately a separate table rather than folding into
-- asn_changes: ports (int array) and cert (issuer string + hostname
-- array) don't share asn_changes' typed int/text columns, so old_value/
-- new_value are JSON here. change_type 'first_seen' is a baseline (no
-- prior observation to diff against), not an event - callers exclude it
-- the same way asn_changes' own 'first_seen' rows are excluded.
CREATE SEQUENCE IF NOT EXISTS attribute_changes_seq;
CREATE TABLE IF NOT EXISTS attribute_changes (
    id BIGINT PRIMARY KEY DEFAULT nextval('attribute_changes_seq'),
    detected_at TIMESTAMP NOT NULL,
    indicator_value TEXT NOT NULL,
    actor TEXT,
    attribute TEXT NOT NULL,        -- 'ports' | 'cert'
    change_type TEXT NOT NULL,      -- 'first_seen' | 'ports_changed' |
                                     -- 'cert_issuer_changed' | 'cert_sans_changed'
    old_value JSON,
    new_value JSON,
    confidence TEXT NOT NULL,
    UNIQUE (indicator_value, attribute, detected_at)
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


# Additive migrations for columns introduced after a database already
# exists on disk - CREATE TABLE IF NOT EXISTS above only creates the table
# on a fresh file, so a preexisting one needs these run explicitly. Each
# statement is idempotent (IF NOT EXISTS), safe to re-run every connect.
_MIGRATIONS = """
ALTER TABLE observations ADD COLUMN IF NOT EXISTS shodan_ports JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS shodan_tags JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS threatfox_matches JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_issuer TEXT;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_not_before TIMESTAMP;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_not_after TIMESTAMP;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_sibling_hostnames JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_sha256 TEXT;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS cert_revoked BOOLEAN;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS discovered_hostnames JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS vt_file_hashes JSON;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS ptr_hostname TEXT;
ALTER TABLE observations ADD COLUMN IF NOT EXISTS resolved_ip JSON;
"""


def init_schema(con: duckdb.DuckDBPyConnection) -> None:
    con.execute(SCHEMA)
    con.execute(_MIGRATIONS)


def _json(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)


_OBS_COLUMNS = (
    "observed_at", "indicator_type", "indicator_value", "actor", "campaign",
    "source", "source_url", "hl_events", "hl_events_7d", "hl_first_seen",
    "hl_last_seen", "hl_ports", "hl_tags", "hl_threat_level",
    "shodan_ports", "shodan_tags", "threatfox_matches",
    "cert_issuer", "cert_not_before", "cert_not_after", "cert_sibling_hostnames",
    "cert_sha256", "cert_revoked", "discovered_hostnames", "vt_file_hashes",
    "ptr_hostname", "resolved_ip",
    "asn", "netname", "country_code", "abuse_contact", "metadata",
)
_OBS_JSON_COLUMNS = {"hl_ports", "hl_tags", "shodan_ports", "shodan_tags",
                     "threatfox_matches", "cert_sibling_hostnames",
                     "discovered_hostnames", "vt_file_hashes", "resolved_ip", "metadata"}


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


def latest_ports_for(con: duckdb.DuckDBPyConnection, ip: str,
                     before) -> dict[str, Any] | None:
    """Most recent prior Shodan-sourced observation of `ip` that carried
    a port list, strictly before `before` - the baseline for port-change
    detection, mirroring latest_asn_for."""
    row = con.execute(
        """SELECT observed_at, shodan_ports FROM observations
           WHERE indicator_value = ? AND source = 'shodan'
             AND shodan_ports IS NOT NULL AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [ip, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "ports": json.loads(row[1])}


def latest_cert_for(con: duckdb.DuckDBPyConnection, domain: str,
                    before) -> dict[str, Any] | None:
    """Most recent prior Cert-Spotter-sourced observation of `domain`
    that carried a cert issuer, strictly before `before` - the baseline
    for certificate-change detection, mirroring latest_asn_for. Includes
    cert_sha256/cert_revoked too - the baseline for _record_cert_hash_change,
    a separate diff from the issuer/SANs one this function was originally
    written for (see core.py's _record_cert_change vs _record_cert_hash_change)."""
    row = con.execute(
        """SELECT observed_at, cert_issuer, cert_sibling_hostnames, cert_sha256, cert_revoked
           FROM observations
           WHERE indicator_value = ? AND source = 'certspotter'
             AND cert_issuer IS NOT NULL AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [domain, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "issuer": row[1],
            "sibling_hostnames": json.loads(row[2]) if row[2] else [],
            "sha256": row[3], "revoked": row[4]}


def latest_hostnames_for(con: duckdb.DuckDBPyConnection, ip: str,
                         before) -> dict[str, Any] | None:
    """Most recent prior host-discovery observation of `ip` (Shodan
    InternetDB hostnames unioned with Hackertarget reverse-IP domains,
    see core.py's _log_cluster_enrichment_history), strictly before
    `before` - the baseline for detecting a new domain pointed at a
    tracked IP, mirroring latest_ports_for."""
    row = con.execute(
        """SELECT observed_at, discovered_hostnames FROM observations
           WHERE indicator_value = ? AND source = 'hostdiscovery'
             AND discovered_hostnames IS NOT NULL AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [ip, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "hostnames": json.loads(row[1]) if row[1] else []}


def latest_ptr_for(con: duckdb.DuckDBPyConnection, ip: str,
                   before) -> dict[str, Any] | None:
    """Most recent prior PTR-sourced observation of `ip`, strictly
    before `before` - the baseline for PTR-change detection, mirroring
    latest_ports_for. Deliberately does NOT filter on
    `ptr_hostname IS NOT NULL` the way latest_ports_for filters on
    shodan_ports: a NULL ptr_hostname here is itself a legitimate,
    confirmed "no PTR record" observation (see pivot.ptr_lookup), not a
    missing/unattempted one - a 'ptr' source row only ever exists when
    the lookup succeeded (core._log_cluster_enrichment_history gates
    the write on "error" not in ptr), so excluding NULLs would silently
    drop "went from having a PTR to having none" (or vice versa) as a
    usable future baseline."""
    row = con.execute(
        """SELECT observed_at, ptr_hostname FROM observations
           WHERE indicator_value = ? AND source = 'ptr' AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [ip, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "hostname": row[1]}


def latest_resolved_ip_for(con: duckdb.DuckDBPyConnection, domain: str,
                           before) -> dict[str, Any] | None:
    """Most recent prior dns_resolve-sourced observation of `domain`
    that carried a resolved_ip value, strictly before `before` - the
    baseline for domain-hosting-shift detection, mirroring
    latest_ports_for. resolved_ip is written as a JSON list (possibly
    empty, for a confirmed-dead domain) whenever pivot.resolve_host
    returned a definitive answer (not None/inconclusive) - see
    core._log_cluster_enrichment_history - so `resolved_ip IS NOT NULL`
    correctly excludes only rows where this source was never
    successfully written, not empty-but-successful ones (an empty
    Python list serializes to JSON '[]', not SQL NULL)."""
    row = con.execute(
        """SELECT observed_at, resolved_ip FROM observations
           WHERE indicator_value = ? AND source = 'dns_resolve'
             AND resolved_ip IS NOT NULL AND observed_at < ?
           ORDER BY observed_at DESC LIMIT 1""", [domain, before]).fetchone()
    if row is None:
        return None
    return {"observed_at": row[0], "resolved_ip": json.loads(row[1])}

# latest_vt_file_hashes_for (source='virustotal_files') was removed along
# with the automatic VT file-hash pivot it backed - that sweep exhausted
# the VT free tier's daily quota against a modest number of tracked IPs.
# The vt_file_hashes column and 'virustotal_files' source stay in the
# schema/migrations (never retroactively dropped, see _MIGRATIONS) but are
# no longer written to. VirusTotal file-hash pivots are on-demand only now
# (pivot_observable/pivot_and_expand).


def record_attribute_change(con: duckdb.DuckDBPyConnection, *, detected_at,
                            indicator_value: str, attribute: str, change_type: str,
                            confidence: str, actor: str | None = None,
                            old_value: Any = None, new_value: Any = None) -> None:
    con.execute(
        """INSERT INTO attribute_changes (detected_at, indicator_value, actor, attribute,
               change_type, old_value, new_value, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (indicator_value, attribute, detected_at) DO UPDATE SET
               actor = excluded.actor, change_type = excluded.change_type,
               old_value = excluded.old_value, new_value = excluded.new_value,
               confidence = excluded.confidence""",
        [detected_at, indicator_value, actor, attribute, change_type,
         _json(old_value), _json(new_value), confidence])


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


def _rows(con: duckdb.DuckDBPyConnection, sql: str,
         params: list[Any] | None = None) -> list[dict[str, Any]]:
    cur = con.execute(sql, params or [])
    columns = [d[0] for d in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]


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


_TRACKED_OBSERVABLES_SQL = """
WITH tracked_ips AS (
    SELECT DISTINCT o.indicator_value
    FROM observations o
    JOIN actors a ON a.actor_name = o.actor
    WHERE a.tracked = TRUE
),
latest_actor AS (
    SELECT indicator_value, actor FROM (
        SELECT indicator_value, actor,
               row_number() OVER (PARTITION BY indicator_value
                                  ORDER BY observed_at DESC) AS rn
        FROM observations WHERE actor IS NOT NULL
    ) WHERE rn = 1
),
latest_hl AS (
    SELECT indicator_value, observed_at AS hl_observed_at, hl_events,
           hl_last_seen, hl_ports, hl_tags, hl_threat_level
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations WHERE source = 'honeylabs'
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
        FROM observations WHERE asn IS NOT NULL
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
latest_shodan AS (
    SELECT indicator_value, observed_at AS shodan_observed_at,
           shodan_ports, shodan_tags
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations WHERE source = 'shodan'
    ) WHERE rn = 1
),
latest_threatfox AS (
    SELECT indicator_value, observed_at AS threatfox_observed_at,
           threatfox_matches
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations WHERE source = 'threatfox'
    ) WHERE rn = 1
)
SELECT t.indicator_value, la.actor,
       h.hl_observed_at, h.hl_events, h.hl_last_seen, h.hl_ports, h.hl_tags,
       h.hl_threat_level, na.asn, na.netname, na.country_code,
       c.asn_change_at, c.old_asn, c.new_asn, c.old_netname, c.new_netname,
       c.change_type, c.confidence AS asn_change_confidence,
       z.zeek_day, z.zeek_direction, z.zeek_hit_count, z.zeek_last_ts,
       s.shodan_observed_at, s.shodan_ports, s.shodan_tags,
       tf.threatfox_observed_at, tf.threatfox_matches
FROM tracked_ips t
LEFT JOIN latest_actor la ON la.indicator_value = t.indicator_value
LEFT JOIN latest_hl h ON h.indicator_value = t.indicator_value
LEFT JOIN latest_asn na ON na.indicator_value = t.indicator_value
LEFT JOIN latest_asn_change c ON c.indicator_value = t.indicator_value
LEFT JOIN latest_zeek z ON z.indicator_value = t.indicator_value
LEFT JOIN latest_shodan s ON s.indicator_value = t.indicator_value
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
        with _connect_retry(read_only=True) as con:
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
                 "shodan_observed_at", "threatfox_observed_at"):
            r[k] = _cell(r[k])
        for k in ("hl_ports", "hl_tags", "shodan_ports", "shodan_tags", "threatfox_matches"):
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
        with _connect_retry(read_only=True) as con:
            observations = _rows(con,
                """SELECT observed_at, source, source_url, actor, campaign,
                          hl_events, hl_events_7d, hl_first_seen, hl_last_seen,
                          hl_ports, hl_tags, hl_threat_level,
                          shodan_ports, shodan_tags, threatfox_matches,
                          asn, netname, country_code, abuse_contact, metadata
                   FROM observations WHERE indicator_value = ?
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
        for k in ("hl_ports", "hl_tags", "shodan_ports", "shodan_tags", "threatfox_matches"):
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
