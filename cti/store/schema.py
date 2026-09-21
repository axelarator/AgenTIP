"""The DuckDB schema.

## Why `observations` changed shape

The old table had 52 columns and was mostly empty. Measured on the live
database (3942 rows): five columns were 100% NULL, another fifteen were
under 1%, and the whole table needed 36 idempotent `ALTER TABLE ... ADD
COLUMN IF NOT EXISTS` statements run on *every* read-write connect to
stay migratable.

Note on the five 100%-NULL ones (`campaign`, `source_url`,
`abuse_contact`, `hl_events_7d`, `infostealer_urls`): they are NOT dead
code and are kept. `campaign`/`source_url` are written by the inbox
ingest path and read 0% only because the inbox happens to be empty;
`hl_events_7d` is written on every HoneyLabs row but normalized to NULL
by the MCP switch; `infostealer_urls` is written but has so far always
been empty; `abuse_contact` is still read by observable_history. Being
empty today is not the same as being unused.

The cause was structural: `source` is already a discriminator (a row is
from `rdap` OR `tls_live` OR `webamon`, never several), but each new
source added its own columns to the shared table. Adding a source
required DDL, so retired sources left their columns behind forever.

Now the spine is narrow and everything source-specific lives in one
`payload` JSON column. Adding a source needs no DDL at all.

## Why the view exists

`observations_wide` projects the payload back out under the original
column names. The eight analytics queries, the `tracked_observables`
CTE, the dashboard and `query_duckdb` all keep working with a one-word
change (`observations` -> `observations_wide`), which is what makes the
migration reviewable instead of a rewrite of every SQL string.

Retired-provider fields (`shodan_*`, `vt_file_hashes`,
`discovered_hostnames`, `cert_*`) are NOT dropped: they hold real
history (154 Shodan rows, 20 Cert Spotter rows). They stay readable in
the view and are simply never written.
"""
from __future__ import annotations

import duckdb

SCHEMA = """
CREATE SEQUENCE IF NOT EXISTS observations_seq;

-- The narrow spine. Everything source-specific is in `payload`.
CREATE TABLE IF NOT EXISTS observations (
    id            BIGINT PRIMARY KEY DEFAULT nextval('observations_seq'),
    observed_at   TIMESTAMP NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    actor         TEXT,
    source        TEXT NOT NULL,
    payload       JSON,
    UNIQUE (observed_at, indicator_value, source)
);
CREATE INDEX IF NOT EXISTS obs_ip_time ON observations (indicator_value, observed_at);
CREATE INDEX IF NOT EXISTS obs_actor   ON observations (actor, observed_at);

CREATE SEQUENCE IF NOT EXISTS asn_changes_seq;
CREATE TABLE IF NOT EXISTS asn_changes (
    id           BIGINT PRIMARY KEY DEFAULT nextval('asn_changes_seq'),
    detected_at  TIMESTAMP NOT NULL,
    indicator_value TEXT NOT NULL,
    actor        TEXT,
    old_asn      BIGINT, old_netname TEXT,
    new_asn      BIGINT, new_netname TEXT,
    change_type  TEXT NOT NULL,
    confidence   TEXT,
    UNIQUE (indicator_value, detected_at)
);

CREATE TABLE IF NOT EXISTS actors (
    actor_name    TEXT PRIMARY KEY,
    first_observed TIMESTAMP,
    last_observed  TIMESTAMP,
    known_asns    JSON,
    known_ports   JSON,
    cluster_slug  TEXT,
    notes         TEXT,
    tracked       BOOLEAN DEFAULT TRUE
);

CREATE SEQUENCE IF NOT EXISTS correlations_seq;
CREATE TABLE IF NOT EXISTS correlations (
    id          BIGINT PRIMARY KEY DEFAULT nextval('correlations_seq'),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    actor       TEXT,
    correlation_type TEXT NOT NULL,
    indicators  JSON,
    confidence  TEXT,
    narrative   TEXT,
    suggested_opensearch_query TEXT,
    created_by  TEXT
);

-- Every finding the specialists produce, not only the ones worth saving as
-- a durable correlation. On 2026-09-21 that was 1 of 5: the other four -
-- a cert rotation, a workers.dev link, a PTR loss - existed nowhere but
-- the run trace, which is a debug artifact that caps lists at 40 elements
-- and strings at 2000 chars. The interesting leads are usually among the
-- ones not worth persisting as correlations, so they get a home here.
--
-- correlation_type NULL means "worth saying, not worth storing" - the
-- documented way a specialist declines to file one, not a missing value.
CREATE SEQUENCE IF NOT EXISTS findings_seq;
CREATE TABLE IF NOT EXISTS findings (
    id          BIGINT PRIMARY KEY DEFAULT nextval('findings_seq'),
    day         DATE NOT NULL,
    family      TEXT NOT NULL,
    actor       TEXT,
    headline    TEXT NOT NULL,
    detail      TEXT,
    indicators  JSON,
    correlation_type TEXT,
    confidence  TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (day, family, headline)
);
CREATE INDEX IF NOT EXISTS findings_day ON findings (day);

CREATE TABLE IF NOT EXISTS zeek_matches (
    day        DATE NOT NULL,
    indicator_value TEXT NOT NULL,
    actor      TEXT,
    direction  TEXT NOT NULL,
    hit_count  BIGINT,
    ports      JSON,
    first_ts   TIMESTAMP,
    last_ts    TIMESTAMP,
    log_files  JSON,
    UNIQUE (day, indicator_value, direction)
);

CREATE SEQUENCE IF NOT EXISTS attribute_changes_seq;
CREATE TABLE IF NOT EXISTS attribute_changes (
    id          BIGINT PRIMARY KEY DEFAULT nextval('attribute_changes_seq'),
    detected_at TIMESTAMP NOT NULL,
    indicator_value TEXT NOT NULL,
    actor       TEXT,
    attribute   TEXT NOT NULL,
    change_type TEXT NOT NULL,
    old_value   JSON,
    new_value   JSON,
    confidence  TEXT,
    UNIQUE (indicator_value, attribute, detected_at)
);

CREATE TABLE IF NOT EXISTS opendir_files (
    indicator_value TEXT NOT NULL,
    url        TEXT NOT NULL,
    path       TEXT NOT NULL,
    is_dir     BOOLEAN,
    size       TEXT,
    mtime      TEXT,
    actor      TEXT,
    first_seen TIMESTAMP,
    last_seen  TIMESTAMP,
    UNIQUE (indicator_value, url, path)
);

-- NEW: verdicts from the probe VM's analysis container. Only JSON ever
-- crosses the SSH channel - no sample bytes reach this host, so there is
-- deliberately no blob column here.
CREATE TABLE IF NOT EXISTS opendir_samples (
    indicator_value TEXT NOT NULL,
    url         TEXT NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT,
    size        BIGINT,
    magic       TEXT,
    mime        TEXT,
    yara_hits   JSON,
    strings_sample JSON,
    extracted   JSON,
    verdict     TEXT,
    actor       TEXT,
    analyzed_at TIMESTAMP,
    UNIQUE (indicator_value, url, path)
);

CREATE SEQUENCE IF NOT EXISTS active_scans_seq;
CREATE TABLE IF NOT EXISTS active_scans (
    id          BIGINT PRIMARY KEY DEFAULT nextval('active_scans_seq'),
    ran_at      TIMESTAMP NOT NULL,
    indicator_value TEXT NOT NULL,
    actor       TEXT,
    tools       JSON,
    summary     JSON,
    zeek_first_ts TIMESTAMP,
    zeek_last_ts  TIMESTAMP
);

"""

# Payload keys projected by observations_wide, in the order the old table
# declared them. (key, sql_type). A JSON key is extracted with ->> (which
# yields TEXT) and cast; JSON-valued keys are extracted with -> so they
# stay JSON for callers that json.loads() them.
_SCALAR_FIELDS: tuple[tuple[str, str], ...] = (
    ("campaign", "TEXT"), ("source_url", "TEXT"), ("abuse_contact", "TEXT"),
    ("hl_events", "BIGINT"), ("hl_events_7d", "BIGINT"), ("hl_first_seen", "TIMESTAMP"),
    ("hl_last_seen", "TIMESTAMP"), ("hl_threat_level", "TEXT"),
    ("asn", "BIGINT"), ("netname", "TEXT"), ("country_code", "TEXT"),
    ("cert_issuer", "TEXT"), ("cert_not_before", "TIMESTAMP"),
    ("cert_not_after", "TIMESTAMP"), ("cert_sha256", "TEXT"),
    ("cert_revoked", "BOOLEAN"),
    ("ptr_hostname", "TEXT"),
    ("tls_sha256", "TEXT"), ("tls_issuer", "TEXT"), ("tls_subject", "TEXT"),
    ("tls_not_before", "TEXT"), ("tls_not_after", "TEXT"),
    ("http_status", "INTEGER"), ("http_title", "TEXT"),
    ("http_server", "TEXT"), ("http_final_url", "TEXT"),
    ("webamon_report_id", "TEXT"), ("webamon_risk_score", "DOUBLE"),
    ("webamon_fingerprint_dom", "TEXT"), ("webamon_fingerprint_ssl", "TEXT"),
    ("webamon_last_scan", "TEXT"),
    ("infostealer_count", "INTEGER"),
    # Fields the probe VM has been computing and the write path discarding.
    # body_sha256 is the pivot the SilkParasite reporting turned on: a decoy
    # page byte-identical across 13 hosts, which survives the domain, the IP
    # and the provider all changing.
    ("body_sha256", "TEXT"),
    ("favicon_mmh3", "TEXT"),
    ("content_type", "TEXT"),
    ("tls_serial", "TEXT"),
    ("tls_spki_sha256", "TEXT"),
    ("tls_self_signed", "BOOLEAN"),
    ("tls_version", "TEXT"),
    ("whois_registrar", "TEXT"),
    ("whois_registrant_email", "TEXT"),
    ("whois_created", "TEXT"),
    ("cdn_provider", "TEXT"),
)

_JSON_FIELDS: tuple[str, ...] = (
    "hl_ports", "hl_tags", "metadata", "threatfox_matches",
    "cert_sibling_hostnames", "discovered_hostnames", "vt_file_hashes",
    "resolved_ip", "tls_sans", "nmap_ports", "ip_hostnames", "subdomains",
    "infostealer_urls",
    # From the observe pass: record sets and header maps, each one selector
    # whose value is the whole set rather than one per member.
    "dns_ns", "dns_mx", "dns_txt", "http_headers", "http_tech",
    # Passive sources. Named for where they came from, never merged with
    # the live equivalents: internetdb_ports is somebody else's scan at an
    # unknown time, and pdns_records is history, not current resolution.
    "internetdb_ports", "internetdb_cpes", "internetdb_tags",
    "internetdb_vulns", "internetdb_hostnames", "pdns_records",
    # Retired providers. Never written any more, but 154 Shodan rows and
    # 7 VirusTotal rows exist and stay readable.
    "shodan_ports", "shodan_tags",
)

OBS_SCALAR_KEYS = frozenset(k for k, _ in _SCALAR_FIELDS)
OBS_JSON_KEYS = frozenset(_JSON_FIELDS)
OBS_PAYLOAD_KEYS = OBS_SCALAR_KEYS | OBS_JSON_KEYS


def _wide_view_sql() -> str:
    cols = [
        "id", "observed_at", "indicator_type", "indicator_value", "actor",
        "source", "payload",
    ]
    for key, sqltype in _SCALAR_FIELDS:
        cols.append(f"CAST(payload->>'$.{key}' AS {sqltype}) AS {key}")
    for key in _JSON_FIELDS:
        # ->> gives the inner JSON text, which is what json.loads() wants
        # and what the old JSON-typed columns handed back.
        cols.append(f"payload->>'$.{key}' AS {key}")
    return ("CREATE OR REPLACE VIEW observations_wide AS SELECT\n  "
            + ",\n  ".join(cols) + "\nFROM observations;")


def init_schema(con: duckdb.DuckDBPyConnection) -> None:
    from .selectors import SCHEMA as SELECTOR_SCHEMA

    con.execute(SCHEMA)
    con.execute(SELECTOR_SCHEMA)
    con.execute(_wide_view_sql())
