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


# How recently a domain must have been resolved for its answer to count as
# current. Matches the HoneyLabs freshness window the IP ladder uses, so the
# two kinds age out at the same rate.
DOMAIN_FRESH_DAYS = 7

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
),
-- The domain half of the status ladder. Nothing below here existed, which
-- is why every domain reported never-enriched.
indicator_kind AS (
    SELECT indicator_value, indicator_type FROM (
        SELECT indicator_value, indicator_type,
               row_number() OVER (PARTITION BY indicator_value
                                  ORDER BY observed_at DESC) AS rn
        FROM observations_wide WHERE indicator_type IS NOT NULL
    ) WHERE rn = 1
),
last_observed AS (
    SELECT indicator_value, max(observed_at) AS last_observed_at
    FROM observations_wide GROUP BY indicator_value
),
latest_resolve AS (
    -- An empty list is an answer (the name resolves to nothing); NULL means
    -- nobody asked. The status ladder depends on telling those apart.
    SELECT indicator_value, observed_at AS resolve_observed_at, resolved_ip
    FROM (
        SELECT *, row_number() OVER (PARTITION BY indicator_value
                                      ORDER BY observed_at DESC) AS rn
        FROM observations_wide
        WHERE source IN ('dns_resolve', 'observe_dns') AND resolved_ip IS NOT NULL
    ) WHERE rn = 1
),
latest_domain_change AS (
    SELECT indicator_value, max(detected_at) AS domain_change_at
    FROM attribute_changes
    WHERE attribute IN ('resolved_ip', 'cert', 'cert_hash')
      AND change_type <> 'first_seen'
    GROUP BY indicator_value
)
SELECT t.indicator_value, la.actor, k.indicator_type,
       lo.last_observed_at, r.resolve_observed_at, r.resolved_ip,
       dc.domain_change_at,
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
LEFT JOIN indicator_kind k ON k.indicator_value = t.indicator_value
LEFT JOIN last_observed lo ON lo.indicator_value = t.indicator_value
LEFT JOIN latest_resolve r ON r.indicator_value = t.indicator_value
LEFT JOIN latest_domain_change dc ON dc.indicator_value = t.indicator_value
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


def _domain_status(now: datetime, row: dict[str, Any]) -> str:
    """Derived status for a domain, in precedence order.

    `_tracking_status` cannot answer this. Its whole ladder below Zeek is
    HoneyLabs, then an ASN change, then whether a HoneyLabs row exists -
    and all three are IP-only paths. Every domain fell off the end to
    `never-enriched`, which is how 58 domains carrying dozens of
    observations each came to be reported as untouched.

    The ladder here uses what a domain actually has:

      in-network  Zeek saw it. Type-agnostic, stays first.
      resolving   its newest resolution answered with an address
      unresolved  its newest resolution answered with nothing. This is
                  the domain going dark - the signal there was no way to
                  see before, and the reason `quiet` is not good enough
      moved       its address or certificate changed recently
      quiet       observed recently, nothing changed
      never-enriched   genuinely no observations
    """
    zeek_recent = False
    if row.get("zeek_last_ts") is not None:
        zeek_recent = (now - row["zeek_last_ts"]) <= timedelta(days=1)
    elif row.get("zeek_day") is not None:
        zeek_recent = (now.date() - row["zeek_day"]) <= timedelta(days=1)
    if zeek_recent:
        return "in-network"

    resolved_at = row.get("resolve_observed_at")
    fresh = resolved_at is not None and (now - resolved_at) <= timedelta(days=DOMAIN_FRESH_DAYS)
    if fresh:
        # An empty list is an answer, not a gap: dns_resolve writes [] when
        # the name resolves to nothing. None means we never asked.
        addresses = row.get("resolved_ip")
        if addresses:
            return "resolving"
        if addresses is not None:
            return "unresolved"

    changed_at = row.get("domain_change_at")
    if changed_at is not None and (now - changed_at) <= timedelta(days=30):
        return "moved"
    if row.get("last_observed_at") is not None:
        return "quiet"
    return "never-enriched"


def indicator_status(now: datetime, indicator_type: str | None,
                     row: dict[str, Any]) -> str:
    """Status for an indicator of either kind.

    The two ladders stay separate rather than merging into one because
    they are answering different questions with different evidence, and
    folding them produced the bug: a domain evaluated against HoneyLabs
    freshness can only ever come back `never-enriched`.
    """
    if (indicator_type or "").startswith("domain"):
        return _domain_status(now, row)
    return _tracking_status(now, row)


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
        # resolved_ip arrives from observations_wide as a JSON *string*;
        # the domain ladder needs the list, and it has to be decoded before
        # the status call rather than in the loop below.
        if r.get("resolved_ip") is not None:
            r["resolved_ip"] = json.loads(r["resolved_ip"])
        r["status"] = indicator_status(now, r.get("indicator_type"), r)
        for k in ("hl_observed_at", "hl_last_seen", "asn_change_at", "zeek_day", "zeek_last_ts",
                 "nmap_observed_at", "threatfox_observed_at",
                 "last_observed_at", "resolve_observed_at", "domain_change_at"):
            r[k] = _cell(r[k])
        for k in ("hl_ports", "hl_tags", "nmap_ports", "threatfox_matches"):
            r[k] = json.loads(r[k]) if r[k] is not None else []
    return {"observables": rows, "count": len(rows)}


def _fold_current(observations: list[dict[str, Any]]) -> dict[str, Any]:
    """Latest non-null value per payload field, with where it came from.

    Iterates the schema's own key sets rather than a hardcoded field list.
    That is the entire point: `observable_history` named nineteen columns by
    hand and every payload field added since - the whole observe pass,
    InternetDB, mnemonic - was invisible until someone noticed. A list
    written out here would rot the same way the next time a key is added.
    """
    from .schema import OBS_JSON_KEYS, OBS_SCALAR_KEYS

    keys = OBS_SCALAR_KEYS | OBS_JSON_KEYS
    current: dict[str, Any] = {}
    for o in observations:              # ascending, so later rows win
        payload = o.get("payload") or {}
        for key in keys:
            value = payload.get(key)
            if value in (None, "", [], {}):
                continue
            current[key] = {"value": value, "source": o["source"],
                            "observed_at": o["observed_at"]}
    return current


def _selector_detail(con, indicator: str) -> list[dict[str, Any]]:
    """This indicator's selectors, each with what it proves and how rare it is.

    The taxonomy already carries `means` and `never` prose per type, written
    to be read by a human; the profile page is the first thing that can show
    it. Rarity comes from `rarity.assess`, never recomputed here - every
    de-noising decision (CDN ranges, mass-provider list, the global-count
    threshold) stays in the module that owns it.
    """
    from . import rarity, selectors as S

    out = []
    for row in S.for_indicator(con, indicator):
        selector_type = row["selector_type"]
        spec = S.TYPES.get(selector_type)
        verdict = rarity.assess(con, selector_type, row["selector_value"])
        # Who else carries it. The taxonomy's prose is written for the
        # shared case - "the same leaf certificate is installed on both
        # hosts" - and beside a single host's attribute that invites the
        # obvious question, which two? Naming them answers it.
        carriers = [c["indicator_value"]
                    for c in S.sharing(con, selector_type, row["selector_value"])
                    if c["indicator_value"] != indicator]
        out.append({
            **{k: _cell(v) for k, v in row.items()},
            "selector_class": S.selector_class(selector_type),
            "artefact": S.artefact(selector_type),
            "means": spec.means if spec else None,
            "never": spec.never if spec else None,
            "local_count": verdict["local_count"],
            "global_count": verdict["global_count"],
            "can_promote": verdict["can_promote"],
            "why_not": verdict["why_not"],
            "carriers": carriers,
        })
    return out


def finding_days() -> dict[str, Any]:
    """Days that have findings, newest first."""
    try:
        with connect_retry(read_only=True) as con:
            found = _rows(con,
                """SELECT day, count(*) AS findings,
                          count(*) FILTER (WHERE correlation_type IS NOT NULL) AS saved
                   FROM findings GROUP BY day ORDER BY day DESC""")
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    for row in found:
        row["day"] = _cell(row["day"])
    return {"days": found, "count": len(found)}


def findings_for(day: str) -> dict[str, Any]:
    """One day's findings, with every indicator at full length.

    This is what makes the portal correct on a day the model abbreviates in
    prose: `indicators` has always carried complete values, and rendering
    them as chips does not depend on the narrative saying so.
    """
    try:
        with connect_retry(read_only=True) as con:
            found = _rows(con,
                """SELECT id, day, family, actor, headline, detail, indicators,
                          correlation_type, confidence, created_at
                   FROM findings WHERE day = ?
                   ORDER BY correlation_type IS NULL, family, headline""", [day])
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    for row in found:
        row["day"] = _cell(row["day"])
        row["created_at"] = _cell(row["created_at"])
        row["indicators"] = json.loads(row["indicators"]) if row["indicators"] else []
        row["saved"] = row["correlation_type"] is not None
    return {"day": day, "findings": found, "count": len(found)}


def indicator_index() -> dict[str, Any]:
    """One row per indicator that has ever been observed.

    Wider than `tracked_observables`, which is scoped to indicators whose
    actor carries `tracked = TRUE`. An indicator can hold a hundred
    observations and a full selector bag while that flag is off, and it
    should still be findable.
    """
    try:
        with connect_retry(read_only=True) as con:
            found = _rows(con, """
                WITH obs AS (
                    SELECT indicator_value,
                           max(indicator_type) AS indicator_type,
                           min(observed_at)    AS first_seen,
                           max(observed_at)    AS last_seen,
                           count(*)            AS observations,
                           count(DISTINCT source) AS sources
                    FROM observations_wide GROUP BY indicator_value
                ),
                sel AS (
                    SELECT indicator_value, count(*) AS selectors
                    FROM selectors GROUP BY indicator_value
                ),
                act AS (
                    SELECT indicator_value, actor FROM (
                        SELECT indicator_value, actor,
                               row_number() OVER (PARTITION BY indicator_value
                                                  ORDER BY observed_at DESC) AS rn
                        FROM observations_wide WHERE actor IS NOT NULL
                    ) WHERE rn = 1
                )
                SELECT o.indicator_value, o.indicator_type, a.actor,
                       o.first_seen, o.last_seen, o.observations, o.sources,
                       coalesce(s.selectors, 0) AS selectors
                FROM obs o
                LEFT JOIN sel s ON s.indicator_value = o.indicator_value
                LEFT JOIN act a ON a.indicator_value = o.indicator_value
                ORDER BY o.last_seen DESC, o.indicator_value""")
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}

    # Status is not computed here. It needs the per-indicator evidence
    # tracked_observables and indicator_profile gather, and recomputing it
    # from this aggregate would be a third ladder that could disagree with
    # the other two - which is the bug this whole change set exists to fix.
    for row in found:
        for k in ("first_seen", "last_seen"):
            row[k] = _cell(row[k])
    return {"indicators": found, "count": len(found)}


def selector_types_for(value: Any) -> dict[str, Any]:
    """Which selector types carry this value.

    The portal links a hash chip here without knowing what kind of hash it
    is, and it must not guess. The first version of the chip inferred the
    type from the value's shape - 64 hex characters, so probably a body
    hash - which was right for one of the three hashes in a JadeProx
    finding and silently wrong for the other two: a certificate digest and
    an SPKI digest both went to a body-hash page that found nothing, making
    real links look like dead ends.
    """
    try:
        with connect_retry(read_only=True) as con:
            found = _rows(con,
                """SELECT selector_type,
                          count(DISTINCT indicator_value) AS indicators,
                          min(first_seen) AS first_seen,
                          max(last_seen)  AS last_seen
                   FROM selectors WHERE selector_value = ?
                   GROUP BY selector_type
                   ORDER BY indicators DESC, selector_type""", [str(value)])
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}
    for row in found:
        row["first_seen"] = _cell(row["first_seen"])
        row["last_seen"] = _cell(row["last_seen"])
    return {"value": str(value), "types": found}


def selector_detail(selector_type: str | None, selector_value: Any) -> dict[str, Any]:
    """Who else carries this selector value, and what that is worth.

    `selector_type` may be None, in which case it is resolved from the
    value - see selector_types_for. Every verdict comes from the module
    that owns it, so this never re-decides anything.
    """
    from . import rarity, selectors as S

    if not selector_type:
        resolved = selector_types_for(selector_value)
        if "error" in resolved:
            return resolved
        if not resolved["types"]:
            return {"selector_type": None, "selector_value": str(selector_value),
                    "indicators": [], "other_types": [],
                    "not_a_selector": True}
        selector_type = resolved["types"][0]["selector_type"]
        other_types = [t["selector_type"] for t in resolved["types"][1:]]
    else:
        other_types = []

    spec = S.TYPES.get(selector_type)
    try:
        with connect_retry(read_only=True) as con:
            verdict = rarity.assess(con, selector_type, selector_value)
            carriers = S.sharing(con, selector_type, selector_value)
            apexes = rarity.apexes_for(con, selector_type, selector_value)
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}

    return {
        "selector_type": selector_type,
        "selector_value": S.normalize(selector_type, selector_value),
        "selector_class": S.selector_class(selector_type),
        "artefact": S.artefact(selector_type),
        "means": spec.means if spec else None,
        "never": spec.never if spec else None,
        "local_count": verdict["local_count"],
        "global_count": verdict["global_count"],
        "global_source": verdict.get("global_source"),
        "can_promote": verdict["can_promote"],
        "why_not": verdict["why_not"],
        "apex_spread": apexes,
        # A value can be more than one kind of thing - the same string could
        # be a cert digest on one host and something else elsewhere. Naming
        # the others lets the page offer them rather than pick silently.
        "other_types": other_types,
        "indicators": [{k: _cell(v) for k, v in c.items()} for c in carriers],
    }


def indicator_profile(value: str) -> dict[str, Any]:
    """Everything known about one indicator, domain or IP.

    A new function rather than a wider `observable_history` because that one
    has a pinned return shape and a live caller, while this answers a
    different question: not "what did we see, when" but "what is this, what
    does it share, and what does that prove".

    Nothing here recomputes a judgement. The links come from
    `expand.candidates_for`, which already applies the corroboration rule and
    the rarity gates; this function renders its verdict, it does not
    second-guess it.
    """
    from . import expand

    try:
        with connect_retry(read_only=True) as con:
            observations = _rows(con,
                """SELECT observed_at, source, actor, indicator_type, payload
                   FROM observations_wide WHERE indicator_value = ?
                   ORDER BY observed_at ASC""", [value])
            changes = _rows(con,
                """SELECT detected_at, attribute, change_type, old_value,
                          new_value, confidence, actor
                   FROM attribute_changes WHERE indicator_value = ?
                   ORDER BY detected_at DESC""", [value])
            asn_changes = _rows(con,
                """SELECT detected_at, old_asn, old_netname, new_asn,
                          new_netname, change_type, confidence
                   FROM asn_changes WHERE indicator_value = ?
                   ORDER BY detected_at ASC""", [value])
            zeek_matches = _rows(con,
                """SELECT day, direction, hit_count, ports, first_ts, last_ts
                   FROM zeek_matches WHERE indicator_value = ?
                   ORDER BY day ASC""", [value])
            opendirs = _rows(con,
                """SELECT url, path, is_dir, size, mtime, first_seen, last_seen
                   FROM opendir_files WHERE indicator_value = ?
                   ORDER BY last_seen DESC, path""", [value])
            scans = _rows(con,
                """SELECT ran_at, tools, summary FROM active_scans
                   WHERE indicator_value = ? ORDER BY ran_at DESC""", [value])
            # indicators is a JSON array, so this is a containment test
            # rather than a join. Verified against the live table.
            correlations = _rows(con,
                """SELECT id, created_at, actor, correlation_type, indicators,
                          confidence, narrative
                   FROM correlations
                   WHERE list_contains(CAST(indicators AS VARCHAR[]), ?)
                   ORDER BY created_at DESC""", [value])
            changed = con.execute(
                """SELECT max(detected_at) FROM attribute_changes
                   WHERE indicator_value = ?
                     AND attribute IN ('resolved_ip', 'cert', 'cert_hash')
                     AND change_type <> 'first_seen'""", [value]).fetchone()
            domain_change_at = changed[0] if changed else None

            selectors_here = _selector_detail(con, value)
            links = [c.to_dict() for c in expand.candidates_for(con, value)]
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}

    for o in observations:
        o["payload"] = json.loads(o["payload"]) if o["payload"] is not None else {}

    indicator_type = next((o["indicator_type"] for o in reversed(observations)
                           if o.get("indicator_type")), None)

    now = datetime.now()
    latest_hl = next((o for o in reversed(observations)
                      if o["source"] == "honeylabs"), None)
    latest_change = next((c for c in asn_changes[::-1]
                          if c["change_type"] != "first_seen"), None)
    latest_zeek = zeek_matches[-1] if zeek_matches else None
    latest_resolve = next(
        (o for o in reversed(observations)
         if o["source"] in ("dns_resolve", "observe_dns")
         and (o.get("payload") or {}).get("resolved_ip") is not None), None)
    status = indicator_status(now, indicator_type, {
        "hl_observed_at": latest_hl["observed_at"] if latest_hl else None,
        "hl_events": (latest_hl["payload"].get("hl_events") if latest_hl else None),
        "hl_last_seen": _parse_ts((latest_hl["payload"].get("hl_last_seen")
                                   if latest_hl else None)),
        "asn_change_at": latest_change["detected_at"] if latest_change else None,
        "zeek_day": latest_zeek["day"] if latest_zeek else None,
        "zeek_last_ts": latest_zeek["last_ts"] if latest_zeek else None,
        "last_observed_at": observations[-1]["observed_at"] if observations else None,
        "resolve_observed_at": latest_resolve["observed_at"] if latest_resolve else None,
        "resolved_ip": ((latest_resolve.get("payload") or {}).get("resolved_ip")
                        if latest_resolve else None),
        "domain_change_at": domain_change_at,
    })

    current = _fold_current([{**o, "observed_at": _cell(o["observed_at"])}
                             for o in observations])
    for o in observations:
        o["observed_at"] = _cell(o["observed_at"])
    for c in changes:
        c["detected_at"] = _cell(c["detected_at"])
        for k in ("old_value", "new_value"):
            c[k] = json.loads(c[k]) if c[k] is not None else None
    for c in asn_changes:
        c["detected_at"] = _cell(c["detected_at"])
    for z in zeek_matches:
        for k in ("day", "first_ts", "last_ts"):
            z[k] = _cell(z[k])
        z["ports"] = json.loads(z["ports"]) if z["ports"] is not None else []
    for d in opendirs:
        for k in ("first_seen", "last_seen", "mtime"):
            d[k] = _cell(d[k])
    for s in scans:
        s["ran_at"] = _cell(s["ran_at"])
        for k in ("tools", "summary"):
            s[k] = json.loads(s[k]) if s[k] is not None else None
    for c in correlations:
        c["created_at"] = _cell(c["created_at"])
        c["indicators"] = json.loads(c["indicators"]) if c["indicators"] else []

    actors = sorted({o["actor"] for o in observations if o.get("actor")})
    return {
        "indicator": value,
        "indicator_type": indicator_type,
        "status": status,
        "actors": actors,
        "first_seen": observations[0]["observed_at"] if observations else None,
        "last_seen": observations[-1]["observed_at"] if observations else None,
        "observation_count": len(observations),
        "sources": sorted({o["source"] for o in observations if o.get("source")}),
        "current": current,
        "observations": observations,
        "changes": changes,
        "asn_changes": asn_changes,
        "zeek_matches": zeek_matches,
        "opendir_files": opendirs,
        "active_scans": scans,
        "correlations": correlations,
        "selectors": selectors_here,
        "links": links,
    }


def _parse_ts(value: Any) -> datetime | None:
    """payload timestamps come back as ISO strings; the status ladder diffs
    them against datetime.now()."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    return None


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
                          indicator_type, payload,
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
            changed = con.execute(
                """SELECT max(detected_at) FROM attribute_changes
                   WHERE indicator_value = ?
                     AND attribute IN ('resolved_ip', 'cert', 'cert_hash')
                     AND change_type <> 'first_seen'""", [ip]).fetchone()
            domain_change_at = changed[0] if changed else None
    except TrackingBusy:
        return {"error": "tracking DB busy (daily job likely running); retry shortly"}
    except duckdb.IOException as e:
        return {"error": f"tracking DB unavailable: {e}"}

    # The whole reason this function looked empty. The SELECT above named
    # nineteen columns, every one of them from the IP enrichment path, and
    # never touched `payload` - where the observe pass, InternetDB, mnemonic,
    # the certificates, the body hashes and the DNS records all live. A domain
    # came back as ~170 rows with nothing in them but a date, a source and an
    # actor.
    #
    # Decoded here rather than in the stringify loop below because the domain
    # status ladder reads resolved_ip out of it.
    for o in observations:
        o["payload"] = json.loads(o["payload"]) if o["payload"] is not None else {}

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

    # The domain half, read off the rows already in hand rather than by
    # querying again. tests/test_tracking.py pins that this detail status
    # equals the one tracked_observables() computes, so the two must be fed
    # the same facts from the same ladder.
    indicator_type = next((o["indicator_type"] for o in reversed(observations)
                           if o.get("indicator_type")), None)
    latest_resolve = next(
        (o for o in reversed(observations)
         if o["source"] in ("dns_resolve", "observe_dns")
         and (o.get("payload") or {}).get("resolved_ip") is not None), None)
    status = indicator_status(now, indicator_type, {
        "hl_observed_at": latest_hl["observed_at"] if latest_hl else None,
        "hl_events": latest_hl["hl_events"] if latest_hl else None,
        "hl_last_seen": latest_hl["hl_last_seen"] if latest_hl else None,
        "asn_change_at": latest_change["detected_at"] if latest_change else None,
        "zeek_day": latest_zeek["day"] if latest_zeek else None,
        "zeek_last_ts": latest_zeek["last_ts"] if latest_zeek else None,
        "last_observed_at": observations[-1]["observed_at"] if observations else None,
        "resolve_observed_at": latest_resolve["observed_at"] if latest_resolve else None,
        "resolved_ip": ((latest_resolve.get("payload") or {}).get("resolved_ip")
                        if latest_resolve else None),
        "domain_change_at": domain_change_at,
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
