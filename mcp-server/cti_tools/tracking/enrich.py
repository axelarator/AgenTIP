"""Budgeted daily enrichment: HoneyLabs telemetry + registry ASN data,
with ASN-change detection against prior observations.

HoneyLabs telemetry comes over their hosted MCP server (see hl_mcp for
why, and for the OPSEC exception it makes): one session per batch,
back-to-back calls with light pacing, so the HoneyLabs phase runs in
minutes rather than the half hour the direct 10 req/min API took. The
MCP quota is not publicly documented, so the batch stays capped
(CTI_HL_BUDGET, default 400); mid-batch 429s adaptively slow the pace
with backoff retries, and a credit-exhausted (402) or persistently
rate-limited response stops further HoneyLabs calls but keeps
everything already collected - enrichment degrades, never crashes.

Registry lookups (RIPEstat + rdap.org, free/no-key, still via the
Win11 VM SSH hop) run as a second phase with their own smaller cap.

Deliberately bypasses core.honeylabs_context: its TTL cache is sized
for interactive pivots and would mask the staleness this pipeline
exists to measure.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import duckdb

from .. import pivot
from . import hl_mcp, store

log = logging.getLogger(__name__)

HL_DAILY_BUDGET = int(os.environ.get("CTI_HL_BUDGET", "400"))
HL_MIN_INTERVAL = float(os.environ.get("CTI_HL_MIN_INTERVAL", "6.0"))
HL_RATE_RETRY_SECS = float(os.environ.get("CTI_HL_RATE_RETRY_SECS", "30"))
HL_RATE_MAX_RETRIES = 3
HL_MAX_INTERVAL = 15.0
HL_PREFILTER_CHUNK = 32
HL_MAX_CONSECUTIVE_ERRORS = 5
RDAP_DAILY_CAP = int(os.environ.get("CTI_RDAP_CAP", "150"))
RECHECK_AFTER_DAYS = 7      # HoneyLabs re-check window
RDAP_RECHECK_DAYS = 30      # registry data moves much slower
STALE_BASELINE_DAYS = 90    # older baselines downgrade change confidence


@dataclass
class EnrichResult:
    ip: str
    honeylabs: dict[str, Any] | None = None
    registry: dict[str, Any] | None = None   # {asn, netname, country_code, ...}
    errors: list[str] = field(default_factory=list)


def build_worklist(con: duckdb.DuckDBPyConnection,
                   budget: int = HL_DAILY_BUDGET) -> tuple[list[str], set[str]]:
    """(ips_to_enrich, rdap_due) - never-enriched tracked IPs first,
    then the stalest re-checks, truncated to budget."""
    # HoneyLabs/RDAP/RIPEstat are IP-only sources - exclude domain
    # observations (e.g. from pivot_cluster's Shodan/ThreatFox history
    # logging) so they don't reach the IP-prefilter/CIDR logic below.
    fresh_cutoff = datetime.now() - timedelta(days=RECHECK_AFTER_DAYS)
    never = [r[0] for r in con.execute(
        """SELECT DISTINCT o.indicator_value FROM observations o
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND o.indicator_type IN ('ipv4', 'ipv6')
             AND NOT EXISTS (
               SELECT 1 FROM observations e
               WHERE e.indicator_value = o.indicator_value
                 AND e.source = 'honeylabs')
           ORDER BY o.indicator_value""").fetchall()]
    stale = [r[0] for r in con.execute(
        """SELECT e.indicator_value FROM observations e
           JOIN observations o ON o.indicator_value = e.indicator_value
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND e.source = 'honeylabs'
             AND o.indicator_type IN ('ipv4', 'ipv6')
           GROUP BY e.indicator_value
           HAVING max(e.observed_at) < ?
           ORDER BY max(e.observed_at)""", [fresh_cutoff]).fetchall()]
    seen: set[str] = set()
    worklist = [ip for ip in never + stale
                if not (ip in seen or seen.add(ip))][:budget]

    rdap_cutoff = datetime.now() - timedelta(days=RDAP_RECHECK_DAYS)
    rdap_fresh = {r[0] for r in con.execute(
        """SELECT indicator_value FROM observations
           WHERE source = 'rdap' GROUP BY indicator_value
           HAVING max(observed_at) >= ?""", [rdap_cutoff]).fetchall()}
    rdap_due = {ip for ip in worklist if ip not in rdap_fresh}
    return worklist, rdap_due


def _ts(value: Any) -> datetime | None:
    """ISO string (Z-suffixed or not) -> naive UTC datetime, else None."""
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _port_list(ports: Any) -> list[int]:
    """HoneyLabs top_ports items are dicts ({"port": N, ...}); accept
    bare ints too, mirroring summarize_honeylabs's defensiveness."""
    out = []
    for p in ports or []:
        n = _as_int(p.get("port") if isinstance(p, dict) else p)
        if n is not None:
            out.append(n)
    return out


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    s = str(value).upper().lstrip("AS").strip()
    return int(s) if s.isdigit() else None


def _registry_lookup(ip: str) -> dict[str, Any]:
    """ASN from RIPEstat (authoritative, includes holder), netname from
    the RIR's RDAP record. Both free/no-key; failures are partial."""
    result: dict[str, Any] = {"asn": None, "netname": None,
                              "country_code": None, "as_holder": None}
    try:
        ripe = pivot.ripestat_lookup(ip)
        asns = ripe.get("asn") or []
        result["asn"] = _as_int(asns[0]) if asns else None
        result["as_holder"] = ripe.get("as_holder")
        geo = ripe.get("geolocation") or {}
        result["country_code"] = geo.get("country")
    except pivot.PivotError as e:
        result["error_ripestat"] = str(e)
    rdap = pivot.rdap_lookup(ip, "ip")
    if "error" in rdap:
        result["error_rdap"] = rdap["error"]
    else:
        result["netname"] = rdap.get("name") or rdap.get("handle")
    return result


async def _hl_phase(results: list[EnrichResult], api_key: str,
                    notes: dict[str, Any]) -> None:
    """Two passes over one MCP session, paced under the shared 10/min
    limit: first prefilter the worklist in /32 cidr_set chunks (one
    call per HL_PREFILTER_CHUNK IPs; a 0 count is an observed absence,
    recorded without a per-IP call), then full lookups for just the
    IPs with events. A 429 widens the inter-call interval for the rest
    of the batch, backs off, and retries a few times; a
    credit-exhausted (402) response, a still-limited call after all
    retries, or a run of consecutive failures (dead session) ends the
    phase early, keeping everything already collected."""
    consecutive_errors = 0
    interval = HL_MIN_INTERVAL
    calls_made = 0

    class _StopPhase(Exception):
        pass

    async def _paced(fn, *args, label=""):
        """Pace, call, and retry-on-429; raises _StopPhase when the
        phase should end (quota gone or the session looks dead)."""
        nonlocal interval, calls_made, consecutive_errors
        for attempt in range(HL_RATE_MAX_RETRIES + 1):
            if calls_made:
                await asyncio.sleep(interval)
            try:
                out = await fn(*args)
                calls_made += 1
                notes["hl_calls"] += 1
                consecutive_errors = 0
                return out
            except pivot.PivotError as e:
                calls_made += 1
                rate, budget = hl_mcp.is_rate_or_budget(str(e))
                if rate and not budget and attempt < HL_RATE_MAX_RETRIES:
                    interval = min(max(interval * 2, 1.0), HL_MAX_INTERVAL)
                    log.info("HoneyLabs MCP rate limit at %s; backing off "
                             "%ss and slowing pace to %.1fs",
                             label, HL_RATE_RETRY_SECS, interval)
                    await asyncio.sleep(HL_RATE_RETRY_SECS)
                    continue
                notes["errors"] += 1
                if rate or budget:
                    notes["budget_exhausted"] = True
                    log.warning("HoneyLabs budget/rate limit hit at %s; "
                                "no further lookups today", label)
                    raise _StopPhase from e
                consecutive_errors += 1
                if consecutive_errors >= HL_MAX_CONSECUTIVE_ERRORS:
                    log.warning("%d consecutive HoneyLabs MCP failures at "
                                "%s; abandoning telemetry for this run",
                                consecutive_errors, label)
                    raise _StopPhase from e
                raise

    pending: list[EnrichResult] = []
    try:
        async with hl_mcp.open_session(api_key) as session:
            for start in range(0, len(results), HL_PREFILTER_CHUNK):
                chunk = results[start:start + HL_PREFILTER_CHUNK]
                ips = [r.ip for r in chunk]
                try:
                    counts = await _paced(hl_mcp.prefilter, session, ips,
                                          label=f"prefilter[{ips[0]}..]")
                except pivot.PivotError as e:
                    # Chunk-shaped failure only; fall back to per-IP.
                    log.warning("prefilter chunk failed (%s); falling back "
                                "to per-IP lookups for %d IPs", e, len(ips))
                    pending.extend(chunk)
                    continue
                for r in chunk:
                    if counts.get(r.ip) == 0:
                        r.honeylabs = hl_mcp.not_observed()
                        notes["hl_prefiltered_absent"] += 1
                    else:
                        pending.append(r)
            log.info("HoneyLabs prefilter: %d of %d IPs absent, "
                     "%d full lookups to go",
                     notes["hl_prefiltered_absent"], len(results),
                     len(pending))
            for res in pending:
                try:
                    res.honeylabs = await _paced(hl_mcp.lookup, session,
                                                 res.ip, label=res.ip)
                except pivot.PivotError as e:
                    res.errors.append(f"honeylabs: {e}")
    except _StopPhase:
        return


def enrich_ips(ips: list[str], rdap_due: set[str],
               api_key: str | None = None) -> tuple[list[EnrichResult], dict[str, Any]]:
    """Network phase - callers must NOT hold a DuckDB connection while
    this runs (it can take minutes at the paced rate)."""
    api_key = api_key or os.environ.get(pivot.HONEYLABS_API_KEY_ENV)
    notes: dict[str, Any] = {"hl_calls": 0, "hl_prefiltered_absent": 0,
                             "registry_calls": 0, "budget_exhausted": False,
                             "hl_skipped": api_key is None, "errors": 0}
    results = [EnrichResult(ip=ip) for ip in ips]
    if api_key is not None and results:
        try:
            asyncio.run(_hl_phase(results, api_key, notes))
        except pivot.PivotError as e:
            # Session never came up (or died unrecoverably); registry
            # phase still runs.
            notes["errors"] += 1
            notes["hl_session_error"] = str(e)
            log.warning("HoneyLabs MCP session failed: %s", e)
    for res in results:
        hl_asn = _as_int((res.honeylabs or {}).get("asn"))
        want_registry = (res.ip in rdap_due
                         or (res.honeylabs is not None and hl_asn is None))
        if want_registry and notes["registry_calls"] < RDAP_DAILY_CAP:
            res.registry = _registry_lookup(res.ip)
            notes["registry_calls"] += 1
    return results, notes


def _actor_map(con: duckdb.DuckDBPyConnection, ips: list[str]) -> dict[str, str]:
    if not ips:
        return {}
    rows = con.execute(
        """SELECT indicator_value, actor FROM (
               SELECT indicator_value, actor,
                      row_number() OVER (PARTITION BY indicator_value
                                         ORDER BY observed_at DESC) AS rn
               FROM observations
               WHERE actor IS NOT NULL AND indicator_value IN
                   (SELECT unnest(?::TEXT[])))
           WHERE rn = 1""", [ips]).fetchall()
    return dict(rows)


def _confidence(new_source: str, baseline: dict[str, Any],
                corroborated: bool) -> str:
    conf = "high" if (new_source == "rdap"
                      and (baseline["source"] == "rdap" or corroborated)) \
        else "medium"
    age = datetime.now() - baseline["observed_at"]
    if age > timedelta(days=STALE_BASELINE_DAYS) and conf != "low":
        conf = {"high": "medium", "medium": "low"}[conf]
    return conf


def apply_results(con: duckdb.DuckDBPyConnection, results: list[EnrichResult],
                  today: date) -> dict[str, Any]:
    """Write phase: observation rows, ASN-change rows, actor refresh.
    One short-lived rw connection, no network."""
    observed_at = datetime.combine(today, datetime.min.time())
    actors = _actor_map(con, [r.ip for r in results])
    changes: list[dict[str, Any]] = []
    enriched = 0
    for res in results:
        actor = actors.get(res.ip)
        hl = res.honeylabs
        hl_asn = _as_int((hl or {}).get("asn"))
        reg = res.registry or {}
        new_asn = reg.get("asn") or hl_asn
        new_netname = reg.get("netname") or (hl or {}).get("as_org")
        new_source = "rdap" if reg.get("asn") is not None else "honeylabs"

        baseline = (store.latest_asn_for(con, res.ip, observed_at)
                    if new_asn is not None else None)

        if hl is not None:
            tags = [t for t in [hl.get("verdict_label"), hl.get("verdict")]
                    if t] + list(hl.get("known_scanners") or [])
            store.upsert_observation(
                con, observed_at=observed_at, indicator_value=res.ip,
                source="honeylabs", actor=actor,
                hl_events=hl.get("events"), hl_events_7d=hl.get("events_7d"),
                hl_first_seen=_ts(hl.get("first_seen")),
                hl_last_seen=_ts(hl.get("last_seen")),
                hl_ports=_port_list(hl.get("ports")) or None,
                hl_tags=tags or None,
                hl_threat_level=hl.get("verdict"),
                asn=hl_asn, netname=hl.get("as_org"),
                country_code=hl.get("country"),
                metadata={"verdict_confidence": hl.get("verdict_confidence"),
                          "cves": hl.get("cves"), "malware": hl.get("malware")})
            enriched += 1
        if reg.get("asn") is not None or reg.get("netname"):
            store.upsert_observation(
                con, observed_at=observed_at, indicator_value=res.ip,
                source="rdap", actor=actor,
                asn=reg.get("asn"), netname=reg.get("netname"),
                country_code=reg.get("country_code"),
                metadata={"as_holder": reg.get("as_holder")})

        if new_asn is None:
            continue
        if baseline is None:
            change = {"change_type": "first_seen", "confidence": "medium",
                      "old_asn": None, "old_netname": None}
        elif baseline["asn"] != new_asn:
            corroborated = hl_asn is not None and hl_asn == reg.get("asn")
            change = {"change_type": "asn_change",
                      "confidence": _confidence(new_source, baseline, corroborated),
                      "old_asn": baseline["asn"], "old_netname": baseline["netname"]}
        elif (baseline["netname"] and new_netname
              and baseline["netname"] != new_netname):
            change = {"change_type": "netname_change", "confidence": "medium",
                      "old_asn": baseline["asn"], "old_netname": baseline["netname"]}
        else:
            change = None
        if change:
            store.record_asn_change(
                con, detected_at=observed_at, indicator_value=res.ip,
                actor=actor, new_asn=new_asn, new_netname=new_netname, **change)
            changes.append({"ip": res.ip, "actor": actor, "new_asn": new_asn,
                            "new_netname": new_netname, **change})
        if actor:
            store.upsert_actor(con, actor, observed_at, asns=[new_asn],
                               ports=_port_list((hl or {}).get("ports")))
    return {"ips_enriched": enriched, "asn_changes": changes}
