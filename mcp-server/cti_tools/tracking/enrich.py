"""Budgeted daily enrichment: HoneyLabs telemetry + registry ASN data,
with ASN-change detection against prior observations.

Budget model: HoneyLabs' free tier is ~500 credits/day at 10 req/min,
and every call rides the Win11 VM SSH hop, so the loop is serial,
paced, and capped (CTI_HL_BUDGET, default 400 - leaving headroom for
interactive pivot_observable use). Registry lookups (RIPEstat +
rdap.org, free/no-key but same SSH hop) get their own smaller cap.
A 402/429 mid-loop stops further HoneyLabs calls but keeps everything
already collected - enrichment degrades, never crashes.

Deliberately bypasses core.honeylabs_context: its TTL cache is sized
for interactive pivots and would mask the staleness this pipeline
exists to measure.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

import duckdb

from .. import pivot
from . import store

log = logging.getLogger(__name__)

HL_DAILY_BUDGET = int(os.environ.get("CTI_HL_BUDGET", "400"))
HL_MIN_INTERVAL = float(os.environ.get("CTI_HL_MIN_INTERVAL", "6.5"))
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
    fresh_cutoff = datetime.now() - timedelta(days=RECHECK_AFTER_DAYS)
    never = [r[0] for r in con.execute(
        """SELECT DISTINCT o.indicator_value FROM observations o
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND NOT EXISTS (
               SELECT 1 FROM observations e
               WHERE e.indicator_value = o.indicator_value
                 AND e.source = 'honeylabs')
           ORDER BY o.indicator_value""").fetchall()]
    stale = [r[0] for r in con.execute(
        """SELECT e.indicator_value FROM observations e
           JOIN observations o ON o.indicator_value = e.indicator_value
           JOIN actors a ON a.actor_name = o.actor
           WHERE a.tracked AND e.source = 'honeylabs'
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


def enrich_ips(ips: list[str], rdap_due: set[str],
               api_key: str | None = None) -> tuple[list[EnrichResult], dict[str, Any]]:
    """Network phase - callers must NOT hold a DuckDB connection while
    this runs (it can take minutes at the paced rate)."""
    api_key = api_key or os.environ.get(pivot.HONEYLABS_API_KEY_ENV)
    notes: dict[str, Any] = {"hl_calls": 0, "registry_calls": 0,
                             "budget_exhausted": False,
                             "hl_skipped": api_key is None, "errors": 0}
    results: list[EnrichResult] = []
    hl_available = api_key is not None
    for i, ip in enumerate(ips):
        res = EnrichResult(ip=ip)
        if hl_available:
            if i:
                time.sleep(HL_MIN_INTERVAL)
            try:
                res.honeylabs = pivot.honeylabs_lookup(ip, api_key)
                notes["hl_calls"] += 1
            except pivot.PivotError as e:
                msg = str(e)
                res.errors.append(f"honeylabs: {msg}")
                notes["errors"] += 1
                if "402" in msg or "429" in msg:
                    hl_available = False
                    notes["budget_exhausted"] = True
                    log.warning("HoneyLabs budget/rate limit hit at %s; "
                                "no further lookups today", ip)
        hl_asn = _as_int((res.honeylabs or {}).get("asn"))
        want_registry = ip in rdap_due or (res.honeylabs is not None and hl_asn is None)
        if want_registry and notes["registry_calls"] < RDAP_DAILY_CAP:
            res.registry = _registry_lookup(ip)
            notes["registry_calls"] += 1
        results.append(res)
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
