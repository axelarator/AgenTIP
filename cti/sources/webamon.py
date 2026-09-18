"""Webamon threat-intelligence client - the passive-enrichment layer that
replaces the retired scan platforms (Shodan InternetDB, VirusTotal,
Hackertarget, Cert Spotter). Webamon continuously scans and indexes the
web; we query that index for a domain's latest scan (certificate, DNS,
ASN, tech stack, kit fingerprints), an IP's hosted domains (the reverse-IP
/ passive-hostname replacement), and infostealer-log hits, and can submit
a fresh scan when the index has nothing recent.

Unlike pivot.py's sources, these calls are made **directly from this host**
rather than through the probe VM: they hit Webamon's SaaS, not the tracked
indicator's own infrastructure, so there's no adversary-facing traffic to
keep off the analyst's host - the same deliberate exception already made
for the HoneyLabs MCP server.

Every function returns a plain dict, or `{"error": "..."}` on failure -
never raises into the enrichment sweep - so `_cached_pivot` and the
snapshot/history consumers can gate on `"error" not in result` exactly as
they do for the pivot sources.

Auth: header `x-api-key: <WEBAMON_API_KEY>`. Base `https://pro.webamon.com`.
A soft daily budget (CTI_WEBAMON_DAILY_BUDGET, default 1000) is tracked in
a small JSON counter next to the pivot cache and checked before each call,
so a runaway sweep can't blow the plan's quota. The counter is a file (not
the DuckDB store) on purpose: this is called from core._sweep_lifecycle's
6-thread pool, and a per-call DuckDB read-write connection would contend on
DuckDB's single-writer-per-process file lock. A file counter with an
in-process lock is racy across the cron and MCP-server processes, but the
budget is only a soft guard, so a small over/undercount is acceptable.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from datetime import date
from typing import Any

from . import budget, http

BASE_URL = os.environ.get("CTI_WEBAMON_BASE", "https://pro.webamon.com")
USER_AGENT = "cti-agent"
WEBAMON_API_KEY_ENV = "WEBAMON_API_KEY"
HTTP_TIMEOUT = 30

_DAILY_BUDGET_ENV = "CTI_WEBAMON_DAILY_BUDGET"
_DAILY_BUDGET_DEFAULT = 1000
_RESCAN_DAYS_ENV = "CTI_WEBAMON_RESCAN_DAYS"
_RESCAN_DAYS_DEFAULT = 7

# Curated field list for scan-index queries: everything useful for
# enrichment, deliberately excluding `dom` (full page HTML) and
# `page_scripts` (both large and never stored).
_SCAN_FIELDS = ("report_id,date,scan_status,resolved_url,resolved_domain,"
                "page_title,meta,certificate,domain,server,technology,fingerprint,tag")

# Mirror core.DATA_DIR without importing core (core imports this module).
def _api_key() -> str | None:
    return os.environ.get(WEBAMON_API_KEY_ENV)


def rescan_days() -> int:
    try:
        return int(os.environ.get(_RESCAN_DAYS_ENV, _RESCAN_DAYS_DEFAULT))
    except ValueError:
        return _RESCAN_DAYS_DEFAULT


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
# The daily counter that used to live here - its own JSON file, its own
# read-modify-write, its own inline atomic write - is now
# sources/budget.py, shared with RDAP and HoneyLabs and safe under the
# parallel fan-out. The urllib transport is now sources/http.py.
#
# Webamon is one of the two documented via="direct" exceptions: it queries
# the vendor's own scan index, not the indicator's own infrastructure, so
# routing it through the probe VM would spend that host's egress allowance
# for no OPSEC benefit.

def quota_used_today() -> int:
    return budget.used_today("webamon")


def _daily_budget() -> int:
    return budget.cap("webamon")


def _get(path: str, params: dict[str, Any]) -> Any:
    key = _api_key()
    if not key:
        return {"error": f"no {WEBAMON_API_KEY_ENV} configured"}
    try:
        budget.spend("webamon", 1)
    except budget.BudgetExhausted:
        return {"error": "webamon daily budget exhausted"}

    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{BASE_URL.rstrip('/')}/{path.lstrip('/')}?{query}"
    try:
        return http.get_json(url, via="direct", headers={"x-api-key": key},
                             timeout=HTTP_TIMEOUT)
    except http.HttpError as e:
        # These three are worth naming rather than collapsing into one
        # error: they are the difference between "fix your key", "upgrade
        # your plan" and "wait a minute".
        if e.status == 401:
            return {"error": "webamon auth failed (check WEBAMON_API_KEY)"}
        if e.status == 403:
            return {"error": "webamon forbidden (plan/quota)"}
        if e.status == 429:
            return {"error": "webamon rate limited"}
        if e.status is not None:
            return {"error": f"webamon HTTP {e.status}"}
        return {"error": f"failed to reach webamon: {e}"}




def _search(params: dict[str, Any]) -> Any:
    """GET /search, returning the parsed response dict or {"error": ...}."""
    result = _get("/search", params)
    if isinstance(result, dict) and "error" in result:
        return result
    if not isinstance(result, dict):
        return {"error": "webamon returned a non-object response"}
    return result


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #
def _cert(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "issuer": entry.get("issuer"),
        "subject": entry.get("subject_name"),
        "sans": entry.get("san_list") or [],
        "not_before": entry.get("valid_from_utc"),
        "not_after": entry.get("valid_to_utc"),
        "protocol": entry.get("protocol"),
    }


def normalize_scan(doc: dict[str, Any]) -> dict[str, Any]:
    """Pull the enrichment-relevant fields out of a Webamon scan document.
    Drops `dom`/`page_scripts` (large, never stored)."""
    if not isinstance(doc, dict):
        return {}
    meta = doc.get("meta") or {}
    fp = doc.get("fingerprint") or {}
    certs = [_cert(c) for c in (doc.get("certificate") or []) if isinstance(c, dict)]
    ips = []
    for d in (doc.get("domain") or []):
        if not isinstance(d, dict):
            continue
        asn = d.get("asn") or {}
        ips.append({"name": d.get("name"), "ip": d.get("ip"),
                    "server": d.get("server"),
                    "asn": asn.get("number"), "asn_name": asn.get("name"),
                    "asn_network": asn.get("network"),
                    "country": (d.get("country") or {}).get("iso")})
    return {
        "report_id": doc.get("report_id"),
        "date": doc.get("date"),
        "scan_status": doc.get("scan_status"),
        "resolved_url": doc.get("resolved_url"),
        "resolved_domain": doc.get("resolved_domain"),
        "page_title": doc.get("page_title"),
        "risk_score": meta.get("risk_score"),
        "certificates": certs,
        "ips": ips,
        "technology": doc.get("technology") or [],
        "fingerprint": {k: fp.get(k) for k in
                        ("dom", "ssl", "tech", "cookies", "asn", "scripts", "links", "domains")},
    }


# --------------------------------------------------------------------------- #
# public lookups
# --------------------------------------------------------------------------- #
def search_domain(domain: str, size: int = 5) -> dict[str, Any]:
    """Latest Webamon scan(s) for a domain (scans index). Returns
    {"total_hits", "results": [normalized...], "latest": normalized|None}."""
    resp = _search({"lucene_query": f'domain.name:"{domain}"', "index": "scans",
                    "fields": _SCAN_FIELDS, "size": size})
    if "error" in resp:
        return resp
    results = [normalize_scan(r) for r in (resp.get("results") or [])]
    # A scan matches `domain.name:"X"` whenever ANY domain it loaded equals X
    # - including a malicious page that merely fetched X as a resource. For
    # enrichment we want a scan actually *of* X, so prefer the newest result
    # whose submission resolved to the queried domain; fall back to the
    # newest result only when none does.
    own = [r for r in results if r.get("resolved_domain") == domain]
    latest = (own or results)[0] if results else None
    return {"total_hits": resp.get("total_hits"), "results": results, "latest": latest}


def search_ip(ip: str, size: int = 50) -> dict[str, Any]:
    """Domains Webamon has scanned resolving to this IP (server.ip on the
    scans index) - the reverse-IP / passive-hostname replacement. Returns
    {"total_hits", "domains": [...], "results": [{resolved_domain,date,page_title}]}."""
    resp = _search({"lucene_query": f'server.ip:"{ip}"', "index": "scans",
                    "fields": "resolved_domain,date,page_title", "size": size})
    if "error" in resp:
        return resp
    results = resp.get("results") or []
    domains = sorted({r.get("resolved_domain") for r in results if r.get("resolved_domain")})
    return {"total_hits": resp.get("total_hits"), "domains": domains, "results": results}


def infostealers(term: str, size: int = 25) -> dict[str, Any]:
    """Infostealer-log hits for a domain. The plaintext `password` field is
    dropped at this boundary - only the masked `password_peek` is kept.

    Both clauses are phrase-quoted, and every returned row is re-checked
    against `term` before it counts. Unquoted, `username:@example.com` gets
    analyzed into tokens and ORs into a match against most of the index: a
    deliberately nonsense domain came back with 572k "hits" on aarp.org /
    canva.com / netflix.com, so every tracked domain looked compromised.
    Re-checking client-side keeps that from depending on how the index
    happens to analyze a field.

    `total_hits` is how many rows actually matched `term`; `raw_total_hits`
    is what the index claimed for the query, and `capped` means the page
    came back full, so the real total may be higher than what was counted.
    """
    quoted = f'"{term}"'
    resp = _search({"lucene_query": f'domain:{quoted} OR username:"@{term}"',
                    "index": "infostealers", "size": size})
    if "error" in resp:
        return resp
    raw = [r for r in (resp.get("results") or []) if isinstance(r, dict)]
    needle = term.lower()
    out = []
    for r in raw:
        domain = (r.get("domain") or "").lower()
        username = (r.get("username") or "").lower()
        if not (domain == needle or domain.endswith("." + needle)
                or f"@{needle}" in username):
            continue
        out.append({k: r.get(k) for k in
                    ("domain", "url", "username", "password_peek", "source",
                     "file_name", "file_sha256", "ingest_date")})
    return {"total_hits": len(out), "raw_total_hits": resp.get("total_hits"),
            "capped": len(raw) >= size, "results": out}


def fingerprint_siblings(fp_hash: str, kind: str = "dom", size: int = 25) -> dict[str, Any]:
    """Other scanned domains sharing a Webamon kit fingerprint
    (fingerprint.dom / fingerprint.ssl) - the campaign-cluster signal that
    stands in for the plan-gated /clusters endpoint. Returns
    {"total_hits", "domains": [...]}."""
    resp = _search({"lucene_query": f'fingerprint.{kind}:"{fp_hash}"', "index": "scans",
                    "fields": "resolved_domain,date", "size": size})
    if "error" in resp:
        return resp
    domains = sorted({r.get("resolved_domain") for r in (resp.get("results") or [])
                      if r.get("resolved_domain")})
    return {"total_hits": resp.get("total_hits"), "domains": domains}


def submit_scan(submission_url: str) -> dict[str, Any]:
    """Submit a fresh Webamon scan (their infrastructure, not ours).
    Returns {"report_id": ...} or {"error": ...}."""
    resp = _get("/scan", {"submission_url": submission_url})
    if isinstance(resp, dict) and "error" in resp:
        return resp
    if isinstance(resp, dict) and resp.get("report_id"):
        return {"report_id": resp["report_id"]}
    return {"error": f"unexpected scan response: {resp!r}"[:200]}


def poll_scan(report_id: str) -> dict[str, Any] | None:
    """Fetch a submitted scan's result by polling the scans index for its
    report_id. Returns the normalized scan, or None if not indexed yet."""
    resp = _search({"lucene_query": f'report_id:"{report_id}"', "index": "scans",
                    "fields": _SCAN_FIELDS, "size": 1})
    if "error" in resp:
        return None
    results = resp.get("results") or []
    return normalize_scan(results[0]) if results else None


def status() -> dict[str, Any]:
    """Cheap connectivity/quota check for --check-access style callers."""
    if not _api_key():
        return {"ok": False, "error": f"no {WEBAMON_API_KEY_ENV} configured"}
    resp = _search({"search": "example.com", "results": "domain.name", "size": 1})
    return {"ok": "error" not in resp, "used_today": quota_used_today(),
            "budget": _daily_budget(), **({"error": resp["error"]} if "error" in resp else {})}
