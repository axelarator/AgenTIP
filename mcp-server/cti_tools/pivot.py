"""On-demand infrastructure pivoting against free, no-recurring-cost
public data sources.

This is a deliberate, narrow exception to this tool's "no external API
calls" design: report_ingest.py already fetches a URL you explicitly
hand it, but this module reaches out to third-party enrichment
services to ask "what else is tied to this indicator" - only when a
caller calls pivot_observable for a specific value, never automatically
or on a schedule. See SKILL.md's "Infrastructure pivoting" section for
when to reach for it.

Sources, none of which require a paid plan:
- RDAP (WHOIS's standardized successor) via the public rdap.org
  bootstrap redirector - no API key, no per-registry bootstrap logic
  needed on our side.
- RIPEstat's free Data API - no API key, covers ASN/network context
  and geolocation for any routed IP, not just RIPE-region space.
- VirusTotal's public API - free tier, but does require your own API
  key (VT_API_KEY env var) and is rate-limited (4 req/min, 500/day as
  of writing). Gives reputation, resolution history (VT's equivalent
  of passive DNS), and file/URL detection verdicts. Skipped gracefully
  if no key is configured - RDAP/RIPEstat still work without one.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "cti-agent-pivot/1.0 (+local analysis tool, on-demand only)"
TIMEOUT = 15
VT_API_KEY_ENV = "VT_API_KEY"


class PivotError(Exception):
    pass


def _get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        raise PivotError(f"{url} returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise PivotError(f"failed to reach {url}: {e.reason}") from e


def classify(value: str) -> str:
    """Best-effort observable type: "ip", "url", "hash", or "domain"
    (the fallback). Same shape of heuristic as report_ingest's
    extraction, not a strict validator."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if v.startswith(("http://", "https://")):
        return "url"
    if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
        return "hash"
    return "domain"


def rdap_lookup(value: str, kind: str) -> dict[str, Any]:
    """Registration data (registrar/holder, creation/expiry events,
    nameservers) via rdap.org - the public bootstrap redirector that
    routes to whichever registry actually holds the record, so this
    doesn't need its own per-TLD/per-RIR bootstrap table."""
    path = "ip" if kind == "ip" else "domain"
    try:
        data = _get_json(f"https://rdap.org/{path}/{value}")
    except PivotError as e:
        return {"error": str(e)}
    return {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "status": data.get("status"),
        "events": [{"action": e.get("eventAction"), "date": e.get("eventDate")}
                   for e in data.get("events", [])],
        "entities": [{"roles": e.get("roles"), "handle": e.get("handle")}
                     for e in data.get("entities", [])],
        "nameservers": ([ns.get("ldhName") for ns in data.get("nameservers", [])]
                         if kind == "domain" else None),
    }


def ripestat_lookup(ip: str) -> dict[str, Any]:
    """ASN/network context and geolocation for an IP via RIPEstat's
    free Data API (no key). Three cheap calls merged into one result;
    each failure is recorded independently rather than aborting the
    whole lookup."""
    result: dict[str, Any] = {}

    try:
        net = _get_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")
        net_data = net.get("data") or {}
        result["asn"] = net_data.get("asns")
        result["prefix"] = net_data.get("prefix")
    except PivotError as e:
        result["network_info_error"] = str(e)

    asns = result.get("asn") or []
    if asns:
        try:
            overview = _get_json(f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asns[0]}")
            result["as_holder"] = (overview.get("data") or {}).get("holder")
        except PivotError as e:
            result["as_overview_error"] = str(e)

    try:
        geo = _get_json(f"https://stat.ripe.net/data/geoloc/data.json?resource={ip}")
        locations = (geo.get("data") or {}).get("locations") or []
        result["geolocation"] = locations[0] if locations else None
    except PivotError as e:
        result["geoloc_error"] = str(e)

    return result


def virustotal_lookup(value: str, kind: str, api_key: str) -> dict[str, Any]:
    """Reputation and resolution-history data via VirusTotal's public
    API v3. domain/ip lookups include VT's resolution history (its
    passive-DNS equivalent); hash lookups return detection verdicts and
    known filenames; url lookups return detection verdicts. Raises
    PivotError on request failure - the caller decides whether that's
    fatal or just a missing section in a larger result."""
    headers = {"x-apikey": api_key}

    if kind == "domain":
        base = _get_json(f"https://www.virustotal.com/api/v3/domains/{value}", headers)
        resolutions = _get_json(
            f"https://www.virustotal.com/api/v3/domains/{value}/resolutions?limit=20", headers)
        attrs = (base.get("data") or {}).get("attributes", {})
        return {
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "resolutions": [
                {"ip": r["attributes"].get("ip_address"), "date": r["attributes"].get("date")}
                for r in resolutions.get("data", [])
            ],
        }

    if kind == "ip":
        base = _get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{value}", headers)
        resolutions = _get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{value}/resolutions?limit=20", headers)
        attrs = (base.get("data") or {}).get("attributes", {})
        return {
            "reputation": attrs.get("reputation"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "resolutions": [
                {"domain": r["attributes"].get("host_name"), "date": r["attributes"].get("date")}
                for r in resolutions.get("data", [])
            ],
        }

    if kind == "hash":
        base = _get_json(f"https://www.virustotal.com/api/v3/files/{value}", headers)
        attrs = (base.get("data") or {}).get("attributes", {})
        return {
            "names": attrs.get("names"),
            "type_description": attrs.get("type_description"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "popular_threat_classification": attrs.get("popular_threat_classification"),
        }

    if kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
        base = _get_json(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers)
        attrs = (base.get("data") or {}).get("attributes", {})
        return {
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "categories": attrs.get("categories"),
            "last_final_url": attrs.get("last_final_url"),
        }

    raise PivotError(f"unsupported kind for VirusTotal lookup: {kind}")
