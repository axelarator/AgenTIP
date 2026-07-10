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
import socket
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

USER_AGENT = "cti-agent-pivot/1.0 (+local analysis tool, on-demand only)"
TIMEOUT = 15
VT_API_KEY_ENV = "VT_API_KEY"

# Nameserver substrings that indicate a domain has been sinkholed/taken
# down rather than being live adversary infrastructure. Extend as you
# encounter new takedown providers.
_SINKHOLE_NS_PATTERNS = (
    "sinkhole", "microsoftinternetsafety.net", "shadowserver", "sink-dns",
    "sinkdns", "unallocated", "cscdns-sinkhole", "sinkholed",
)


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
    # A read-phase timeout raises a bare TimeoutError (not URLError), and a
    # reset raises ConnectionError - both OSError subclasses. Catch them so
    # every caller reliably gets a PivotError to turn into {"error": ...}
    # instead of an exception escaping mid-pivot. ValueError covers a
    # non-JSON body from a rate-limit/error page.
    except (TimeoutError, OSError) as e:
        raise PivotError(f"failed to reach {url}: {e}") from e
    except ValueError as e:
        raise PivotError(f"{url} returned an unparseable response: {e}") from e


def _get_text(url: str, headers: dict[str, str] | None = None) -> str:
    """Fetch a plain-text response (some free enrichment endpoints return
    newline-delimited text rather than JSON)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise PivotError(f"{url} returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise PivotError(f"failed to reach {url}: {e.reason}") from e
    except (TimeoutError, OSError) as e:
        raise PivotError(f"failed to reach {url}: {e}") from e


def resolve_host(host: str) -> list[str] | None:
    """Current A/AAAA answers for a hostname via the system resolver, or
    [] if it doesn't resolve (NXDOMAIN/no address, or resolves only to
    null-route/loopback sentinels - see below), or None if the lookup was
    inconclusive (resolver error). The []-vs-None distinction is what lets
    lifecycle classification tell "dead" (really doesn't resolve) apart
    from "couldn't check right now".

    Answers of 0.0.0.0/:: (unspecified) or 127.0.0.0/8/::1 (loopback) are
    dropped before returning: they're what a local resolver's DNS-based
    egress control (sinkholing a domain to "nowhere") returns instead of
    NXDOMAIN, and a bare truthiness check on the raw getaddrinfo result
    would otherwise read that as a real, live answer and misclassify a
    null-routed domain as "active". Real infrastructure being hunted here
    is never legitimately reachable at those addresses, so this can't
    hide a genuine resolution.

    Deliberately does NOT touch socket.setdefaulttimeout: that's
    process-global state, and pivot_cluster resolves many hosts
    concurrently, so mutating it per-call would race across threads and
    could leave every other socket in the process on a short timeout.
    Relies on the system resolver's own timeout instead; callers that
    fan this out should bound it at the thread-pool level."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    except OSError:
        return None
    addrs = {info[4][0] for info in infos}
    real = set()
    for addr in addrs:
        try:
            parsed = ipaddress.ip_address(addr.split("%", 1)[0])  # strip IPv6 zone id, if any
        except ValueError:
            real.add(addr)  # unparseable is unexpected; don't silently drop it
            continue
        if not (parsed.is_unspecified or parsed.is_loopback):
            real.add(addr)
    return sorted(real)


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


def certspotter_lookup(domain: str) -> dict[str, Any]:
    """Certificate-transparency history for a domain via SSLMate's Cert
    Spotter API - the free, no-key stand-in for crt.sh (which is no longer
    reliably reachable). Returns every hostname seen in a CT-logged
    certificate for the domain and its subdomains (`hostnames`), plus a
    per-issuance summary (issuer + validity window). Those sibling
    hostnames are the pivot leads: infrastructure the same operator stood
    up under the same name that you might not have observed directly.

    The public endpoint is rate-limited without an API token; a 429/HTTP
    error comes back as {"error": ...} rather than raising, so a batch
    pivot degrades gracefully."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names&expand=issuer")
    try:
        data = _get_json(url)
    except PivotError as e:
        return {"error": str(e)}
    if not isinstance(data, list):
        return {"error": "unexpected Cert Spotter response shape"}

    hostnames: set[str] = set()
    issuances = []
    for iss in data:
        names = iss.get("dns_names") or []
        for n in names:
            hostnames.add(n.lstrip("*.").lower())
        issuer = iss.get("issuer")
        issuances.append({
            "issuer": issuer.get("name") if isinstance(issuer, dict) else issuer,
            "not_before": iss.get("not_before"),
            "not_after": iss.get("not_after"),
            "dns_names": names,
        })
    return {
        "issuance_count": len(issuances),
        "hostnames": sorted(hostnames),
        "issuances": issuances[:50],  # cap the verbose part; hostnames is the pivot surface
    }


def hackertarget_reverse_ip(ip: str) -> dict[str, Any]:
    """Domains currently/recently hosted on an IP via Hackertarget's free
    reverse-IP endpoint (plain text, no key, low daily quota). Treat the
    result as co-hosting, NOT confirmed shared ownership: on shared
    hosting these are unrelated tenants. Their own error/quota strings
    come back as {"error": ...}."""
    try:
        text = _get_text(f"https://api.hackertarget.com/reverseiplookup/?q={ip}").strip()
    except PivotError as e:
        return {"error": str(e)}
    low = text.lower()
    # Hackertarget signals "nothing here" / quota / bad input as a single
    # human-readable line rather than an HTTP error, e.g. "No DNS A records
    # found" or "API count exceeded". Catch the known phrases explicitly.
    if not text or any(marker in low for marker in
                       ("api count exceeded", "no dns", "no records", "invalid", "error")):
        return {"error": text or "empty response"}
    # Defense in depth: real results are one hostname per line. Drop any
    # line that can't be a hostname (has spaces, or no dot) so a novel
    # status message can't slip through as a bogus domain.
    domains = sorted({line.strip() for line in text.splitlines()
                      if line.strip() and " " not in line.strip() and "." in line.strip()})
    if not domains:
        return {"error": text or "no domains returned"}
    return {"domains": domains}


def _is_past(date_str: str | None) -> bool:
    if not date_str:
        return False
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < datetime.now(timezone.utc)


def classify_domain_lifecycle(rdap: dict[str, Any] | None,
                               resolved: list[str] | None) -> str:
    """Best-effort lifecycle state for a domain from its RDAP record and
    a live resolution attempt: "sinkholed", "expired", "active", "dead",
    or "unknown". Signals are checked most-conclusive first."""
    if isinstance(rdap, dict):
        nameservers = [(ns or "").lower() for ns in (rdap.get("nameservers") or [])]
        if any(pat in ns for ns in nameservers for pat in _SINKHOLE_NS_PATTERNS):
            return "sinkholed"
        statuses = " ".join(rdap.get("status") or []).lower()
        if any(k in statuses for k in
               ("pending delete", "redemption", "client hold", "server hold", "inactive")):
            return "expired"
        for ev in rdap.get("events") or []:
            if (ev.get("action") or "").lower() in ("expiration", "expiry") and _is_past(ev.get("date")):
                return "expired"
    if resolved:
        return "active"
    if resolved == []:  # resolution attempted and the name has no address
        return "dead"
    return "unknown"


def classify_ip_lifecycle(ripestat: dict[str, Any] | None) -> str:
    """Lifecycle state for an IP: "routed" if it's in an announced prefix
    with an origin ASN, "unrouted" if not currently announced, "unknown"
    if the lookup failed."""
    if not isinstance(ripestat, dict) or ripestat.get("network_info_error"):
        return "unknown"
    return "routed" if ripestat.get("prefix") else "unrouted"
