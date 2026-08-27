"""On-demand infrastructure pivoting against free, no-recurring-cost
public data sources.

This is a deliberate, narrow exception to this tool's "no external API
calls" design: report_ingest.py already fetches a URL you explicitly
hand it, but this module reaches out to third-party enrichment
services to ask "what else is tied to this indicator". pivot_observable
is strictly on-demand - only when a caller names a specific value.
pivot_cluster (core.py) sweeps a whole cluster and IS run on a
schedule: the daily cron (scripts/daily_tracking.py) calls it once per
tracked cluster so lifecycle status and open ports don't go stale
between manual pivots. See SKILL.md's "Infrastructure pivoting" section
for when to reach for either by hand.

Sources, none of which require a paid plan:
- RDAP (WHOIS's standardized successor) via the public rdap.org
  bootstrap redirector - no API key, no per-registry bootstrap logic
  needed on our side.
- RIPEstat's free Data API - no API key, covers ASN/network context
  and geolocation for any routed IP, not just RIPE-region space.
- VirusTotal's public API - free tier, but does require your own API
  key (VT_API_KEY env var) and is rate-limited (4 req/min, 500/day as
  of writing). Gives reputation, resolution history (VT's equivalent
  of passive DNS), file/URL detection verdicts, and - for IPs -
  communicating_files/downloaded_files: samples VT has actually seen
  talk to or fetch from that IP, useful for finding malware hashes
  tied to a tracked C2 IP when the source report only gave you the
  infrastructure, not per-sample coverage. Skipped gracefully if no
  key is configured - RDAP/RIPEstat still work without one.
- Shodan InternetDB (internetdb.shodan.io) - no API key, no published
  rate limit; open ports, hostnames, CPEs, vulns, and tags Shodan has
  observed for an IP. IP only.
- ThreatFox (abuse.ch) - free IOC-matching API; checks a domain/ip/
  url/hash against abuse.ch's own malware-C2 IOC database and returns
  any matching threat/malware-family tags. Covers every observable
  kind through one query endpoint. Requires your own free Auth-Key
  (THREATFOX_API_KEY env var; register at https://auth.abuse.ch/) -
  abuse.ch's unified Auth Portal requires this header on every
  ThreatFox call now, including search_ioc, despite the query API
  historically being keyless. Skipped gracefully if no key is
  configured.
- HoneyLabs (honeylabs.net) - honeypot-fleet telemetry for an IP:
  how often, how recently, and against which ports/CVEs their sensors
  have seen it scanning. Free tier needs your own API key
  (HONEYLABS_API_KEY env var; 500 credits/day, 10 req/min). Presence
  here usually reads as mass-scanner/opportunistic background noise -
  a counter-signal for "dedicated C2" - while absence on an otherwise
  active IP is the quiet-infrastructure signal. Skipped gracefully if
  no key is configured; deliberately no keyless fallback (keyless
  lookups would burn the probe VM egress IP's shared 60/hr allowance).

Every one of these lookups names a tracked indicator to a third party
(the domain/IP/hash being pivoted on), so - same as active
fingerprinting - none of it originates from this host. All HTTP calls
and DNS resolution route through cti_tools.vm_proxy, which proxies them
through the Win11 probe VM over its restricted SSH channel. See
vm_proxy's module docstring for why.
"""
from __future__ import annotations

import base64
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

from . import vm_proxy

USER_AGENT = "cti-agent-pivot/1.0 (+local analysis tool, on-demand only)"
VT_API_KEY_ENV = "VT_API_KEY"
HONEYLABS_API_KEY_ENV = "HONEYLABS_API_KEY"
THREATFOX_API_KEY_ENV = "THREATFOX_API_KEY"

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
    body = _get_text(url, headers)
    try:
        return json.loads(body)
    except ValueError as e:
        raise PivotError(f"{url} returned an unparseable response: {e}") from e


def _get_text(url: str, headers: dict[str, str] | None = None) -> str:
    """Fetch a response body (some free enrichment endpoints return
    newline-delimited text rather than JSON, hence text rather than
    always decoding JSON here). Proxied through the Win11 VM - see the
    module docstring."""
    try:
        result = vm_proxy.http_fetch(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    except vm_proxy.VMProxyError as e:
        raise PivotError(f"failed to reach {url}: {e}") from e
    status = result.get("status")
    if status is not None and status >= 400:
        raise PivotError(f"{url} returned HTTP {status}")
    return str(result.get("body") or "")


def _post_json(url: str, payload: dict[str, Any],
                headers: dict[str, str] | None = None) -> Any:
    """POST a JSON body and parse a JSON response - the ThreatFox-shaped
    counterpart to _get_json. Proxied through the Win11 VM like every
    other pivot call; see the module docstring."""
    try:
        result = vm_proxy.http_fetch(
            url, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                          **(headers or {})},
            method="POST", data=json.dumps(payload))
    except vm_proxy.VMProxyError as e:
        raise PivotError(f"failed to reach {url}: {e}") from e
    status = result.get("status")
    body = str(result.get("body") or "")
    if status is not None and status >= 400:
        # Error responses here (e.g. ThreatFox's {"query_status":
        # "unknown_auth_key"}) are themselves small JSON documents whose
        # detail is far more actionable than the bare status code - surface
        # it when present instead of just "returned HTTP 403".
        try:
            detail = json.loads(body)
        except ValueError:
            detail = body or None
        raise PivotError(f"{url} returned HTTP {status}" + (f": {detail}" if detail else ""))
    try:
        return json.loads(body)
    except ValueError as e:
        raise PivotError(f"{url} returned an unparseable response: {e}") from e


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

    Resolution itself happens on the Win11 VM (see vm_proxy.resolve_dns)
    rather than via this host's own resolver - same reasoning as every
    other pivot lookup in this module."""
    try:
        raw_addrs = vm_proxy.resolve_dns(host)
    except vm_proxy.VMProxyError:
        return None
    if raw_addrs is None or not raw_addrs:
        return raw_addrs
    real = set()
    for addr in raw_addrs:
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
        result = {
            "reputation": attrs.get("reputation"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "resolutions": [
                {"domain": r["attributes"].get("host_name"), "date": r["attributes"].get("date")}
                for r in resolutions.get("data", [])
            ],
        }
        # Files VT has actually observed talking to this IP (its C2/callback
        # traffic) or fetched from it (dropped/staged payloads) - the two
        # relationships that can turn "we tracked this IP" into "here is a
        # sample that used it", which resolution history alone can't do.
        # Each entry carries just enough to triage by hand before filing
        # anything: VT's own suggested family label plus the detection
        # ratio, not a blind hash dump - a communicating/downloaded
        # relationship on VT means "this file talked to this IP", not
        # "this file belongs to the actor you're tracking that IP for".
        for relationship, key in (("communicating_files", "communicating_files"),
                                   ("downloaded_files", "downloaded_files")):
            try:
                rel = _get_json(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{value}/{relationship}?limit=20",
                    headers)
            except PivotError:
                rel = {"data": []}
            result[key] = [
                {
                    "sha256": f["id"],
                    "names": (f.get("attributes") or {}).get("names", [])[:3],
                    "suggested_label": ((f.get("attributes") or {}).get("popular_threat_classification") or {})
                        .get("suggested_threat_label"),
                    "malicious": ((f.get("attributes") or {}).get("last_analysis_stats") or {}).get("malicious"),
                    "total_engines": sum(((f.get("attributes") or {}).get("last_analysis_stats") or {}).values())
                        if (f.get("attributes") or {}).get("last_analysis_stats") else None,
                    "first_submission_date": (f.get("attributes") or {}).get("first_submission_date"),
                }
                for f in rel.get("data", [])
            ]
        return result

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


def honeylabs_lookup(ip: str, api_key: str) -> dict[str, Any]:
    """Honeypot-fleet telemetry for an IP via HoneyLabs' lookup API:
    event volume/recency across their sensors, their own verdict
    (recognized scanner / threat labeling), plus the ports, client
    fingerprints, and CVEs it was seen probing. Raises PivotError on
    request failure (including HTTP 429/402 when the rate limit or
    daily credit budget is exhausted) - the caller decides whether
    that's fatal or just a missing section in a larger result.

    Response shapes confirmed against the live endpoint (2026-08-17):
    an unobserved IP returns a compact {"observed": false,
    "total_events": 0, "message": ...}; an observed one returns rich
    top-level fields (total_events, events_24h/7d, first/last_seen,
    verdict{...}, geo{...}, known_scanners, top_ports, fingerprints,
    cve_matches, malware, ...) - NOT the "totals" wrapper the public
    docs sketch."""
    data = _get_json(f"https://honeylabs.net/lookup/{ip}?format=json",
                     {"Authorization": f"Bearer {api_key}"})
    if not isinstance(data, dict):
        raise PivotError("unexpected HoneyLabs response shape")
    geo = data.get("geo") or {}
    verdict = data.get("verdict") or {}
    return {
        "events": data.get("total_events"),
        "events_24h": data.get("events_24h"),
        "events_7d": data.get("events_7d"),
        "first_seen": data.get("first_seen"),
        "last_seen": data.get("last_seen"),
        "country": geo.get("country_code"),
        "asn": geo.get("asn"),
        "as_org": geo.get("org"),
        "verdict": verdict.get("verdict"),
        "verdict_label": verdict.get("label"),
        "verdict_detail": verdict.get("detail"),
        "verdict_confidence": verdict.get("confidence"),
        "known_scanners": data.get("known_scanners"),
        "ports": data.get("top_ports"),
        "fingerprints": data.get("fingerprints"),
        "cves": data.get("cve_matches"),
        "malware": data.get("malware"),
    }


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


def shodan_internetdb_lookup(ip: str) -> dict[str, Any]:
    """Open ports, hostnames, CPEs, vulns, and tags Shodan has observed
    for an IP, via their free, keyless InternetDB endpoint. Called
    directly (not via _get_json) because InternetDB signals "nothing on
    record for this IP" as an HTTP 404 rather than an empty body - a
    routine, expected outcome for infrastructure Shodan hasn't scanned,
    not a failure - so it's normalized to the same empty shape a hit
    would have rather than surfacing as {"error": ...}. Any other >=400
    status is a real failure and does become {"error": ...}."""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        result = vm_proxy.http_fetch(url, headers={"User-Agent": USER_AGENT})
    except vm_proxy.VMProxyError as e:
        return {"error": f"failed to reach {url}: {e}"}
    status = result.get("status")
    if status == 404:
        return {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []}
    if status is not None and status >= 400:
        return {"error": f"{url} returned HTTP {status}"}
    try:
        data = json.loads(str(result.get("body") or ""))
    except ValueError as e:
        return {"error": f"{url} returned an unparseable response: {e}"}
    return {
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
        "tags": data.get("tags", []),
        "vulns": data.get("vulns", []),
    }


def threatfox_lookup(value: str, api_key: str) -> dict[str, Any]:
    """Check a domain/ip/url/hash against abuse.ch's ThreatFox database
    of known malware C2/infrastructure IOCs - a free POST-JSON query API
    (requires an Auth-Key from https://auth.abuse.ch/, THREATFOX_API_KEY
    env var) that matches on the literal IOC value regardless of kind,
    so it applies to every observable type pivot_observable handles.
    query_status "no_result" is a legitimate "not a known IOC" outcome
    (returned as {"matches": []}, not an error); anything else
    unexpected becomes {"error": ...}."""
    try:
        data = _post_json("https://threatfox-api.abuse.ch/api/v1/",
                          {"query": "search_ioc", "search_term": value},
                          headers={"Auth-Key": api_key})
    except PivotError as e:
        return {"error": str(e)}
    if not isinstance(data, dict):
        return {"error": "unexpected ThreatFox response shape"}
    status = data.get("query_status")
    if status == "no_result":
        return {"matches": []}
    if status != "ok":
        return {"error": f"ThreatFox query_status={status!r}"}
    matches = [
        {
            "ioc": m.get("ioc"),
            "threat_type": m.get("threat_type"),
            "malware": m.get("malware_printable") or m.get("malware"),
            "confidence_level": m.get("confidence_level"),
            "first_seen": m.get("first_seen_utc"),
            "last_seen": m.get("last_seen_utc"),
            "tags": m.get("tags"),
        }
        for m in (data.get("data") or [])
        if isinstance(m, dict)
    ]
    return {"matches": matches}


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
