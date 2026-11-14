"""Looking an indicator up: the pivot sources, the probe's observe pass, the
lifecycle verdict they add up to, and the snapshot stamped onto a newly
filed observable.

All of this is network work and none of it takes the cluster lock. The
functions that file results (observables, expand) call into here first and
write afterwards.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import time
from datetime import datetime
from datetime import timezone
from typing import Any

from ..errors import normalize_probe
from ..errors import ok
from ..probe import vm_proxy
from ..sources import cache
from ..sources import passive
from ..sources import pivot
from ..store import entities
from ..sources import webamon
from ..store import cdn as cdn_ranges
from ..store import hosting
from ..tracking.history import _log_cluster_enrichment_history
from ..util import asn_int
from ..util import new_values
from ..util import now_iso


# Which newly-added observable categories get queued for fingerprinting.
# Only domains/ips: they're the addresses you'd actively connect to.
# hashes/urls/etc aren't something you probe, and the ja4*/jarm
# categories are themselves fingerprint *results*, not queue inputs.
_FINGERPRINTABLE_CATEGORIES = ("domains", "ips")
# Public alias so the CLI/callers can reference the same tuple without
# reaching for the underscore-prefixed name (mirrors OBSERVABLE_CATEGORIES
# below).
FINGERPRINTABLE_CATEGORIES = _FINGERPRINTABLE_CATEGORIES

# Values that pass extraction/dedup but are essentially never an actor's
# own infrastructure - public DNS resolvers and the root domains of
# hyperscale/security vendors that show up constantly as prose mentions
# (a linked writeup, "hosted via Cloudflare", a contact address) rather
# than as the IOC itself. report_ingest.extract_observables is a blind
# regex over report text (see its docstring on over-matching) and
# add_observable trusts whatever it's handed verbatim, so without a gate
# here a false match turns into a live JARM scan / SSH round-trip
# exactly like a real IOC would. Deliberately exact-match only, not
# subdomain matching - a subdomain of e.g. github.io or amazonaws.com is
# routine, genuinely-attacker-controlled shared hosting, not a false
# positive, so only the bare apex domain (never itself attacker infra)
# is listed. Curated, not exhaustive - extend as new false positives
# turn up in real ingests, the same way _TLDS is extended in
# cti/report/ingest.py. This only gates the fingerprinting *queue*; the
# value is still tracked as an observable exactly as before.
_KNOWN_NON_ACTOR_DOMAINS = {
    "microsoft.com", "microsoftinternetsafety.net", "google.com",
    "github.com", "githubusercontent.com", "cloudflare.com",
    "virustotal.com", "example.com", "mandiant.com", "crowdstrike.com",
    "sophos.com", "kaspersky.com", "malwarebytes.com", "godaddy.com",
    "sinkhole.abuse.ch", "iana.org",
}
# Same idea for IPs - well-known public DNS resolvers, the ones most
# likely to appear in report text as "the malware checks connectivity
# against 8.8.8.8" rather than as adversary infrastructure.
_KNOWN_NON_ACTOR_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
}


def _is_ipv4(value: str) -> bool:
    """True only for a parseable IPv4 literal. Used to strip IPv6 out of
    pivot results before filing - functional rule: ignore IPv6 for
    pivoting and probing, since the probe VM has no IPv6 route."""
    return entities.entity_type(str(value)) == "ipv4"


def _is_probe_worthy(category: str, value: str) -> tuple[bool, str]:
    """Whether our own probe may scan this value. Applied by the netwatch
    watchlist (and reported at filing time as `scan_skipped`) - not to
    whether a value gets tracked as an observable at all, which stays
    exactly as permissive as before. Returns (True, "") if fine to scan,
    else (False, reason)."""
    if category == "ips":
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False, "not a valid IP literal"
        if addr.is_private or addr.is_loopback or addr.is_link_local \
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return False, "private/reserved/loopback/link-local address, not routable adversary infra"
        if addr.version == 6:
            return False, "IPv6 - the probe VM has no IPv6 route, active fingerprinting would only ever time out"
        if value in _KNOWN_NON_ACTOR_IPS:
            return False, "known non-actor infrastructure (public DNS resolver)"
    elif category == "domains":
        if value.strip().lower() in _KNOWN_NON_ACTOR_DOMAINS:
            return False, "known non-actor infrastructure (major vendor/CDN/sinkhole domain)"
    return True, ""


# Pivot enrichment cache. Webamon calls count against a daily budget and
# HoneyLabs credits are metered, so refetching the same indicator on every
# pivot burns through both; RDAP/RIPEstat and the probe-VM round-trips are
# also slow and worth not repeating. This caches each source's answer for
# a value for a short TTL. It is NOT cluster data - just a transient
# enrichment cache under _registry - and only successful lookups are
# cached (never errors or a missing-key skip note). Set
# CTI_PIVOT_CACHE_TTL=0 to disable caching entirely.
_PIVOT_CACHE_TTL_ENV = "CTI_PIVOT_CACHE_TTL"
_PIVOT_CACHE_TTL_DEFAULT = 3600


# The pivot cache used to live here: one 8.8 MB JSON dict, fully re-read
# and fully re-written on every miss, under a lock, from a six-thread pool.
# It is now sources/cache.py, one file per key - no read-modify-write, no
# lock, and a corrupt entry costs one lookup instead of the whole cache.
#
# _is_soft_failure and _norm_live moved to cti/errors.py as is_failure and
# normalize_probe, joining the inline `"error" not in x` guard that was
# repeated seventeen times in this file.

def _cached_pivot(source: str, value: str, fetch) -> Any:
    """Cache a source lookup for `value`. See sources/cache.py."""
    return cache.cached(source, value, fetch)


def _observe(value: str, kind: str,
             ports: list[int] | None = None) -> dict[str, Any]:
    """One observation pass, cached like every other source.

    `ports` are ports already KNOWN to be open on this host, from an earlier
    active scan or a report. Passing them is not a scan - it tells httpx and
    tlsx where to look instead of assuming 80/443. The first live sweep
    found nothing at all on 143.246.217.59 for exactly this reason: its
    services are on 4443, 8443 and 8080, and the default probe found no web
    service and no certificate while reporting no error.

    Discovering NEW ports is still active_scan's job; this only reuses what
    is already on the record.
    """
    try:
        # normalize_probe strips the `error: None` the helper sets on
        # success. Without it every result looked failed: errors.is_failure
        # tests for the PRESENCE of an "error" key, not its truthiness, so
        # the first live sweep computed a full observe pass and discarded it
        # silently. This is the same trap normalize_probe was written for -
        # _live_http already goes through it.
        return _cached_pivot(
            f"observe_{kind}", value,
            lambda: normalize_probe(vm_proxy.observe(value, kind=kind, ports=ports)))
    except vm_proxy.VMProxyError as e:
        return {"error": str(e)}


def _tls_from_observe(observed: Any) -> dict[str, Any]:
    """The `tls` enrichment key, read off the observe pass.

    There used to be a second, separate openssl handshake (`tls_live`) whose
    only job was to produce this. tlsx, inside the observe pass, already
    fetches the same certificate and returns a superset - serial, SPKI hash,
    revocation, self-signed and mismatch flags - so every sweep was making
    two TLS connections to each adversary host to learn one thing twice.

    The shape is unchanged (`{"cert": {sha256, issuer, subject, sans,
    not_before, not_after, protocol}}` or `{"error": ...}`), so the three
    consumers - the cluster snapshot, the change detector and the sweep row -
    needed no edit. Verified equal on 73 same-day pairs: identical SHA-256 and
    identical SAN sets every time.

    No fallback to an openssl grab when tlsx fails. That is a real loss of
    resilience, taken deliberately: a tlsx failure now shows up as an error on
    the observe pass for that host that day, not as a silently different tool
    answering instead.
    """
    if not ok(observed):
        return observed if isinstance(observed, dict) else {"error": "no observe result"}
    tls = observed.get("tls") or {}
    if not tls.get("cert_sha256"):
        return {"error": (observed.get("errors") or {}).get("tls")
                         or "no certificate presented"}
    return {
        "cert": {
            "sha256": tls.get("cert_sha256"),
            "issuer": tls.get("issuer"),
            # The full DN, as the old grab reported it - the CN alone would
            # drop the organisation a stock certificate is identified by.
            "subject": tls.get("subject_dn") or tls.get("subject_cn"),
            "sans": tls.get("sans") or [],
            "not_before": tls.get("not_before"),
            "not_after": tls.get("not_after"),
            "protocol": tls.get("tls_version"),
        },
        "resolved_ip": tls.get("resolved_ip"),
    }


def _live_http(host: str) -> dict[str, Any]:
    try:
        return _cached_pivot("http_live", host,
                             lambda: normalize_probe(vm_proxy.http_probe(f"https://{host}")))
    except vm_proxy.VMProxyError as e:
        return {"error": str(e)}


def _webamon_domain(domain: str) -> dict[str, Any]:
    return _cached_pivot("webamon", domain, lambda: webamon.search_domain(domain))


def _webamon_ip(ip: str) -> dict[str, Any]:
    return _cached_pivot("webamon_ip", ip, lambda: webamon.search_ip(ip))


def _webamon_infostealers(domain: str) -> dict[str, Any]:
    return _cached_pivot("webamon_is", domain, lambda: webamon.infostealers(domain))


def _internetdb(ip: str) -> dict[str, Any]:
    """Shodan's free keyless view of an address. Passive: no packet reaches
    the indicator, which is why this runs in the ordinary sweep while nmap
    and naabu stay on request."""
    return _cached_pivot("internetdb", ip, lambda: passive.internetdb(ip))


def _pdns(value: str, *, asn: int | None = None) -> dict[str, Any]:
    """Passive resolution history, the one thing no live probe can answer.

    Skipped entirely for an address on shared hosting or a CDN. A Cloudflare
    address has had tens of thousands of names on it and every one of them
    would arrive here as history; the answer would be both enormous and
    meaningless, and the same gate already protects webamon_ip and the
    co-hosting selectors.
    """
    if hosting.is_shared_asn(asn):
        return {"skipped": "shared hosting - passive DNS would return the "
                           "provider's tenants, not this actor's history"}
    if cdn_ranges.is_cdn(value):
        return {"skipped": "CDN address - see above"}
    return _cached_pivot("pdns", value, lambda: passive.pdns(value))


def _subdomains_for(domain: str) -> dict[str, Any]:
    """Passive subdomain discovery for the automatic sweep: subfinder unioned
    with Wayback CDX, both run on the probe VM. Flag-only (never auto-filed
    here - see the "subdomains" spec). Returns {"subdomains": [...]} or
    {"error": ...}."""
    subs: set[str] = set()
    errors = []
    for source, fn in (("subfinder", vm_proxy.subfinder), ("wayback", vm_proxy.wayback_cdx)):
        try:
            r = _cached_pivot(source, domain, lambda fn=fn: normalize_probe(fn(domain)))
        except vm_proxy.VMProxyError as e:
            errors.append(str(e))
            continue
        if isinstance(r, dict) and "error" not in r:
            subs |= {s.lower() for s in (r.get("subdomains") or [])}
    if not subs and errors:
        return {"error": "; ".join(errors)}
    return {"subdomains": sorted(subs)}


def pivot_observable(value: str) -> dict[str, Any]:
    """On-demand infrastructure pivot for a single hash/domain/ip/url.
    Display only: no cluster data is written, unlike ingest_report -
    though successful lookups are cached transiently under _registry to
    respect source rate limits (see CTI_PIVOT_CACHE_TTL). If a pivot
    surfaces something worth keeping, record it yourself via
    append_hunt_log, add_gap, or by filing the new indicator into a
    cluster.

    Sources: RDAP (registration data, domain/ip); RIPEstat (ASN/network
    context, ip); Webamon (a domain's latest scan - cert, DNS, ASN, tech,
    kit fingerprints - and its infostealer-log hits; an IP's hosted
    domains, the reverse-IP replacement); a live TLS grab and HTTP probe
    from the probe VM (a domain's current certificate and liveness);
    PTR (ip); ThreatFox known-malware-C2 IOC match (THREATFOX_API_KEY);
    and HoneyLabs honeypot telemetry (ip, HONEYLABS_API_KEY). ThreatFox/
    HoneyLabs are skipped with a note when their key is unset; the rest
    need no key (Webamon uses WEBAMON_API_KEY, surfacing an error dict if
    unset). See summarize_honeylabs for how to read the HoneyLabs result.
    """
    kind = pivot.classify(value)
    result: dict[str, Any] = {"value": value, "kind": kind}

    threatfox_key = os.environ.get(pivot.THREATFOX_API_KEY_ENV)
    if not threatfox_key:
        result["threatfox"] = {
            "skipped": f"set {pivot.THREATFOX_API_KEY_ENV} to enable ThreatFox lookups"}
    else:
        result["threatfox"] = _cached_pivot(
            "threatfox", value, lambda: pivot.threatfox_lookup(value, threatfox_key))

    if kind in ("domain", "ip"):
        result["rdap"] = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, kind))
    if kind == "ip":
        result["ripestat"] = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        result["webamon_ip"] = _webamon_ip(value)  # hosted domains (reverse-IP replacement)
        result["ptr"] = _cached_pivot("ptr", value, lambda: pivot.ptr_lookup(value))
        result["honeylabs"] = honeylabs_context(value)
    if kind == "domain":
        result["webamon"] = _webamon_domain(value)  # latest scan: cert, DNS, ASN, kit fingerprints
        result["webamon_infostealers"] = _webamon_infostealers(value)  # compromised creds (masked)
        # Current certificate, from the observe pass (cached, and the daily
        # sweep runs the same call) rather than a second handshake.
        result["tls"] = _tls_from_observe(_observe(value, "domain"))
        result["http"] = _live_http(value)  # live liveness/title/server

    return result


def honeylabs_context(ip: str) -> dict[str, Any]:
    """Cached HoneyLabs honeypot-telemetry lookup for an IP. Returns the
    normalized lookup dict, a {"skipped": ...} note if HONEYLABS_API_KEY
    is unset, or {"error": ...} on lookup failure - never raises, so
    pipeline callers can enrich opportunistically without wrapping it."""
    api_key = os.environ.get(pivot.HONEYLABS_API_KEY_ENV)
    if not api_key:
        return {"skipped":
                f"set {pivot.HONEYLABS_API_KEY_ENV} to enable HoneyLabs honeypot-telemetry lookups"}
    try:
        return _cached_pivot("honeylabs", ip, lambda: pivot.honeylabs_lookup(ip, api_key))
    except pivot.PivotError as e:
        return {"error": str(e)}


def summarize_honeylabs(result: dict[str, Any]) -> str | None:
    """One-line, provenance-ready reading of a honeylabs_context result,
    or None for skipped/error results (so callers write nothing).

    The interpretation cuts both ways, and the line should keep that
    legible to whoever reads the provenance list later: heavy presence
    in honeypot telemetry usually means a mass scanner / opportunistic
    background noise (a counter-signal for "dedicated C2"), while
    absence on an otherwise-active IP is the quiet-infrastructure
    signal."""
    if not isinstance(result, dict) or "skipped" in result or "error" in result:
        return None
    today = datetime.now(timezone.utc).date().isoformat()
    events = result.get("events")
    if not events:
        return (f"HoneyLabs telemetry {today}: no honeypot activity on record - "
                "quiet infrastructure, not a known mass scanner")
    parts = [f"{events} honeypot events"]
    detail = []
    if result.get("events_24h"):
        detail.append(f"{result['events_24h']} in 24h")
    first_seen, last_seen = result.get("first_seen"), result.get("last_seen")
    if first_seen and last_seen:
        detail.append(f"seen {first_seen[:10]} to {last_seen[:10]}")
    if detail:
        parts[0] += f" ({', '.join(detail)})"
    ports = [str(p.get("port")) for p in (result.get("ports") or [])[:3]
             if isinstance(p, dict) and p.get("port") is not None]
    if ports:
        parts.append(f"top ports {','.join(ports)}")
    # cve_matches item shape unconfirmed (always empty on live samples so
    # far) - accept either bare strings or dicts carrying an id.
    cves = [c if isinstance(c, str) else c.get("id")
            for c in (result.get("cves") or [])[:3]]
    cves = [c for c in cves if c]
    if cves:
        parts.append(f"probing {', '.join(cves)}")
    if result.get("verdict"):
        label = result.get("verdict_label") or result["verdict"]
        qualifiers = ", ".join(q for q in (result.get("verdict_detail"),
                                            result.get("verdict_confidence"))
                               if q)
        parts.append(f"verdict: {label}" + (f" ({qualifiers})" if qualifiers else ""))
        return f"HoneyLabs telemetry {today}: {', '.join(parts)}"
    return (f"HoneyLabs telemetry {today}: {', '.join(parts)} - "
            "opportunistic scanner profile, weigh against dedicated-C2 hypotheses")


_PIVOT_CLUSTER_WORKERS = 6


def _threatfox_enrichment(value: str) -> dict[str, Any] | None:
    """Cached ThreatFox lookup for pivot_cluster's sweep, or None if
    THREATFOX_API_KEY isn't configured - mirrors pivot_observable's own
    skip-gracefully behavior rather than raising or logging a skip note
    per observable."""
    api_key = os.environ.get(pivot.THREATFOX_API_KEY_ENV)
    if not api_key:
        return None
    return _cached_pivot("threatfox", value, lambda: pivot.threatfox_lookup(value, api_key))


def _run_sources(calls: dict[str, Any], timings: dict[str, float] | None
                 ) -> dict[str, Any]:
    """Run one indicator's source lookups at once and time each.

    They used to run one after another, so an indicator cost the SUM of its
    lookups - a single IP on sliver-c2 took over three minutes. None depends
    on another except through what a call itself waits on, so they run
    concurrently and an indicator costs roughly its slowest lookup.

    Each provider still sees at most one request per indicator in flight,
    the same as the serial version: this widens the indicator, not the pool
    of indicators. Probe-VM calls still queue on vm_proxy's slot limit.

    Waits for every call before raising, then raises the first failure in
    `calls` order - the same one the serial version would have hit first -
    so the sweep's per-indicator catch-all sees what it always saw.
    """
    def timed(name: str, fn):
        t0 = time.monotonic()
        try:
            return fn()
        finally:
            if timings is not None:
                timings[name] = round(time.monotonic() - t0, 2)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(calls), thread_name_prefix="cti-source") as ex:
        futures = {name: ex.submit(timed, name, fn) for name, fn in calls.items()}
        concurrent.futures.wait(futures.values())
    return {name: fut.result() for name, fut in futures.items()}


def _domain_lifecycle(value: str, ports: list[int] | None = None,
                      timings: dict[str, float] | None = None
                      ) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """`timings`, if given, is filled with seconds per source lookup."""
    # Live current-cert grab (replaces Cert Spotter's CT history), a live
    # HTTP probe, the domain's latest Webamon scan (ASN/tech/kit
    # fingerprints), its infostealer hits, and passive subdomain discovery
    # (subfinder + Wayback, flag-only). All day-over-day attribute diffs -
    # see _log_cluster_enrichment_history.
    # `observe` is one CLI pass on the probe VM. It supersedes the separate
    # tls_grab and http_probe calls for everything they returned AND carries
    # the fields those two never surfaced - body and favicon digests, the
    # certificate serial and SPKI hash, the nameserver set, the registrar.
    # Those are what the selector index is built from. The certificate for
    # the `tls` key is read off this result; the openssl grab that used to
    # produce it is gone.
    got = _run_sources({
        "rdap": lambda: _cached_pivot("rdap", value,
                                      lambda: pivot.rdap_lookup(value, "domain")),
        "resolve": lambda: pivot.resolve_host(value),  # live, not cached — liveness is the point
        "observe": lambda: _observe(value, "domain", ports),
        "http": lambda: _live_http(value),
        "webamon": lambda: _webamon_domain(value),
        "webamon_infostealers": lambda: _webamon_infostealers(value),
        "subdomains": lambda: _subdomains_for(value),
        # Where this name pointed before it pointed where it does now.
        "pdns": lambda: _pdns(value),
        "threatfox": lambda: _threatfox_enrichment(value),
    }, timings)
    rdap, resolved = got["rdap"], got["resolve"]
    status = pivot.classify_domain_lifecycle(rdap, resolved)
    detail = {"resolved": resolved,
             "nameservers": rdap.get("nameservers") if isinstance(rdap, dict) else None}
    enrichment: dict[str, Any] = {
        "observe": got["observe"],
        "tls": _tls_from_observe(got["observe"]),
        **{k: got[k] for k in ("http", "webamon", "webamon_infostealers",
                               "subdomains", "pdns")},
    }
    if got["threatfox"] is not None:
        enrichment["threatfox"] = got["threatfox"]
    return status, detail, enrichment


def _ip_lifecycle(value: str, ports: list[int] | None = None,
                  timings: dict[str, float] | None = None
                  ) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """`timings`, if given, is filled with seconds per source lookup."""
    ripe_done = concurrent.futures.Future()

    def ripestat():
        try:
            ripe = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        except BaseException as e:
            ripe_done.set_exception(e)
            raise
        ripe_done.set_result(ripe)
        return ripe

    def pdns():
        # The one dependency: the shared-hosting gate needs the ASN. A
        # failed RIPEstat lookup fails the indicator either way, so pdns
        # just skips the gate rather than raising a second time.
        try:
            ripe = ripe_done.result()
        except Exception:  # noqa: BLE001 - whatever the lookup raised; see above
            ripe = None
        asn = ripe.get("asn") if isinstance(ripe, dict) else None
        return _pdns(value, asn=asn)

    got = _run_sources({
        "ripestat": ripestat,
        "observe": lambda: _observe(value, "ip", ports),
        # Domains Webamon has scanned resolving to this IP - the reverse-IP
        # / hosted-domain signal (replaces Shodan hostnames + Hackertarget).
        # Open ports are no longer discovered automatically here: that's
        # nmap, run on demand via active_scan (see the port-change signal).
        "webamon_ip": lambda: _webamon_ip(value),
        # Reverse-DNS PTR record - a day-over-day attribute diff like ASN
        # (see the "ptr" spec in cti/store/changes.py).
        "ptr": lambda: _cached_pivot("ptr", value, lambda: pivot.ptr_lookup(value)),
        # Ports, CPEs and vulns somebody else already scanned for. Stale by
        # nature, so recorded as passive throughout and never merged with
        # nmap's - see sources/passive.py.
        "internetdb": lambda: _internetdb(value),
        # What has lived here before. dnsx answers the present tense only.
        "pdns": pdns,
        "threatfox": lambda: _threatfox_enrichment(value),
    }, timings)
    ripe = got["ripestat"]
    status = pivot.classify_ip_lifecycle(ripe)
    detail = {"asn": ripe.get("asn") if isinstance(ripe, dict) else None,
             "prefix": ripe.get("prefix") if isinstance(ripe, dict) else None,
             "as_holder": ripe.get("as_holder") if isinstance(ripe, dict) else None}
    enrichment: dict[str, Any] = {k: got[k] for k in ("observe", "webamon_ip", "ptr",
                                                        "internetdb", "pdns")}
    if got["threatfox"] is not None:
        enrichment["threatfox"] = got["threatfox"]
    return status, detail, enrichment


def _sweep_lifecycle(domains: list[str], ips: list[str],
                      known_ports: dict[str, list[int]] | None = None,
                      timings: dict[tuple[str, str], dict[str, float]] | None = None
                      ) -> dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]:
    """Concurrent, lock-free lifecycle+enrichment sweep for a batch of
    domains/ips - the network phase shared by pivot_cluster (rechecking
    already-tracked observables) and the add-time enrichment path
    (add_observable/ingest_report/pivot_and_expand, for genuinely new
    ones). Never call this while holding _data_lock: a batch of RDAP/
    RIPEstat/Webamon/probe-VM/ThreatFox round-trips can take a while,
    and every other MCP tool call would block behind the lock for the
    duration - see pivot_cluster's docstring for why its own network
    phase already runs unlocked. A single lookup blowing up is recorded
    as an ("unknown", {"error": ...}, {}) tuple rather than sinking the
    whole batch.

    `timings`, if given, is filled with {(cat, value): {source: seconds}}.
    It is kept out of the returned tuples on purpose: `detail` is written
    onto the observable, and a cluster file should not change every day
    because a lookup was slower."""
    # Ports already known open on a host, so the observe pass looks where
    # the services actually are rather than assuming 80/443.
    known_ports = known_ports or {}
    jobs = ([("domains", v, _domain_lifecycle) for v in domains]
            + [("ips", v, _ip_lifecycle) for v in ips])
    results: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]] = {}
    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_PIVOT_CLUSTER_WORKERS) as ex:
            futures = {}
            for cat, v, fn in jobs:
                kwargs = {}
                if timings is not None:
                    kwargs["timings"] = timings.setdefault((cat, v), {})
                futures[ex.submit(fn, v, known_ports.get(v), **kwargs)] = (cat, v)
            for fut in concurrent.futures.as_completed(futures):
                cat, v = futures[fut]
                try:
                    results[(cat, v)] = fut.result()
                except Exception as e:  # noqa: BLE001 - one lookup must not sink the sweep; recorded
                    results[(cat, v)] = ("unknown", {"error": str(e)}, {})
    return results


def _new_values(data: dict[str, Any], category: str, values: list[str]) -> list[str]:
    """Values not already tracked on this cluster in this category.

    A thin bind of util.new_values to the cluster-record shape. The
    same two lines were also inlined in _file_new_observables (whose
    docstring said they were "kept in sync"), in _add_observable_locked
    and in _merge_observables.
    """
    return new_values({o["value"] for o in data["observables"][category]}, values)

def _stamp_webamon_summary(entry: dict[str, Any], webamon: dict[str, Any]) -> None:
    """Stamp a compact Webamon snapshot (report_id, last scan date, risk
    score, kit fingerprints) onto an observable. Accepts both a domain
    result (carries `latest`) and an IP result (carries only `total_hits`/
    `domains`)."""
    latest = webamon.get("latest")
    summary: dict[str, Any] = {"checked": now_iso(), "total_hits": webamon.get("total_hits")}
    if isinstance(latest, dict):
        summary.update({
            "report_id": latest.get("report_id"),
            "last_scan": latest.get("date"),
            "risk_score": latest.get("risk_score"),
            "fingerprint_dom": (latest.get("fingerprint") or {}).get("dom"),
            "fingerprint_ssl": (latest.get("fingerprint") or {}).get("ssl"),
        })
    entry["webamon"] = summary


# _asn_int moved to cti/util.py, where it replaced tracking.enrich._as_int
# too - the two disagreed on leading whitespace.

def _apply_enrichment_snapshot(entry: dict[str, Any], category: str,
                                detail: dict[str, Any], enrichment: dict[str, Any]) -> None:
    """Stamp the latest known asn/netname/ports/cert/tags snapshot onto an
    observable entry from a (status, detail, enrichment) tuple - the shape
    _domain_lifecycle/_ip_lifecycle/_sweep_lifecycle already produce.
    Called both at add-time (for a genuinely new observable) and from
    pivot_cluster's write phase (to keep an already-tracked observable's
    snapshot current) - see _merge_observables and pivot_cluster.

    asn/netname/cert are overwritten (this is a point-in-time snapshot,
    not history - the history lives in the tracking-store attribute_changes
    table, see _log_cluster_enrichment_history). ports and tags are
    unioned, never dropped, mirroring tracking.store.upsert_actor's own
    "known values only ever widen" convention - a port or tag seen once
    stays recorded even if a later check doesn't re-see it."""
    tags = set(entry.get("tags") or [])
    if category == "ips":
        # detail["asn"] comes straight from RIPEstat's "asns" field
        # (see pivot.ripestat_lookup / _ip_lifecycle) - plural because a
        # prefix can technically have more than one announcing origin -
        # so it's a list here, not a bare int; take the first as the
        # observable's own asn, matching enrich.py's _registry_lookup
        # (_as_int(asns[0])) and the DuckDB observations.asn column.
        asn_list = detail.get("asn")
        if asn_list:
            asn_value = asn_int(asn_list)
            entry["asn"] = (asn_value if asn_value is not None else
                            (asn_list[0] if isinstance(asn_list, list) else asn_list))
        if detail.get("as_holder"):
            entry["netname"] = detail["as_holder"]
        webamon_ip = enrichment.get("webamon_ip")
        if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
            # Hosted domains Webamon has scanned on this IP. Suppress when the
            # IP is shared hosting - those are every other tenant, not this
            # actor's infra (same rationale as the retired Hackertarget
            # co-hosting signal). The verdict is stamped on the entry so
            # rank and the expansion sweep read the same answer.
            hosts = webamon_ip.get("domains") or []
            ptr = enrichment.get("ptr")
            shared, why = hosting.is_shared(
                asn=entry.get("asn"),
                ptr=ptr.get("hostname") if isinstance(ptr, dict) else None)
            if shared:
                entry["shared_hosting"] = why
            else:
                entry.pop("shared_hosting", None)
                if hosts:
                    entry["ip_hostnames"] = sorted(set(entry.get("ip_hostnames") or []) | set(hosts))
            _stamp_webamon_summary(entry, webamon_ip)
    elif category == "domains":
        tls = enrichment.get("tls")
        if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
            cert = tls["cert"]
            entry["cert"] = {"issuer": cert.get("issuer"), "subject": cert.get("subject"),
                              "sans": cert.get("sans") or [],
                              "not_before": cert.get("not_before"),
                              "not_after": cert.get("not_after"),
                              "sha256": cert.get("sha256"),
                              "checked": now_iso(), "source": "observe_tls"}
            # Revocation comes from the observe pass, not this one: the
            # openssl grab has never produced it, so cert_revoked had been
            # permanently None since Cert Spotter was retired. tlsx checks
            # it, and a None here still means "not checked" rather than
            # "not revoked" - which is why it is only set when known.
            observed_tls = (enrichment.get("observe") or {}).get("tls") or {}
            for field in ("revoked", "untrusted"):
                if observed_tls.get(field) is not None:
                    entry["cert"][field] = observed_tls[field]
        http = enrichment.get("http")
        if isinstance(http, dict) and "error" not in http and http.get("status") is not None:
            entry["http"] = {"status": http.get("status"), "title": http.get("title"),
                              "server": http.get("server"), "final_url": http.get("final_url")}
        webamon = enrichment.get("webamon")
        if isinstance(webamon, dict) and "error" not in webamon:
            _stamp_webamon_summary(entry, webamon)
    threatfox = enrichment.get("threatfox")
    if isinstance(threatfox, dict) and "error" not in threatfox:
        for m in threatfox.get("matches") or []:
            if m.get("malware"):
                tags.add(f"threatfox:malware:{m['malware']}")
            tags |= {f"threatfox:tag:{t}" for t in (m.get("tags") or [])}
    if tags:
        entry["tags"] = sorted(tags)


# Stays here, not in history.py, and the reason is load-bearing: it calls
# _log_cluster_enrichment_history as a bare global, so the name resolves in
# THIS module's namespace - which is what makes `monkeypatch.setattr(core,
# "_log_cluster_enrichment_history", ...)` take effect. Moved alongside the
# function it calls, the patch silently stopped applying and a test that
# asserts a store outage is survivable went green for the wrong reason.
def _record_enrichment(actor: str, enrichment: dict, *, when: str | None = None
                       ) -> str | None:
    """Persist an add-time enrichment result to the tracking store.

    pivot_cluster has always done this at the end of a sweep. Nothing else
    did, so every other path that pays for a full _sweep_lifecycle - adding
    an observable, ingesting a report, expanding a pivot - computed live
    TLS, HTTP, DNS, Webamon and ThreatFox data, wrote a snapshot into the
    cluster JSON, and dropped the rest on the floor.

    What that cost is not abstract. A freshly ingested domain produced zero
    observation rows, so it had no baseline, so its first real change was
    invisible - the diff had nothing to compare against - and no selectors,
    so it could not be linked to anything until the next daily sweep
    happened to touch it. The most interesting moment in an indicator's
    life is the one we were throwing away.

    Called OUTSIDE the cluster-JSON lock and after its write, the same way
    pivot_cluster does it: a different store with its own locking, and a
    hiccup there must not undo a cluster write that already landed.
    """
    if not enrichment:
        return None
    observed_at = datetime.fromisoformat(when or now_iso()).replace(tzinfo=None)
    return _log_cluster_enrichment_history(actor, observed_at, enrichment)
