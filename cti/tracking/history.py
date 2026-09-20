"""Writing what a sweep saw into the tracking store.

Split out of core.py, which was 2660 lines. This is the half of an
enrichment pass that produces *history*: one dated observation row per
indicator per source, the selectors those rows imply, open-directory
listings, and the certificate hashes filed back onto a cluster.

It is a clean seam because nothing here calls back into core - it takes
an already-computed enrichment result and a cluster dict, and talks only
to the tracking store. The enrichment itself (the probe calls, the
lifecycle classification) stays in core, where the tests that patch
`core._sweep_lifecycle`, `core._observe` and friends can still reach it.

`_log_cluster_enrichment_history` is re-exported by core and patched
there by tests. That keeps working because every caller lives in core
and looks it up as a module global, so patching core's name is what the
call resolves through.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import duckdb

from .. import store as tracking_store
from ..errors import ok
from ..sources import observe as observe_source
from ..store import cdn as cdn_ranges
from ..util import now_iso

# How many passive-DNS records to keep on one observation row. A busy name
# returns hundreds and the tail is repetition; the count and the total are
# both preserved on the source result, so nothing is silently lost.
PDNS_RECORD_CAP = 50

def _log_passive(con, *, value: str, indicator_type: str, actor: str | None,
                 observed_at, enrichment: dict[str, Any]) -> None:
    """Persist the two passive sources, kept apart from their live cousins.

    Both are somebody else's observation at a time we did not choose, which
    is exactly why every field here is named for its source. An
    `internetdb_ports` column cannot be mistaken for the nmap one; a
    `net.passive_port_set` selector cannot match a `net.port_set`.
    """
    idb = enrichment.get("internetdb")
    if isinstance(idb, dict) and "error" not in idb and idb.get("indexed"):
        tracking_store.upsert_observation(
            con, observed_at=observed_at, indicator_value=value,
            source="internetdb", actor=actor, indicator_type=indicator_type,
            internetdb_ports=idb.get("ports") or None,
            internetdb_cpes=idb.get("cpes") or None,
            internetdb_tags=idb.get("tags") or None,
            internetdb_vulns=idb.get("vulns") or None,
            internetdb_hostnames=idb.get("hostnames") or None)
        found: list[tuple[str, Any]] = []
        if idb.get("ports"):
            found.append(("net.passive_port_set", idb["ports"]))
        for cpe in idb.get("cpes") or []:
            found.append(("net.cpe", cpe))
        if found:
            tracking_store.selectors.record_many(
                con, indicator_value=value, found=found, observed_at=observed_at,
                indicator_type=indicator_type, actor=actor, source="internetdb")

    pdns = enrichment.get("pdns")
    if not (isinstance(pdns, dict) and "error" not in pdns
            and not pdns.get("skipped")):
        return
    records = pdns.get("records") or []
    if not records:
        return
    tracking_store.upsert_observation(
        con, observed_at=observed_at, indicator_value=value,
        source="mnemonic_pdns", actor=actor, indicator_type=indicator_type,
        pdns_records=records[:PDNS_RECORD_CAP])

    # Only the A/AAAA answers of a DOMAIN become selectors. The reverse
    # direction - every name that ever pointed at an address - is left as
    # payload: it is unbounded on anything popular, and a name that shared
    # an address with a hundred others years ago is not evidence of
    # anything. The forward direction is bounded by how often one operator
    # moved their own domain.
    if indicator_type != "domain":
        return
    addresses = []
    for record in records:
        if record.get("rrtype") not in ("a", "aaaa"):
            continue
        answer = record.get("answer")
        # The same CDN gate the live path applies. Without it every domain
        # that ever sat behind Cloudflare links to every other one that did.
        if answer and not cdn_ranges.is_cdn(answer):
            addresses.append(answer)
    if addresses:
        tracking_store.selectors.record_many(
            con, indicator_value=value,
            found=[("net.historical_ip", a) for a in sorted(set(addresses))],
            observed_at=observed_at, indicator_type=indicator_type,
            actor=actor, source="mnemonic_pdns")


def _log_observation(con, value: str, indicator_type: str, actor: str | None,
                     observed: dict[str, Any], observed_at) -> None:
    """Persist one observe pass, then record the selectors it implies.

    Two writes, deliberately. The observation row is the time series - what
    this host looked like today, diffable against yesterday. The selectors
    are the index - what it has in common with anything else we track. The
    old pipeline only ever did the first, which is why "who else has this
    certificate?" had no answer.
    """
    http = observed.get("http") or {}
    tls = observed.get("tls") or {}
    dns = observed.get("dns") or {}
    whois = observed.get("whois") or {}
    cdn_info = observed.get("cdn") or {}

    if http:
        tracking_store.upsert_observation(
            con, observed_at=observed_at, indicator_value=value,
            source="observe_http", actor=actor, indicator_type=indicator_type,
            body_sha256=http.get("body_sha256"),
            favicon_mmh3=(str(http["favicon_mmh3"])
                          if http.get("favicon_mmh3") not in (None, "", 0) else None),
            content_type=http.get("content_type"),
            http_status=http.get("status"), http_title=http.get("title"),
            http_server=http.get("server"), http_final_url=http.get("final_url"),
            http_headers=http.get("headers") or None,
            http_tech=http.get("tech") or None)

    if tls:
        tracking_store.upsert_observation(
            con, observed_at=observed_at, indicator_value=value,
            source="observe_tls", actor=actor, indicator_type=indicator_type,
            tls_sha256=tls.get("cert_sha256"), tls_issuer=tls.get("issuer"),
            tls_subject=tls.get("subject_dn") or tls.get("subject_cn"),
            tls_sans=tls.get("sans") or None,
            tls_serial=tls.get("serial"),
            tls_spki_sha256=tls.get("spki_sha256"),
            tls_self_signed=tls.get("self_signed"),
            cert_revoked=tls.get("revoked"),
            tls_version=tls.get("tls_version"),
            tls_not_before=tls.get("not_before"), tls_not_after=tls.get("not_after"))

    if dns or whois or cdn_info:
        tracking_store.upsert_observation(
            con, observed_at=observed_at, indicator_value=value,
            source="observe_dns", actor=actor, indicator_type=indicator_type,
            dns_ns=dns.get("ns") or None, dns_mx=dns.get("mx") or None,
            dns_txt=dns.get("txt") or None,
            whois_registrar=whois.get("registrar"),
            whois_registrant_email=whois.get("registrant_email"),
            whois_created=whois.get("created"),
            cdn_provider=cdn_info.get("provider"))

    # A host that was probed and answered nothing is a recordable fact, not
    # an absence of data. Without this row the timeline cannot show when a
    # C2's services disappeared - sliver-c2's went dark between 2026-09-12
    # and 2026-09-20 and nothing in the store said so.
    responded = observed.get("responded") or {}
    if responded and not any(responded.values()):
        tracking_store.upsert_observation(
            con, observed_at=observed_at, indicator_value=value,
            source="observe_silent", actor=actor, indicator_type=indicator_type,
            metadata={"probed": sorted(responded), "responded": False,
                      "ports": observed.get("known_ports") or []})

    kind = "ip" if indicator_type.startswith("ipv") else "domain"
    tracking_store.selectors.record_many(
        con, indicator_value=value,
        found=observe_source.selectors_from(observed, target=value, kind=kind),
        observed_at=observed_at, indicator_type=indicator_type, actor=actor,
        source="observe")
def _record_opendir(con, *, indicator_value: str, listing: dict[str, Any],
                    observed_at, actor: str | None,
                    indicator_type: str | None = None) -> list[dict[str, Any]]:
    """File one open-directory listing. Returns the genuinely new entries.

    Shared by the loud path (active_scan's dirsearch) and the quiet one
    (an autoindex page the ordinary HTTP probe already fetched), so the
    baseline rule lives once: the first-ever listing for an indicator is a
    baseline where every file is "new" and none of them are an event, and
    only additions against an existing baseline are flagged.
    """
    url = listing.get("url")
    files = listing.get("files") or []
    if not url:
        return []
    had_prior = con.execute(
        "SELECT 1 FROM opendir_files WHERE indicator_value = ? LIMIT 1",
        [indicator_value]).fetchone()
    added = tracking_store.upsert_opendir_files(
        con, indicator_value=indicator_value, url=url, files=files,
        observed_at=observed_at, actor=actor)
    if not (had_prior and added):
        return []
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=indicator_value, actor=actor,
        attribute="opendir_files", change_type="opendir_files",
        confidence="medium", old_value=None,
        new_value={"url": url, "added": [f["path"] for f in added]})
    return added
def _log_cluster_enrichment_history(
        actor: str, observed_at: datetime,
        results: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]) -> str | None:
    """Best-effort: write one dated observation row per ip/domain that got
    fresh live-enrichment data this sweep (TLS/HTTP/Webamon/infostealer/
    subdomains/ThreatFox/PTR/resolved-IP), so the dashboard's per-observable
    timeline can show when these fields were seen or changed - and diff the
    fresh value against the prior baseline, recording a change in
    attribute_changes when something actually moved (see
    cti.store.changes.detect). Returns an error note (never raises) on a tracking-store
    hiccup - pivot_cluster's cluster-JSON write already happened and a
    separate store's outage shouldn't undo or block reporting that success."""
    try:
        with tracking_store.connect(read_only=False) as con:
            for (category, value), (_status, detail, enrichment) in results.items():
                if category == "domains":
                    indicator_type = "domain"
                else:
                    indicator_type = "ipv6" if ":" in value else "ipv4"

                observed = enrichment.get("observe")
                if ok(observed):
                    _log_observation(con, value, indicator_type, actor,
                                     observed, observed_at)

                threatfox = enrichment.get("threatfox")
                if isinstance(threatfox, dict) and "error" not in threatfox:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="threatfox", actor=actor, indicator_type=indicator_type,
                        threatfox_matches=threatfox.get("matches") or None)

                if category == "ips":
                    webamon_ip = enrichment.get("webamon_ip")
                    if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
                        hosts = webamon_ip.get("domains") or []
                        tracking_store.upsert_observation(
                            con, observed_at=observed_at, indicator_value=value,
                            source="webamon", actor=actor, indicator_type=indicator_type,
                            ip_hostnames=hosts or None)
                        tracking_store.detect(con, "ip_hostnames", indicator_value=value,
                                              actor=actor, observed_at=observed_at, new=hosts)
                    _log_passive(con, value=value, indicator_type=indicator_type,
                                 actor=actor, observed_at=observed_at,
                                 enrichment=enrichment)
                    ptr = enrichment.get("ptr")
                    if isinstance(ptr, dict) and "error" not in ptr:
                        tracking_store.upsert_observation(
                            con, observed_at=observed_at, indicator_value=value,
                            source="ptr", actor=actor, indicator_type=indicator_type,
                            ptr_hostname=ptr.get("hostname"))
                        tracking_store.detect(con, "ptr", indicator_value=value, actor=actor,
                                              observed_at=observed_at, new=ptr.get("hostname"))
                    continue

                # --- domains ---
                tls = enrichment.get("tls")
                if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
                    cert = tls["cert"]
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="tls_live", actor=actor, indicator_type="domain",
                        tls_sha256=cert.get("sha256"), tls_issuer=cert.get("issuer"),
                        tls_subject=cert.get("subject"), tls_sans=cert.get("sans") or None,
                        tls_not_before=cert.get("not_before"), tls_not_after=cert.get("not_after"))
                    tracking_store.detect(con, "cert", indicator_value=value, actor=actor,
                                          observed_at=observed_at, new=cert)
                    tracking_store.detect(con, "cert_hash", indicator_value=value, actor=actor,
                                          observed_at=observed_at, new=cert)

                http = enrichment.get("http")
                if isinstance(http, dict) and "error" not in http and http.get("status") is not None:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="http_live", actor=actor, indicator_type="domain",
                        http_status=http.get("status"), http_title=http.get("title"),
                        http_server=http.get("server"), http_final_url=http.get("final_url"))
                    tracking_store.detect(con, "http", indicator_value=value, actor=actor,
                                          observed_at=observed_at, new=http)
                    # The probe already parsed any directory listing on that
                    # page. It was returned and discarded, so open directories
                    # were only ever found by active_scan's dirsearch - a
                    # path brute-force, on request only. Recording it here
                    # costs no extra traffic: the page was fetched either
                    # way, and the quiet path finds what the loud one was
                    # needed for.
                    autoindex = http.get("autoindex")
                    if isinstance(autoindex, dict) and autoindex.get("files"):
                        _record_opendir(con, indicator_value=value,
                                        listing=autoindex, observed_at=observed_at,
                                        actor=actor, indicator_type="domain")

                webamon = enrichment.get("webamon")
                if isinstance(webamon, dict) and "error" not in webamon:
                    latest = webamon.get("latest") or {}
                    fp = latest.get("fingerprint") or {}
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="webamon", actor=actor, indicator_type="domain",
                        webamon_report_id=latest.get("report_id"),
                        webamon_risk_score=latest.get("risk_score"),
                        webamon_fingerprint_dom=fp.get("dom"),
                        webamon_fingerprint_ssl=fp.get("ssl"),
                        webamon_last_scan=latest.get("date"))
                    tracking_store.detect(con, "webamon_fingerprint", indicator_value=value,
                                          actor=actor, observed_at=observed_at, new=fp)

                infostealers = enrichment.get("webamon_infostealers")
                if isinstance(infostealers, dict) and "error" not in infostealers:
                    hits = infostealers.get("results") or []
                    urls = sorted({h.get("url") for h in hits if h.get("url")})
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="webamon_infostealers", actor=actor, indicator_type="domain",
                        infostealer_count=len(hits), infostealer_urls=urls or None)
                    tracking_store.detect(con, "infostealer_hits", indicator_value=value, actor=actor,
                                          observed_at=observed_at,
                                          new={"count": len(hits), "urls": urls})

                # Domains get passive DNS too - where this name pointed
                # before it pointed where it does now. internetdb is
                # address-only and simply absent here.
                _log_passive(con, value=value, indicator_type="domain",
                             actor=actor, observed_at=observed_at,
                             enrichment=enrichment)

                subdomains = enrichment.get("subdomains")
                if isinstance(subdomains, dict) and "error" not in subdomains:
                    subs = subdomains.get("subdomains") or []
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="subdomains", actor=actor, indicator_type="domain",
                        subdomains=subs or None)
                    tracking_store.detect(con, "subdomains", indicator_value=value, actor=actor,
                                          observed_at=observed_at, new=subs)

                # Domain-hosting-shift detection: detail["resolved"] is the
                # same live A-record lookup _domain_lifecycle already runs.
                # None = inconclusive (skip); [] = confirmed dead/sinkholed
                # (a real, recordable answer).
                resolved = detail.get("resolved")
                if resolved is not None:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="dns_resolve", actor=actor, indicator_type="domain",
                        resolved_ip=resolved)
                    tracking_store.detect(con, "resolved_ip", indicator_value=value, actor=actor,
                                          observed_at=observed_at, new=resolved)
    except (tracking_store.TrackingBusy, duckdb.Error) as e:
        # duckdb.Error, not just IOException: this write is documented
        # best-effort - the cluster JSON write has already landed - but the
        # clause only covered lock contention, so a TransactionException
        # (the catalog conflict that hit fox-tempest) escaped, failed the
        # whole sweep, and reported a cluster as unswept whose data was in
        # fact written. The note it returns is surfaced in the digest's
        # phase status by graph/nodes/collect.py, so widening this does not
        # make the failure quiet.
        return f"enrichment history not recorded: {type(e).__name__}: {e}"
    return None
def _file_cert_hash(data: dict[str, Any], domain: str, sha256: str,
                    issuer: str | None, revoked: bool | None, now: str) -> None:
    """Auto-file a certificate's own SHA256 fingerprint onto the cluster's
    hashes list when pivot_cluster sees a new one for an already-tracked
    domain - an attribute of infrastructure already being tracked (like
    ASN/ports/cert issuer), not a new lead, so unlike a discovered
    subdomain or hosted domain (flag-only) this auto-updates without
    analyst confirmation. The `cert-sha256:` value prefix (distinct from
    the existing `sha256:`/`sha1:`/`md5:` file-hash prefixes) plus the
    explicit hash_kind field make this unambiguous as a certificate hash,
    not a file hash; cert_for names the domain it belongs to."""
    value = f"cert-sha256:{sha256}"
    bucket = data["observables"]["hashes"]
    source = f"live TLS grab for {domain}, seen {now[:10]}"
    for entry in bucket:
        if entry["value"] == value:
            if source not in entry["sources"]:
                entry["sources"].append(source)
            entry["last_seen"] = now
            entry["cert_issuer"] = issuer
            entry["cert_revoked"] = revoked
            return
    bucket.append({
        "value": value, "sources": [source], "first_seen": now, "last_seen": now,
        "hash_kind": "certificate", "cert_for": domain,
        "cert_issuer": issuer, "cert_revoked": revoked,
    })
