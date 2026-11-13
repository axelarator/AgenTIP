"""Pivoting from what a cluster already holds: the per-cluster sweep
(`pivot_cluster`) and filing what one indicator leads to
(`pivot_and_expand`).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from .. import membership
from ..sources import pivot
from ..sources import webamon
from ..store import hosting
from ..store import psl
from ..tracking.history import _log_cluster_enrichment_history
from ..util import asn_int
from ..util import now_iso
from .storage import _data_lock, _slug, _synchronized, load_cluster, save_cluster
from .lifecycle import _age_lifecycle, _is_live, member_values, sweep_targets
from .enrich import (
    _apply_enrichment_snapshot, _cached_pivot, _new_values, _record_enrichment,
    _subdomains_for, _sweep_lifecycle, _webamon_domain, _webamon_ip,
)


def pivot_cluster(name: str) -> dict[str, Any]:
    """Sweep every tracked domain and IP for a cluster through the free
    pivot sources and stamp a lifecycle status onto each, turning a
    static observable list into a live "what's still up" view. Domains
    are classified active/dead/sinkholed/expired/unknown (RDAP + a live
    resolution attempt); IPs routed/unrouted/unknown (RIPEstat). The
    status, the time it was checked, and the supporting detail are
    written back onto each observable (unlike pivot_observable, which is
    display-only), and a summary is returned. Successful source lookups
    are cached (see CTI_PIVOT_CACHE_TTL) so re-sweeping is cheap.

    Domains are also enriched via a live TLS grab + HTTP probe from the
    probe VM, Webamon (latest scan, kit fingerprints, infostealer hits),
    and subfinder/Wayback subdomain discovery (flag-only here); ips via
    Webamon hosted-domains and PTR; both via ThreatFox (if
    THREATFOX_API_KEY is set). This enrichment is stamped onto each
    observable's asn/netname/cert/http/webamon/ip_hostnames/tags fields
    (see _apply_enrichment_snapshot) so the current-known-value snapshot
    stays fresh, AND a dated snapshot is recorded to the tracking-store
    history (cti.tracking.store), which also runs day-over-day
    diffing and records a change when something moved - see
    _log_cluster_enrichment_history. Open ports are not discovered here
    (nothing passive replaced Shodan's); they come from report text and
    the on-demand active_scan. The dashboard's per-observable
    profile reads that history back - see get_observables/the dashboard.

    The network lookups run concurrently and, crucially, OUTSIDE the data
    lock - a cluster with dozens of domains would otherwise serialize
    into minutes of blocking I/O with the whole store locked. Only the
    final write-back takes the lock, re-reading the cluster so it applies
    onto current on-disk state."""
    data = load_cluster(name)  # existence check + snapshot the values to check
    domains = sweep_targets(data, "domains")
    ips = sweep_targets(data, "ips")

    # Network phase: concurrent, no lock held.
    known_ports = {o["value"]: o["ports"]
                   for cat in ("domains", "ips")
                   for o in data["observables"][cat]
                   if o.get("ports")}
    timings: dict[tuple[str, str], dict[str, float]] = {}
    results = _sweep_lifecycle(domains, ips, known_ports, timings=timings)

    # Write phase: brief lock, applied onto a fresh read of the cluster.
    now = now_iso()
    with _data_lock():
        data = load_cluster(name)
        summary: dict[str, Any] = {"name": data["name"], "checked": now, "domains": [], "ips": [],
                                   "lifecycle": []}
        for cat in ("domains", "ips"):
            for o in data["observables"][cat]:
                found = results.get((cat, o["value"]))
                if not found:
                    continue
                status, detail, enrichment = found
                o["status"] = status
                o["status_checked"] = now
                o["status_detail"] = detail
                _apply_enrichment_snapshot(o, cat, detail, enrichment)
                # A failed lookup is no evidence either way, so it neither
                # refreshes last_live nor ages the entry.
                moved = (None if status == "unknown"
                         else _age_lifecycle(o, now, _is_live(cat, status, enrichment)))
                if moved:
                    summary["lifecycle"].append(
                        {"category": cat, "value": o["value"], "from": moved[0], "to": moved[1]})
                # A certificate is a selector on its host (tls.cert_sha256,
                # recorded by the observe pass), not a cluster indicator. It
                # used to be filed here into `hashes`, which is how a default
                # catch-all cert served for 248 strangers became a JadeProx
                # observable.
                row = {"value": o["value"], "status": status}
                # Seconds per source lookup. Rides the summary into the run
                # trace only - see _sweep_lifecycle for why not `detail`.
                if timings.get((cat, o["value"])):
                    row["timings"] = timings[(cat, o["value"])]
                tls = enrichment.get("tls")
                if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
                    row["cert_sha256"] = tls["cert"].get("sha256")
                webamon_ip = enrichment.get("webamon_ip")
                if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
                    row["hosted_domains"] = len(webamon_ip.get("domains") or [])
                webamon = enrichment.get("webamon")
                if isinstance(webamon, dict) and "error" not in webamon and webamon.get("latest"):
                    row["webamon_risk"] = webamon["latest"].get("risk_score")
                threatfox = enrichment.get("threatfox")
                if isinstance(threatfox, dict) and "error" not in threatfox:
                    row["threatfox_matches"] = len(threatfox.get("matches") or [])
                row["resolved" if cat == "domains" else "asn"] = \
                    detail.get("resolved") if cat == "domains" else detail.get("asn")
                summary[cat].append(row)
        save_cluster(data)

    # Best-effort history logging to the separate tracking store, outside
    # the cluster-JSON lock above (a different store, its own locking) -
    # done after that write succeeds so a tracking-store hiccup can't
    # undo or block the cluster-JSON update that already landed.
    observed_at = datetime.fromisoformat(now).replace(tzinfo=None)
    history_error = _log_cluster_enrichment_history(data["name"], observed_at, results)
    if history_error:
        summary["history_note"] = history_error
    return summary


def pivot_and_expand(value: str, cluster_name: str,
                     include_cohosted: bool = False) -> dict[str, Any]:
    """Pivot a domain or IP and file the high-confidence new indicators it
    surfaces straight onto an existing cluster (with provenance and a
    hunt-log entry), instead of leaving you to copy each finding back by
    hand. What gets filed:

    - domain: sibling subdomains under the queried name (subfinder +
      Wayback, same operator, high confidence). Webamon kit-fingerprint
      siblings (other scanned domains sharing this domain's dom/ssl
      fingerprint) are surfaced under `review`, not auto-filed.
    - ip: the domains Webamon has scanned resolving to this IP.

    Co-hosted domains on a shared-hosting IP are noise; when the queried
    IP sits in a known shared-hosting ASN (see SHARED_HOSTING_ASNS) they
    are suppressed and a `review["cohosted_domains_suppressed"]` note
    explains why. Otherwise, by default they go to `review` rather than
    being filed; pass include_cohosted=True to file them. Only genuinely
    new indicators are filed; ones already tracked are left as-is.

    Each newly-filed indicator also gets its own live asn/cert/tags
    snapshot (see _apply_enrichment_snapshot) - a second, cheap (cached)
    lookup on the newly-discovered value itself, run in the same unlocked
    network phase as the rest of this pivot; see _sweep_lifecycle for why
    that lookup must not run under _data_lock."""
    data = load_cluster(cluster_name)  # must already exist; expansion targets an investigation
    kind = pivot.classify(value)
    if kind not in ("domain", "ip"):
        raise ValueError(
            f"pivot_and_expand supports domain/ip values; got kind={kind!r} for {value!r}")
    if kind == "ip" and ipaddress.ip_address(value).version == 6:
        # Functional rule: ignore IPv6 for pivoting and probing - the probe
        # VM has no IPv6 route, so nothing downstream can act on the result.
        return _pivot_and_expand_ipv6_skip(value, cluster_name, kind)

    now = now_iso()
    candidates: list[tuple[str, list[str], str]] = []  # (category, values, source)
    review: dict[str, Any] = {}

    if kind == "domain":
        # Sibling subdomains under the queried name (subfinder + Wayback).
        subs = _subdomains_for(value)
        if isinstance(subs, dict) and subs.get("error"):
            review["subdomain_discovery_error"] = subs["error"]
        else:
            all_subs = (subs.get("subdomains") or []) if isinstance(subs, dict) else []
            siblings = [h for h in all_subs if h != value and h.endswith("." + value)]
            candidates.append(("domains", siblings,
                               f"pivot_and_expand via subfinder/Wayback, checked {now}"))
            others = [h for h in all_subs if h != value and not h.endswith("." + value)]
            if others:
                review["other_hostnames"] = others
        # Webamon kit-fingerprint siblings - the campaign-cluster signal,
        # surfaced for review rather than auto-filed (a shared kit isn't
        # proof of the same operator).
        wm = _webamon_domain(value)
        if isinstance(wm, dict) and wm.get("error"):
            # Said, not swallowed: an empty pivot reads as "nothing found",
            # and a rate-limited one is "could not look".
            review["source_errors"] = {"webamon": wm["error"]}
        latest = wm.get("latest") if isinstance(wm, dict) and "error" not in wm else None
        if isinstance(latest, dict):
            fp = latest.get("fingerprint") or {}
            fp_siblings: dict[str, list[str]] = {}
            for kindfp in ("dom", "ssl"):
                if fp.get(kindfp):
                    sib = webamon.fingerprint_siblings(fp[kindfp], kind=kindfp)
                    doms = [d for d in (sib.get("domains") or []) if d != value] \
                        if isinstance(sib, dict) and "error" not in sib else []
                    if doms:
                        fp_siblings[kindfp] = doms
            if fp_siblings:
                review["webamon_fingerprint_siblings"] = fp_siblings
    else:  # ip
        wm = _webamon_ip(value)
        if isinstance(wm, dict) and wm.get("error"):
            review["source_errors"] = {"webamon": wm["error"]}
        hosted = wm.get("domains", []) if isinstance(wm, dict) and "error" not in wm else []
        # Same shared-hosting guard the automatic sweep uses: a shared-
        # hosting ASN's hosted domains are every other tenant, not this
        # actor's infra - suppress before they can be filed or reviewed.
        ripe = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        asn_list = ripe.get("asn") if isinstance(ripe, dict) else None
        asn = asn_int(asn_list)  # RIPEstat gives strings; see _asn_int
        shared, why = hosting.is_shared(asn=asn)
        if hosted and shared:
            review["cohosted_domains_suppressed"] = (
                f"{len(hosted)} co-hosted domains suppressed - "
                f"{value} is shared hosting ({why})")
            hosted = []
        if include_cohosted:
            candidates.append(("domains", hosted,
                               f"pivot_and_expand via Webamon hosted-domains, checked {now}"))
        elif hosted:
            review["cohosted_domains"] = hosted

    new_domains = _new_values(data, "domains",
                              [v for cat, vs, _ in candidates if cat == "domains" for v in vs])
    new_ips = _new_values(data, "ips",
                          [v for cat, vs, _ in candidates if cat == "ips" for v in vs])
    enrichment = _sweep_lifecycle(new_domains, new_ips)  # unlocked - see docstring

    # The new hosts' sweep goes to the store first, unattributed - they are
    # nobody's until accepted - so the score below can read their selectors.
    note = _record_enrichment(None, enrichment, when=now)
    result = _pivot_and_expand_merge(value, kind, cluster_name, now, candidates,
                                     review, enrichment)
    if note:
        result["history_note"] = note
    return result


@_synchronized
def _pivot_and_expand_ipv6_skip(value: str, cluster_name: str, kind: str) -> dict[str, Any]:
    data = load_cluster(cluster_name)
    entry = f"pivot_and_expand on {value}: skipped (IPv6, not pivoted)"
    data["hunt_log"].append({"date": now_iso(), "entry": entry})
    save_cluster(data)
    return {"value": value, "kind": kind, "cluster": cluster_name,
            "filed": {}, "review": {}, "cluster_state": load_cluster(cluster_name)}


@_synchronized
def _pivot_and_expand_merge(value: str, kind: str, cluster_name: str, now: str,
                            candidates: list[tuple[str, list[str], str]],
                            review: dict[str, Any],
                            enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                            ) -> dict[str, Any]:
    """Locked write phase: file each new host as a scored candidate.

    Nothing here touches the cluster's observables. A pivot proposes; the
    relatedness score says how strongly, with its evidence, and
    accept_candidate is the only way in. Each candidate carries the link
    that found it as a dated selector: a subdomain sibling its registered
    domain (`dns.apex`), a co-hosted name the pivoted address
    (`net.resolved_ip`)."""
    data = load_cluster(cluster_name)
    tracked = {o["value"].lower() for cat in ("domains", "ips")
               for o in data["observables"][cat]}
    filed: dict[str, list[str]] = {}
    scores: dict[str, dict[str, Any]] = {}
    for category, values, source in candidates:
        for candidate in dict.fromkeys(values):
            if not candidate or candidate.lower() in tracked:
                continue
            if kind == "ip":
                links = [{"selector_type": "net.resolved_ip", "value": value,
                          "last": now, "source": "pivot_and_expand"}]
            else:
                apex = psl.apex_for_selector(candidate)
                links = ([{"selector_type": "dns.apex", "value": apex, "last": now,
                           "source": "pivot_and_expand"}] if apex else [])
            scored = membership.file_candidate(
                _slug(data), candidate, origin=source, decided_by="pivot",
                reason=f"pivot_and_expand on {value}", links=links,
                members=member_values(data))
            if scored is None:
                continue
            filed.setdefault(category, []).append(candidate)
            scores[candidate] = {"score": round(scored["score"], 3), "band": scored["band"],
                                 "artefacts": scored["artefacts"]}

    filed = {c: sorted(set(v)) for c, v in filed.items() if v}
    total = sum(len(v) for v in filed.values())
    breakdown = ", ".join(f"{len(v)} {c}" for c, v in filed.items()) or "none"
    entry = f"pivot_and_expand on {value}: filed {total} candidate(s) ({breakdown})"
    if scores:
        entry += "; " + ", ".join(f"{v} {s['band']} {s['score']:.2f}"
                                  for v, s in sorted(scores.items(),
                                                     key=lambda kv: -kv[1]["score"])[:10])
    if review:
        n_review = sum(len(v) for v in review.values() if isinstance(v, list))
        if n_review:
            entry += f"; {n_review} left for review"
        for source, error in (review.get("source_errors") or {}).items():
            entry += f"; {source} unavailable ({error}) - incomplete, not a negative"
    data["hunt_log"].append({"date": now, "entry": entry})
    save_cluster(data)

    return {"value": value, "kind": kind, "cluster": cluster_name,
            "filed": filed, "scores": scores, "review": review,
            "cluster_state": load_cluster(cluster_name)}
