"""Weekly coverage expansion: find each cluster's new infrastructure without
anyone searching for it.

The daily sweep re-checks what a cluster already has. Nothing in it finds
anything new: `expand.candidates_for` links indicators that are already in
the local selectors table, so a cluster's coverage only grew when someone
read a new report or ran pivot_and_expand by hand. With a dozen clusters
that stopped happening, and the lists went stale.

This asks the outside question once a week, per cluster:

1. Seeds. The cluster's own live indicators' selectors that can promote a
   link (identity or structural), that Webamon can reverse, and that have
   been priced below provider scale. Identity first, then rarest first.
   Unpriced values are skipped, not assumed rare - the same rule rarity
   applies everywhere else.
2. Reverse. `webamon.reverse_selector` for each seed: who else carries it.
3. Score. Every new host gets one full sweep, which writes its selectors,
   and is then scored against THIS cluster's members
   (`store/relatedness.py`): class x rarity x time overlap per shared
   artefact. Sharing the seed alone is worth what the seed is worth.
4. File. A host at or above CTI_CANDIDATE_MIN_BAND (default `weak`) is
   filed as a scored `candidate` in the membership store: shown in the
   digest with its evidence, never exported until accept_candidate. One
   below it is counted, not filed - its selectors stay in the store, so a
   later pivot can still find and re-score it. A rejected host is never
   re-filed.

Validin is not used: its metered calls are manual-only by design.
"""
from __future__ import annotations

import logging
import os
from datetime import date
from typing import Any

from .. import core, membership, store
from ..netwatch import rules as hunt_rules
from ..netwatch.candidates import pdns as pdns_source
from ..sources import budget, pivot, webamon
from ..store import cdn as cdn_ranges
from ..store import rarity, selectors
from ..util import now_iso

log = logging.getLogger(__name__)

EXPAND_SELECTORS_PER_CLUSTER = 8
# New hosts swept per cluster per run. Each one costs a full enrichment
# sweep (RDAP, observe, Webamon, subdomains), so this, not the reverse
# lookups, is what bounds a run's cost.
EXPAND_HOSTS_PER_CLUSTER = 10
DEFAULT_MIN_BAND = "weak"
BUDGET_KEY = "webamon_expand"
DEFAULT_WEEKDAY = 0  # Monday


def expand_weekday() -> int:
    try:
        day = int(os.environ.get("CTI_EXPAND_WEEKDAY", DEFAULT_WEEKDAY))
    except ValueError:
        return DEFAULT_WEEKDAY
    return day if 0 <= day <= 6 else DEFAULT_WEEKDAY


def due(day: date, forced: bool = False) -> bool:
    return forced or day.weekday() == expand_weekday()


def _tracked_values(data: dict[str, Any]) -> set[str]:
    return {o["value"].lower() for cat in ("domains", "ips")
            for o in data["observables"][cat]}


def _denied(data: dict[str, Any]) -> set[str]:
    """Values this cluster must not sweep again: rejected (the store's and the
    legacy JSON deny list) and already-filed candidates, which are re-scored
    as their own evidence arrives rather than re-discovered."""
    stored = membership.values_with_role(core._slug(data), ("rejected", "candidate"))
    return {d["value"].lower() for d in data.get("denylist") or []} | stored


def min_band() -> str:
    band = os.environ.get("CTI_CANDIDATE_MIN_BAND", DEFAULT_MIN_BAND)
    return band if band in membership.BAND_ORDER else DEFAULT_MIN_BAND


def _live_indicators(data: dict[str, Any]) -> list[str]:
    return [o["value"] for cat in ("domains", "ips")
            for o in data["observables"][cat] if core.lifecycle_of(o) == "active"]


def seeds_for(con, data: dict[str, Any], limit: int = EXPAND_SELECTORS_PER_CLUSTER
              ) -> list[dict[str, Any]]:
    """The selectors worth reversing for this cluster, best first."""
    seen: set[tuple[str, str]] = set()
    out = []
    for indicator in _live_indicators(data):
        for row in selectors.for_indicator(con, indicator):
            key = (row["selector_type"], row["selector_value"])
            if key in seen or not webamon.reversible(key[0]):
                continue
            seen.add(key)
            verdict = rarity.assess(con, *key)
            if not verdict["can_promote"] or verdict["global_count"] is None:
                continue
            out.append({"selector_type": key[0], "selector_value": key[1],
                        "class": selectors.selector_class(key[0]),
                        "global_count": verdict["global_count"],
                        "from": indicator})
    out.sort(key=lambda s: (s["class"] != "identity", s["global_count"],
                            s["selector_type"], s["selector_value"]))
    return out[:limit]


def _owned_elsewhere(slug: str) -> dict[str, str]:
    """value -> cluster, for indicators another cluster already tracks."""
    owners: dict[str, str] = {}
    for name in core.list_clusters():
        if name == slug:
            continue
        try:
            data = core.load_cluster(name)
        except Exception:
            continue
        for value in _tracked_values(data):
            owners.setdefault(value, data["name"])
    return owners


def _new_hosts(data: dict[str, Any], seed: dict[str, Any], owners: dict[str, str],
               report: dict[str, Any]) -> list[str]:
    """Hosts carrying `seed` that this cluster has not seen or refused."""
    try:
        budget.spend(BUDGET_KEY, 1)
    except budget.BudgetExhausted:
        report["budget_exhausted"] = True
        return []
    found = webamon.reverse_selector(seed["selector_type"], seed["selector_value"])
    if "error" in found:
        report["errors"].append(f"{seed['selector_type']}: {found['error']}")
        return []
    skip = _tracked_values(data) | _denied(data)
    out = []
    for host in found.get("indicators") or []:
        host = host.lower().rstrip(".")
        if host in skip or pivot.classify(host) != "domain":
            continue
        if host in owners:
            report["owned_elsewhere"].append({"value": host, "cluster": owners[host]})
            continue
        out.append(host)
    return out


def _rule_candidates(slug: str, data: dict[str, Any], owners: dict[str, str],
                     report: dict[str, Any]) -> list[dict[str, Any]]:
    """Hosts a cluster's own enabled hunt rules match in our snapshots.

    A rule is a human-approved signature, so a snapshot host that matches it
    and is not already tracked is filed straight away - the approval IS the
    judgment the corroboration rule stands in for when nobody wrote a
    signature. It is still only a `candidate`, so an analyst accepts it
    before it exports.
    """
    rules = [r for r in hunt_rules.load()
             if r.cluster == slug and r.action == "candidate"]
    if not rules:
        return []
    skip = _tracked_values(data) | _denied(data)
    filed: list[dict[str, Any]] = []
    with store.connect() as con:
        hits = hunt_rules.evaluate(con, rules)
    for hit in hits:
        host = hit["indicator"].lower().rstrip(".")
        if host in skip:
            continue
        if host in owners:
            report["owned_elsewhere"].append({"value": host, "cluster": owners[host]})
            continue
        if pivot.classify(host) == "ip" and cdn_ranges.is_cdn(host):
            continue
        terms = ", ".join(f"{t}={str(v)[:32]}" for t, v in hit.get("terms") or [])
        filed.append({
            "value": host, "enrich_kind": pivot.classify(host),
            "lifecycle": "candidate",
            "discovered_via": f"hunt-rule:{hit['rule']}",
            "discovered_from": hit["rule"],
            "candidate_reason": f"matches hunt rule {hit['rule']} ({terms})",
            "candidate_linked_to": hit["rule"]})
        skip.add(host)              # one rule filing per host per run
    return filed


def _pdns_candidates(data: dict[str, Any], owners: dict[str, str],
                     report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Co-hosted names and historical addresses of this cluster's live hosts.

    Returns host -> provenance, to be swept and corroborated like a Webamon
    reversal. A co-hosted name off a shared-hosting address is a stranger,
    so those addresses are left out here and the corroboration rule is the
    backstop for any that slip through.
    """
    skip = _tracked_values(data) | _denied(data)
    via: dict[str, dict[str, Any]] = {}
    for indicator in _live_indicators(data):
        kind = pivot.classify(indicator)
        for cand in pdns_source.host_candidates(indicator, kind):
            host = cand.value
            if host in skip or host in via:
                continue
            if host in owners:
                report["owned_elsewhere"].append({"value": host, "cluster": owners[host]})
                continue
            if cand.kind == "ip" and cdn_ranges.is_cdn(host):
                continue
            via[host] = {"via": cand.discovered_via, "from": cand.discovered_from,
                         "reason": cand.reason, "kind": cand.kind, "links": []}
            if cand.kind == "domain" and cand.first_seen:
                # A name found on one of our addresses carries that address,
                # dated by the record - the window the score compares.
                via[host]["links"].append({
                    "selector_type": "net.historical_ip", "value": cand.discovered_from,
                    "first": cand.first_seen, "last": cand.last_seen,
                    "source": "mnemonic_pdns"})
    return via


def expand_cluster(slug: str) -> dict[str, Any]:
    """One cluster's expansion pass. Returns what it filed and why.

    Order: our own sources first - enabled hunt rules over our snapshots,
    then passive-DNS neighbours - and Webamon's reverse lookup only as a
    fallback to fill the host budget. Nothing from Webamon is reached if our
    own sources already found a run's worth of hosts.
    """
    data = core.load_cluster(slug)
    report: dict[str, Any] = {"cluster": data["name"], "seeds": [], "reversed": 0,
                              "swept": 0, "filed": [], "rule_filed": [],
                              "rejected_links": 0, "owned_elsewhere": [],
                              "errors": []}
    owners = _owned_elsewhere(slug)

    # 1. Hunt rules: file matching snapshot hosts directly (no sweep needed -
    # a matched host is already in our snapshots, so its selectors are too).
    for meta in _rule_candidates(slug, data, owners, report):
        host = meta.pop("value")
        meta.pop("enrich_kind", None)
        source = f"hunt-rule {now_iso()[:10]} via {meta['discovered_via'][:96]}"
        scored = core.file_candidate(slug, host, source, meta)
        if scored:
            report["rule_filed"].append({"value": host, **meta, "score": scored["score"],
                                         "band": scored["band"]})

    # 2. Passive DNS neighbours, then Webamon as the fallback.
    via = _pdns_candidates(data, owners, report)
    if len(via) < EXPAND_HOSTS_PER_CLUSTER:
        with store.connect() as con:
            seeds = seeds_for(con, data)
        report["seeds"] = [f"{s['selector_type']}={str(s['selector_value'])[:64]}"
                           for s in seeds]
        for seed in seeds:
            if report.get("budget_exhausted") or len(via) >= EXPAND_HOSTS_PER_CLUSTER:
                break
            report["reversed"] += 1
            for host in _new_hosts(data, seed, owners, report):
                via.setdefault(host, {
                    "via": f"{seed['selector_type']}:{seed['selector_value']}",
                    "from": seed["from"], "kind": "domain",
                    "reason": f"carries {seed['selector_type']}"})

    hosts = list(via)[:EXPAND_HOSTS_PER_CLUSTER]
    if not hosts:
        return report

    # One sweep per new host writes its selectors, so the corroboration
    # rule has something to read. Recorded with no actor: the host is not
    # attributed to anyone until an analyst accepts it. Domains and IPs go
    # to their own lifecycle path (Webamon only ever yields domains; passive
    # DNS adds both).
    sweep_domains = [h for h in hosts if via[h].get("kind") != "ip"]
    sweep_ips = [h for h in hosts if via[h].get("kind") == "ip"]
    results = core._sweep_lifecycle(sweep_domains, sweep_ips)
    report["swept"] = len(hosts)
    note = core._record_enrichment(None, results)
    if note:
        report["errors"].append(note)

    floor = min_band()
    members = core.member_values(data)
    for host in hosts:
        prov = via[host]
        scored = membership.score(core._slug(data), host, members=members)
        if not membership.band_at_least(scored["band"], floor):
            report["rejected_links"] += 1
            continue
        top = scored["evidence"][0] if scored["evidence"] else {}
        metadata = {
            "discovered_via": prov["via"], "discovered_from": prov["from"],
            "candidate_reason": (f"{scored['band']} {scored['score']:.2f}: " + ", ".join(
                f"{k} {v:.2f}" for k, v in list(scored["artefacts"].items())[:3])),
            "candidate_linked_to": top.get("member"),
            "score": round(scored["score"], 3), "band": scored["band"]}
        source = f"auto-pivot {now_iso()[:10]} via {prov['via'][:96]}"
        if core.file_candidate(slug, host, source, metadata, links=prov.get("links")):
            report["filed"].append({"value": host, **metadata})
    return report


def run(day: date, *, forced: bool = False,
        clusters: list[str] | None = None) -> dict[str, Any]:
    """The weekly pass over every cluster. A cluster that fails is recorded
    and skipped; the others still run."""
    if not due(day, forced):
        return {"skipped": f"not the expansion day (weekday {expand_weekday()})"}
    out: dict[str, Any] = {"clusters": {}, "filed_total": 0}
    for slug in clusters if clusters is not None else core.list_clusters():
        try:
            report = expand_cluster(slug)
        except Exception as e:  # noqa: BLE001 - one cluster must not sink the run
            log.exception("expansion failed for %s", slug)
            report = {"cluster": slug, "errors": [f"{type(e).__name__}: {e}"], "filed": []}
        out["clusters"][slug] = report
        out["filed_total"] += (len(report.get("filed") or [])
                               + len(report.get("rule_filed") or []))
        if report.get("budget_exhausted"):
            out["budget_exhausted"] = True
            break
    return out
