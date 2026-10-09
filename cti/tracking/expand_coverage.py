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
3. Verify. Every new host gets one full sweep, which writes its selectors,
   and then has to pass the corroboration rule against THIS cluster's
   indicators - one identity fact, or two independent structural ones.
   Sharing the seed alone is not enough when the seed is structural.
4. File. A host that passes is filed as a `candidate`: swept daily, shown
   in the digest, but left out of exports until accept_candidate. A
   rejected host goes on the cluster's deny list and is never re-filed.

Validin is not used: its metered calls are manual-only by design.
"""
from __future__ import annotations

import logging
import os
from datetime import date
from typing import Any

from .. import core, store
from ..sources import budget, pivot, webamon
from ..store import cdn as cdn_ranges
from ..store import expand, rarity, selectors
from ..util import now_iso

log = logging.getLogger(__name__)

EXPAND_SELECTORS_PER_CLUSTER = 8
# New hosts swept per cluster per run. Each one costs a full enrichment
# sweep (RDAP, observe, Webamon, subdomains), so this, not the reverse
# lookups, is what bounds a run's cost.
EXPAND_HOSTS_PER_CLUSTER = 10
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
    return {d["value"].lower() for d in data.get("denylist") or []}


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


def _only_via_shared_address(candidate: expand.Candidate) -> bool:
    """True when every promoting fact is an address on a CDN edge.

    The selector layer already refuses to record co-hosting selectors on
    CDN space; this is the belt to that brace for the expansion path, where
    a wrong link costs a candidate an analyst has to reject by hand.
    """
    facts = candidate.identity + candidate.structural
    return bool(facts) and all(
        t.startswith("net.") and cdn_ranges.is_cdn(str(v)) for t, v in facts)


def _verify(con, host: str, cluster_indicators: set[str]) -> expand.Candidate | None:
    """The strongest promoted link from `host` into this cluster, or None."""
    best = None
    for candidate in expand.candidates_for(con, host):
        if not candidate.promoted or candidate.indicator.lower() not in cluster_indicators:
            continue
        if _only_via_shared_address(candidate):
            continue
        if best is None or (len(candidate.identity), len(candidate.structural)) > (
                len(best.identity), len(best.structural)):
            best = candidate
    return best


def expand_cluster(slug: str) -> dict[str, Any]:
    """One cluster's expansion pass. Returns what it filed and why."""
    data = core.load_cluster(slug)
    report: dict[str, Any] = {"cluster": data["name"], "seeds": [], "reversed": 0,
                              "swept": 0, "filed": [], "rejected_links": 0,
                              "owned_elsewhere": [], "errors": []}
    with store.connect() as con:
        seeds = seeds_for(con, data)
    report["seeds"] = [f"{s['selector_type']}={str(s['selector_value'])[:64]}" for s in seeds]
    if not seeds:
        return report

    owners = _owned_elsewhere(slug)
    via: dict[str, dict[str, Any]] = {}
    for seed in seeds:
        if report.get("budget_exhausted"):
            break
        report["reversed"] += 1
        for host in _new_hosts(data, seed, owners, report):
            via.setdefault(host, seed)
    hosts = list(via)[:EXPAND_HOSTS_PER_CLUSTER]
    if not hosts:
        return report

    # One sweep per new host writes its selectors, so the corroboration
    # rule has something to read. Recorded with no actor: the host is not
    # attributed to anyone until an analyst accepts it.
    results = core._sweep_lifecycle(hosts, [])
    report["swept"] = len(hosts)
    note = core._record_enrichment(None, results)
    if note:
        report["errors"].append(note)

    cluster_indicators = {v.lower() for v in _live_indicators(data)}
    filed: list[tuple[str, dict[str, Any]]] = []
    with store.connect() as con:
        for host in hosts:
            link = _verify(con, host, cluster_indicators)
            if link is None:
                report["rejected_links"] += 1
                continue
            seed = via[host]
            filed.append((host, {
                "lifecycle": "candidate",
                "discovered_via": f"{seed['selector_type']}:{seed['selector_value']}",
                "discovered_from": seed["from"],
                "candidate_reason": link.reason,
                "candidate_linked_to": link.indicator,
            }))

    for host, metadata in filed:
        source = f"auto-pivot {now_iso()[:10]} via {metadata['discovered_via'][:96]}"
        core.file_candidate(slug, host, source, metadata,
                            {("domains", host): results[("domains", host)]}
                            if ("domains", host) in results else None)
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
        out["filed_total"] += len(report.get("filed") or [])
        if report.get("budget_exhausted"):
            out["budget_exhausted"] = True
            break
    return out
