"""What to scan, and how hard, built from the cluster files.

Tiers, by how live a host is:

  hot    candidate or recently-moved hosts, and dormant ones kept warm -
         a light TLS/HTTP re-fingerprint on the known ports.
  full   active hosts - the light pass plus a naabu + C2-port sweep, so a
         service that moves to an odd port is found without waiting for a
         report.
  sweep  prefix-neighbourhood hosts (Phase 3) - the cluster's port_set
         only, at a low rate.

Scored candidates from the membership store join the hot tier, best first
and capped per cluster (CANDIDATES_PER_CLUSTER), at or above
CTI_CANDIDATE_SCAN_BAND (default `weak`). A candidate is a proposal; the
light profile is what lets it be scored on more than the one link that
surfaced it.

Retired hosts are not scanned. CDN edge addresses are dropped: scanning a
Cloudflare IP fingerprints Cloudflare, not an operator (the same judgment
the selector layer already makes).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import os

from .. import core, membership
from ..store import cdn
from ..store import entities

# A host whose lifecycle moved within this window is still "hot" even once
# it is back to active, so a change gets a few days of close attention.
RECENT_MOVE_DAYS = 7
CANDIDATES_PER_CLUSTER = 25


def _candidate_targets(slug: str, actor: str) -> list[dict[str, Any]]:
    floor = os.environ.get("CTI_CANDIDATE_SCAN_BAND", "weak")
    try:
        found = membership.candidates(slug, min_band=floor)
    except Exception:
        return []
    out = []
    for row in found[:CANDIDATES_PER_CLUSTER]:
        kind = entities.entity_type(row["entity"])
        if kind not in ("domain", "ipv4"):
            continue
        out.append({"value": row["entity"], "kind": "ip" if kind == "ipv4" else "domain",
                    "tier": "hot", "ports": [], "actor": actor, "cluster": slug,
                    "lifecycle": "candidate", "score": row.get("score"),
                    "band": row.get("band")})
    return out


def _tier(entry: dict[str, Any]) -> str | None:
    state = core.lifecycle_of(entry)
    if state == "retired":
        return None
    if state == "candidate":
        return "hot"
    since = entry.get("lifecycle_since")
    moved_recently = False
    if since:
        try:
            dt = datetime.fromisoformat(since)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            moved_recently = (datetime.now(timezone.utc) - dt) <= timedelta(days=RECENT_MOVE_DAYS)
        except (ValueError, TypeError):
            moved_recently = False
    if state == "dormant":
        return "hot"
    # active
    return "hot" if moved_recently else "full"


def build(*, clusters: list[str] | None = None) -> list[dict[str, Any]]:
    """Every scan target across the tracked clusters, de-duplicated by
    (value, port-set) with the strongest tier winning when a value appears
    in more than one cluster."""
    names = clusters if clusters is not None else core.list_clusters()
    rank = {"full": 2, "hot": 1, "sweep": 0}
    best: dict[str, dict[str, Any]] = {}
    for name in names:
        try:
            data = core.load_cluster(name)
        except Exception:
            continue
        actor = data.get("name") or name
        for target in _candidate_targets(core._slug(data), actor):
            if target["kind"] == "ip" and cdn.available() and cdn.is_cdn(target["value"]):
                continue
            best.setdefault(target["value"], target)
        for category, kind in (("ips", "ip"), ("domains", "domain")):
            for entry in data["observables"].get(category, []):
                value = (entry.get("value") or "").strip()
                if not value:
                    continue
                if kind == "ip" and cdn.available() and cdn.is_cdn(value):
                    continue
                tier = _tier(entry)
                if tier is None:
                    continue
                target = {"value": value, "kind": kind, "tier": tier,
                          "ports": entry.get("ports") or [], "actor": actor,
                          "cluster": name, "lifecycle": core.lifecycle_of(entry)}
                prior = best.get(value)
                if prior is None:
                    best[value] = target
                else:
                    # One host, one scan: keep the strongest tier and the
                    # union of every cluster's known ports.
                    merged_ports = sorted(set(prior["ports"]) | set(target["ports"]))
                    if rank[tier] > rank[prior["tier"]]:
                        best[value] = target
                    best[value]["ports"] = merged_ports
    return list(best.values())


def for_tiers(tiers: set[str], *, clusters: list[str] | None = None) -> list[dict[str, Any]]:
    """The watchlist filtered to the tiers a given run covers."""
    return [t for t in build(clusters=clusters) if t["tier"] in tiers]
