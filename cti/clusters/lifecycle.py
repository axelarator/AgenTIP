"""Indicator lifecycle: the states an observable moves through as it goes
quiet (active, dormant, retired), how liveness is judged, and the small
helpers that read observables out of a cluster dict.
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from .. import membership


def _without_inactive(data: dict[str, Any]) -> dict[str, Any]:
    """A copy of the cluster with retired and candidate observables left
    out - what detections and shared exports should see. Dormant entries
    stay: quiet is not gone, and a blocklist that drops a host the week
    before it comes back is worse than one that carries it a while."""
    out = dict(data)
    out["observables"] = {
        cat: [o for o in items if lifecycle_of(o) not in INACTIVE_LIFECYCLES]
        for cat, items in data["observables"].items()}
    return out


def _find_entry(data: dict[str, Any], value: str) -> tuple[str, dict[str, Any]] | None:
    needle = value.strip().lower()
    for cat in ("domains", "ips"):
        for o in data["observables"][cat]:
            if o["value"].lower() == needle:
                return cat, o
    return None


def member_values(data: dict[str, Any]) -> list[str]:
    """The cluster JSON's member indicators: every indicator entry except a
    legacy candidate. Retired and dormant hosts stay members - a link to a
    host the operator used last year is still a link, and the span dates
    decide how much it is worth."""
    return [o["value"] for cat in membership.MEMBER_CATEGORIES
            for o in data["observables"].get(cat, [])
            if membership.member_value(cat, o["value"]) and lifecycle_of(o) != "candidate"]


# The ten _record_*_change functions and _attribute_confidence that used
# to live here are gone: they were the same four-step body ten times over
# (fetch baseline, emit first_seen, return if unchanged, else record).
# They are now ten entries in cti/store/changes.py's SPECS registry,
# driven by one function - see that module for what each spec preserves.












# --------------------------------------------------------------------------- #
# Indicator lifecycle
# --------------------------------------------------------------------------- #
# `last_seen` on an observable means "last re-filed", not "last seen live":
# a domain that died in July still reads as current. `last_live` is the
# sweep's own answer, and `lifecycle` is what it ages into:
#
#   active    -> dormant after DORMANT_DAYS with no live evidence
#   dormant   -> retired after RETIRED_DAYS with no live evidence
#   any state -> active the first time live evidence comes back
#   candidate    filed by the expansion sweep, awaiting accept/reject;
#                ages like active but never becomes active on its own
#
# Retired entries are kept, for history and find_observable, but are no
# longer swept and are left out of exports. Dormant ones are still swept so
# a reactivation is seen; rank drops their change rows meanwhile.
LIFECYCLE_STATES = ("active", "dormant", "retired", "candidate")
INACTIVE_LIFECYCLES = ("retired", "candidate")
_DORMANT_DAYS_DEFAULT = 30
_RETIRED_DAYS_DEFAULT = 90


def _env_days(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except ValueError:
        return default


def dormant_days() -> int:
    return _env_days("CTI_DORMANT_DAYS", _DORMANT_DAYS_DEFAULT)


def retired_days() -> int:
    return _env_days("CTI_RETIRED_DAYS", _RETIRED_DAYS_DEFAULT)


def lifecycle_of(entry: dict[str, Any]) -> str:
    return entry.get("lifecycle") or "active"


def _is_live(category: str, status: str, enrichment: dict[str, Any]) -> bool:
    """Did this sweep see the host doing something?

    A domain is live when it resolves and is neither sinkholed nor expired -
    pivot.classify_domain_lifecycle already orders those checks. An IP is
    only live when something answered on it: being in a routed prefix says
    the network exists, not that the actor is still using the address.
    """
    if category == "domains":
        return status == "active"
    if status != "routed":
        return False
    observed = enrichment.get("observe") or {}
    if not isinstance(observed, dict):
        return False
    tls = observed.get("tls") or {}
    http = observed.get("http") or {}
    # `responded` is per observe stage. Only the stages that contact the
    # host count - `cdn` is a range lookup and answers for any address. A
    # port scan that found something open is a raw-TCP C2 still listening.
    responded = observed.get("responded") or {}
    return (bool(tls.get("cert_sha256")) or isinstance(http.get("status"), int)
            or any(responded.get(stage) for stage in ("http", "tls", "ports")))


def _age_lifecycle(entry: dict[str, Any], now: str, live: bool) -> tuple[str, str] | None:
    """Move an entry along the lifecycle. Returns (from, to) on a change.

    With no `last_live` at all, the clock runs from `first_seen`: a host
    filed from a report and never once seen live is as dormant as one that
    went quiet.
    """
    before = lifecycle_of(entry)
    if live:
        entry["last_live"] = now
        after = "candidate" if before == "candidate" else "active"
    else:
        since = entry.get("last_live") or entry.get("first_seen") or now
        try:
            quiet = (datetime.fromisoformat(now) - datetime.fromisoformat(since)).days
        except (ValueError, TypeError):
            quiet = 0
        if before == "candidate":
            after = "candidate"
        elif quiet >= retired_days():
            after = "retired"
        elif quiet >= dormant_days():
            after = "dormant"
        else:
            after = before
    if after == before and "lifecycle" in entry:
        return None
    entry["lifecycle"] = after
    if after != before or "lifecycle_since" not in entry:
        entry["lifecycle_since"] = now
    return (before, after) if after != before else None


def sweep_targets(data: dict[str, Any], category: str) -> list[str]:
    """Values the daily sweep re-checks: everything but retired entries."""
    return [o["value"] for o in data["observables"][category]
            if lifecycle_of(o) != "retired"]
