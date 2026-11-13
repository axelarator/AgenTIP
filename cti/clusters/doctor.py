"""Checks that the two records of who belongs to a cluster agree.

Membership is stored twice: as the observables in a cluster's JSON file, and
as rows in the `memberships` table in DuckDB. Every change writes the table
first and the file second, so a failed table write stops before the file
changes - but nothing ties the two writes together, and a crash or a failed
save between them leaves the stores disagreeing with nothing to say so.
`membership_drift` says so. It reads and reports; it repairs nothing,
because which side is right is the analyst's call.
"""
from __future__ import annotations

from typing import Any

from .. import store as tracking_store
from ..store import entities
from .lifecycle import member_values
from .storage import _slug, list_clusters, load_cluster


def membership_drift(names: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """Disagreements between each cluster's file and the membership table.

    Returns {cluster slug: {...}} for clusters that disagree, and {} when
    all agree. Per cluster, any of:

      no_membership   in the file as a member, with no row in the table
      no_observable   a seed or accepted member in the table, not in the file
      role_mismatch   in the file as a member, but the table holds it as a
                      candidate or as rejected

    Candidates and rejections that exist only in the table are not drift:
    that is where they live.
    """
    out: dict[str, dict[str, Any]] = {}
    with tracking_store.connect_read() as con:
        for name in names if names is not None else list_clusters():
            data = load_cluster(name)
            slug = _slug(data)
            in_file = {entities.canonical(v) for v in member_values(data)}
            roles = {m["entity"]: m["role"] for m in entities.members(
                con, slug, roles=entities.ROLES)}
            in_table = {e for e, role in roles.items() if role in entities.MEMBER_ROLES}
            found: dict[str, Any] = {}
            missing = sorted(v for v in in_file - in_table if v not in roles)
            if missing:
                found["no_membership"] = missing
            orphaned = sorted(in_table - in_file)
            if orphaned:
                found["no_observable"] = orphaned
            wrong = [{"value": v, "store_role": roles[v]}
                     for v in sorted(in_file - in_table) if v in roles]
            if wrong:
                found["role_mismatch"] = wrong
            if found:
                out[slug] = found
    return out

