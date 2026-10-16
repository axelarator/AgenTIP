"""Cluster membership, as the rest of the package sees it.

The store (`cti/store/entities.py`) holds the roles and enforces who may set
them; this module is the door `core`, the expansion pass, netwatch and the
MCP server go through, so none of them opens a connection or hand-rolls a
role change.

The rule it carries: the cluster JSON lists a cluster's MEMBERS - seeds and
accepted candidates - with their enrichment. Everything a pivot, scan or
rule surfaces is a candidate here, scored against those members, and only
reaches the JSON when an analyst accepts it.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from . import store
from .store import entities as E
from .store import relatedness as R
from .store import spans as SP

# Observable categories that hold indicators (members), as opposed to
# fingerprints measured on an indicator, which are selectors.
MEMBER_CATEGORIES = ("domains", "ips", "urls", "hashes", "emails", "cves", "wallets")

BAND_ORDER = ("noise", "weak", "probable", "strong")

# A server-side fingerprint observable is a selector on the host it was
# measured against. Client fingerprints (ja4, ja4h, ja4t, ja4ssh) describe
# the malware, come from reports, and stay observables; ja4l is a latency.
SERVER_FINGERPRINTS = {"jarm": "tls.jarm", "ja4s": "tls.ja4s", "ja4ts": "tls.ja4ts",
                       "ja4x": "tls.ja4x"}
_JARM_SOURCE = re.compile(r"^JARM against (?P<host>\S+?):(?P<port>\d+) via (?P<via>.+?), "
                          r"(?P<when>\d{4}-\d{2}-\d{2}\S*)$")
_ZEEK_SOURCE = re.compile(r"handshake against (?P<host>\S+?):(?P<port>\d+) "
                          r"\((?P<ip>[^)]*)\), (?P<when>\d{4}-\d{2}-\d{2}\S*)$")


def band_at_least(band: str | None, floor: str) -> bool:
    if band not in BAND_ORDER:
        return False
    return BAND_ORDER.index(band) >= BAND_ORDER.index(floor)


def fingerprint_selector(category: str, value: str, source: str) -> dict[str, Any] | None:
    """The selector a server-fingerprint observable really is, or None when
    the source does not say which host it was measured on."""
    selector_type = SERVER_FINGERPRINTS.get(category)
    if not selector_type:
        return None
    m = _JARM_SOURCE.match(source or "") or _ZEEK_SOURCE.search(source or "")
    if not m:
        return None
    via = m.groupdict().get("via") or ""
    vantage = ("win116" if "win11" in via.lower()
               else "zeek" if "zeek" in (source or "").lower() else "probe")
    return {"indicator": m["host"].lower().rstrip("."), "selector_type": selector_type,
            "value": value, "when": m["when"], "source": f"fingerprint:{category}",
            "vantage": vantage}


def record_fingerprints(rows: Iterable[dict[str, Any]], actor: str | None = None) -> int:
    from .store import selectors as S

    rows = list(rows)
    if not rows:
        return 0
    with store.connect_retry(read_only=False) as con:
        for row in rows:
            S.record(con, indicator_value=row["indicator"], selector_type=row["selector_type"],
                     selector_value=row["value"], observed_at=row.get("when") or row.get("last"),
                     first_seen=row.get("first"), last_seen=row.get("last"),
                     indicator_type=E.entity_type(row["indicator"]), actor=actor,
                     source=row["source"], vantage=row.get("vantage"))
    return len(rows)


def member_value(category: str, value: str) -> bool:
    """Whether a JSON observable is an indicator that can be a member."""
    if category not in MEMBER_CATEGORIES:
        return False
    return not (category == "hashes" and value.lower().startswith("cert-sha256:"))


def mirror_seeds(cluster: str, values: Iterable[tuple[str, str]], *, origin: str,
                 decided_by: str) -> int:
    """Record report- or analyst-filed indicators as seeds.

    A seed overrides a candidate, and a new report naming a rejected value
    re-seeds it: the report is the authority a rejection was made against,
    and a fresh one is new evidence. The reason says so, so it is visible.
    """
    values = [(c, v) for c, v in values if member_value(c, v)]
    if not values:
        return 0
    with store.connect_retry(read_only=False) as con:
        for _category, value in values:
            current = E.membership(con, cluster, value)
            if current and current["role"] in ("seed", "accepted"):
                continue
            reason = ("re-reported after rejection" if current and current["role"] == "rejected"
                      else None)
            E.set_role(con, cluster, value, "seed", decided_by=decided_by,
                       origin=origin, reason=reason)
    return len(values)


def _score_against(con, cluster: str, value: str, extra_members: Iterable[str]):
    members = {m["entity"] for m in E.members(con, cluster)} | {
        E.canonical(m) for m in extra_members}
    return R.score_against(con, value, members)


def file_candidate(cluster: str, value: str, *, origin: str, decided_by: str,
                   reason: str | None = None,
                   links: Iterable[dict[str, Any]] = (),
                   members: Iterable[str] = ()) -> dict[str, Any] | None:
    """File a candidate and score it. Returns the score, or None when the
    cluster already has a verdict on the value (member or rejected).

    `links` are the selectors that surfaced it - {selector_type, value,
    first, last, source} recorded on the candidate - so the score can see
    the link that found it, dated, before any sweep has run. `members`
    adds the cluster JSON's own members to the store's seeds and accepted
    ones, for a cluster not yet migrated into the store.
    """
    from .store import selectors as S

    with store.connect_retry(read_only=False) as con:
        for link in links:
            S.record(con, indicator_value=E.canonical(value),
                     selector_type=link["selector_type"], selector_value=link["value"],
                     observed_at=link.get("last") or link.get("first") or _now(),
                     first_seen=link.get("first"), last_seen=link.get("last"),
                     indicator_type=E.entity_type(value), source=link.get("source") or origin)
        filed = E.file_candidate(con, cluster, value, origin=origin, decided_by=decided_by,
                                 reason=reason)
        if filed is None:
            return None
        result = _score_against(con, cluster, value, members)
        E.record_score(con, cluster, value, score=result.score, band=result.band,
                       evidence=result.to_dict()["evidence"])
        return result.to_dict()


def role(cluster: str, value: str) -> str | None:
    with store.connect_retry(read_only=False) as con:
        found = E.membership(con, cluster, value)
    return found["role"] if found else None


def decide(cluster: str, value: str, new_role: str, *, reason: str | None = None,
           decided_by: str = E.ANALYST) -> dict[str, Any]:
    """Accept or reject a candidate. Raises ValueError if it is not one."""
    with store.connect_retry(read_only=False) as con:
        current = E.membership(con, cluster, value)
        if not current or current["role"] != "candidate":
            raise ValueError(f"{value!r} is not a candidate on cluster {cluster!r}")
        return E.set_role(con, cluster, value, new_role, decided_by=decided_by,
                          reason=reason)


def forget(cluster: str, value: str) -> bool:
    """Drop a membership outright - for remove_observable's false positive.
    The entity and its evidence stay; only the cluster's claim goes."""
    with store.connect_retry(read_only=False) as con:
        found = E.membership(con, cluster, value)
        if not found:
            return False
        con.execute("DELETE FROM memberships WHERE cluster = ? AND entity = ?",
                    [cluster, E.canonical(value)])
    return True


def values_with_role(cluster: str, roles: tuple[str, ...]) -> set[str]:
    with store.connect_retry(read_only=False) as con:
        return {m["entity"] for m in E.members(con, cluster, roles=roles)}


def candidates(cluster: str, *, min_band: str = "noise") -> list[dict[str, Any]]:
    with store.connect_retry(read_only=False) as con:
        found = E.members(con, cluster, roles=("candidate",))
    found = [c for c in found if band_at_least(c.get("band") or "noise", min_band)]
    found.sort(key=lambda c: -(c.get("score") or 0.0))
    return found


def score(cluster: str, value: str, *, record: bool = False,
          members: Iterable[str] = ()) -> dict[str, Any]:
    with store.connect_retry(read_only=False) as con:
        result = _score_against(con, cluster, value, members)
        if record:
            E.record_score(con, cluster, value, score=result.score, band=result.band,
                           evidence=result.to_dict()["evidence"])
        return result.to_dict()


def rescore(cluster: str) -> list[dict[str, Any]]:
    with store.connect_retry(read_only=False) as con:
        return [r.to_dict() for r in R.rescore_cluster(con, cluster)]


def expire(cluster: str, quiet_days: int, now: Any = None) -> list[str]:
    """Reject candidates with no evidence for `quiet_days`.

    Evidence is the latest end of any span on the entity; a candidate with
    no spans at all is measured from when it was filed. Rejected by the
    'expiry' decider, which may only ever close a candidate.
    """
    now_dt = SP.to_ts(now) or _now()
    expired = []
    with store.connect_retry(read_only=False) as con:
        for row in E.members(con, cluster, roles=("candidate",)):
            last = con.execute("SELECT max(end_at) FROM selector_spans WHERE indicator_value = ?",
                               [row["entity"]]).fetchone()[0]
            since = last or row["created_at"]
            quiet = (now_dt - since).days
            if quiet >= quiet_days:
                E.set_role(con, cluster, row["entity"], "rejected", decided_by=E.EXPIRY,
                           reason=(f"no evidence in {quiet} days as a candidate"
                                   + ("" if last else " (never observed)")))
                expired.append(row["entity"])
    return expired


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


__all__ = ["MEMBER_CATEGORIES", "BAND_ORDER", "SERVER_FINGERPRINTS", "band_at_least",
           "fingerprint_selector", "record_fingerprints", "member_value", "mirror_seeds",
           "file_candidate", "role", "decide", "forget", "values_with_role", "candidates",
           "score", "rescore", "expire"]
