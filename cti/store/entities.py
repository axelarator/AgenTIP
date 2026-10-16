"""Entities, cluster memberships and relatedness scores.

The cluster JSON used to be both the evidence and the verdict: anything a
pivot surfaced was written into `observables` as an active indicator, so a
co-resolution from five years ago became a tracked JadeProx domain and
undoing it meant editing records by hand.

Here the two are separate:

* `entities` - every domain, IP, URL, hash or certificate the store knows,
  whether or not anyone thinks it belongs to a cluster.
* `memberships` - what a cluster says about an entity. The ROLE is the
  verdict, and who may set it is fixed in code:

    seed       from a report, or added by the analyst. The ground truth.
    accepted   a candidate the analyst promoted.
    candidate  surfaced by a pivot, scan or rule. Never exported.
    rejected   decided not to belong; never re-filed. Replaces the JSON
               denylist.

  Automatic paths can only ever create a `candidate`, and never overwrite a
  role a person set. That is the whole guard against pivots writing
  membership.
* `relatedness_scores` - append-only. A candidate's score is recomputed as
  evidence arrives, and the history of that number is itself a signal.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

import duckdb

from ..util import rows

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    value       TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    first_seen  TIMESTAMP,
    last_seen   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS memberships (
    cluster     TEXT NOT NULL,
    entity      TEXT NOT NULL,
    role        TEXT NOT NULL,
    origin      TEXT,
    score       DOUBLE,
    band        TEXT,
    reason      TEXT,
    decided_by  TEXT,
    decided_at  TIMESTAMP,
    created_at  TIMESTAMP NOT NULL,
    UNIQUE (cluster, entity)
);
CREATE INDEX IF NOT EXISTS member_entity ON memberships (entity);

CREATE TABLE IF NOT EXISTS relatedness_scores (
    cluster     TEXT NOT NULL,
    entity      TEXT NOT NULL,
    scored_at   TIMESTAMP NOT NULL,
    score       DOUBLE NOT NULL,
    band        TEXT NOT NULL,
    evidence    JSON
);
CREATE INDEX IF NOT EXISTS score_lookup ON relatedness_scores (cluster, entity, scored_at);
"""

ROLES = ("seed", "accepted", "candidate", "rejected")
# What a cluster exports and scores against.
MEMBER_ROLES = ("seed", "accepted")
# Roles only a person may set. An automatic writer (decided_by != analyst)
# asking for one of these is a bug, and raising is how it gets noticed.
HUMAN_ROLES = frozenset({"seed", "accepted", "rejected"})
ANALYST = "analyst"
REPORT = "report"
# Closes a candidate nobody decided on in time. The one automatic decider
# that may set a human role, and only `rejected`, and only on a candidate.
EXPIRY = "expiry"
# Who may set a human role. Report ingest seeds on the report's authority.
_HUMAN_DECIDERS = frozenset({ANALYST, REPORT, "migration"})

_HASH_RE = re.compile(r"^(?:[a-z0-9-]+:)?[0-9a-f]{32,128}$")
_CVE_RE = re.compile(r"^cve-\d{4}-\d{4,}$")


class RoleError(ValueError):
    """An automatic path tried to set or override a role it may not."""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def entity_type(value: str) -> str:
    """ipv4 | ipv6 | url | hash | cert | cve | email | domain. Local and
    syntactic only - the store never imports the source layer."""
    text = value.strip()
    if text.lower().startswith("cert-sha256:"):
        return "cert"
    if _CVE_RE.match(text.lower()):
        return "cve"
    try:
        return f"ipv{ipaddress.ip_address(text).version}"
    except ValueError:
        pass
    if "://" in text:
        return "url"
    if "@" in text and " " not in text:
        return "email"
    if _HASH_RE.match(text.lower()):
        return "hash"
    return "domain"


def canonical(value: str) -> str:
    """Hostnames are case-insensitive and may carry a trailing dot; hashes
    are lowercased. URLs are left alone - their paths are case-sensitive."""
    text = value.strip()
    kind = entity_type(text)
    if kind in ("domain", "hash", "cert", "email"):
        return text.lower().rstrip(".")
    if kind == "cve":
        return text.upper()
    return text


def upsert_entity(con: duckdb.DuckDBPyConnection, value: str, *,
                  seen_at: Any = None, kind: str | None = None) -> str:
    from .spans import to_ts

    value = canonical(value)
    when = to_ts(seen_at) or _now()
    con.execute(
        """INSERT INTO entities (value, type, first_seen, last_seen) VALUES (?, ?, ?, ?)
           ON CONFLICT (value) DO UPDATE SET
               first_seen = least(entities.first_seen, excluded.first_seen),
               last_seen = greatest(entities.last_seen, excluded.last_seen)""",
        [value, kind or entity_type(value), when, when])
    return value


def membership(con: duckdb.DuckDBPyConnection, cluster: str,
               entity: str) -> dict[str, Any] | None:
    found = rows(con, "SELECT * FROM memberships WHERE cluster = ? AND entity = ?",
                 [cluster, canonical(entity)])
    return found[0] if found else None


def set_role(con: duckdb.DuckDBPyConnection, cluster: str, entity: str, role: str, *,
             decided_by: str, origin: str | None = None, reason: str | None = None,
             seen_at: Any = None) -> dict[str, Any]:
    """Create or move a membership, under the rules in the module docstring.

    An automatic writer may create a `candidate`, or refresh one, and
    nothing else: a request that would touch a seed, an accepted member or
    a rejection is refused with RoleError rather than silently ignored, so
    a pivot that tries is visible in the run trace.
    """
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    automatic = decided_by not in _HUMAN_DECIDERS
    expiring = decided_by == EXPIRY and role == "rejected"
    if automatic and role in HUMAN_ROLES and not expiring:
        raise RoleError(f"{decided_by} may not set role {role!r}; only an analyst can")
    entity = upsert_entity(con, entity, seen_at=seen_at)
    current = membership(con, cluster, entity)
    if expiring and (not current or current["role"] != "candidate"):
        raise RoleError("expiry may only close a candidate")
    if current and automatic and current["role"] != "candidate":
        raise RoleError(
            f"{entity} is already {current['role']} on {cluster}; "
            f"{decided_by} cannot change that")
    if role == "rejected" and not (reason or "").strip():
        raise ValueError("a rejection needs a reason - it is what stops the next "
                         "analyst re-adding it")
    now = _now()
    con.execute(
        """INSERT INTO memberships (cluster, entity, role, origin, reason,
               decided_by, decided_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (cluster, entity) DO UPDATE SET
               role = excluded.role,
               origin = coalesce(memberships.origin, excluded.origin),
               reason = coalesce(excluded.reason, memberships.reason),
               decided_by = excluded.decided_by,
               decided_at = excluded.decided_at""",
        [cluster, entity, role, origin, reason, decided_by, now, now])
    return membership(con, cluster, entity)


def file_candidate(con: duckdb.DuckDBPyConnection, cluster: str, entity: str, *,
                   origin: str, decided_by: str, reason: str | None = None,
                   seen_at: Any = None) -> dict[str, Any] | None:
    """The one door automatic paths use. Returns None, writing nothing, when
    the cluster already has a verdict on this entity - including a
    rejection, which is what makes the deny list hold."""
    current = membership(con, cluster, entity)
    if current and current["role"] != "candidate":
        return None
    return set_role(con, cluster, entity, "candidate", decided_by=decided_by,
                    origin=origin, reason=reason, seen_at=seen_at)


def members(con: duckdb.DuckDBPyConnection, cluster: str,
            roles: tuple[str, ...] = MEMBER_ROLES) -> list[dict[str, Any]]:
    placeholders = ", ".join("?" for _ in roles)
    return rows(con,
                f"SELECT m.*, e.type FROM memberships m JOIN entities e ON e.value = m.entity "
                f"WHERE m.cluster = ? AND m.role IN ({placeholders}) "
                f"ORDER BY m.role, m.entity", [cluster, *roles])


def record_score(con: duckdb.DuckDBPyConnection, cluster: str, entity: str, *,
                 score: float, band: str, evidence: list[dict[str, Any]],
                 scored_at: Any = None) -> None:
    """Append a score and mirror the latest onto the membership row."""
    from .spans import to_ts

    entity = canonical(entity)
    when = to_ts(scored_at) or _now()
    con.execute("INSERT INTO relatedness_scores VALUES (?, ?, ?, ?, ?, ?)",
                [cluster, entity, when, score, band, json.dumps(evidence, default=str)])
    con.execute("UPDATE memberships SET score = ?, band = ? WHERE cluster = ? AND entity = ?",
                [score, band, cluster, entity])


def score_history(con: duckdb.DuckDBPyConnection, cluster: str,
                  entity: str) -> list[dict[str, Any]]:
    return rows(con, "SELECT scored_at, score, band, evidence FROM relatedness_scores "
                     "WHERE cluster = ? AND entity = ? ORDER BY scored_at",
                [cluster, canonical(entity)])
