"""Hunt rules: a cluster's signature, written once and matched everywhere.

A rule is a small YAML statement of "what this operator's infrastructure
looks like" - a combination of selector values and open ports distinctive
enough that a host carrying it is probably theirs. It is the Censys-style
saved query, owned by us instead of a vendor.

A rule runs against two things:

* **our own snapshots** (`scope: [snapshots]`). `evaluate` compiles the rule
  to SQL over the `selectors` table, intersected with `service_snapshots`
  for the port constraint, and returns the hosts that match. A host that
  matches a cluster's rule but is not yet tracked by that cluster is a
  candidate - it goes through the SAME corroboration the Webamon expansion
  uses (one identity fact, or two independent structural ones), so a rule
  cannot file anything the evidence would not already support.
* **streaming CT entries** (`scope: [ct]`). A certificate has no JARM and no
  ports, so `match_ct` evaluates only the cert-expressible terms (SAN,
  subject CN, issuer, apex) as a pre-filter. A match queues the names for a
  scan, and the snapshot rule confirms the rest once the scan lands.

Nothing here enables a rule. `suggest` drafts one from what a cluster's
hosts share, a human reads it, and only a file on disk with `enabled: true`
is ever matched. The whole point is that a signature is deliberate.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import duckdb
import yaml

from ..store import rarity
from ..store.selectors import (TYPES, canonical_dn, normalize, selector_class)
from ..util import data_dir

log = logging.getLogger(__name__)

VALID_SCOPES = {"snapshots", "ct"}
VALID_ACTIONS = {"candidate", "alert"}

# Terms a certificate alone can confirm. Everything else in a rule (JARM,
# header order, ja4s, ports) needs a scan, so CT matching treats these as a
# pre-filter and leaves the rest to the snapshot pass.
CT_TERMS = {"tls.san", "dns.apex", "tls.subject_cn", "tls.issuer"}

# Behavioural selectors are worth building a signature from even though they
# cannot promote a candidate alone: a rule combines several, and the
# combination is what discriminates. Contextual types never belong in a rule.
_SUGGESTABLE_CLASSES = {"identity", "structural", "behavioural"}


@dataclass
class Rule:
    """One signature. `where` is {all:[term...], any:[term...], ports:[int]}
    where each term is a single-key {selector_type: value} mapping."""
    id: str
    where: dict[str, Any]
    scope: list[str] = field(default_factory=lambda: ["snapshots"])
    action: str = "candidate"
    cluster: str | None = None
    enabled: bool = False
    note: str | None = None
    source: str | None = None  # the file it was loaded from

    def terms(self, block: str) -> list[tuple[str, Any]]:
        """The (selector_type, value) pairs in where.all or where.any."""
        out = []
        for term in self.where.get(block) or []:
            if isinstance(term, dict) and len(term) == 1:
                (stype, value), = term.items()
                out.append((stype, value))
        return out

    @property
    def ports(self) -> list[int]:
        return [int(p) for p in (self.where.get("ports") or [])]


def _coerce(raw: dict[str, Any], source: str | None) -> Rule | None:
    """One mapping from a YAML file into a validated Rule, or None."""
    rid = str(raw.get("id") or "").strip()
    if not rid:
        log.warning("hunt rule in %s has no id; skipped", source)
        return None
    where = raw.get("where") or {}
    if not isinstance(where, dict) or not (
            where.get("all") or where.get("any") or where.get("ports")):
        log.warning("hunt rule %s has an empty `where`; skipped", rid)
        return None
    scope = [s for s in (raw.get("scope") or ["snapshots"]) if s in VALID_SCOPES]
    if not scope:
        log.warning("hunt rule %s has no valid scope; skipped", rid)
        return None
    action = raw.get("action") or "candidate"
    if action not in VALID_ACTIONS:
        log.warning("hunt rule %s has action %r; skipped", rid, action)
        return None
    rule = Rule(id=rid, where=where, scope=scope, action=action,
                cluster=raw.get("cluster"), enabled=bool(raw.get("enabled")),
                note=raw.get("note"), source=source)
    # An unknown selector type can never match anything in our table, so a
    # rule that rests on one is a typo, not a signature. Flag it loudly.
    for block in ("all", "any"):
        for stype, _ in rule.terms(block):
            if stype not in TYPES:
                log.warning("hunt rule %s references unknown selector %r", rid, stype)
    return rule


def rules_dir() -> Path:
    d = data_dir() / "hunt_rules"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load(*, directory: Path | None = None, enabled_only: bool = True
         ) -> list[Rule]:
    """Every rule under data/hunt_rules/. A file may hold one rule or a list.

    `enabled_only` is the default because a disabled rule is a draft awaiting
    a human; only `suggest`/inspection ever wants the full set.
    """
    directory = directory or rules_dir()
    out: list[Rule] = []
    for path in sorted(directory.glob("*.y*ml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except (yaml.YAMLError, OSError) as e:
            log.warning("could not read hunt rule %s: %s", path, e)
            continue
        items = doc if isinstance(doc, list) else [doc]
        for raw in items:
            if not isinstance(raw, dict):
                continue
            rule = _coerce(raw, path.name)
            if rule and (rule.enabled or not enabled_only):
                out.append(rule)
    return out


# --------------------------------------------------------------------------- #
# Snapshot matching: compile the rule to SQL over selectors + snapshots
# --------------------------------------------------------------------------- #

def _selector_subquery(stype: str, value: Any, params: list[Any]) -> str:
    params.extend([stype, normalize(stype, value)])
    return ("SELECT indicator_value FROM selectors "
            "WHERE selector_type = ? AND selector_value = ?")


def compile_sql(rule: Rule) -> tuple[str, list[Any]]:
    """The rule as one SELECT yielding the hosts that satisfy it.

    `all` terms intersect, `any` terms union, and the whole thing intersects
    the open-port set from service_snapshots. Matching by position, every
    piece yields a single `indicator_value` column.
    """
    params: list[Any] = []
    pieces: list[str] = []

    all_terms = rule.terms("all")
    if all_terms:
        pieces.append(" INTERSECT ".join(
            f"({_selector_subquery(t, v, params)})" for t, v in all_terms))

    any_terms = rule.terms("any")
    if any_terms:
        pieces.append("(" + " UNION ".join(
            f"({_selector_subquery(t, v, params)})" for t, v in any_terms) + ")")

    if rule.ports:
        placeholders = ", ".join("?" for _ in rule.ports)
        pieces.append(
            f"(SELECT target AS indicator_value FROM service_snapshots "
            f"WHERE open AND port IN ({placeholders}))")
        params.extend(rule.ports)

    if not pieces:
        return "SELECT NULL AS indicator_value WHERE FALSE", []
    body = " INTERSECT ".join(f"({p})" for p in pieces)
    return f"SELECT DISTINCT indicator_value FROM ({body})", params


def evaluate(con: duckdb.DuckDBPyConnection, rules: Iterable[Rule]
             ) -> list[dict[str, Any]]:
    """Run each snapshot-scoped rule and return its hits.

    One row per (rule, host): {rule, cluster, action, indicator, terms}. The
    caller decides what a hit is worth - a `candidate` hit is verified
    against the cluster before anything is filed.
    """
    out: list[dict[str, Any]] = []
    for rule in rules:
        if "snapshots" not in rule.scope:
            continue
        sql, params = compile_sql(rule)
        try:
            hits = [r[0] for r in con.execute(sql, params).fetchall()]
        except duckdb.Error as e:
            log.warning("hunt rule %s failed to evaluate: %s", rule.id, e)
            continue
        for indicator in hits:
            if indicator is None:
                continue
            out.append({"rule": rule.id, "cluster": rule.cluster,
                        "action": rule.action, "indicator": indicator,
                        "terms": rule.terms("all") + rule.terms("any")})
    return out


# --------------------------------------------------------------------------- #
# CT matching: a cert pre-filter, evaluated in memory on the stream
# --------------------------------------------------------------------------- #

def _apex_match(pattern: str, name: str) -> bool:
    name = name.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    return name == pattern or name.endswith("." + pattern)


def _term_matches_cert(stype: str, value: Any, entry: dict[str, Any]) -> bool:
    """Whether one CT-expressible term matches a certificate.

    SAN, subject CN and issuer values are treated as regexes (an exact string
    is a valid regex that matches itself), so a rule can say `.*\\.evil\\.com`
    for a SAN or an issuer DN fragment. An apex is a suffix match.
    """
    sans = [str(s).lower().lstrip("*.").rstrip(".")
            for s in (entry.get("sans") or []) if s]
    if stype == "dns.apex":
        return any(_apex_match(str(value), s) for s in sans)
    try:
        rx = re.compile(str(value), re.IGNORECASE)
    except re.error:
        return False
    if stype == "tls.san":
        return any(rx.search(s) for s in sans)
    if stype == "tls.subject_cn":
        return bool(rx.search(canonical_dn(str(entry.get("subject") or ""))))
    if stype == "tls.issuer":
        return bool(rx.search(canonical_dn(str(entry.get("issuer") or ""))))
    return False


def _ct_block(rule: Rule, block: str) -> list[tuple[str, Any]]:
    return [(t, v) for t, v in rule.terms(block) if t in CT_TERMS]


def match_ct(entry: dict[str, Any], rules: Iterable[Rule]
             ) -> list[dict[str, Any]]:
    """Which CT-scoped rules this certificate pre-matches, and the names to
    queue. `entry` is {sans:[...], subject: "...", issuer: "..."}.

    Only the cert-expressible terms are checked; a rule with no such term is
    skipped, because a certificate cannot confirm a JARM or a port. The scan
    the hit triggers is what confirms the rest.
    """
    out: list[dict[str, Any]] = []
    sans = [str(s).lower().lstrip("*.").rstrip(".")
            for s in (entry.get("sans") or []) if s]
    for rule in rules:
        if "ct" not in rule.scope:
            continue
        ct_all = _ct_block(rule, "all")
        ct_any = _ct_block(rule, "any")
        if not ct_all and not ct_any:
            continue
        if ct_all and not all(_term_matches_cert(t, v, entry) for t, v in ct_all):
            continue
        if ct_any and not any(_term_matches_cert(t, v, entry) for t, v in ct_any):
            continue
        out.append({"rule": rule.id, "cluster": rule.cluster,
                    "action": rule.action, "names": sorted(set(sans))})
    return out


# --------------------------------------------------------------------------- #
# Suggestion: draft a rule from what a cluster's hosts already share
# --------------------------------------------------------------------------- #

def _open_ports(con: duckdb.DuckDBPyConnection, indicators: list[str]
                ) -> list[int]:
    if not indicators:
        return []
    placeholders = ", ".join("?" for _ in indicators)
    rows = con.execute(
        f"SELECT DISTINCT port FROM service_snapshots "
        f"WHERE open AND port > 0 AND target IN ({placeholders}) ORDER BY port",
        indicators).fetchall()
    return [r[0] for r in rows]


def suggest(con: duckdb.DuckDBPyConnection, indicators: list[str], *,
            cluster: str | None = None, min_hosts: int = 2
            ) -> dict[str, Any]:
    """Draft a rule from the selectors that several of a cluster's hosts share.

    A value is a candidate term when it is held by at least `min_hosts` of
    the cluster's own indicators, its type is not contextual, and the value
    is not provider-scale (the same rarity gate the expansion uses). The
    draft is returned disabled; a human edits and enables it.
    """
    live = [i for i in indicators if i]
    if len(live) < min_hosts:
        return {"cluster": cluster, "draft": None,
                "why": f"need >= {min_hosts} hosts, have {len(live)}"}

    placeholders = ", ".join("?" for _ in live)
    rows = con.execute(
        f"SELECT selector_type, selector_value, "
        f"       count(DISTINCT indicator_value) AS hosts "
        f"FROM selectors WHERE indicator_value IN ({placeholders}) "
        f"GROUP BY 1, 2 HAVING count(DISTINCT indicator_value) >= ? "
        f"ORDER BY hosts DESC", [*live, min_hosts]).fetchall()

    terms, evidence = [], []
    for stype, value, hosts in rows:
        cls = selector_class(stype)
        if cls not in _SUGGESTABLE_CLASSES:
            continue
        verdict = rarity.assess(con, stype, value)
        # Promotable types must clear the rarity gate; behavioural ones only
        # need to not be globally common, since they never promote alone.
        if cls in ("identity", "structural") and not verdict["can_promote"]:
            continue
        if verdict["provider_scale"]:
            continue
        terms.append({stype: value})
        evidence.append({"selector_type": stype, "selector_value": value,
                         "class": cls, "hosts": hosts,
                         "global_count": verdict["global_count"]})

    if not terms:
        return {"cluster": cluster, "draft": None,
                "why": "no shared, non-contextual, non-provider selectors"}

    scope = ["snapshots"]
    if any(next(iter(t)) in CT_TERMS for t in terms):
        scope.append("ct")
    draft = {
        "id": f"{(cluster or 'cluster')}-draft",
        "cluster": cluster,
        "enabled": False,
        "note": (f"drafted from {len(live)} host(s) sharing {len(terms)} "
                 f"selector(s); review before enabling"),
        "where": {"all": terms, "ports": _open_ports(con, live)},
        "scope": scope,
        "action": "candidate",
    }
    return {"cluster": cluster, "draft": draft, "evidence": evidence,
            "hosts": live}
