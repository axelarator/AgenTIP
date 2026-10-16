"""How closely a candidate is related to a cluster, as a number with reasons.

`expand.candidates_for` answers yes or no: one identity fact, or two
independent structural ones, promotes. That rule is right and is kept - it
is the invariant this module is tested against - but a yes/no cannot say
"weakly related, and here is why", and it never asks WHEN two indicators
shared a value. Both gaps cost real cleanup on 2026-10-16: kakatown.com was
filed onto JadeProx for sharing an address the vendor trio reached 5.7
years after kakatown left it.

## The score

Shared (type, value) pairs are grouped by artefact (`selectors.artefact`),
so one certificate or one address counts once however many columns it
fills. Each artefact weighs

    class_weight x rarity x temporal

* class_weight - identity 0.85, structural 0.56, behavioural 0.12,
  contextual 0. Structural is 0.56 rather than a round 0.5 so that two
  independent structural facts reach "strong" (1 - 0.44^2 = 0.806), which
  is the old promote rule. Contextual is zero: an ASN or a country can be
  shown beside a finding and can never add to one, which is also why an
  operator spread across a dozen ASNs loses nothing.
* rarity - 0 for a provider-scale or globally common value (`rarity.assess`).
  An unpriced value counts in full, exactly as it did before global counts
  existed. A priced one decays with log10 of its index-wide count.
* temporal - 1 when the two holders' spans overlap, otherwise
  exp(-gap_days / tau). tau is short for addresses, which are reassigned
  between tenants routinely, and long for content and key digests, whose
  reuse a year later is still the same operator's material.

Artefacts combine by noisy-OR, `1 - prod(1 - w)`: independent facts
reinforce, and no pile of weak ones reaches certainty. Behavioural facts
combine among themselves first and are capped at BEHAVIOURAL_CAP, inside
"weak": a stock TLS stack, a stock TCP stack and a common port set are three
facts about software, and no number of those may promote anything.

Some links are a candidate's selector VALUE being a member, not two
holders sharing a value: `www.update-trellix.com`'s `dns.apex` is the seed
`update-trellix.com` (an apex carries no `dns.apex` of its own), and
kakatown.com's `net.historical_ip` is the seed IP 192.252.186.62. The
reverse holds too: a candidate IP is linked to every member whose address
selectors name it. Those pairs are dated against when the member was
ACTIVE - the spans of its own selectors, and of members' selectors naming
it - so a seed IP from a 2026 report does not lend its weight to a name
that sat on it in 2019.

## Demotions

Two shapes of value look like identity and are not:

* a default certificate - a stock self-signed subject. Its digest is shared
  by every unconfigured install, so a certificate artefact on a holder that
  also carries `tls.default_subject` is capped at behavioural.
* a catch-all - one server presenting the same certificate (or page) for
  every hostname pointed at it. 37.1.220.158 served one self-signed cert
  for 248 unrelated names. When the holders of a certificate or page value
  collapse onto one address, the value is a statement about that address,
  and is scored as one behavioural fact. Address selectors themselves are
  exempt: every holder of an IP is on that IP by definition.

And one shape of holder: a CDN edge. Everything measured on a Cloudflare
address - its JARM, its TCP stack, its open ports - is Cloudflare's, so a
pair through a CDN edge on either side is shown and weighs nothing.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

import duckdb

from ..util import rows
from . import cdn, entities
from .rarity import assess
from .selectors import artefact, selector_class
from .spans import closest_gap

CLASS_WEIGHT = {"identity": 0.85, "structural": 0.56, "behavioural": 0.12,
                "contextual": 0.0}

BANDS = ((0.80, "strong"), (0.50, "probable"), (0.20, "weak"), (0.0, "noise"))

# Decay constants, in days, for the gap between two holders' spans.
TAU_ADDRESS = 30.0     # IPs, PTRs, co-hosting: reassigned between tenants
TAU_CONTENT = 180.0    # bodies, favicons, keys, cert digests: reused material
TAU_DEFAULT = 90.0
_ADDRESS_PREFIXES = ("net.resolved_ip", "net.historical_ip", "net.reverse_dns",
                     "net.cohosted_domain", "net.prefix", "net.asn")
_CONTENT_SUFFIXES = ("_sha256", "_mmh3", "fp_dom", "fp_dom_structure", "fp_ssl")

# A value held by at least this many indicators that all sit on one address
# is that address's catch-all, not a shared deployment.
CATCHALL_MIN_HOLDERS = 5
_ADDRESS_TYPES = ("net.resolved_ip", "net.historical_ip")
_CATCHALL_ARTEFACTS = ("certificate", "page")

# The most that behavioural facts, together, may contribute. Inside "weak".
BEHAVIOURAL_CAP = 0.35


def band(score: float) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "noise"


def tau(selector_type: str) -> float:
    if selector_type.startswith(_ADDRESS_PREFIXES):
        return TAU_ADDRESS
    if selector_type.endswith(_CONTENT_SUFFIXES) or selector_type == "tls.cert_sha256":
        return TAU_CONTENT
    return TAU_DEFAULT


def temporal_factor(selector_type: str, gap: float | None) -> float:
    """1.0 for overlap; decays with the gap. An unknown gap (no spans on one
    side - a pre-span row) is treated as overlap, the behaviour before spans
    existed, rather than as evidence of distance."""
    if gap is None or gap <= 0:
        return 1.0
    return math.exp(-gap / tau(selector_type))


def rarity_factor(verdict: dict[str, Any]) -> float:
    if verdict.get("provider_scale"):
        return 0.0
    count = verdict.get("global_count")
    if count is None or count <= 1:
        return 1.0
    return max(0.0, 1.0 - math.log10(count) / 4.5)


@dataclass
class Pair:
    selector_type: str
    selector_value: str
    member: str
    cls: str
    artefact: str
    gap_days: float | None
    global_count: int | None
    weight: float
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.selector_type, "value": self.selector_value[:120],
                "member": self.member, "class": self.cls, "artefact": self.artefact,
                "gap_days": None if self.gap_days is None else round(self.gap_days, 1),
                "global_count": self.global_count, "weight": round(self.weight, 4),
                "note": self.note}


@dataclass
class Relatedness:
    entity: str
    score: float
    band: str
    pairs: list[Pair] = field(default_factory=list)

    @property
    def artefacts(self) -> dict[str, float]:
        best: dict[str, float] = {}
        for p in self.pairs:
            best[p.artefact] = max(best.get(p.artefact, 0.0), p.weight)
        return best

    def to_dict(self) -> dict[str, Any]:
        return {"entity": self.entity, "score": round(self.score, 4), "band": self.band,
                "artefacts": {k: round(v, 4) for k, v in sorted(
                    self.artefacts.items(), key=lambda kv: -kv[1])},
                "evidence": [p.to_dict() for p in sorted(
                    self.pairs, key=lambda p: -p.weight)]}


# Types that state the same fact from different sources. A live lookup
# (net.resolved_ip) and a passive-DNS record (net.historical_ip) both say
# "this name pointed at this address", each with its own dates, so a name
# on an address in 2019 and another on it in 2026 meet here - and the span
# gap, not the type name, decides what that is worth.
_EQUIVALENT = {"net.resolved_ip": ("net.resolved_ip", "net.historical_ip"),
               "net.historical_ip": ("net.resolved_ip", "net.historical_ip")}


def _types(selector_type: str) -> tuple[str, ...]:
    return _EQUIVALENT.get(selector_type, (selector_type,))


def _in(types: tuple[str, ...]) -> str:
    return ", ".join("?" for _ in types)


def _spans(con, selector_type: str, value: str, indicator: str
           ) -> list[tuple[datetime, datetime]]:
    types = _types(selector_type)
    found = con.execute(
        f"SELECT start_at, end_at FROM selector_spans WHERE selector_type IN ({_in(types)}) "
        "AND selector_value = ? AND indicator_value = ?",
        [*types, value, indicator]).fetchall()
    if found:
        return [(a, b) for a, b in found]
    # A row recorded before spans existed: its first/last is the best window.
    legacy = con.execute(
        f"SELECT first_seen, last_seen FROM selectors WHERE selector_type IN ({_in(types)}) "
        "AND selector_value = ? AND indicator_value = ?",
        [*types, value, indicator]).fetchall()
    return [(a, b) for a, b in legacy if a is not None and b is not None]


# Selector types whose value is itself an entity that can be a member.
_ENTITY_VALUED = ("net.resolved_ip", "net.historical_ip", "dns.apex")


def _activity(con, indicator: str) -> list[tuple[datetime, datetime]]:
    """When an indicator was observed doing anything: the spans of its own
    selectors, and of address selectors naming it."""
    found = con.execute(
        "SELECT start_at, end_at FROM selector_spans WHERE indicator_value = ? "
        "UNION ALL SELECT start_at, end_at FROM selector_spans "
        "WHERE selector_value = ? AND selector_type IN ('net.resolved_ip', 'net.historical_ip')",
        [indicator, indicator]).fetchall()
    return [(a, b) for a, b in found]


def _holders(con, selector_type: str, value: str) -> list[str]:
    types = _types(selector_type)
    return [r[0] for r in con.execute(
        "SELECT DISTINCT indicator_value FROM selectors "
        f"WHERE selector_type IN ({_in(types)}) AND selector_value = ?",
        [*types, value]).fetchall()]


def _catchall_address(con, selector_type: str, value: str) -> str | None:
    """The single address every holder of this value sits on, if any."""
    holders = _holders(con, selector_type, value)
    if len(holders) < CATCHALL_MIN_HOLDERS:
        return None
    placeholders = ", ".join("?" for _ in holders)
    addresses = {r[0] for r in con.execute(
        f"SELECT DISTINCT selector_value FROM selectors "
        f"WHERE indicator_value IN ({placeholders}) "
        f"AND selector_type IN ('net.resolved_ip', 'net.historical_ip')",
        holders).fetchall()}
    # Holders that are themselves IPs count as that address.
    addresses |= {h for h in holders if entities.entity_type(h).startswith("ipv")}
    return next(iter(addresses)) if len(addresses) == 1 else None


def _is_cdn_edge(indicator: str) -> bool:
    return entities.entity_type(indicator).startswith("ipv") and cdn.is_cdn(indicator)


def _has_default_cert(con, indicator: str) -> bool:
    return con.execute(
        "SELECT 1 FROM selectors WHERE indicator_value = ? "
        "AND selector_type = 'tls.default_subject' LIMIT 1", [indicator]).fetchone() is not None


def score_against(con: duckdb.DuckDBPyConnection, entity: str,
                  members: Iterable[str]) -> Relatedness:
    """Relatedness of `entity` to a set of holders - a cluster's members, or
    a single other indicator for a pairwise question."""
    entity = entities.canonical(entity)
    member_set = {entities.canonical(m) for m in members} - {entity}
    mine = con.execute(
        "SELECT DISTINCT selector_type, selector_value FROM selectors "
        "WHERE indicator_value = ?", [entity]).fetchall()

    pairs: list[Pair] = []
    verdicts: dict[tuple[str, str], dict[str, Any]] = {}
    catchall: dict[tuple[str, str], str | None] = {}
    entity_default_cert = _has_default_cert(con, entity)
    entity_on_cdn = _is_cdn_edge(entity)
    for selector_type, value in mine:
        sharers = [h for h in _holders(con, selector_type, value) if h in member_set]
        if selector_type in _ENTITY_VALUED and value in member_set and value not in sharers:
            sharers.append(value)       # the value itself is a member
        if not sharers:
            continue
        key = (selector_type, value)
        verdict = verdicts.setdefault(key, assess(con, selector_type, value))
        cls = selector_class(selector_type)
        group = artefact(selector_type)
        note = None
        if (cls in ("identity", "structural") and group in _CATCHALL_ARTEFACTS
                and key not in catchall):
            catchall[key] = _catchall_address(con, selector_type, value)
        if catchall.get(key):
            cls, group = "behavioural", "address"
            note = f"catch-all on {catchall[key]}"
        elif group == "certificate" and cls in ("identity", "structural"):
            if entity_default_cert or any(_has_default_cert(con, s) for s in sharers):
                cls, note = "behavioural", "default certificate"
        rare = rarity_factor(verdict)
        if rare == 0.0:
            note = verdict.get("why_not") or "provider-scale value"
        mine_spans = _spans(con, selector_type, value, entity)
        for member in sharers:
            if selector_type == "dns.apex" and member == value:
                gap = None              # a registration fact; it has no span to compare
            elif member == value:
                gap = closest_gap(mine_spans, _activity(con, member))
            else:
                gap = closest_gap(mine_spans, _spans(con, selector_type, value, member))
            weight = CLASS_WEIGHT[cls] * rare * temporal_factor(selector_type, gap)
            note_here = note
            if entity_on_cdn or _is_cdn_edge(member):
                weight, note_here = 0.0, "through a CDN edge - the CDN's property"
            pairs.append(Pair(selector_type, value, member, cls, group, gap,
                              verdict.get("global_count"), weight, note_here))

    if entities.entity_type(entity).startswith("ipv") and not entity_on_cdn:
        mine_activity = _activity(con, entity)
        for selector_type, member in con.execute(
                "SELECT DISTINCT selector_type, indicator_value FROM selectors "
                "WHERE selector_value = ? AND selector_type IN "
                "('net.resolved_ip', 'net.historical_ip')", [entity]).fetchall():
            if member not in member_set:
                continue
            verdict = assess(con, selector_type, entity)
            gap = closest_gap(_spans(con, selector_type, entity, member), mine_activity)
            weight = (CLASS_WEIGHT[selector_class(selector_type)] * rarity_factor(verdict)
                      * temporal_factor(selector_type, gap))
            pairs.append(Pair(selector_type, entity, member, selector_class(selector_type),
                              artefact(selector_type), gap, verdict.get("global_count"),
                              weight, f"{member} resolved here"))

    result = Relatedness(entity, 0.0, "noise", pairs)
    result.score = combine(pairs)
    result.band = band(result.score)
    return result


def combine(pairs: Iterable[Pair]) -> float:
    """Noisy-OR over artefacts, with behavioural facts capped as a group.

    An artefact's class is the strongest class any of its pairs carries, so
    a certificate demoted on one pair and not another counts as the latter.
    """
    best: dict[str, tuple[float, str]] = {}
    for p in pairs:
        if p.artefact not in best or p.weight > best[p.artefact][0]:
            best[p.artefact] = (p.weight, p.cls)
    strong_rest, behavioural_rest = 1.0, 1.0
    for weight, cls in best.values():
        if cls == "behavioural":
            behavioural_rest *= (1.0 - weight)
        else:
            strong_rest *= (1.0 - weight)
    behavioural = min(1.0 - behavioural_rest, BEHAVIOURAL_CAP)
    return 1.0 - strong_rest * (1.0 - behavioural)


def score_candidate(con: duckdb.DuckDBPyConnection, cluster: str, entity: str, *,
                    record: bool = False) -> Relatedness:
    """Score one entity against a cluster's seeds and accepted members."""
    members = [m["entity"] for m in entities.members(con, cluster)]
    result = score_against(con, entity, members)
    if record:
        entities.record_score(con, cluster, entity, score=result.score,
                              band=result.band,
                              evidence=result.to_dict()["evidence"])
    return result


def rescore_cluster(con: duckdb.DuckDBPyConnection, cluster: str
                    ) -> list[Relatedness]:
    """Re-score every candidate on a cluster and record the results."""
    out = []
    for row in entities.members(con, cluster, roles=("candidate",)):
        out.append(score_candidate(con, cluster, row["entity"], record=True))
    out.sort(key=lambda r: -r.score)
    return out


def pairs_between(con: duckdb.DuckDBPyConnection, a: str, b: str) -> Relatedness:
    """What two indicators share, when, and what it is worth."""
    return score_against(con, a, [b])


def shared_with_anything(con: duckdb.DuckDBPyConnection, indicator: str,
                         limit: int = 200) -> list[dict[str, Any]]:
    """Every (type, value) this indicator holds that anything else also holds."""
    value = entities.canonical(indicator)
    return rows(con, """
        WITH mine AS (SELECT selector_type, selector_value FROM selectors
                      WHERE indicator_value = ?)
        SELECT s.selector_type, s.selector_value,
               count(DISTINCT s.indicator_value) AS others,
               string_agg(DISTINCT s.indicator_value, ', ') AS holders
        FROM selectors s JOIN mine m USING (selector_type, selector_value)
        WHERE s.indicator_value <> ?
        GROUP BY 1, 2 ORDER BY 3 DESC LIMIT ?""", [value, value, limit])


__all__ = ["CLASS_WEIGHT", "BANDS", "BEHAVIOURAL_CAP", "combine", "Relatedness", "Pair", "band", "score_against",
           "score_candidate", "rescore_cluster", "pairs_between",
           "shared_with_anything"]
