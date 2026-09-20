"""Deterministic triage, run before any model sees the digest.

## Why this exists

The old design handed the whole digest to one model and told it to "pick
at most 3 noteworthy items". On a real day that digest is dominated by
`ip_hostnames` rows on shared-hosting IPs: in the 2026-09-18 digest,
four of the sixteen attribute changes are Cloudflare and AWS addresses
(104.21.60.187, 172.67.200.55, 15.197.148.33, 3.33.130.190), each
listing hundreds of unrelated tenant domains, each row kilobytes wide.
Those rows are not signal - `analytics.SHARED_HOSTING_ASNS` already
knows those ASNs, and the skill already says a hosted-domain list on
shared hosting is never a lead - but the model paid for them in context
and weighed them against its 3-item budget anyway.

So the suppression runs here, in code, for free, before the fan-out.
What reaches a specialist is already worth its tokens.

Nothing here decides whether something is *interesting* - that is the
specialists' job, and it needs judgement. This only drops what is
provably noise and orders the rest.
"""
from __future__ import annotations

import json
from typing import Any

from cti.sources.pivot import is_shared_hosting_hostname
from cti.tracking.analytics import SHARED_HOSTING_ASNS
from cti.util import asn_int

from ..state import ATTRIBUTE_FAMILY, FAMILY_ATTRIBUTES, CTIState, Item

# How many items each specialist may weigh.
#
# A flat 2 per family was the first thing tried and it was wrong. The
# families are not the same size: `hosting` owns four attribute types and
# `opendir` owns one. On 2026-09-18 that flat budget spent both of
# hosting's slots on the two highest-scoring fingerprint rows and never
# showed it 208.91.112.55 gaining four hostnames on a dedicated ASN -
# which the previous single-pass design did surface, and which was a real
# lead. Budget therefore scales with how much ground a family covers.
#
# opendir gets more than its one attribute would suggest because its items
# are individual files, not indicators: ten files in one directory is one
# event described ten ways, and the interesting one is rarely the first.
ITEMS_PER_FAMILY = {
    "infra_change": 4,
    "cert_tls": 3,
    "hosting": 4,
    "opendir": 8,
    # Links are already filtered by the corroboration rule, so the ones
    # that reach here have passed a bar no other family's items have to
    # clear. Six because a real campaign surfaces as a handful of linked
    # pairs at once - the source reporting's certificate was on 8 hosts -
    # and showing two of them would describe a cluster as a coincidence.
    "infrastructure": 6,
}
DEFAULT_ITEM_BUDGET = 3

CONFIDENCE_WEIGHT = {"high": 3.0, "medium": 2.0, "low": 1.0}

# Base score per change type. These are priors about how hard a change is
# to explain innocently, not about how alarming it sounds. An issuer
# change means someone rebuilt TLS; a new subdomain means someone
# registered a name, which happens constantly.
CHANGE_WEIGHT = {
    # A corroborated link outranks every change type: a change says one
    # host moved, a link says two hosts are the same operation.
    "selector_link": 4.0,
    "cert_issuer_changed": 3.0,
    "cert_new": 2.5,
    "webamon_fingerprint_changed": 3.0,
    "ports_changed": 2.5,
    "asn_change": 2.5,
    "infostealer_hits": 2.0,
    "resolved_ip_changed": 1.5,
    "ptr_changed": 1.5,
    "http_server_changed": 1.5,
    "cert_sans_changed": 1.5,
    "http_title_changed": 0.5,
    "ip_hostnames_changed": 0.5,
    "subdomains_changed": 0.5,
    "opendir_files": 3.0,
}


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return value
    return value


def _looks_like_shared_hosting(item: Item, asn_by_indicator: dict[str, int]) -> bool:
    """Shared-hosting suppression, both halves.

    The ASN half was already wired up. The hostname half existed in
    pivot.is_shared_hosting_hostname and had no caller at all - so a PTR
    flip on something plainly named like a CDN edge node was weighed the
    same as one on dedicated infrastructure, which is exactly the
    distinction the analyst rules ask for.
    """
    if item.family == "infrastructure":
        # The selector layer already applied a stricter, purpose-built gate:
        # co-hosting selectors are never recorded on a CDN or big-cloud
        # address, and a body hash is suppressed for an IP behind a CDN. A
        # link that survived that is a link, and re-suppressing it here on
        # the ASN alone would drop exactly the promoted pairs this family
        # exists to surface.
        return False
    asn = asn_by_indicator.get(item.indicator)
    if asn is not None and asn in SHARED_HOSTING_ASNS:
        return True
    if item.attribute == "ptr":
        for value in (item.old_value, item.new_value):
            if isinstance(value, str) and is_shared_hosting_hostname(value):
                return True
    return False


def _asn_index(digest: dict[str, Any], indicators: list[str]) -> dict[str, int]:
    """Indicator -> ASN.

    The digest only carries an ASN when the ASN itself changed, which is
    exactly the day the row is *not* routine - so on a normal day every
    hosted-domain row arrives with no ASN attached and the shared-hosting
    rule has nothing to match on. The last known ASN therefore comes from
    the store.

    It has to be the ASN and not a shortcut. The obvious shortcut - "an IP
    listing dozens of unrelated domains is shared hosting" - looks right
    and is wrong: 208.91.112.55 carries 48 hostnames and is STAC4749's
    own tracked infrastructure on AS40934 (Fortinet), while the Cloudflare
    and AWS addresses beside it carry 40-50 each. The counts are
    indistinguishable; the ASNs are not.

    A store that cannot be read is not an error here - an un-suppressed
    row costs tokens, a failed Stage B costs the day.
    """
    index: dict[str, int] = {}
    for row in digest.get("asn_pivots") or []:
        asn = asn_int(row.get("new_asn"))
        if asn is not None:
            index[row["indicator_value"]] = asn
    for row in digest.get("cross_actor_asn_overlap") or []:
        asn = asn_int(row.get("asn"))
        if asn is not None:
            index[row["indicator_value"]] = asn
    for row in digest.get("new_indicators_in_known_asns") or []:
        asn = asn_int(row.get("asn"))
        if asn is not None:
            index[row["indicator_value"]] = asn

    unknown = [i for i in indicators if i not in index]
    if unknown:
        index.update(_asn_from_store(unknown))
    return index


def _asn_from_store(indicators: list[str]) -> dict[str, int]:
    from cti.store import connect_retry

    placeholders = ", ".join("?" for _ in indicators)
    try:
        with connect_retry(read_only=True) as con:
            rows = con.execute(
                f"""SELECT indicator_value, asn FROM (
                        SELECT indicator_value, asn,
                               row_number() OVER (PARTITION BY indicator_value
                                                  ORDER BY observed_at DESC) AS rn
                        FROM observations_wide
                        WHERE indicator_value IN ({placeholders}) AND asn IS NOT NULL
                    ) WHERE rn = 1""", list(indicators)).fetchall()
    except Exception:
        return {}
    return {value: asn for value, asn in rows if asn is not None}


def _items_from_attribute_changes(digest: dict[str, Any]) -> list[Item]:
    out = []
    for row in digest.get("attribute_changes") or []:
        attribute = row.get("attribute")
        family = ATTRIBUTE_FAMILY.get(attribute)
        if family is None:
            continue  # an attribute with no owning specialist yet
        out.append(Item(
            family=family, attribute=attribute,
            actor=row.get("actor"), indicator=row.get("indicator_value"),
            change_type=row.get("change_type") or "",
            confidence=row.get("confidence") or "medium",
            detected_at=str(row.get("detected_at") or "") or None,
            old_value=_as_json(row.get("old_value")),
            new_value=_as_json(row.get("new_value")),
        ))
    return out


def _items_from_asn_pivots(digest: dict[str, Any]) -> list[Item]:
    """ASN changes live in their own table, not attribute_changes - a
    separate schema from before the generalized diff existed. They are
    the same kind of signal, so they become items too."""
    out = []
    for row in digest.get("asn_pivots") or []:
        out.append(Item(
            family="infra_change", attribute="asn", actor=row.get("actor"),
            indicator=row.get("indicator_value"),
            change_type=row.get("change_type") or "asn_change",
            confidence=row.get("confidence") or "medium",
            detected_at=str(row.get("detected_at") or "") or None,
            old_value={"asn": row.get("old_asn"), "netname": row.get("old_netname")},
            new_value={"asn": row.get("new_asn"), "netname": row.get("new_netname")},
            source_section="asn_pivots",
        ))
    return out


def _items_from_open_directories(digest: dict[str, Any]) -> list[Item]:
    out = []
    for row in digest.get("open_directories") or []:
        out.append(Item(
            family="opendir", attribute="opendir_files", actor=row.get("actor"),
            indicator=row.get("indicator_value"),
            change_type="opendir_files", confidence="high",
            detected_at=str(row.get("first_seen") or "") or None,
            new_value={"url": row.get("url"), "path": row.get("path"),
                       "size": row.get("size")},
            source_section="open_directories",
        ))
    return out


def _items_from_infrastructure_links(digest: dict[str, Any]) -> list[Item]:
    """Candidate links, already judged by the corroboration rule.

    These are not attribute changes and do not belong in the same shape as
    one, but they go through the same Item so the fan-out, the budget and
    the suppression all work unchanged.

    Only promoted candidates become items. A held-back candidate is a link
    the rule declined to make, and its reason is already in the digest for
    a human to read; handing three hundred of them to a model would be the
    exact mistake the ranker exists to prevent. The count is carried on
    every item so the specialist knows what it is not being shown.
    """
    links = (digest.get("infrastructure_links") or {})
    promoted = links.get("promoted") or []
    held = links.get("held_back_total") or 0
    out = []
    for row in promoted:
        out.append(Item(
            family="infrastructure", attribute="selector_link",
            actor=row.get("actor"),
            indicator=row.get("seed") or "",
            change_type="selector_link",
            # The rule is deterministic and was applied before this point:
            # an identity selector, or two independent structural ones. That
            # is a high-confidence claim by construction.
            confidence="high",
            detected_at=str(digest.get("day") or "") or None,
            old_value={"held_back": held},
            new_value={"linked_to": row.get("linked_to"),
                       "reason": row.get("reason"),
                       "identity": row.get("identity"),
                       "structural": row.get("structural"),
                       "corroborating": row.get("corroborating")},
            source_section="infrastructure_links",
        ))
    return out


def score(item: Item, asn_by_indicator: dict[str, int]) -> Item:
    base = CHANGE_WEIGHT.get(item.change_type, 1.0)
    item.score = base * CONFIDENCE_WEIGHT.get(item.confidence, 1.0)

    if _looks_like_shared_hosting(item, asn_by_indicator):
        item.suppressed = (
            "shared hosting: a change on a CDN or big-cloud address says "
            "something about the provider's tenants, not about this actor")
        item.score = 0.0
    elif item.change_type == "first_seen":
        item.suppressed = (
            "first observation, not a change - this is the baseline every "
            "future diff is measured against")
        item.score = 0.0
    return item


def rank(state: CTIState) -> dict:
    """Normalize the digest into scored items and split them by family."""
    digest = state.get("digest_json") or {}
    items = (_items_from_attribute_changes(digest)
             + _items_from_asn_pivots(digest)
             + _items_from_open_directories(digest)
             + _items_from_infrastructure_links(digest))
    asn_by_indicator = _asn_index(digest, [i.indicator for i in items])
    items = [score(item, asn_by_indicator) for item in items]

    ranked: dict[str, list[Item]] = {}
    for family in FAMILY_ATTRIBUTES:
        candidates = [i for i in items if i.family == family and not i.suppressed]
        candidates.sort(key=lambda i: (-i.score, i.detected_at or "", i.indicator),
                        reverse=False)
        budget = ITEMS_PER_FAMILY.get(family, DEFAULT_ITEM_BUDGET)
        ranked[family] = _latest_per_indicator(candidates)[:budget]

    return {"items": items, "ranked": ranked}


def _latest_per_indicator(items: list[Item]) -> list[Item]:
    """One row per (indicator, attribute), the most recent.

    The digest window is several days wide, so a domain whose resolved IP
    moves every day contributes one row per day. Spending a specialist's
    two-item budget on the same domain twice is the same mistake the
    single pass made, just smaller.
    """
    best: dict[tuple[str, str, str], Item] = {}
    for item in items:
        key = (item.indicator, item.attribute, _discriminator(item))
        current = best.get(key)
        if current is None or (item.detected_at or "") > (current.detected_at or ""):
            best[key] = item
    return sorted(best.values(), key=lambda i: (-i.score, i.indicator))


def _discriminator(item: Item) -> str:
    """What makes two rows for the same indicator genuinely different.

    For most attributes, nothing: a domain whose IP moves daily produces
    one row per day and only the newest matters. Open-directory rows are
    the exception - every file in a directory shares the indicator and the
    attribute, so keying on those alone collapses a whole directory into
    one file, which is how the most interesting file goes missing.
    """
    if item.attribute == "opendir_files" and isinstance(item.new_value, dict):
        return str(item.new_value.get("path") or "")
    return ""


def families_with_work(state: CTIState) -> list[str]:
    """Which specialists have anything to do. A family with no items is
    never dispatched, so a quiet day costs nothing."""
    return [family for family, items in (state.get("ranked") or {}).items() if items]
