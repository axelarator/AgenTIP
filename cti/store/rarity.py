"""How much a shared selector value is worth.

Class (in `selectors.py`) caps what a TYPE can prove. This module handles
what a particular VALUE can prove, which class alone cannot express:
`ns1.evil-actor.com` and `ns1.cloudflare.com` are the same type and mean
completely different things.

## The global count

A page hash on 13 hosts is a lead; the same hash on 10 million is not. This
module was written believing that count was unpurchasable at this tier -
crt.sh stopped ingesting, urlscan needs a key and caps totals at 10,000 -
and the belief was wrong. Webamon's search index answers it exactly, for one
budget unit, on a key that is already configured: 48,843,549 scans share
example.com's cookie fingerprint and 2 share its SSL fingerprint.

`fill_global_counts` takes that counter as an argument rather than importing
it. The layering here is one-way - sources import store, never the reverse -
and injecting the counter also puts the budget spend at the call site, where
whoever pays for it can see it.

Global counts are scarce, so they are fetched only for values that already
have `local_count > 1` and a class that could promote: a value linking
nothing does not need to be priced.

Alongside it, the two rarity measures that need no network at all:

* **provider values**. A registrar or a nameserver set naming a mass
  provider is a statement about where the operator shops, not about which
  hosts are theirs. That is a knowable list, vendored like the CDN ranges.
* **local spread**. A value held by many of our own indicators across many
  registered domains is describing something shared rather than linking
  something specific.

All three are recorded, and each is usable without the others.
"""
from __future__ import annotations

import functools
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from ..util import rows
from . import psl
from .selectors import can_promote, normalize

_PROVIDERS_PATH = Path(__file__).with_name("data") / "mass_dns_providers.txt"


@functools.lru_cache(maxsize=1)
def _mass_providers() -> tuple[str, ...]:
    try:
        text = _PROVIDERS_PATH.read_text()
    except OSError:
        return ()
    return tuple(line.strip().lower() for line in text.splitlines()
                 if line.strip() and not line.startswith("#"))


def is_mass_dns(value: str) -> bool:
    """Whether a nameserver set belongs to a provider with mass customers.

    Matched per member: a set is only a link if EVERY member is custom. One
    mass-provider nameserver in the set is enough to make the whole set a
    statement about the provider.
    """
    providers = _mass_providers()
    if not providers:
        return False
    for member in str(value).lower().split(","):
        member = member.strip().rstrip(".")
        if any(member == p or member.endswith("." + p) for p in providers):
            return True
    return False


def value_is_provider_scale(selector_type: str, selector_value: Any) -> bool:
    """Whether this VALUE names a shared service rather than a resource."""
    if selector_type == "dns.ns_set":
        return is_mass_dns(str(selector_value))
    return False


def refresh(con: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """Recompute selector_stats from the selectors table.

    Free: one GROUP BY, no network. `global_count` is left untouched so a
    source that can fill it later is not clobbered by a local refresh.
    """
    computed = con.execute("""
        SELECT selector_type, selector_value,
               count(DISTINCT indicator_value) AS local_count,
               count(DISTINCT actor) FILTER (WHERE actor IS NOT NULL) AS actors
        FROM selectors GROUP BY 1, 2""").fetchall()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    written = 0
    for selector_type, selector_value, local_count, actors in computed:
        con.execute("""
            INSERT INTO selector_stats
                (selector_type, selector_value, local_count, global_count,
                 global_source, checked_at)
            VALUES (?, ?, ?, NULL, NULL, ?)
            ON CONFLICT (selector_type, selector_value) DO UPDATE SET
                local_count = excluded.local_count,
                checked_at = excluded.checked_at""",
            [selector_type, selector_value, local_count, now])
        written += 1
    return {"values": written}


# Above this many index-wide hits a value describes the internet rather than
# an operator, whatever its class. Calibrated on measured values: example.com
# has 4388 scans of its own DOM digest, so a threshold near ten thousand does
# not punish a heavily rescanned single site, while the fingerprints that are
# genuinely everywhere - tech 22M, cookies 48.8M, scripts 17.8M, ASN 6.8M,
# cert config 1.3M - are all orders of magnitude above it.
PROVIDER_SCALE_GLOBAL_COUNT = 10_000


def fill_global_counts(con: duckdb.DuckDBPyConnection, counter, *,
                       limit: int = 50, can_price=None) -> dict[str, Any]:
    """Price the selector values that could matter, using an injected counter.

    `counter(selector_type, selector_value)` returns
    {"count": int, "source": str, "exact": bool} or {"error": ...} -
    `webamon.global_count` has that shape. Passing it in keeps this module
    free of source imports and keeps the API spend visible to the caller.

    `can_price(selector_type)` filters types the counter cannot answer at all
    before they consume a slot - `webamon.reversible` has that shape. Without
    it a run spent four of its fifty slots on dns.apex and dns.ns_set, which
    no web-scan index carries and which returned an error every time.

    Only values with local_count > 1 and a promoting class are priced, largest
    local spread first, at most `limit` per run. A value that links nothing
    does not need a price, and the budget is better spent on the ones that do.
    """
    candidates = []
    for row in rows(con, """
            SELECT selector_type, selector_value, local_count
            FROM selector_stats
            WHERE local_count > 1 AND global_count IS NULL
            ORDER BY local_count DESC"""):
        if not can_promote(row["selector_type"]):
            continue
        if can_price is not None and not can_price(row["selector_type"]):
            continue
        candidates.append(row)
        if len(candidates) >= limit:
            break

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    priced, skipped, errors = 0, 0, []
    for row in candidates:
        result = counter(row["selector_type"], row["selector_value"])
        if not isinstance(result, dict) or "error" in result:
            errors.append((row["selector_type"], (result or {}).get("error")))
            continue
        count = result.get("count")
        if count is None:
            skipped += 1
            continue
        con.execute("""
            UPDATE selector_stats SET global_count = ?, global_source = ?,
                                      checked_at = ?
            WHERE selector_type = ? AND selector_value = ?""",
            [int(count), result.get("source") or "unknown", now,
             row["selector_type"], row["selector_value"]])
        priced += 1
    return {"candidates": len(candidates), "priced": priced,
            "unpriceable": skipped, "errors": errors}


def apexes_for(con: duckdb.DuckDBPyConnection, selector_type: str,
               selector_value: Any) -> int:
    """How many distinct registered domains carry this value.

    Spread across registered domains, not indicator count: six hosts under
    one apex is one operator's infrastructure, six hosts under six apexes
    sharing a registrar is a statement about the registrar.
    """
    value = normalize(selector_type, selector_value)
    if value is None:
        return 0
    seen = set()
    for row in rows(con,
                    "SELECT indicator_value FROM selectors "
                    "WHERE selector_type = ? AND selector_value = ?",
                    [selector_type, value]):
        indicator = row["indicator_value"]
        seen.add(psl.registered_domain(indicator) or indicator)
    return len(seen)


def globally_common(con: duckdb.DuckDBPyConnection, selector_type: str,
                    selector_value: Any) -> bool:
    """Whether a priced value is too widespread to link anything.

    False when the value has no price yet, which is the safe default: an
    unpriced value is judged on its class and on the provider list, exactly
    as it was before any global source existed.
    """
    value = normalize(selector_type, selector_value)
    if value is None:
        return False
    found = rows(con, "SELECT global_count FROM selector_stats "
                      "WHERE selector_type = ? AND selector_value = ?",
                 [selector_type, value])
    count = found[0]["global_count"] if found else None
    return count is not None and count > PROVIDER_SCALE_GLOBAL_COUNT


def assess(con: duckdb.DuckDBPyConnection, selector_type: str,
           selector_value: Any) -> dict[str, Any]:
    """Everything known about one selector value's discriminating power."""
    value = normalize(selector_type, selector_value)
    stats = rows(con,
                 "SELECT local_count, global_count, global_source, checked_at "
                 "FROM selector_stats WHERE selector_type = ? AND selector_value = ?",
                 [selector_type, value])
    stat = stats[0] if stats else {"local_count": None, "global_count": None,
                                   "global_source": None, "checked_at": None}

    global_count = stat["global_count"]
    # A count above the threshold is provider-scale however the value looks:
    # this is the gate that catches the values no vendored list could name,
    # because nobody knows in advance which DOM digest is on 17 million sites.
    globally_common = (global_count is not None
                       and global_count > PROVIDER_SCALE_GLOBAL_COUNT)
    provider_scale = value_is_provider_scale(selector_type, value) or globally_common
    usable = can_promote(selector_type) and not provider_scale

    reason = None
    if not can_promote(selector_type):
        reason = f"{selector_type} is corroboration-only by class"
    elif globally_common:
        reason = (f"{global_count:,} hits on {stat['global_source'] or 'the index'} - "
                  f"the value describes the internet, not an operator")
    elif provider_scale:
        reason = ("the value names a mass provider - a statement about where "
                  "the operator shops, not about which hosts are theirs")

    return {"selector_type": selector_type, "selector_value": value,
            "local_count": stat["local_count"], "global_count": global_count,
            "global_source": stat["global_source"],
            "provider_scale": provider_scale, "can_promote": usable,
            "why_not": reason}
