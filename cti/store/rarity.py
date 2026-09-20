"""How much a shared selector value is worth.

Class (in `selectors.py`) caps what a TYPE can prove. This module handles
what a particular VALUE can prove, which class alone cannot express:
`ns1.evil-actor.com` and `ns1.cloudflare.com` are the same type and mean
completely different things.

## Why not a global count

The plan for this module called for a `global_count` - how common the value
is on the internet - on the theory that a page hash on 13 hosts is a lead
and one on 10 million is not. That is the right idea and it is mostly not
purchasable at this tier: crt.sh is dead, urlscan's result API needs a key
and caps totals at 10,000, and there is no free index that will tell you how
many hosts serve a given certificate or how many domains a registrar has.

So `global_count` stays in the schema for the sources that can fill it, and
the rarity that actually runs is the part that can be computed honestly:

* **provider values**. A registrar or a nameserver set naming a mass
  provider is a statement about where the operator shops, not about which
  hosts are theirs. That is a knowable list, vendored like the CDN ranges.
* **local spread**. A value held by many of our own indicators across many
  registered domains is describing something shared rather than linking
  something specific.

Both are recorded, so a later global source refines rather than replaces.
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

    provider_scale = value_is_provider_scale(selector_type, value)
    usable = can_promote(selector_type) and not provider_scale

    reason = None
    if not can_promote(selector_type):
        reason = f"{selector_type} is corroboration-only by class"
    elif provider_scale:
        reason = ("the value names a mass provider - a statement about where "
                  "the operator shops, not about which hosts are theirs")

    return {"selector_type": selector_type, "selector_value": value,
            "local_count": stat["local_count"], "global_count": stat["global_count"],
            "provider_scale": provider_scale, "can_promote": usable,
            "why_not": reason}
