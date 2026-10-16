"""Our own candidate sources - find new infrastructure without a vendor.

Three streams, each feeding the existing candidate flow rather than a new
one:

- pdns:          co-hosted names and historical addresses of tracked hosts,
                 returned as candidate host values to sweep and verify.
- neighbourhood: the announced prefix (capped at /24) of each active cluster
                 IP, returned as `sweep`-tier scan targets.
- ct:            a self-hosted certstream feed, matched against CT-scoped
                 hunt rules, resolved, and queued as `hot` scan targets.

A `Candidate` is just a host value plus where it came from. The expansion
pass sweeps it, then applies the same corroboration rule (one identity fact
or two independent structural ones) before anything is filed - so a
candidate source can only ever propose, never promote.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    """A host a candidate source proposes, with its provenance."""
    value: str
    kind: str                     # "domain" or "ip"
    discovered_via: str           # a selector-shaped tag, e.g. net.historical_ip:1.2.3.4
    discovered_from: str          # the tracked indicator it was found through
    reason: str                   # human-readable, for the hunt log
    # The passive-DNS window the link was live in, when the source gives
    # one. Carried onto the candidate as a dated selector, so a name that
    # shared an address years ago scores as the stranger it is.
    first_seen: int | None = None
    last_seen: int | None = None
