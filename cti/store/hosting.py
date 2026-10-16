"""Is this address shared hosting?

A domain on a shared address shares a provider with thousands of other
customers, not an operator with them. Every gate that asks that question
used to read one hardcoded tuple of three ASNs (AWS, Alibaba, Cloudflare),
so a cluster domain on Hostinger or GoDaddy shared hosting surfaced every
other tenant as a hosted-domain "lead" and every tenant shuffle as an ASN
change.

Two tests, either of which is enough:

1. The ASN is a shared-hosting or big-cloud provider
   (data/shared_hosting_asns.txt). VPS-first providers are left out on
   purpose: actors rent dedicated addresses there.
2. The PTR names a CDN or load-balancer edge (pivot's suffix list).

There is deliberately no co-tenancy test ("more than N domains on one
address"). It looks right and is wrong: 208.91.112.55 carries 48 hostnames
and is STAC4749's own infrastructure, while the Cloudflare and AWS
addresses beside it carry 40-50 each - see graph/nodes/rank.py:_asn_index.
"""
from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

_ASNS_PATH = Path(__file__).with_name("data") / "shared_hosting_asns.txt"


@functools.lru_cache(maxsize=1)
def shared_asns() -> tuple[int, ...]:
    """The shared-hosting ASNs, sorted. Empty if the data file is missing."""
    try:
        text = _ASNS_PATH.read_text()
    except OSError:
        return ()
    out = set()
    for line in text.splitlines():
        token = line.split("#", 1)[0].strip()
        if token.isdigit():
            out.add(int(token))
    return tuple(sorted(out))


def is_shared_asn(asn: Any) -> bool:
    return asn is not None and asn in shared_asns()


def is_shared(*, asn: Any = None, ptr: str | None = None) -> tuple[bool, str | None]:
    """(shared, why) from whatever is known about one address."""
    from ..sources.pivot import is_shared_hosting_hostname

    if is_shared_asn(asn):
        return True, f"shared-hosting ASN {asn}"
    if ptr and is_shared_hosting_hostname(ptr):
        return True, f"PTR {ptr} is a CDN or load-balancer edge"
    return False, None


def entry_shared(entry: dict[str, Any]) -> tuple[bool, str | None]:
    """The verdict for a cluster IP entry, from what the sweep stamped on it."""
    if entry.get("shared_hosting"):
        return True, entry["shared_hosting"]
    return is_shared(asn=entry.get("asn"))
