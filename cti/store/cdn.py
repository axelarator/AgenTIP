"""Is this address shared CDN infrastructure?

Two domains behind the same Cloudflare edge address are not linked - they
share a provider, and the provider has millions of customers. That is the
difference the source reporting drew when it said the link was "shared
registration of hoster-kg.com, not a shared server".

The gate that already existed in this repo keyed on the *indicator's* ASN,
which is no help for a domain: a domain has no ASN, so a domain resolving
into a CDN passed straight through. Backfilling this repo's own data with
that gate still produced seven Cloudflare addresses as "structural" links.

This is the interim answer: the published ranges, vendored as data like the
public suffix list. `cdncheck` on the probe VM replaces it with a maintained
list covering every major CDN, WAF and cloud - at which point this file
becomes the offline fallback rather than the primary check.
"""
from __future__ import annotations

import functools
import ipaddress
from pathlib import Path

_RANGES_PATH = Path(__file__).with_name("data") / "cdn_ranges.txt"


@functools.lru_cache(maxsize=1)
def _networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        text = _RANGES_PATH.read_text()
    except OSError:
        return ()
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return tuple(out)


def available() -> bool:
    return bool(_networks())


@functools.lru_cache(maxsize=8192)
def is_cdn(address: str) -> bool:
    """True if the address is in a known shared-CDN range."""
    try:
        addr = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    return any(addr in net for net in _networks()
               if net.version == addr.version)
