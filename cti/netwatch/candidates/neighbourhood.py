"""Scan the announced prefix around a tracked address.

An operator who rents one address often rents its neighbours, so the /24 a
tracked IP sits in is worth a low-and-slow sweep for new listeners. This
turns each active cluster IP into a set of `sweep`-tier scan targets, which
the queue hands to the probe on the weekly pass.

Bounds, because this is the one source that could balloon:

* the range is the MORE SPECIFIC of the announced prefix and the /24 around
  the address, so a /22 announcement is still only swept a /24 at a time.
* shared-hosting and big-cloud prefixes are skipped: scanning them
  fingerprints the provider's other tenants, not an operator (the same
  judgment `cti/store/hosting.py` already makes).
* at most MAX_NEIGHBOUR_HOSTS per address, and the netwatch budget caps the
  run on top of that.

The sweep uses the cluster's own port_set only - we are looking for the same
service on a new address, not port-scanning strangers.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

from ... import core
from ...sources import pivot
from ...store import hosting
from .. import queue
from . import Candidate

log = logging.getLogger(__name__)

# The widest neighbourhood a single address contributes. A /24 is 254 usable
# hosts; anything wider is an announcement, not a neighbourhood.
MAX_NEIGHBOUR_HOSTS = 254


def _range_for(ip: str, prefix: str | None) -> ipaddress.IPv4Network | None:
    """The /24 (or narrower announced prefix) to sweep around `ip`."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:          # IPv6 neighbourhoods are not swept
        return None
    slash24 = ipaddress.ip_network(f"{ip}/24", strict=False)
    if not prefix:
        return slash24
    try:
        announced = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return slash24
    if announced.version != 4:
        return slash24
    # The more specific (smaller) of the two, as long as it holds the address.
    if announced.prefixlen >= 24 and addr in announced:
        return announced
    return slash24


def _port_set(data: dict[str, Any]) -> list[int]:
    """The union of ports the cluster's hosts are known to listen on."""
    ports: set[int] = set()
    for cat in ("ips", "domains"):
        for o in data["observables"].get(cat, []):
            for p in o.get("ports") or []:
                ports.add(int(p))
    return sorted(ports)


def sweep_targets(data: dict[str, Any], *,
                  max_hosts: int = MAX_NEIGHBOUR_HOSTS) -> list[dict[str, Any]]:
    """`sweep`-tier scan targets for every active IP's neighbourhood.

    Returns watchlist-shaped targets so the queue and `jobs` treat them the
    same as any other scan target. The tracked address itself is excluded;
    the watchlist already covers it.
    """
    actor = data.get("name")
    ports = _port_set(data)
    tracked = {o["value"] for cat in ("ips", "domains")
               for o in data["observables"].get(cat, [])}
    out: list[dict[str, Any]] = []
    for o in data["observables"].get("ips", []):
        if core.lifecycle_of(o) != "active":
            continue
        ip = o["value"]
        info = pivot.ripestat_lookup(ip)
        if hosting.is_shared_asn((info.get("asn") or [None])[0]):
            log.info("neighbourhood: skipping %s (shared-hosting ASN)", ip)
            continue
        net = _range_for(ip, info.get("prefix"))
        if net is None:
            continue
        hosts = [str(h) for h in net.hosts()][:max_hosts]
        for host in hosts:
            if host in tracked:
                continue
            out.append({
                "value": host, "kind": "ip", "tier": "sweep",
                "ports": ports, "actor": actor, "cluster": data.get("name"),
                "lifecycle": "candidate",
                "discovered_via": f"net.prefix:{net.with_prefixlen}",
                "discovered_from": ip})
    return out


def enqueue(clusters: list[str] | None = None) -> dict[str, Any]:
    """Queue the neighbourhood sweep targets for every cluster. The next
    scan run with the `sweep` tier drains them. Returns a per-cluster count."""
    names = clusters if clusters is not None else core.list_clusters()
    summary: dict[str, int] = {}
    total = 0
    for name in names:
        try:
            data = core.load_cluster(name)
        except Exception as e:  # noqa: BLE001 - one bad cluster must not stop the rest
            log.warning("neighbourhood: cannot load %s: %s", name, e)
            continue
        targets = sweep_targets(data)
        if targets:
            n = queue.enqueue(targets, source=f"neigh-{name}")
            summary[name] = n
            total += n
    return {"clusters": summary, "queued": total}
