"""Certificate Transparency candidates from a self-hosted stream.

Every certificate a public CA issues is published to CT logs within minutes,
and `certstream-server-go` republishes the firehose over a local websocket -
no vendor, no key, no quota. A newly issued certificate is the earliest
possible sighting of infrastructure being stood up: the operator has the
name and the cert before the service is even listening.

We cannot scan the firehose, so a certificate is only interesting if it
matches a CT-scoped hunt rule - a SAN regex, an issuer or subject pattern,
an apex. A match resolves the names through the probe and queues the live
ones as `hot` scan targets; the scan and its snapshot rule confirm the rest.

`ingest_entries` is the testable core (feed it parsed certs). `stream`
drives it from the websocket for a bounded run, meant to be invoked by a
systemd user unit; it imports `websockets` lazily so the rest of the module
works without it.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Iterable

from ...probe import vm_proxy
from .. import queue, rules as rules_mod

log = logging.getLogger(__name__)

DEFAULT_STREAM_URL = "ws://127.0.0.1:4000/"
# CT hits are scanned on the hourly hot pass, with the common web ports -
# the name exists before the service, so a broad port guess is wrong more
# often than it helps.
CT_PORTS = [443, 8443]


def parse_certstream(message: dict[str, Any]) -> dict[str, Any] | None:
    """A certstream-server-go `certificate_update` into {sans, subject, issuer}.

    Returns None for heartbeats and anything without a leaf certificate.
    """
    if message.get("message_type") != "certificate_update":
        return None
    leaf = ((message.get("data") or {}).get("leaf_cert")) or {}
    sans = leaf.get("all_domains") or []
    subject = (leaf.get("subject") or {}).get("aggregated") \
        or (leaf.get("subject") or {}).get("CN") or ""
    issuer = (leaf.get("issuer") or {}).get("aggregated") \
        or (leaf.get("issuer") or {}).get("CN") or ""
    if not sans and not subject:
        return None
    return {"sans": sans, "subject": subject, "issuer": issuer}


def _resolvable(name: str, resolve: Callable[[str], list[str] | None]) -> bool:
    """Only queue a name that resolves now - an unissued cert's SAN may name
    a host that does not exist yet, and scanning nothing wastes a slot."""
    if name.startswith("*"):
        return False
    try:
        return bool(resolve(name))
    except Exception as e:  # noqa: BLE001 - a probe hiccup must not sink the run
        log.debug("resolve %s failed: %s", name, e)
        return False


def ingest_entries(entries: Iterable[dict[str, Any]], *,
                   rules: list[rules_mod.Rule] | None = None,
                   resolve: Callable[[str], list[str] | None] | None = None,
                   enqueue: bool = True) -> dict[str, Any]:
    """Match parsed certificates against CT rules, resolve, queue the hits.

    `entries` are {sans, subject, issuer} dicts (what `parse_certstream`
    yields). Returns a summary; a non-empty `targets` lists what was queued.
    """
    rules = rules if rules is not None else [
        r for r in rules_mod.load() if "ct" in r.scope]
    resolve = resolve or vm_proxy.resolve_dns
    if not rules:
        return {"entries": 0, "matched": 0, "queued": 0, "targets": []}

    seen: set[str] = set()
    targets: list[dict[str, Any]] = []
    matched = n = 0
    for entry in entries:
        n += 1
        hits = rules_mod.match_ct(entry, rules)
        if not hits:
            continue
        matched += 1
        for hit in hits:
            for name in hit["names"]:
                if name in seen or not _resolvable(name, resolve):
                    continue
                seen.add(name)
                targets.append({
                    "value": name, "kind": "domain", "tier": "hot",
                    "ports": CT_PORTS, "actor": hit.get("cluster"),
                    "cluster": hit.get("cluster"),
                    "lifecycle": "candidate",
                    "discovered_via": f"ct:{hit['rule']}",
                    "discovered_from": hit["rule"]})
    queued = queue.enqueue(targets, source="ct") if (enqueue and targets) else 0
    return {"entries": n, "matched": matched,
            "queued": queued, "targets": targets}


async def stream(url: str = DEFAULT_STREAM_URL, *, seconds: float = 60.0,
                 rules: list[rules_mod.Rule] | None = None) -> dict[str, Any]:
    """Consume the certstream websocket for `seconds`, queueing CT hits.

    A bounded run so a systemd user unit can cron it; it is not a daemon.
    Imports `websockets` lazily so importing this module never requires it.
    """
    import asyncio
    import json

    try:
        import websockets
    except ImportError:
        return {"error": "the websockets package is not installed"}

    rules = rules if rules is not None else [
        r for r in rules_mod.load() if "ct" in r.scope]
    if not rules:
        return {"error": "no CT-scoped hunt rules are enabled"}

    parsed: list[dict[str, Any]] = []
    loop = asyncio.get_event_loop()
    deadline = loop.time() + seconds
    try:
        async with websockets.connect(url, max_size=2 ** 20) as ws:
            while loop.time() < deadline:
                try:
                    raw = await asyncio.wait_for(
                        ws.recv(), timeout=max(0.0, deadline - loop.time()))
                except asyncio.TimeoutError:
                    break
                try:
                    entry = parse_certstream(json.loads(raw))
                except (json.JSONDecodeError, TypeError):
                    continue
                if entry:
                    parsed.append(entry)
    except Exception as e:  # noqa: BLE001 - report, never crash the unit
        log.warning("certstream connection failed: %s", e)
        return {"error": str(e), "consumed": len(parsed)}

    result = ingest_entries(parsed, rules=rules)
    result["consumed"] = len(parsed)
    return result
