"""A small on-disk queue of extra scan targets.

The watchlist is built from the cluster files, but candidate discovery finds
hosts that are not in any cluster yet - a name off a CT match, an address in
a tracked host's prefix. Those need scanning before they can be verified, so
they are dropped here and `jobs.run` drains them alongside the watchlist.

One JSON file per enqueue batch under data/netwatch/queue/, each a list of
targets in the watchlist's own shape ({value, kind, tier, ports, actor,
cluster, discovered_via}). Draining is destructive: a target is scanned once
off the queue and, if it is worth keeping, becomes a tracked candidate that
the watchlist covers from then on.
"""
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from ..util import data_dir

log = logging.getLogger(__name__)


def queue_dir() -> Path:
    d = data_dir() / "netwatch" / "queue"
    d.mkdir(parents=True, exist_ok=True)
    return d


def enqueue(targets: list[dict[str, Any]], *, source: str) -> int:
    """Append a batch of scan targets. Returns how many were written."""
    targets = [t for t in targets if t.get("value")]
    if not targets:
        return 0
    path = queue_dir() / f"{source}-{uuid.uuid4().hex[:12]}.json"
    path.write_text(json.dumps(targets))
    log.info("queued %d scan target(s) from %s", len(targets), source)
    return len(targets)


def drain(*, tiers: set[str] | None = None) -> list[dict[str, Any]]:
    """Read and remove queued targets, de-duplicated by value.

    `tiers` keeps only targets whose tier a given run covers, so an hourly
    `hot` run takes CT hits but leaves neighbourhood `sweep` work for the
    weekly pass. A taken target is removed from its file so the next run of
    the same tier does not re-scan it; a file emptied of everything is
    unlinked.
    """
    best: dict[str, dict[str, Any]] = {}
    for path in sorted(queue_dir().glob("*.json")):
        try:
            batch = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            log.warning("bad queue file %s: %s", path, e)
            path.unlink(missing_ok=True)
            continue
        kept = []
        for t in batch if isinstance(batch, list) else []:
            value = (t.get("value") or "").strip()
            if not value:
                continue
            if tiers is not None and t.get("tier") not in tiers:
                kept.append(t)              # out of scope this run; leave it
                continue
            prior = best.get(value)
            if prior is None:
                best[value] = t
            else:
                prior["ports"] = sorted(set(prior.get("ports") or [])
                                        | set(t.get("ports") or []))
        if kept:
            path.write_text(json.dumps(kept))
        else:
            path.unlink(missing_ok=True)
    return list(best.values())


def pending() -> int:
    """How many target files are waiting, for status output."""
    return len(list(queue_dir().glob("*.json")))
