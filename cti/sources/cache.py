"""The one file-backed TTL cache.

## What this replaces

Three implementations of the same idea: core._cached_pivot (the source
lookups), core._fetch_report_text (fetched report bodies), and webamon's
daily quota counter. Two of them shared the same six-line "read JSON,
swallow any error" body.

## Why it is one file per key now

The old pivot cache was a single dict in one 8.8 MB JSON file, fully
re-read and fully re-written on *every* cache miss, under a lock, from a
six-thread pool. That was the hottest I/O path in the pipeline, and the
LangGraph fan-out would have made it worse: more concurrency meant more
whole-file rewrites contending for the same lock.

One file per key removes the read-modify-write entirely. Writes are
atomic and independent, so no lock is needed, concurrent writers cannot
clobber each other, and a corrupt entry costs one lookup instead of the
whole cache. The trade is inode count, which is free here.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Callable

from ..errors import is_failure
from ..util import atomic_write_text, read_json, write_json
from ..util import data_dir

DEFAULT_TTL = 3600


def _root() -> Path:
    return data_dir() / "_registry" / "cache"


def _ttl(env: str, default: int = DEFAULT_TTL) -> int:
    try:
        return int(os.environ.get(env, default))
    except ValueError:
        return default


def _path(namespace: str, key: str) -> Path:
    # Hash the key: indicator values contain /, :, and arbitrary length,
    # and a URL-shaped key would otherwise create directories.
    digest = hashlib.sha256(f"{namespace}:{key}".encode()).hexdigest()
    return _root() / namespace / digest[:2] / f"{digest}.json"


def cached(namespace: str, key: str, fetch: Callable[[], Any], *,
           ttl_env: str = "CTI_PIVOT_CACHE_TTL", ttl: int | None = None) -> Any:
    """Return a fresh cached value for `key`, else call `fetch()`, cache a
    successful result, and return it.

    `fetch` may raise - exceptions propagate uncached, so a transient
    outage is not remembered as the answer.

    Soft failures are not cached either. That rule exists because of a
    real incident: the old gate only checked a top-level "error" key,
    while RIPEstat returns a per-sub-call "<name>_error", so a run where
    every sub-call failed cached the failure as if it were the answer -
    and for the whole TTL afterwards every sweep reported the IP as
    "unknown" with no error anywhere to explain it. errors.is_failure now
    catches both shapes.
    """
    seconds = ttl if ttl is not None else _ttl(ttl_env)
    if seconds <= 0:
        return fetch()

    path = _path(namespace, key)
    entry = read_json(path, default={})
    if entry and time.time() - entry.get("ts", 0) < seconds:
        return entry["result"]

    result = fetch()
    if not is_failure(result):
        try:
            write_json(path, {"ts": time.time(), "key": key, "result": result})
        except OSError:
            pass  # a cache we can't write is a slow cache, not a broken run
    return result


def cached_text(namespace: str, key: str, fetch: Callable[[], str], *,
                ttl_env: str = "CTI_REPORT_CACHE_TTL") -> str:
    """Text-valued variant: a fetched report body is a string, so the
    is_failure() dict check doesn't apply and an empty result is still a
    result worth not re-fetching."""
    seconds = _ttl(ttl_env)
    if seconds <= 0:
        return fetch()
    path = _path(namespace, key)
    entry = read_json(path, default={})
    if entry and time.time() - entry.get("ts", 0) < seconds:
        return entry["result"]
    result = fetch()
    try:
        write_json(path, {"ts": time.time(), "key": key, "result": result})
    except OSError:
        pass
    return result


def clear(namespace: str | None = None) -> int:
    """Drop cached entries. Returns how many files were removed."""
    root = _root() / namespace if namespace else _root()
    removed = 0
    if not root.exists():
        return 0
    for p in root.rglob("*.json"):
        try:
            p.unlink()
            removed += 1
        except OSError:
            pass
    return removed
