"""Rate and credit budgets, shared across everything that spends them.

## Why this exists

Three providers meter us and each was counted differently:

  Webamon    a JSON counter file, read-modify-written per call
  RDAP       an in-process integer in the daily enrichment loop
  HoneyLabs  not counted at all - enforced by pacing a sequential loop

That worked while the pipeline was one process doing one thing at a time.
It stops working the moment work fans out: two workers read the same
count, both see budget remaining, both spend. The HoneyLabs case is the
sharpest, because its limit is 10 requests/minute as well as 500
credits/day, and a fan-out has no sequential loop to pace.

## Why a lock file rather than the DuckDB table

Budgets are spent during the network phase, and the network phase
deliberately holds no database connection - DuckDB's write lock is
process-exclusive, so holding it across minutes of HTTP would serialize
the whole pipeline behind one sweep. A small flock'd counter file is
cross-process safe, costs microseconds, and is released immediately.
"""
from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from typing import Iterator
from ..util import data_dir

# provider -> (env var naming the daily cap, default cap, min seconds
# between calls). A min_interval of 0 means only the daily cap applies.
PROVIDERS = {
    "webamon": ("CTI_WEBAMON_DAILY_BUDGET", 1000, 0.0),
    "honeylabs": ("CTI_HL_BUDGET", 400, 6.0),
    "rdap": ("CTI_RDAP_CAP", 150, 0.0),
}


class BudgetExhausted(RuntimeError):
    """The daily cap for this provider is spent.

    Callers turn this into a skip note, never a crash: a missing
    enrichment is a gap in one row, an exception is a lost sweep.
    """


def _dir() -> Path:
    d = data_dir() / "_registry" / "budgets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(provider: str) -> Path:
    return _dir() / f"{provider}.json"


def cap(provider: str) -> int:
    env, default, _ = PROVIDERS[provider]
    try:
        return int(os.environ.get(env, default))
    except ValueError:
        return default


def min_interval(provider: str) -> float:
    try:
        return float(os.environ.get(f"CTI_{provider.upper()}_MIN_INTERVAL",
                                    PROVIDERS[provider][2]))
    except ValueError:
        return PROVIDERS[provider][2]


@contextmanager
def _locked(provider: str) -> Iterator[Path]:
    path = _path(provider)
    lock = path.with_suffix(".lock")
    lock.touch(exist_ok=True)
    with open(lock, "r+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield path
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def used_today(provider: str) -> int:
    return int(_read(_path(provider)).get(date.today().isoformat(), 0))


def remaining(provider: str) -> int:
    return max(0, cap(provider) - used_today(provider))


def spend(provider: str, n: int = 1) -> int:
    """Reserve `n` units and return the new total.

    Reserve, not record: the count goes up *before* the call is made, so
    a crashed or timed-out request still costs its budget. Under-counting
    is how you get rate-limited; over-counting just leaves headroom.

    Raises BudgetExhausted if the cap is already spent. The check and the
    increment happen under one lock, which is the whole point - separately
    they race.
    """
    today = date.today().isoformat()
    with _locked(provider) as path:
        data = _read(path)
        current = int(data.get(today, 0))
        if current >= cap(provider):
            raise BudgetExhausted(
                f"{provider} daily budget exhausted ({current}/{cap(provider)})")
        # Keep only today: the file is a counter, not a history, and
        # history here would grow without bound for no reader.
        path.write_text(json.dumps({today: current + n}))
        return current + n


_last_call: dict[str, float] = {}


def pace(provider: str) -> None:
    """Sleep as needed to honour the provider's minimum call interval.

    In-process only, deliberately. Cross-process pacing would need the
    lock held across the sleep, which would serialize every worker behind
    the slowest provider. The daily cap above is the cross-process
    guarantee; this is the per-minute one, and the pipeline runs its
    metered fan-outs inside a single process.
    """
    interval = min_interval(provider)
    if interval <= 0:
        return
    now = time.monotonic()
    wait = interval - (now - _last_call.get(provider, 0.0))
    if wait > 0:
        time.sleep(wait)
    _last_call[provider] = time.monotonic()


def reset(provider: str) -> None:
    """Test helper: clear today's count."""
    with _locked(provider) as path:
        path.write_text("{}")
    _last_call.pop(provider, None)
