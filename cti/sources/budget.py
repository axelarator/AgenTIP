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
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from ..util import data_dir

# provider -> its caps. A monthly cap of None means only the daily one
# applies, which was true of every provider until Validin: its free tier
# meters both, and the monthly is the binding one - 10 a day would be 300 a
# month against a ceiling of 50. A budget that enforced only the daily cap
# would have looked healthy right up to the point the provider started
# refusing, three days in.
@dataclass(frozen=True)
class Provider:
    daily_env: str
    daily: int
    min_interval: float = 0.0        # seconds between calls; 0 disables
    monthly_env: str | None = None
    monthly: int | None = None


PROVIDERS: dict[str, Provider] = {
    "webamon": Provider("CTI_WEBAMON_DAILY_BUDGET", 1000),
    "honeylabs": Provider("CTI_HL_BUDGET", 400, 6.0),
    "rdap": Provider("CTI_RDAP_CAP", 150),
    "validin": Provider("CTI_VALIDIN_DAILY_BUDGET", 10, 0.0,
                        "CTI_VALIDIN_MONTHLY_BUDGET", 50),
}


class BudgetExhausted(RuntimeError):
    """The cap for this provider is spent.

    Callers turn this into a skip note, never a crash: a missing
    enrichment is a gap in one row, an exception is a lost sweep.
    """


def _dir() -> Path:
    d = data_dir() / "_registry" / "budgets"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(provider: str) -> Path:
    return _dir() / f"{provider}.json"


def _int_env(name: str | None, default: int | None) -> int | None:
    if name is None:
        return default
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def cap(provider: str) -> int:
    spec = PROVIDERS[provider]
    return _int_env(spec.daily_env, spec.daily)


def monthly_cap(provider: str) -> int | None:
    spec = PROVIDERS[provider]
    if spec.monthly is None:
        return None
    return _int_env(spec.monthly_env, spec.monthly)


def min_interval(provider: str) -> float:
    try:
        return float(os.environ.get(f"CTI_{provider.upper()}_MIN_INTERVAL",
                                    PROVIDERS[provider].min_interval))
    except ValueError:
        return PROVIDERS[provider].min_interval


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


def used_this_month(provider: str) -> int:
    """Units spent since the 1st, from the per-day counts on file."""
    prefix = date.today().strftime("%Y-%m-")
    return sum(int(n) for day, n in _read(_path(provider)).items()
               if str(day).startswith(prefix))


def remaining(provider: str) -> int:
    """Units still spendable now - the tighter of the two caps.

    A caller that wants to explain which cap is binding asks for both; a
    caller that just wants to know whether it may proceed wants this.
    """
    left = cap(provider) - used_today(provider)
    month = monthly_cap(provider)
    if month is not None:
        left = min(left, month - used_this_month(provider))
    return max(0, left)


def remaining_monthly(provider: str) -> int | None:
    month = monthly_cap(provider)
    if month is None:
        return None
    return max(0, month - used_this_month(provider))


def spend(provider: str, n: int = 1) -> int:
    """Reserve `n` units and return the new daily total.

    Reserve, not record: the count goes up *before* the call is made, so
    a crashed or timed-out request still costs its budget. Under-counting
    is how you get rate-limited; over-counting just leaves headroom.

    Raises BudgetExhausted if either cap is already spent, naming which one
    - "10/10 today" and "50/50 this month" call for different responses,
    the first being "come back tomorrow" and the second "that is the tier".
    The check and the increment happen under one lock, which is the whole
    point: separately they race.
    """
    today = date.today().isoformat()
    month_prefix = date.today().strftime("%Y-%m-")
    with _locked(provider) as path:
        data = _read(path)
        current = int(data.get(today, 0))
        if current + n > cap(provider):
            raise BudgetExhausted(
                f"{provider} daily budget exhausted ({current}/{cap(provider)} today)")

        month_cap = monthly_cap(provider)
        if month_cap is not None:
            month_used = sum(int(v) for day, v in data.items()
                             if str(day).startswith(month_prefix))
            if month_used + n > month_cap:
                raise BudgetExhausted(
                    f"{provider} monthly budget exhausted "
                    f"({month_used}/{month_cap} this month)")

        # Keep the current month only. The file needs history now - a
        # monthly cap cannot be enforced from a single day's count - but a
        # month of days is 31 entries, so it is still bounded.
        kept = {day: v for day, v in data.items()
                if str(day).startswith(month_prefix)}
        kept[today] = current + n
        path.write_text(json.dumps(kept))
        return current + n


# The key under which units spent outside this process are recorded. A date
# key would be wrong - we do not know WHICH days they fell on, only that
# they fell in this month - and sorting it with the dates is harmless
# because every reader filters on the month prefix.
def _carry_key() -> str:
    return date.today().strftime("%Y-%m-carried")


def reconcile(provider: str, used_this_month_remotely: int) -> dict:
    """Record spend the provider counted that this counter never saw.

    A local counter starts at zero and the account does not. This key had
    already spent 5 of its 50 monthly lookups through the provider's web UI
    before anything here counted one, so the local budget would have
    cheerfully authorised 50 more and met a 429 on the 46th - the exact
    failure the budget exists to prevent.

    Only ever adjusts upward. The provider is the authority on what has
    been spent, but a lower remote figure (a reset, a plan change, a
    counter that lags) must not hand back budget we believe is gone.
    """
    month_prefix = date.today().strftime("%Y-%m-")
    with _locked(provider) as path:
        data = _read(path)
        ours = sum(int(v) for day, v in data.items()
                   if str(day).startswith(month_prefix))
        carried = int(data.get(_carry_key(), 0))
        # What we would count without the existing carry, versus theirs.
        shortfall = used_this_month_remotely - ours
        if shortfall <= 0:
            return {"carried": carried, "ours": ours,
                    "theirs": used_this_month_remotely, "adjusted": 0}
        data[_carry_key()] = carried + shortfall
        path.write_text(json.dumps(data))
        return {"carried": carried + shortfall, "ours": ours + shortfall,
                "theirs": used_this_month_remotely, "adjusted": shortfall}


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
