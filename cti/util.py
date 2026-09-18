"""Primitives that were implemented more than once in the old tree.

Each function here replaces two to four near-copies. The docstrings say
which, because in several cases the copies disagreed and the disagreement
was the bug.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import duckdb


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #
# Two _now()s existed with DIFFERENT formats - core.py emitted
# "...+00:00", stix.py emitted "...000Z" - for timestamps on the same
# objects. Both are kept, named for their output target so the choice is
# deliberate rather than whichever module you happened to import.

def now_iso() -> str:
    """ISO-8601 with a +00:00 offset. The cluster JSON store's format."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def now_stix() -> str:
    """STIX 2.1 timestamp: millisecond precision, literal Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def is_stale(observed_at: datetime, days: int) -> bool:
    return datetime.now() - observed_at > timedelta(days=days)


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #

def atomic_write_text(path: Path, text: str) -> None:
    """Write text so readers never see a partial file: write to a temp file
    in the same directory, then os.replace (atomic on the same filesystem).

    Prevents a crash mid-write from leaving truncated JSON, and prevents a
    .json/.md pair from going out of sync on a torn write. Replaces
    core._atomic_write_text and webamon's own inline tmp.write_text/replace.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default: Any = None) -> Any:
    """Best-effort JSON read. A missing, empty, or corrupt file is the
    default, never an exception - these are all caches and queues where a
    lost entry is recoverable and a crash is not."""
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError, ValueError):
        return default if default is not None else {}


def write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data))


_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    text = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    return _SLUG_STRIP.sub("-", text.lower()).strip("-")


# --------------------------------------------------------------------------- #
# Values
# --------------------------------------------------------------------------- #

def new_values(existing: Iterable[str], candidates: Iterable[str]) -> list[str]:
    """Candidates not already in `existing`, deduped, order-preserving.

    Replaces four copies: core._new_values, the identical two lines inside
    core._file_new_observables (whose docstring admitted they were "kept in
    sync"), and the two inline set-comprehension guards in
    _add_observable_locked and _merge_observables.
    """
    seen = set(existing)
    return [v for v in dict.fromkeys(candidates) if v and v not in seen]


def asn_int(value: Any) -> int | None:
    """Normalize an ASN to int, or None if unparseable.

    RIPEstat reports ASNs as strings ("16509", occasionally "AS16509") and
    hands back a list when an IP is announced by more than one;
    SHARED_HOSTING_ASNS and the tracking store use ints. Coercing once is
    what keeps `asn in SHARED_HOSTING_ASNS` honest - comparing the raw
    string never matched, so shared-hosting suppression silently did
    nothing and stamped fifty other tenants' domains onto tracked AWS IPs.

    This replaces two implementations that DISAGREED. core._asn_int used
    `text[2:]` after an explicit .strip(); tracking.enrich._as_int used
    `.upper().lstrip("AS")` before its .strip(). lstrip takes a character
    SET, so enrich's version also ate the leading "S" of a hypothetical
    "ASS..." and, worse, failed outright on a leading space (" AS16509"):
    lstrip found no leading A or S, then .strip() left "AS16509", which
    isn't all-digits, so it returned None where core returned 16509. The
    strip-then-slice form below is the correct one.
    """
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return int(text) if text.isdigit() else None


def asn_ints(values: Any) -> list[int]:
    """asn_int over a list, dropping the unparseable."""
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    return [n for n in (asn_int(v) for v in values) if n is not None]


# --------------------------------------------------------------------------- #
# DuckDB
# --------------------------------------------------------------------------- #

def rows(con: duckdb.DuckDBPyConnection, sql: str,
         params: list[Any] | None = None) -> list[dict[str, Any]]:
    """Execute and return dicts. Was defined identically in both
    tracking/store.py and tracking/analytics.py."""
    cur = con.execute(sql, params or [])
    columns = [d[0] for d in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]
