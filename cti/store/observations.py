"""Writing observation rows.

One row per (day, indicator, source). A same-day re-run for the same
triple updates in place, which is what makes the whole daily pipeline
idempotent per day.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any

import duckdb

from .schema import OBS_JSON_KEYS, OBS_PAYLOAD_KEYS

_SPINE = ("observed_at", "indicator_type", "indicator_value", "actor", "source")


def _jsonable(value: Any) -> Any:
    """Payload values reach us as real Python objects, including datetimes
    (hl_first_seen, cert_not_before, ...). The old wide table had typed
    TIMESTAMP columns so those went in as-is; a JSON payload needs them
    as ISO-8601 text. observations_wide casts them straight back with
    CAST(payload->>'$.k' AS TIMESTAMP), which parses ISO-8601.
    """
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"cannot store {type(value).__name__} in an observation payload")


def _encode(value: Any) -> Any:
    """A caller may hand us either a Python object or an already-JSON
    string (the old store's _json passed str through unmodified so a
    caller holding serialized JSON wasn't double-encoded). Preserve that,
    because tracking/enrich.py relies on it."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def upsert_observation(con: duckdb.DuckDBPyConnection, *, observed_at,
                       indicator_value: str, source: str, **fields: Any) -> None:
    """Insert one observation row, merging into any existing row for the
    same (observed_at, indicator_value, source).

    The merge matters: the old wide table updated only the columns a
    caller passed, leaving the rest alone. With one payload column a
    naive `payload = excluded.payload` would silently drop keys written
    earlier the same day by the same source, so the upsert uses
    json_merge_patch to keep that behaviour.
    """
    unknown = set(fields) - set(_SPINE) - OBS_PAYLOAD_KEYS
    if unknown:
        raise ValueError(f"unknown observation fields: {sorted(unknown)}")

    actor = fields.pop("actor", None)
    indicator_type = fields.pop("indicator_type", "ipv4")
    fields.pop("observed_at", None)
    fields.pop("indicator_value", None)
    fields.pop("source", None)

    payload = {k: (_encode(v) if k in OBS_JSON_KEYS else v)
               for k, v in fields.items() if v is not None}

    con.execute(
        """INSERT INTO observations
             (observed_at, indicator_type, indicator_value, actor, source, payload)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT (observed_at, indicator_value, source) DO UPDATE SET
             indicator_type = excluded.indicator_type,
             actor = coalesce(excluded.actor, observations.actor),
             payload = json_merge_patch(
                 coalesce(observations.payload, '{}'), excluded.payload)""",
        [observed_at, indicator_type, indicator_value, actor, source,
         json.dumps(payload, default=_jsonable)])
