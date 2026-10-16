"""What has looked at an indicator, from where, and when.

A profile is only as complete as its collection. This answers, per
indicator, which sources and vantages have observed it and how recently -
so a gap ("no Windows-client view", "no passive DNS in a month") is a fact
the pipeline and the analyst can see, rather than an absence nobody notices.
"""
from __future__ import annotations

from typing import Any

import duckdb

from ..util import rows


def coverage(con: duckdb.DuckDBPyConnection, indicator: str) -> dict[str, Any]:
    """Per (source, vantage): the selector spans it contributed, and per
    vantage: the last service snapshot."""
    spans = rows(con, """
        SELECT source, coalesce(vantage, '') AS vantage,
               count(*) AS spans, count(DISTINCT selector_type) AS selector_types,
               min(start_at) AS first_seen, max(end_at) AS last_seen
        FROM selector_spans WHERE indicator_value = ?
        GROUP BY 1, 2 ORDER BY last_seen DESC""", [indicator])
    scans = rows(con, """
        SELECT vantage, count(DISTINCT scan_id) AS scans,
               count(*) FILTER (WHERE open) AS open_ports,
               max(scanned_at) AS last_scanned
        FROM service_snapshots WHERE target = ?
        GROUP BY 1 ORDER BY last_scanned DESC""", [indicator])
    observations = rows(con, """
        SELECT source, count(*) AS observations, max(observed_at) AS last_observed
        FROM observations WHERE indicator_value = ?
        GROUP BY 1 ORDER BY last_observed DESC""", [indicator])
    for group in (spans, scans, observations):
        for row in group:
            for key, value in row.items():
                if hasattr(value, "isoformat"):
                    row[key] = value.isoformat()
    vantages = sorted({r["vantage"] for r in spans if r["vantage"]} |
                      {r["vantage"] for r in scans})
    return {"indicator": indicator, "vantages": vantages, "selector_sources": spans,
            "scans": scans, "observations": observations}
