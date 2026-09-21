"""The DuckDB tracking store.

Was one 1061-line module. Split by what the code actually does:

  connection.py    opening the file, and the process-exclusive lock
  schema.py        DDL, and the narrow-table/wide-view split
  observations.py  writing observation rows
  changes.py       day-over-day attribute diffs (the spec registry)
  writes.py        actors, correlations, ASN changes, opendirs, scans
  query.py         the MCP + dashboard read surface
  budget.py        rate and credit budgets, shared across parallel work
"""
from __future__ import annotations

from ..errors import TrackingBusy
from .changes import (SPECS, asn_confidence, baseline, confidence, detect,
                      record_attribute_change)
from .connection import connect, connect_retry, db_path
from .observations import upsert_observation
from .query import (QUERY_MAX_BYTES, QUERY_MAX_ROWS, actor_summary,
                    indicator_index, indicator_profile, observable_history,
                    selector_detail, run_readonly_query,
                    save_correlation,
                    tracked_observables)
from . import selectors
from .schema import init_schema
from .writes import (CORRELATION_TYPES, insert_correlation, latest_asn_for,
                     record_active_scan, record_asn_change, upsert_actor,
                     upsert_opendir_files, upsert_opendir_samples,
                     upsert_zeek_match)

__all__ = [
    "SPECS", "CORRELATION_TYPES", "QUERY_MAX_BYTES", "QUERY_MAX_ROWS",
    "TrackingBusy", "actor_summary", "asn_confidence", "baseline",
    "confidence", "connect", "connect_retry", "db_path", "detect",
    "init_schema", "insert_correlation", "latest_asn_for",
    "indicator_index", "indicator_profile", "observable_history",
    "selector_detail", "record_active_scan",
    "record_asn_change",
    "selectors",
    "record_attribute_change", "run_readonly_query", "save_correlation",
    "tracked_observables", "upsert_actor", "upsert_observation",
    "upsert_opendir_files", "upsert_opendir_samples", "upsert_zeek_match",
]
