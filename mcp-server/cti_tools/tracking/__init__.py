"""Time-indexed actor tracking layer on DuckDB.

This package is the temporal complement to the JSON cluster store in
cti_tools.core: core owns the canonical cluster/TTP/diamond data, while
tracking keeps per-day observation rows so infrastructure changes (ASN
moves, port shifts, activity gaps) are visible over time instead of
being collapsed into a single overwritten first_seen/last_seen pair.

Public surface re-exported here is what server.py wraps as MCP tools;
everything else is internal to the daily Stage A pipeline.
"""
from .store import actor_summary, run_readonly_query, save_correlation

__all__ = ["actor_summary", "run_readonly_query", "save_correlation"]
