"""Stage A digest: the compact, bounded file that is the ONLY thing
the Stage B agent reads by default.

Token frugality is the design constraint: every section is capped at
MAX_ROWS with an explicit "...N more, query the DB" line, and a day
with no signals collapses to a single NO ACTIVITY marker that Stage B's
wrapper script uses to skip the agent invocation entirely. A .json
twin is written alongside for tests and any future dashboard view.
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[3]

MAX_ROWS = 15
NO_ACTIVITY = "NO ACTIVITY"


def digest_dir() -> Path:
    return Path(os.environ.get("CTI_TRACKING_DIGESTS",
                               _REPO_ROOT / "data" / "tracking" / "digests"))


def _fmt(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    if value is None:
        return "-"
    return str(value)


def _table(rows: list[dict[str, Any]], columns: list[str]) -> list[str]:
    lines = ["| " + " | ".join(columns) + " |",
             "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows[:MAX_ROWS]:
        lines.append("| " + " | ".join(_fmt(row.get(c)) for c in columns) + " |")
    if len(rows) > MAX_ROWS:
        lines.append(f"\n...{len(rows) - MAX_ROWS} more, query the DB.")
    return lines


def _has_signals(sections: dict[str, Any]) -> bool:
    ingest = sections.get("ingest") or {}
    enrich = sections.get("enrich") or {}
    # first_seen rows are baselines, not events - a seed-backlog day of
    # nothing but baselines should not wake the Stage B agent.
    changes = [c for c in enrich.get("asn_changes") or []
               if c.get("change_type") != "first_seen"]
    return bool(
        ingest.get("rows_ingested")
        or changes
        or sections.get("zeek_matches")
        or sections.get("new_ips_in_known_asns")
        or sections.get("temporal_clusters")
    )


def write(day: date, sections: dict[str, Any]) -> Path:
    """Render and write the digest for `day`. `sections` carries the
    phase results assembled by daily_tracking.py: status (per-phase
    ok/failed), ingest, enrich, enrich_notes, zeek, plus the analytics
    lists (asn_pivots, zeek_matches, new_ips_in_known_asns,
    temporal_clusters, recent_actor_activity)."""
    out_dir = digest_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"{day.isoformat()}.md"
    json_path = out_dir / f"{day.isoformat()}.json"
    json_path.write_text(json.dumps(sections, indent=2, default=str) + "\n")

    lines = [f"# Tracking digest {day.isoformat()}", ""]
    status = sections.get("status") or {}
    failed = {k: v for k, v in status.items() if v != "ok"}
    if failed:
        lines += ["## Phase status", ""]
        lines += [f"- {phase}: {result}" for phase, result in failed.items()]
        lines.append("")

    if not _has_signals(sections):
        lines += [NO_ACTIVITY, ""]
        md_path.write_text("\n".join(lines))
        return md_path

    ingest = sections.get("ingest") or {}
    if ingest.get("rows_ingested"):
        lines += ["## Ingested reports", ""]
        lines += [f"- {f['file']}: {f['ingested']} rows"
                  + (f", {f['skipped']} skipped" if f.get("skipped") else "")
                  for f in ingest.get("files", [])]
        lines.append("")

    notes = sections.get("enrich_notes") or {}
    enrich = sections.get("enrich") or {}
    if notes:
        summary = (f"HoneyLabs calls: {notes.get('hl_calls', 0)}, "
                   f"registry calls: {notes.get('registry_calls', 0)}, "
                   f"errors: {notes.get('errors', 0)}")
        if notes.get("hl_skipped"):
            summary += " - HONEYLABS_API_KEY unset, telemetry skipped"
        if notes.get("budget_exhausted"):
            summary += " - HONEYLABS BUDGET EXHAUSTED mid-run"
        lines += ["## Enrichment", "", summary, ""]

    changes = enrich.get("asn_changes") or []
    real_changes = [c for c in changes if c["change_type"] != "first_seen"]
    if real_changes:
        lines += ["## ASN / netname changes", ""]
        lines += _table(real_changes,
                        ["ip", "actor", "change_type", "old_asn", "new_asn",
                         "new_netname", "confidence"])
        lines.append("")

    zeek = sections.get("zeek_matches") or []
    if zeek:
        lines += ["## Zeek log matches (tracked IPs seen in lab traffic)", ""]
        lines += _table(zeek, ["day", "indicator_value", "actor", "direction",
                               "hit_count", "ports"])
        lines.append("")
    elif (sections.get("zeek") or {}).get("skipped"):
        lines += ["## Zeek log matches", "", "Zeek xref: unavailable "
                  f"({sections['zeek']['skipped']})", ""]

    new_ips = sections.get("new_ips_in_known_asns") or []
    if new_ips:
        lines += ["## New IPs in known-actor ASNs", ""]
        lines += _table(new_ips, ["observed_at", "indicator_value", "asn",
                                  "matches_actor", "attributed_to"])
        lines.append("")

    clusters = sections.get("temporal_clusters") or []
    if clusters:
        lines += ["## Temporal anomalies (weekly IP count >2x median)", ""]
        lines += _table(clusters, ["actor", "week", "ips", "median_ips"])
        lines.append("")

    activity = sections.get("recent_actor_activity") or []
    if activity:
        lines += ["## Actor activity (30d)", ""]
        lines += _table(activity, ["actor", "unique_ips", "last_activity",
                                   "total_observations"])
        lines.append("")

    md_path.write_text("\n".join(lines))
    return md_path
