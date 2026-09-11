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


def narrative_dir() -> Path:
    """Where Stage B (scripts/daily_narrative.sh) writes its one
    markdown file per day. That script hardcodes the same default path
    rather than reading this env var - CTI_TRACKING_NARRATIVES exists
    here for parity with digest_dir() (tests, dashboard) but isn't yet
    plumbed into the shell script."""
    return Path(os.environ.get("CTI_TRACKING_NARRATIVES",
                               _REPO_ROOT / "data" / "tracking" / "narratives"))


MAX_LIST_ITEMS = 20


def _cap_lists(obj: Any, max_items: int = MAX_LIST_ITEMS) -> Any:
    """Recursively cap any list inside a parsed JSON value to
    `max_items`, so one oversized field can't blow the digest past its
    token budget - e.g. attribute_changes.old_value/new_value, where a
    reverse-IP hostname pivot on a shared-hosting IP can otherwise
    carry thousands of unrelated co-hosted domains (see the 2026-09-10
    Fox Tempest digest blowup)."""
    if isinstance(obj, list):
        capped = [_cap_lists(v, max_items) for v in obj[:max_items]]
        if len(obj) > max_items:
            capped.append(f"...{len(obj) - max_items} more")
        return capped
    if isinstance(obj, dict):
        return {k: _cap_lists(v, max_items) for k, v in obj.items()}
    return obj


def _fmt(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    if value is None:
        return "-"
    if isinstance(value, str) and value[:1] in "[{":
        # old_value/new_value columns come back as JSON text (see
        # store.py's JSON column type) - cap any oversized list before
        # it hits the table.
        try:
            return json.dumps(_cap_lists(json.loads(value)))
        except (ValueError, TypeError):
            return value
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
    register = sections.get("register") or {}
    # first_seen rows are baselines, not events - a seed-backlog day of
    # nothing but baselines should not wake the Stage B agent.
    changes = [c for c in enrich.get("asn_changes") or []
               if c.get("change_type") != "first_seen"]
    return bool(
        ingest.get("rows_ingested")
        or register.get("actors_registered")
        or changes
        or sections.get("attribute_changes")  # already excludes first_seen, see ATTRIBUTE_CHANGES
        or sections.get("new_indicators_in_known_asns")
        or sections.get("cross_actor_asn_overlap")
        or sections.get("temporal_clusters")
    )


def write(day: date, sections: dict[str, Any]) -> Path:
    """Render and write the digest for `day`. `sections` carries the
    phase results assembled by daily_tracking.py: status (per-phase
    ok/failed), ingest, register, pivot_sweep, enrich, enrich_notes,
    plus the analytics lists (asn_pivots, attribute_changes,
    port_patterns, new_indicators_in_known_asns,
    cross_actor_asn_overlap, temporal_clusters, recent_actor_activity).

    Deliberately excludes Zeek/OpenSearch/Arkime cross-referencing -
    that's a separate, on-demand capability
    (cti_tools.tracking.opensearch_xref.run_daily_xref), not part of
    this routine daily narrative (see daily_tracking.py's own docstring)."""
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

    sweep_errors = (sections.get("pivot_sweep") or {}).get("errors") or {}
    if sweep_errors:
        lines += ["## Pivot sweep issues", ""]
        lines += [f"- {slug}: {err}" for slug, err in sweep_errors.items()]
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

    register = sections.get("register") or {}
    if register.get("actors_registered"):
        lines += ["## New clusters registered for tracking", ""]
        lines += [f"- {actor}: {count} IPs"
                  for actor, count in register.get("ips_by_actor", {}).items()]
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

    attr_changes = sections.get("attribute_changes") or []
    if attr_changes:
        lines += ["## Indicator attribute changes (ports/certificates)", ""]
        lines += _table(attr_changes,
                        ["detected_at", "indicator_value", "actor", "attribute",
                         "change_type", "old_value", "new_value", "confidence"])
        lines.append("")

    patterns = sections.get("port_patterns") or []
    if patterns:
        # HoneyLabs-observed scan/attack ports per actor - distinct from
        # the attribute-changes table above, which tracks Shodan's *open
        # service* ports on tracked infra. Keep the header explicit so
        # Stage B doesn't conflate "actor gets scanned on port X" with
        # "actor's C2 listens on port X".
        lines += ["## Port scan patterns (HoneyLabs telemetry, per actor)", ""]
        lines += _table(patterns, ["actor", "port", "ip_count", "last_seen"])
        lines.append("")

    new_ips = sections.get("new_indicators_in_known_asns") or []
    if new_ips:
        lines += ["## New unattributed IPs in known-actor ASNs "
                  "(first observation ever falls in this window)", ""]
        lines += _table(new_ips, ["observed_at", "indicator_value", "asn",
                                  "matches_actor", "first_seen"])
        lines.append("")

    overlap = sections.get("cross_actor_asn_overlap") or []
    if overlap:
        lines += ["## Cross-actor ASN overlap "
                  "(already attributed elsewhere - NOT new, lead only)", ""]
        lines += _table(overlap, ["indicator_value", "asn", "matches_actor",
                                  "attributed_to", "first_seen"])
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
