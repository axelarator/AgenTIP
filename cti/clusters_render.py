"""Rendering a cluster record as markdown.

Split out of core.py. Pure by construction: it takes the cluster dict and
the destination path, so it has no idea where the store lives and cannot
be caught out by DATA_DIR being patched to one directory while
CTI_DATA_DIR points at another - which is the state the test suite
actually runs in, and the reason several other candidates for extraction
were left in core.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .report import ingest as report_ingest
from .util import atomic_write_text

OBSERVABLE_CATEGORIES = report_ingest.OBSERVABLE_CATEGORIES

# Copied verbatim from core, not re-derived: _date_only's behaviour on a
# partial date depends on the optional day group.
_DATE_ONLY_RE = re.compile(r"^(\d{4})-(\d{2})(?:-(\d{2}))?")

def _date_only(value: str | None) -> str | None:
    """Normalize an ISO-ish date/datetime/year-month string to plain
    YYYY-MM-DD, or return the value unchanged if it doesn't start with
    at least YYYY-MM. Observable-level first_seen/last_seen/
    status_checked are always machine-generated via now_iso() so this is a
    no-op slice for them, but cluster-level first_seen/last_seen
    (update_profile's free-text params) show up in the wild as "2025-09"
    (month precision only) or "2022-12-01T00:00:00Z" (full datetime) as
    well as plain dates - a day-less value is padded to its 1st (the
    conventional stand-in for "day unknown") so every first/last-seen
    display in the app agrees on one format; anything that doesn't even
    have YYYY-MM is passed through unmangled rather than corrupted."""
    if not value:
        return None
    m = _DATE_ONLY_RE.match(value)
    if not m:
        return value
    year, month, day = m.groups()
    return f"{year}-{month}-{day or '01'}"
def write_markdown(data: dict[str, Any], md_path: Path) -> None:
    """Regenerate the human-readable view. Never hand-edit the .md file —
    it's derived from the .json, which is the source of truth."""
    d = data["diamond"]
    lines = [
        f"# {data['name']}",
        "",
        data.get("description", ""),
        "",
        "## Profile",
        f"- STIX ID: `{data.get('stix_id', 'unknown')}`",
        f"- Aliases: {', '.join(data.get('aliases') or []) or 'none'}",
        f"- Confidence: {data.get('confidence')}",
        f"- First seen: {_date_only(data.get('first_seen')) or 'unknown'}",
        f"- Last seen: {_date_only(data.get('last_seen')) or 'unknown'}",
        "",
        "## Diamond model",
        f"- Adversary: {d['adversary']}",
        f"- Capability: {d['capability']}",
        f"- Infrastructure: {d['infrastructure']}",
        f"- Victim: {d['victim']}",
        "",
        "## TTP coverage",
        "| Technique | Name | Status | Notes | Updated |",
        "|---|---|---|---|---|",
    ]
    for t in data["ttps"]:
        lines.append(f"| {t['id']} | {t['name']} | {t['status']} | "
                      f"{t.get('notes', '')} | {t['updated']} |")
    lines += ["", "## Detection inventory (this cluster's detections plus technique-scoped ones from the shared registry)",
              "| ID | Description | Status | Scope | Covers | Updated |", "|---|---|---|---|---|---|"]
    for det in data["detections"]:
        lines.append(f"| {det['id']} | {det['description']} | {det['status']} | "
                      f"{det.get('scope', 'technique')} | "
                      f"{', '.join(det.get('covers_ttps', [])) or ', '.join(det['technique_ids'])} | "
                      f"{det['updated']} |")
    lines += ["", "## Relationships"]
    for rel in data.get("relationships", []):
        lines.append(f"- **{rel['relationship_type']}** → {rel['target_cluster']}"
                      f"{' — ' + rel['description'] if rel.get('description') else ''}")
    if not data.get("relationships"):
        lines.append("none")
    lines += ["", "## Gaps backlog", "| Description | Priority | Created |",
              "|---|---|---|"]
    for g in data["gaps"]:
        lines.append(f"| {g['description']} | {g['priority']} | {g['created']} |")
    lines += ["", "## Observables"]
    obs = data["observables"]
    for category in OBSERVABLE_CATEGORIES:
        items = obs.get(category, [])
        lines.append(f"\n### {category.capitalize()} ({len(items)})")
        if items:
            lines.append("| Value | Status | Sources | First seen | Last seen | Last checked |")
            lines.append("|---|---|---|---|---|---|")
            for o in items:
                # last_seen tracks provenance (last time a source re-filed
                # this value), not liveness - status_checked (from
                # pivot_cluster) is the "last actually re-verified" date,
                # so it gets its own column rather than piggybacking on
                # Status like it used to.
                lines.append(f"| {o['value']} | {o.get('status') or ''} | {', '.join(o['sources'])} | "
                              f"{_date_only(o.get('first_seen')) or ''} | "
                              f"{_date_only(o.get('last_seen')) or ''} | "
                              f"{_date_only(o.get('status_checked')) or ''} |")
        else:
            lines.append("none")
    lines += ["", "## Report sources"]
    for r in data["report_sources"]:
        lines.append(f"- **{r['ingested']}** — {r['source']} "
                      f"(TTPs: {', '.join(r['ttps_found']) or 'none'})")
    lines += ["", "## Hunt log (append-only)"]
    for h in data["hunt_log"]:
        lines.append(f"- **{h['date']}** — {h['entry']}")
    atomic_write_text(md_path, "\n".join(lines) + "\n")
