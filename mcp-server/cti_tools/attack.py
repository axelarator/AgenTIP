"""Bundled MITRE ATT&CK Enterprise technique reference data.

A static, flat technique_id -> canonical name lookup, generated once
from the official MITRE STIX corpus (attack-stix-data) and committed
under attack_data/ so technique_id/name validation works fully offline
- consistent with this tool's "no external services" design. Nothing
here makes a network call at runtime.

Regenerate with `scripts/refresh_attack_data.py` when a new ATT&CK
release ships (revoked/deprecated techniques change over time - e.g.
T1562 "Impair Defenses" was revoked and replaced by T1685 "Disable or
Modify Tools" upstream).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_DATA_PATH = Path(__file__).with_name("attack_data") / "enterprise_attack_techniques.json"
_TECHNIQUES: dict[str, dict[str, Any]] | None = None


def _load() -> dict[str, dict[str, Any]]:
    global _TECHNIQUES
    if _TECHNIQUES is None:
        _TECHNIQUES = json.loads(_DATA_PATH.read_text())
    return _TECHNIQUES


def lookup(technique_id: str) -> dict[str, Any] | None:
    """Raw reference entry for a technique ID, or None if unknown."""
    return _load().get(technique_id.upper())


def canonical_name(technique_id: str) -> str | None:
    """The name this tool's other data (cluster TTP notes, STIX export)
    uses for a technique: the sub-technique's own name prefixed with its
    parent's, e.g. "Command and Scripting Interpreter: PowerShell" for
    T1059.001 - matching the convention already used across this repo's
    cluster data, not ATT&CK's bare sub-technique name."""
    entry = lookup(technique_id)
    return entry["display_name"] if entry else None


def validate(technique_id: str, technique_name: str) -> str | None:
    """Return a human-readable warning if technique_id is unknown,
    revoked/deprecated, or technique_name doesn't match either the bare
    ATT&CK name or this repo's "Parent: Sub" display convention. Returns
    None when everything checks out. Never raises - this is advisory,
    not a hard gate, since local/private technique IDs or a slightly
    stale bundled corpus shouldn't block an analyst from recording what
    they observed."""
    entry = lookup(technique_id)
    if entry is None:
        return f"{technique_id} is not a known ATT&CK Enterprise technique ID (per bundled corpus)"

    if entry["revoked"]:
        replacement = entry.get("revoked_by")
        hint = f"; revoked, replaced by {replacement}" if replacement else "; revoked upstream"
        return f"{technique_id} ({entry['name']}) has been revoked in ATT&CK{hint}"

    if entry["deprecated"]:
        return f"{technique_id} ({entry['name']}) is deprecated in ATT&CK"

    given = technique_name.strip().lower()
    if given not in (entry["name"].lower(), entry["display_name"].lower()):
        return (f"{technique_id} canonical name is {entry['display_name']!r}; "
                f"got {technique_name!r} - double check this is the right technique")
    return None
