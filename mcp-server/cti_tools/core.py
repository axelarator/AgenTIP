"""Core business logic for threat cluster tracking.

Protocol-agnostic on purpose: server.py (MCP) and cli.py (Pi / any Bash
tool) both call these same functions so the two invocation surfaces stay
identical. No MCP or argparse imports belong in this file.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import stix

# Data lives at the repo root (`<repo>/data/clusters`) so it's shared
# across every harness surface (MCP server, CLI, any future UI) rather
# than nested inside mcp-server/. Override with CTI_DATA_DIR for tests
# or alternate deployments (e.g. a separate private data repo).
_REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("CTI_DATA_DIR", _REPO_ROOT / "data" / "clusters"))

# 0-4 TTP coverage scale -> ATT&CK Navigator color. Edit to match your
# own detection lifecycle if you change the scale in the skill.
STATUS_COLORS = {
    0: "#eeeeee",  # no coverage
    1: "#fadb87",  # idea only
    2: "#ffb347",  # built, unvalidated
    3: "#8bc98b",  # validated, in production
    4: "#4f9d4f",  # validated + tuned
}

STATUS_LABELS = {
    0: "no coverage",
    1: "idea only",
    2: "built, unvalidated",
    3: "validated, in production",
    4: "validated + tuned",
}


class ClusterNotFound(Exception):
    pass


def _path(name: str) -> Path:
    safe = name.strip().lower().replace(" ", "-")
    return DATA_DIR / f"{safe}.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_cluster(name: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "created": _now(),
        # Stable STIX 2.1 Intrusion Set identifier, minted once and kept
        # for the life of the cluster so shared bundles stay dedupable.
        "stix_id": stix.new_intrusion_set_id(),
        "aliases": [],
        "confidence": None,        # 0-100, STIX confidence scale
        "first_seen": None,
        "last_seen": None,
        "diamond": {
            "adversary": "unknown",
            "capability": "unknown",
            "infrastructure": "unknown",
            "victim": "unknown",
        },
        "ttps": [],       # [{id, name, status, notes, updated}]
        "hunt_log": [],   # [{date, entry}] append-only
        "detections": [], # [{id, description, status, updated}]
        "gaps": [],       # [{description, priority, created}]
    }


def _migrate(data: dict[str, Any]) -> dict[str, Any]:
    """Backfill fields added after a cluster was first created, so old
    JSON files on disk keep loading without a manual migration step."""
    data.setdefault("stix_id", stix.new_intrusion_set_id())
    data.setdefault("aliases", [])
    data.setdefault("confidence", None)
    data.setdefault("first_seen", None)
    data.setdefault("last_seen", None)
    data.setdefault("diamond", {
        "adversary": "unknown", "capability": "unknown",
        "infrastructure": "unknown", "victim": "unknown",
    })
    for key in ("ttps", "hunt_log", "detections", "gaps"):
        data.setdefault(key, [])
    return data


def load_cluster(name: str) -> dict[str, Any]:
    p = _path(name)
    if not p.exists():
        raise ClusterNotFound(f"No cluster named {name!r}")
    return _migrate(json.loads(p.read_text()))


def save_cluster(data: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(data["name"])
    p.write_text(json.dumps(data, indent=2))
    _write_markdown(data)


def list_clusters() -> list[str]:
    if not DATA_DIR.exists():
        return []
    return sorted(p.stem for p in DATA_DIR.glob("*.json"))


def create_cluster(name: str, description: str = "") -> dict[str, Any]:
    if _path(name).exists():
        raise FileExistsError(f"Cluster {name!r} already exists")
    data = _new_cluster(name, description)
    save_cluster(data)
    return data


def get_cluster(name: str) -> dict[str, Any]:
    return load_cluster(name)


def update_profile(name: str, adversary: str | None = None,
                    capability: str | None = None,
                    infrastructure: str | None = None,
                    victim: str | None = None,
                    aliases: list[str] | None = None,
                    confidence: int | None = None,
                    first_seen: str | None = None,
                    last_seen: str | None = None) -> dict[str, Any]:
    """Update Diamond Model fields and/or STIX-flavored profile metadata.
    Only provided fields are changed; everything else is left as-is."""
    data = load_cluster(name)
    d = data["diamond"]
    if adversary is not None:
        d["adversary"] = adversary
    if capability is not None:
        d["capability"] = capability
    if infrastructure is not None:
        d["infrastructure"] = infrastructure
    if victim is not None:
        d["victim"] = victim
    if aliases is not None:
        data["aliases"] = aliases
    if confidence is not None:
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be 0-100")
        data["confidence"] = confidence
    if first_seen is not None:
        data["first_seen"] = first_seen
    if last_seen is not None:
        data["last_seen"] = last_seen
    save_cluster(data)
    return data


def update_ttp(name: str, technique_id: str, technique_name: str,
                status: int, notes: str = "") -> dict[str, Any]:
    if not 0 <= status <= 4:
        raise ValueError("status must be 0-4")
    data = load_cluster(name)
    ttps = data["ttps"]
    for t in ttps:
        if t["id"] == technique_id:
            t.update(name=technique_name, status=status, notes=notes,
                      updated=_now())
            break
    else:
        ttps.append({"id": technique_id, "name": technique_name,
                      "status": status, "notes": notes, "updated": _now()})
    save_cluster(data)
    return data


def append_hunt_log(name: str, entry: str) -> dict[str, Any]:
    data = load_cluster(name)
    data["hunt_log"].append({"date": _now(), "entry": entry})
    save_cluster(data)
    return data


def add_detection(name: str, detection_id: str, description: str,
                   status: str = "draft") -> dict[str, Any]:
    data = load_cluster(name)
    data["detections"].append({
        "id": detection_id, "description": description,
        "status": status, "updated": _now(),
    })
    save_cluster(data)
    return data


def add_gap(name: str, description: str, priority: str = "medium") -> dict[str, Any]:
    data = load_cluster(name)
    data["gaps"].append({
        "description": description, "priority": priority, "created": _now(),
    })
    save_cluster(data)
    return data


def export_navigator_layer(name: str) -> dict[str, Any]:
    data = load_cluster(name)
    return {
        "name": f"{data['name']} TTP coverage",
        "versions": {"attack": "16", "navigator": "5.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": data.get("description", ""),
        "techniques": [
            {
                "techniqueID": t["id"],
                "score": t["status"],
                "color": STATUS_COLORS.get(t["status"], "#eeeeee"),
                "comment": t.get("notes", ""),
            }
            for t in data["ttps"]
        ],
        "gradient": {
            "colors": [STATUS_COLORS[0], STATUS_COLORS[4]],
            "minValue": 0,
            "maxValue": 4,
        },
        "legendItems": [
            {"label": f"{k} - {v}", "color": STATUS_COLORS[k]}
            for k, v in STATUS_LABELS.items()
        ],
    }


def export_stix_bundle(name: str) -> dict[str, Any]:
    """Export the cluster as a STIX 2.1 bundle (Intrusion Set + Attack
    Patterns + Relationships + Notes) for sharing outside this tool."""
    data = load_cluster(name)
    return stix.to_bundle(data)


def import_stix_bundle(bundle: dict[str, Any], name: str | None = None,
                        overwrite: bool = False) -> dict[str, Any]:
    """Create or update a cluster from an external STIX 2.1 bundle
    containing an Intrusion Set (plus optional Attack Patterns /
    Relationships / Notes). Existing local fields not present in the
    bundle (hunt log, detections, gaps) are preserved on update."""
    parsed = stix.from_bundle(bundle)
    cluster_name = name or parsed["name"]
    p = _path(cluster_name)
    if p.exists():
        if not overwrite:
            raise FileExistsError(
                f"Cluster {cluster_name!r} already exists; pass overwrite=True to merge")
        data = load_cluster(cluster_name)
        data["stix_id"] = parsed["stix_id"]
        data["description"] = parsed["description"] or data["description"]
        data["aliases"] = sorted(set(data["aliases"]) | set(parsed["aliases"]))
        data["first_seen"] = parsed["first_seen"] or data["first_seen"]
        data["last_seen"] = parsed["last_seen"] or data["last_seen"]
        existing_ids = {t["id"] for t in data["ttps"]}
        for t in parsed["ttps"]:
            if t["id"] not in existing_ids:
                data["ttps"].append(t)
        for note in parsed["notes"]:
            data["hunt_log"].append(note)
    else:
        data = _new_cluster(cluster_name, parsed["description"])
        data["stix_id"] = parsed["stix_id"]
        data["aliases"] = parsed["aliases"]
        data["first_seen"] = parsed["first_seen"]
        data["last_seen"] = parsed["last_seen"]
        data["ttps"] = parsed["ttps"]
        data["hunt_log"] = parsed["notes"]
    save_cluster(data)
    return data


def _write_markdown(data: dict[str, Any]) -> None:
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
        f"- First seen: {data.get('first_seen') or 'unknown'}",
        f"- Last seen: {data.get('last_seen') or 'unknown'}",
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
    lines += ["", "## Detection inventory",
              "| ID | Description | Status | Updated |", "|---|---|---|---|"]
    for det in data["detections"]:
        lines.append(f"| {det['id']} | {det['description']} | "
                      f"{det['status']} | {det['updated']} |")
    lines += ["", "## Gaps backlog", "| Description | Priority | Created |",
              "|---|---|---|"]
    for g in data["gaps"]:
        lines.append(f"| {g['description']} | {g['priority']} | {g['created']} |")
    lines += ["", "## Hunt log (append-only)"]
    for h in data["hunt_log"]:
        lines.append(f"- **{h['date']}** — {h['entry']}")
    md_path = _path(data["name"]).with_suffix(".md")
    md_path.write_text("\n".join(lines) + "\n")
