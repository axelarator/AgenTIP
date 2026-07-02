"""STIX 2.1 (sub)serialization for threat cluster tracking.

Deliberately hand-rolled JSON, not the `stix2` library: the object graph
here is small (Intrusion Set, Attack Pattern, Relationship, Note) and a
hard dependency on a validating library isn't worth it for a tool whose
whole design point is "no external services, minimal deps". If your
downstream consumer needs strict spec validation, run the exported
bundle through `stix2validator` before sharing it.

Design notes:
- Intrusion Set id is minted once per cluster (uuid4) and persisted in
  the cluster's JSON as `stix_id`, so re-exporting the same cluster
  always produces the same Intrusion Set SDO id — required for
  consumers to dedupe/update rather than duplicate on re-import.
- Attack Pattern ids are derived deterministically (uuid5) from the
  ATT&CK technique ID, under a fixed namespace. That means two
  independent exports referencing T1059 mint the *same* attack-pattern
  id, which is what you want for interoperability even without sharing
  MITRE's actual STIX corpus.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

SPEC_VERSION = "2.1"

# Fixed, arbitrary namespace for this tool's deterministic STIX ids.
# Do not change this once clusters have been shared — it would break
# id stability for every previously exported Attack Pattern.
_NAMESPACE = uuid.UUID("d2e5a6f0-2b8e-4f7a-9b1a-6c9a2f3e7b4d")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def new_intrusion_set_id() -> str:
    return f"intrusion-set--{uuid.uuid4()}"


def _attack_pattern_id(technique_id: str) -> str:
    return f"attack-pattern--{uuid.uuid5(_NAMESPACE, technique_id.upper())}"


def _relationship_id(source_ref: str, target_ref: str) -> str:
    return f"relationship--{uuid.uuid5(_NAMESPACE, source_ref + ':' + target_ref)}"


def _note_id(intrusion_set_id: str, date: str, entry: str) -> str:
    return f"note--{uuid.uuid5(_NAMESPACE, intrusion_set_id + date + entry)}"


def to_bundle(data: dict[str, Any]) -> dict[str, Any]:
    """Render a tracked cluster as a STIX 2.1 Bundle."""
    intrusion_set_id = data["stix_id"]
    created = data.get("created") or _now()
    modified = _now()

    intrusion_set: dict[str, Any] = {
        "type": "intrusion-set",
        "spec_version": SPEC_VERSION,
        "id": intrusion_set_id,
        "created": created,
        "modified": modified,
        "name": data["name"],
        "description": data.get("description", ""),
    }
    if data.get("aliases"):
        intrusion_set["aliases"] = data["aliases"]
    if data.get("first_seen"):
        intrusion_set["first_seen"] = data["first_seen"]
    if data.get("last_seen"):
        intrusion_set["last_seen"] = data["last_seen"]

    objects: list[dict[str, Any]] = [intrusion_set]

    for t in data.get("ttps", []):
        ap_id = _attack_pattern_id(t["id"])
        attack_pattern = {
            "type": "attack-pattern",
            "spec_version": SPEC_VERSION,
            "id": ap_id,
            "created": t.get("updated") or created,
            "modified": t.get("updated") or modified,
            "name": t["name"],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": t["id"],
                "url": f"https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/",
            }],
            # Non-standard, namespaced per STIX custom-property rules:
            # our 0-4 detection coverage scale, not part of the spec.
            "x_cti_agent_coverage_status": t["status"],
        }
        objects.append(attack_pattern)
        objects.append({
            "type": "relationship",
            "spec_version": SPEC_VERSION,
            "id": _relationship_id(intrusion_set_id, ap_id),
            "created": t.get("updated") or created,
            "modified": t.get("updated") or modified,
            "relationship_type": "uses",
            "source_ref": intrusion_set_id,
            "target_ref": ap_id,
            "description": t.get("notes", ""),
        })

    for h in data.get("hunt_log", []):
        objects.append({
            "type": "note",
            "spec_version": SPEC_VERSION,
            "id": _note_id(intrusion_set_id, h["date"], h["entry"]),
            "created": h["date"],
            "modified": h["date"],
            "content": h["entry"],
            "object_refs": [intrusion_set_id],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, intrusion_set_id)}",
        "objects": objects,
    }


def from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Parse a STIX 2.1 bundle into the fields `core.py` needs to
    create or merge a cluster. Raises ValueError if no Intrusion Set is
    present — that's the anchor object this tool tracks."""
    objects = bundle.get("objects", [])
    intrusion_sets = [o for o in objects if o.get("type") == "intrusion-set"]
    if not intrusion_sets:
        raise ValueError("bundle has no intrusion-set object to anchor a cluster on")
    iset = intrusion_sets[0]
    intrusion_set_id = iset["id"]

    attack_patterns = {o["id"]: o for o in objects if o.get("type") == "attack-pattern"}
    relationships = [o for o in objects if o.get("type") == "relationship"
                      and o.get("relationship_type") == "uses"
                      and o.get("source_ref") == intrusion_set_id]
    notes = [o for o in objects if o.get("type") == "note"
             and intrusion_set_id in o.get("object_refs", [])]

    ttps = []
    for rel in relationships:
        ap = attack_patterns.get(rel["target_ref"])
        if not ap:
            continue
        technique_id = next(
            (ref["external_id"] for ref in ap.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if not technique_id:
            continue
        ttps.append({
            "id": technique_id,
            "name": ap.get("name", technique_id),
            "status": ap.get("x_cti_agent_coverage_status", 0),
            "notes": rel.get("description", ""),
            "updated": rel.get("modified") or _now(),
        })

    hunt_notes = [
        {"date": n.get("created") or _now(), "entry": n.get("content", "")}
        for n in notes
    ]

    return {
        "name": iset.get("name", "imported-cluster"),
        "description": iset.get("description", ""),
        "stix_id": intrusion_set_id,
        "aliases": iset.get("aliases", []),
        "first_seen": iset.get("first_seen"),
        "last_seen": iset.get("last_seen"),
        "ttps": ttps,
        "notes": hunt_notes,
    }
