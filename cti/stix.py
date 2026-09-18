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

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any

SPEC_VERSION = "2.1"

# Map this tool's hash algo prefixes to STIX hash-algorithm names and
# back, and infer algo from bare-hash length when no prefix is stored.
_HASH_ALGO_TO_STIX = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
_HASH_STIX_TO_ALGO = {v: k for k, v in _HASH_ALGO_TO_STIX.items()}
_HASH_LEN_TO_STIX = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

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


def _relationship_id(source_ref: str, target_ref: str, relationship_type: str) -> str:
    # relationship_type is part of the namespaced input (not just the
    # source/target pair) so two different relationship types between
    # the same pair of objects - e.g. a TTP "uses" link and, separately,
    # a cross-cluster "uses" vs. "related-to" link - never collide.
    return f"relationship--{uuid.uuid5(_NAMESPACE, source_ref + ':' + target_ref + ':' + relationship_type)}"


def _note_id(intrusion_set_id: str, date: str, entry: str) -> str:
    return f"note--{uuid.uuid5(_NAMESPACE, intrusion_set_id + date + entry)}"


def _indicator_id(pattern: str) -> str:
    # Deterministic from the STIX pattern, so the same IOC exported from
    # two different clusters mints the same Indicator id and merges to a
    # single object (mirroring how Attack Pattern ids dedupe).
    return f"indicator--{uuid.uuid5(_NAMESPACE, pattern)}"


def _pattern_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def observable_to_pattern(category: str, value: str) -> str | None:
    """STIX 2.1 pattern for one tracked observable, or None for
    categories that have no clean STIX Cyber-observable representation
    (cves -> would be a Vulnerability SDO, wallets -> no standard SCO,
    ja4/ja4s/ja4h/ja4l/ja4x/ja4t/ja4ts/ja4ssh/jarm -> no standard SCO for
    TLS/TCP/SSH fingerprints), which are simply left out of the bundle
    rather than forced."""
    if category == "hashes":
        if ":" in value:
            algo, digest = value.split(":", 1)
            # A certificate's own SHA-256 fingerprint (filed as
            # `cert-sha256:<hash>` from the live TLS grab) is an
            # x509-certificate, not a file hash - it has a clean SCO.
            if algo.lower() == "cert-sha256":
                return f"[x509-certificate:hashes.'SHA-256' = '{_pattern_escape(digest)}']"
            stix_algo = _HASH_ALGO_TO_STIX.get(algo.lower())
        else:
            digest = value
            stix_algo = _HASH_LEN_TO_STIX.get(len(value))
        if not stix_algo:
            return None
        return f"[file:hashes.'{stix_algo}' = '{_pattern_escape(digest)}']"
    if category == "domains":
        return f"[domain-name:value = '{_pattern_escape(value)}']"
    if category == "ips":
        try:
            objtype = "ipv6-addr" if ipaddress.ip_address(value).version == 6 else "ipv4-addr"
        except ValueError:
            objtype = "ipv4-addr"
        return f"[{objtype}:value = '{_pattern_escape(value)}']"
    if category == "urls":
        return f"[url:value = '{_pattern_escape(value)}']"
    if category == "emails":
        return f"[email-addr:value = '{_pattern_escape(value)}']"
    return None


_PATTERN_RE = re.compile(r"\[\s*([a-z0-9-]+):(\S+?)\s*=\s*'(.*)'\s*\]")


def pattern_to_observable(pattern: str) -> tuple[str, str] | None:
    """Inverse of observable_to_pattern: (category, value) from a simple
    single-comparison STIX pattern, or None if it isn't one we emit."""
    m = _PATTERN_RE.match(pattern or "")
    if not m:
        return None
    objtype, path, raw = m.groups()
    value = raw.replace("\\'", "'").replace("\\\\", "\\")
    if objtype == "file":
        algo_m = re.search(r"hashes\.'([^']+)'", path)
        algo = _HASH_STIX_TO_ALGO.get(algo_m.group(1)) if algo_m else None
        if not algo:
            return None
        return "hashes", f"{algo}:{value}"
    if objtype == "x509-certificate":
        return "hashes", f"cert-sha256:{value}"
    return {
        "domain-name": ("domains", value),
        "ipv4-addr": ("ips", value),
        "ipv6-addr": ("ips", value),
        "url": ("urls", value),
        "email-addr": ("emails", value),
    }.get(objtype)


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
            "id": _relationship_id(intrusion_set_id, ap_id, "uses"),
            "created": t.get("updated") or created,
            "modified": t.get("updated") or modified,
            "relationship_type": "uses",
            "source_ref": intrusion_set_id,
            "target_ref": ap_id,
            "description": t.get("notes", ""),
        })

    for rel in data.get("relationships", []):
        objects.append({
            "type": "relationship",
            "spec_version": SPEC_VERSION,
            "id": _relationship_id(intrusion_set_id, rel["target_stix_id"], rel["relationship_type"]),
            "created": rel.get("created") or created,
            "modified": rel.get("created") or modified,
            "relationship_type": rel["relationship_type"],
            "source_ref": intrusion_set_id,
            "target_ref": rel["target_stix_id"],
            "description": rel.get("description", ""),
            # Custom property (x_ prefix per STIX spec) carrying the
            # target cluster's name through export: the target
            # Intrusion Set object itself isn't included in this
            # cluster's bundle, so its name wouldn't otherwise survive
            # a round trip through from_bundle on another system.
            "x_cti_agent_target_name": rel["target_cluster"],
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

    # Tracked observables become STIX Indicators (with a pattern) tied to
    # the Intrusion Set by an `indicates` relationship, so the IOCs a
    # cluster has accumulated survive an export instead of being dropped.
    for category, items in data.get("observables", {}).items():
        for o in items:
            pattern = observable_to_pattern(category, o["value"])
            if not pattern:
                continue
            ind_id = _indicator_id(pattern)
            first = o.get("first_seen") or created
            last = o.get("last_seen") or modified
            objects.append({
                "type": "indicator",
                "spec_version": SPEC_VERSION,
                "id": ind_id,
                "created": first,
                "modified": last,
                "name": o["value"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": first,
                # Custom prop so the exact category round-trips even for
                # patterns pattern_to_observable could otherwise only
                # approximate; parsing falls back to the pattern if absent.
                "x_cti_agent_category": category,
            })
            objects.append({
                "type": "relationship",
                "spec_version": SPEC_VERSION,
                "id": _relationship_id(ind_id, intrusion_set_id, "indicates"),
                "created": first,
                "modified": last,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": intrusion_set_id,
            })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, intrusion_set_id)}",
        "objects": objects,
    }


def merge_bundles(bundles: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge several single-cluster bundles (as produced by to_bundle)
    into one self-contained bundle. Objects are deduplicated by id -
    two clusters sharing an ATT&CK technique produce the same
    deterministic Attack Pattern id, for instance, and should end up as
    one object in the merged bundle, not two copies of it."""
    objects_by_id: dict[str, Any] = {}
    for bundle in bundles:
        for obj in bundle.get("objects", []):
            objects_by_id.setdefault(obj["id"], obj)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NAMESPACE, '|'.join(sorted(objects_by_id)))}",
        "objects": list(objects_by_id.values()),
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
    all_relationships = [o for o in objects if o.get("type") == "relationship"
                          and o.get("source_ref") == intrusion_set_id]
    ttp_relationships = [r for r in all_relationships
                         if r.get("relationship_type") == "uses"
                         and r.get("target_ref") in attack_patterns]
    # Cross-cluster links: same source Intrusion Set, but the target
    # isn't one of this bundle's own Attack Patterns - i.e. a
    # relationship to another cluster's Intrusion Set (which, per
    # to_bundle, isn't itself included in a single-cluster export).
    cross_cluster_relationships = [r for r in all_relationships
                                    if r.get("target_ref") not in attack_patterns]
    notes = [o for o in objects if o.get("type") == "note"
             and intrusion_set_id in o.get("object_refs", [])]

    ttps = []
    for rel in ttp_relationships:
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

    relationships = [
        {
            "relationship_type": rel["relationship_type"],
            "target_cluster": rel.get("x_cti_agent_target_name", rel["target_ref"]),
            "target_stix_id": rel["target_ref"],
            "description": rel.get("description", ""),
            "source": "",
            "created": rel.get("created") or _now(),
        }
        for rel in cross_cluster_relationships
    ]

    hunt_notes = [
        {"date": n.get("created") or _now(), "entry": n.get("content", "")}
        for n in notes
    ]

    # Reconstruct tracked observables from any Indicator objects in the
    # bundle (the inverse of to_bundle's Indicator emission), deduped
    # per category, so IOCs survive a full export/import round trip.
    observables: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") != "indicator":
            continue
        parsed = pattern_to_observable(o.get("pattern", ""))
        if not parsed:
            continue
        category, value = parsed
        category = o.get("x_cti_agent_category", category)
        bucket = observables.setdefault(category, [])
        if value not in bucket:
            bucket.append(value)

    return {
        "name": iset.get("name", "imported-cluster"),
        "description": iset.get("description", ""),
        "stix_id": intrusion_set_id,
        "aliases": iset.get("aliases", []),
        "first_seen": iset.get("first_seen"),
        "last_seen": iset.get("last_seen"),
        "ttps": ttps,
        "notes": hunt_notes,
        "relationships": relationships,
        "observables": observables,
    }
