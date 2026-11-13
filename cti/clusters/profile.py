"""The analyst-written parts of a cluster profile: description and Diamond
fields, ATT&CK techniques, the hunt log, detections, relationships and gaps.
"""
from __future__ import annotations

from typing import Any

from .. import attack
from ..util import now_iso
from .storage import (
    DETECTION_SCOPES, _detection_scope, _load_detection_registry, _reverse_index,
    _save_detection_registry, _synchronized, list_clusters, load_cluster,
    save_cluster,
)


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


@_synchronized
def update_profile(name: str, description: str | None = None,
                    adversary: str | None = None,
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
    if description is not None:
        data["description"] = description
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


@_synchronized
def update_ttp(name: str, technique_id: str, technique_name: str,
                status: int, notes: str = "") -> dict[str, Any]:
    if not 0 <= status <= 4:
        raise ValueError("status must be 0-4")
    # ATT&CK ids are upper case. remove_ttp already matched without regard
    # to case; this did not, so t1059 and T1059 could both be stored.
    technique_id = technique_id.strip().upper()
    data = load_cluster(name)
    ttps = data["ttps"]
    for t in ttps:
        if t["id"].upper() == technique_id:
            t["id"] = technique_id
            t.update(name=technique_name, status=status, notes=notes,
                      updated=now_iso())
            break
    else:
        ttps.append({"id": technique_id, "name": technique_name,
                      "status": status, "notes": notes, "updated": now_iso()})
    save_cluster(data)
    # Advisory only, checked against the bundled MITRE corpus - never
    # blocks the write, since a stale bundle or a legitimately custom ID
    # shouldn't stop an analyst from recording what they observed.
    warning = attack.validate(technique_id, technique_name)
    if warning:
        data = {**data, "warning": warning}
    return data


@_synchronized
def remove_ttp(name: str, technique_id: str) -> dict[str, Any]:
    """Remove a technique from a cluster's TTP coverage table - the
    counterpart to update_ttp, for dropping a mis-attributed technique or
    one whose ATT&CK ID was revoked (update_ttp's validation flags those
    but can't remove them, since it only upserts). Matches technique_id
    case-insensitively. Raises if the cluster or the technique isn't
    found. The returned cluster carries a transient `removed` id."""
    data = load_cluster(name)
    tid = technique_id.strip().upper()
    kept = [t for t in data["ttps"] if t["id"].upper() != tid]
    if len(kept) == len(data["ttps"]):
        raise ValueError(f"no technique {technique_id!r} tracked on cluster {name!r}")
    data["ttps"] = kept
    save_cluster(data)
    return {**data, "removed": technique_id}


@_synchronized
def append_hunt_log(name: str, entry: str) -> dict[str, Any]:
    data = load_cluster(name)
    data["hunt_log"].append({"date": now_iso(), "entry": entry})
    save_cluster(data)
    return data


@_synchronized
def add_detection(detection_id: str, description: str, technique_ids: list[str],
                   status: str = "draft", cluster_name: str | None = None,
                   scope: str | None = None) -> dict[str, Any]:
    """Upsert a detection into the shared detection registry
    (data/clusters/_registry/detections.json) rather than into one
    cluster's own record.

    scope decides which clusters the detection is joined onto:
    "technique" for a generic behavioral detection that covers every
    adversary using the technique (joined by technique_id), "cluster"
    for one keyed to a specific actor's artifacts (shown only on the
    clusters it names). Defaults to "cluster" when cluster_name is given
    and "technique" otherwise; on an update it's left unchanged unless
    passed. A cluster-scoped detection must name at least one cluster.

    technique_ids is required (at least one) - that's what makes the
    detection discoverable from get_technique_usage(). cluster_name adds
    that cluster to the detection's clusters; pass it to also get the
    refreshed cluster view back.
    """
    if not technique_ids:
        raise ValueError("add_detection requires at least one technique_id")
    if scope is not None and scope not in DETECTION_SCOPES:
        raise ValueError(f"scope must be one of {DETECTION_SCOPES}, got {scope!r}")
    if cluster_name is not None:
        load_cluster(cluster_name)  # raises ClusterNotFound if it doesn't exist

    registry = _load_detection_registry()
    now = now_iso()
    existing = next((d for d in registry["detections"] if d["id"] == detection_id), None)
    new_scope = scope or (_detection_scope(existing) if existing
                          else ("cluster" if cluster_name else "technique"))
    new_clusters = list(existing["clusters"]) if existing else []
    if cluster_name and cluster_name not in new_clusters:
        new_clusters.append(cluster_name)
    if new_scope == "cluster" and not new_clusters:
        raise ValueError("a cluster-scoped detection needs cluster_name")

    # Clusters it was joined onto before this update, so any it drops off
    # (e.g. narrowed to cluster scope) get their views refreshed too.
    before = {c for c in list_clusters()
              if existing and any(d["id"] == detection_id
                                  for d in load_cluster(c)["detections"])}

    if existing:
        existing.update(description=description, status=status, scope=new_scope,
                        technique_ids=sorted(set(existing["technique_ids"]) | set(technique_ids)),
                        clusters=new_clusters, updated=now)
    else:
        registry["detections"].append({
            "id": detection_id, "description": description, "status": status,
            "scope": new_scope, "technique_ids": sorted(set(technique_ids)),
            "clusters": new_clusters, "created": now, "updated": now,
        })
    _save_detection_registry(registry)

    # The cluster JSON's `detections` field (and its rendered markdown)
    # is a snapshot from the last time that cluster was saved - refresh
    # every cluster this detection now joins onto or just left, not only
    # cluster_name, so no cluster's .md view is left stale.
    for cname in list_clusters():
        data = load_cluster(cname)
        joined = any(d["id"] == detection_id for d in data["detections"])
        if joined or cname in before:
            save_cluster(data)

    if cluster_name:
        return load_cluster(cluster_name)
    return next(d for d in registry["detections"] if d["id"] == detection_id)


def get_technique_usage(technique_id: str | None = None) -> dict[str, Any]:
    """Reverse index from technique to adversary: for a given ATT&CK
    technique, which tracked clusters use it and what detections (if
    any) cover it - the "who uses what" view that per-cluster TTP
    tables alone don't answer. Omit technique_id to get the full matrix
    across every technique any tracked cluster has logged."""
    by_technique = _reverse_index()["techniques"]

    if technique_id is None:
        return {"techniques": sorted(by_technique.values(), key=lambda e: e["technique_id"])}

    tid = technique_id.upper()
    entry = next((e for e in by_technique.values() if e["technique_id"].upper() == tid), None)
    if entry is None:
        entry = {"technique_id": tid, "name": attack.canonical_name(tid) or tid,
                  "used_by": [], "detections": []}
    return entry


@_synchronized
def add_relationship(name: str, relationship_type: str, target_cluster: str,
                      description: str = "", source: str = "") -> dict[str, Any]:
    """Record a structured relationship from this cluster to another
    tracked cluster - e.g. "uses" for a supply-chain/tooling link
    (customer of an MSaaS, deploys another cluster's backdoor), or
    "related-to" for a suspected-but-unconfirmed overlap. This is the
    structured counterpart to the free-text "See cluster 'X'"
    cross-references already common in hunt log entries; it exports as
    a real STIX Relationship between the two Intrusion Sets rather than
    prose the receiving system has to parse."""
    data = load_cluster(name)
    target = load_cluster(target_cluster)  # raises ClusterNotFound if it doesn't exist
    data["relationships"].append({
        "relationship_type": relationship_type,
        "target_cluster": target["name"],
        "target_stix_id": target["stix_id"],
        "description": description,
        "source": source,
        "created": now_iso(),
    })
    save_cluster(data)
    return data


@_synchronized
def add_gap(name: str, description: str, priority: str = "medium") -> dict[str, Any]:
    data = load_cluster(name)
    data["gaps"].append({
        "description": description, "priority": priority, "created": now_iso(),
    })
    save_cluster(data)
    return data


def _find_gap(data: dict[str, Any], description: str, name: str) -> dict[str, Any]:
    """The one gap `description` names.

    Gaps have no id; their text is what identifies them. An exact match
    wins. Otherwise the text may be the start of a gap's description, in
    any case, as long as it is the start of only one - so changing a
    priority does not mean resending a paragraph character for character.
    """
    gaps = data["gaps"]
    exact = [g for g in gaps if g["description"] == description]
    if exact:
        return exact[0]
    needle = description.strip().lower()
    starts = [g for g in gaps if needle and g["description"].lower().startswith(needle)]
    if len(starts) == 1:
        return starts[0]
    if len(starts) > 1:
        raise ValueError(
            f"that text is the start of {len(starts)} gaps in cluster {name!r}; "
            "give more of the description")
    raise ValueError(f"no gap matching that description in cluster {name!r}")


@_synchronized
def update_gap(name: str, description: str, new_description: str | None = None,
               priority: str | None = None) -> dict[str, Any]:
    """Revise a gap in place - for when it's been investigated and its
    status/priority needs updating, but it's worth keeping a record of
    what was tried (e.g. "pivoted against X, came up empty, don't
    re-try without new data") rather than silently disappearing the way
    remove_gap would. Only fields you pass are changed, same convention
    as update_profile. Stamps an `updated` timestamp on the gap either
    way, so its history is visible even if only the priority moved.

    `description` names the gap by its text, or by the start of it (see
    _find_gap). Raises if the cluster doesn't exist, no gap matches, or the
    text is the start of more than one."""
    data = load_cluster(name)
    g = _find_gap(data, description, name)
    if new_description is not None:
        g["description"] = new_description
    if priority is not None:
        g["priority"] = priority
    g["updated"] = now_iso()
    save_cluster(data)
    return data


@_synchronized
def remove_gap(name: str, description: str) -> dict[str, Any]:
    """Remove a gap from a cluster's backlog outright - the counterpart
    to add_gap, for a gap that's fully closed and not worth keeping a
    record of (see update_gap instead if you'd rather revise it in
    place, e.g. downgrading priority with a note on what was tried).

    `description` names the gap by its text, or by the start of it (see
    _find_gap). Raises if the cluster doesn't exist, no gap matches, or the
    text is the start of more than one. The returned cluster carries a
    transient `removed` gap dict (not persisted)."""
    data = load_cluster(name)
    removed = _find_gap(data, description, name)
    data["gaps"] = [g for g in data["gaps"] if g is not removed]
    save_cluster(data)
    return {**data, "removed": removed}


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
