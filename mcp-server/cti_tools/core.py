"""Core business logic for threat cluster tracking.

Protocol-agnostic on purpose: server.py (MCP) and cli.py (Pi / any Bash
tool) both call these same functions so the two invocation surfaces stay
identical. No MCP or argparse imports belong in this file.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from . import attack, pivot, report_ingest, stix

try:
    import fcntl  # POSIX-only; the lock degrades to a no-op elsewhere.
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

# Data lives at the repo root (`<repo>/data/clusters`) so it's shared
# across every harness surface (MCP server, CLI, any future UI) rather
# than nested inside mcp-server/. Override with CTI_DATA_DIR for tests
# or alternate deployments (e.g. a separate private data repo).
_REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("CTI_DATA_DIR", _REPO_ROOT / "data" / "clusters"))

# Which newly-added observable categories get queued for fingerprinting.
# Only domains/ips: they're the addresses you'd actively connect to.
# hashes/urls/etc aren't something you probe, and the ja4*/jarm
# categories are themselves fingerprint *results*, not queue inputs.
_FINGERPRINTABLE_CATEGORIES = ("domains", "ips")
# Public alias so the CLI/callers can reference the same tuple without
# reaching for the underscore-prefixed name (mirrors OBSERVABLE_CATEGORIES
# below).
FINGERPRINTABLE_CATEGORIES = _FINGERPRINTABLE_CATEGORIES

# Values that pass extraction/dedup but are essentially never an actor's
# own infrastructure - public DNS resolvers and the root domains of
# hyperscale/security vendors that show up constantly as prose mentions
# (a linked writeup, "hosted via Cloudflare", a contact address) rather
# than as the IOC itself. report_ingest.extract_observables is a blind
# regex over report text (see its docstring on over-matching) and
# add_observable trusts whatever it's handed verbatim, so without a gate
# here a false match turns into a live JARM scan / SSH round-trip
# exactly like a real IOC would. Deliberately exact-match only, not
# subdomain matching - a subdomain of e.g. github.io or amazonaws.com is
# routine, genuinely-attacker-controlled shared hosting, not a false
# positive, so only the bare apex domain (never itself attacker infra)
# is listed. Curated, not exhaustive - extend as new false positives
# turn up in real ingests, the same way _TLDS is extended in
# report_ingest.py. This only gates the fingerprinting *queue*; the
# value is still tracked as an observable exactly as before.
_KNOWN_NON_ACTOR_DOMAINS = {
    "microsoft.com", "microsoftinternetsafety.net", "google.com",
    "github.com", "githubusercontent.com", "cloudflare.com",
    "virustotal.com", "example.com", "mandiant.com", "crowdstrike.com",
    "sophos.com", "kaspersky.com", "malwarebytes.com", "godaddy.com",
    "sinkhole.abuse.ch", "iana.org",
}
# Same idea for IPs - well-known public DNS resolvers, the ones most
# likely to appear in report text as "the malware checks connectivity
# against 8.8.8.8" rather than as adversary infrastructure.
_KNOWN_NON_ACTOR_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
}


def _is_probe_worthy(category: str, value: str) -> tuple[bool, str]:
    """Gate applied only to what reaches the active-probing queue, right
    before _enqueue_pending_fingerprints - not to whether a value gets
    tracked as an observable at all, which stays exactly as permissive
    as before (empty/skipped fingerprint results are still an expected,
    fine outcome for infra that just isn't reachable). Returns
    (True, "") if fine to queue, else (False, reason)."""
    if category == "ips":
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False, "not a valid IP literal"
        if addr.is_private or addr.is_loopback or addr.is_link_local \
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return False, "private/reserved/loopback/link-local address, not routable adversary infra"
        if value in _KNOWN_NON_ACTOR_IPS:
            return False, "known non-actor infrastructure (public DNS resolver)"
    elif category == "domains":
        if value.strip().lower() in _KNOWN_NON_ACTOR_DOMAINS:
            return False, "known non-actor infrastructure (major vendor/CDN/sinkhole domain)"
    return True, ""

# The observable categories a cluster tracks. Single source of truth
# lives in report_ingest (the extractor); re-exported here so the rest
# of core, the CLI, and callers can reference core.OBSERVABLE_CATEGORIES
# without reaching across modules.
OBSERVABLE_CATEGORIES = report_ingest.OBSERVABLE_CATEGORIES

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


_EXTRACTION_EMPTY_WARNING = (
    "no observables or TTPs were extracted from this source - the page may "
    "keep IOCs/techniques in a table, image, or PDF appendix the plain-text "
    "extractor can't reach, or it may genuinely contain none. Don't treat "
    "this the same as a clean report with nothing to report; check the "
    "source manually if that seems unlikely."
)


def _nothing_extracted(extracted: dict[str, list[str]]) -> bool:
    return not any(extracted[c] for c in (*OBSERVABLE_CATEGORIES, "ttps"))


def _path(name: str) -> Path:
    safe = name.strip().lower().replace(" ", "-")
    return DATA_DIR / f"{safe}.json"


def _pending_fingerprints_path() -> Path:
    # A function (not a module-level constant) so it re-reads DATA_DIR
    # each call - tests monkeypatch DATA_DIR per-test, and a precomputed
    # path would silently keep pointing at the real data dir instead.
    return DATA_DIR.parent / "pending_fingerprints.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write_text(path: Path, text: str) -> None:
    """Write text so readers never see a partial file: write to a temp
    file in the same directory, then os.replace (atomic on the same
    filesystem). Prevents a crash mid-write from leaving a truncated
    JSON, and prevents the .json/.md pair from going out of sync on a
    torn write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# Serializes mutating operations across processes (the MCP server and
# the CLI both write the same store) so two read-modify-write sequences
# can't interleave and clobber each other. Reads (load/list/find) don't
# take it. Reentrant within a thread so a locked op calling another
# locked helper won't deadlock on flock.
import threading  # noqa: E402  (kept next to the lock it serves)

_lock_state = threading.local()


@contextmanager
def _data_lock() -> Iterator[None]:
    if fcntl is None:  # non-POSIX: best-effort, no cross-process lock
        yield
        return
    depth = getattr(_lock_state, "depth", 0)
    if depth:  # already held in this thread; re-acquiring flock would deadlock
        _lock_state.depth = depth + 1
        try:
            yield
        finally:
            _lock_state.depth -= 1
        return
    lock_path = DATA_DIR / "_registry" / ".lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "w")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        _lock_state.depth = 1
        yield
    finally:
        _lock_state.depth = 0
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def _synchronized(fn):
    """Decorator: run a mutating public operation under _data_lock."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with _data_lock():
            return fn(*args, **kwargs)

    return wrapper


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
        "detections": [], # computed join onto the shared registry at load time, not stored
        "gaps": [],       # [{description, priority, created}]
        # each entry: {value, sources: [...], first_seen, last_seen}
        "observables": {c: [] for c in OBSERVABLE_CATEGORIES},
        "report_sources": [],  # [{source, ingested, observables_found, ttps_found}]
        "relationships": [],  # [{relationship_type, target_cluster, target_stix_id, description, source, created}]
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
    for key in ("ttps", "hunt_log", "detections", "gaps", "report_sources", "relationships"):
        data.setdefault(key, [])
    data.setdefault("observables", {})
    for category in OBSERVABLE_CATEGORIES:
        data["observables"].setdefault(category, [])
    return data


def load_cluster(name: str) -> dict[str, Any]:
    p = _path(name)
    if not p.exists():
        raise ClusterNotFound(f"No cluster named {name!r}")
    data = _migrate(json.loads(p.read_text()))
    # Detections live in the shared registry, keyed by technique - not
    # duplicated per cluster - so what a cluster "has" is always a live
    # join against its current TTP table, computed on every load rather
    # than trusted from whatever was last written to disk.
    data["detections"] = _detections_for_cluster(data)
    return data


def save_cluster(data: dict[str, Any]) -> None:
    p = _path(data["name"])
    _atomic_write_text(p, json.dumps(data, indent=2))
    _write_markdown(data)


def list_clusters() -> list[str]:
    if not DATA_DIR.exists():
        return []
    return sorted(p.stem for p in DATA_DIR.glob("*.json"))


@_synchronized
def create_cluster(name: str, description: str = "") -> dict[str, Any]:
    if _path(name).exists():
        raise FileExistsError(f"Cluster {name!r} already exists")
    data = _new_cluster(name, description)
    save_cluster(data)
    return data


def get_cluster(name: str) -> dict[str, Any]:
    return load_cluster(name)


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
    data["hunt_log"].append({"date": _now(), "entry": entry})
    save_cluster(data)
    return data


def _registry_path() -> Path:
    # Under DATA_DIR (not a sibling of it) so tests that monkeypatch
    # DATA_DIR to an isolated tmp dir get an isolated registry for free.
    # A subdirectory, not a file directly in DATA_DIR, so it can never
    # collide with list_clusters()'s non-recursive `*.json` glob there.
    return DATA_DIR / "_registry" / "detections.json"


def _load_detection_registry() -> dict[str, Any]:
    p = _registry_path()
    if not p.exists():
        return {"detections": []}
    return json.loads(p.read_text())


def _save_detection_registry(registry: dict[str, Any]) -> None:
    _atomic_write_text(_registry_path(), json.dumps(registry, indent=2))


# --- reverse index cache ----------------------------------------------------
# find_observable and get_technique_usage answer "which clusters have this
# IOC / use this technique". Computed naively they load and parse every
# cluster file on every call - fine at a handful of clusters, O(n) file
# I/O as the store grows. This caches both reverse maps in one file,
# rebuilt only when the underlying clusters or the detection registry
# actually change (detected by a size+mtime fingerprint), so lookups are
# a single file read in the common case. The cache is self-healing: a
# stale or corrupt index just triggers a rebuild, never a wrong answer.

def _index_path() -> Path:
    return DATA_DIR / "_registry" / "index.json"


def _index_signature() -> str:
    """A fingerprint of everything the index is derived from. Any change
    to a cluster file or the detection registry changes this string,
    which invalidates the cache. Uses nanosecond mtime + size, which is
    reliable on Linux and cheap to compute (a stat per file, no reads)."""
    parts = []
    if DATA_DIR.exists():
        for p in sorted(DATA_DIR.glob("*.json")):  # top-level only; skips _registry/
            st = p.stat()
            parts.append(f"{p.name}:{st.st_size}:{st.st_mtime_ns}")
    reg = _registry_path()
    if reg.exists():
        st = reg.stat()
        parts.append(f"@registry:{st.st_size}:{st.st_mtime_ns}")
    return "|".join(parts)


def _build_reverse_index() -> dict[str, Any]:
    registry = _load_detection_registry()
    observables: dict[str, list[dict[str, Any]]] = {}
    techniques: dict[str, dict[str, Any]] = {}
    for cname in list_clusters():
        data = load_cluster(cname)
        for category in OBSERVABLE_CATEGORIES:
            for o in data["observables"].get(category, []):
                match = {
                    "cluster": data["name"], "category": category,
                    "value": o["value"], "sources": o["sources"],
                    "first_seen": o["first_seen"], "last_seen": o["last_seen"],
                }
                stored = o["value"].lower()
                keys = {stored}
                # hashes are findable with or without their algo prefix
                if category == "hashes" and ":" in stored:
                    keys.add(stored.split(":", 1)[1])
                for k in keys:
                    observables.setdefault(k, []).append(match)
        for t in data["ttps"]:
            tid = t["id"]
            entry = techniques.setdefault(tid, {
                "technique_id": tid,
                "name": attack.canonical_name(tid) or t["name"],
                "used_by": [], "detections": [],
            })
            entry["used_by"].append({
                "cluster": data["name"], "status": t["status"], "notes": t.get("notes", ""),
            })
    for det in registry["detections"]:
        for tid in det["technique_ids"]:
            if tid in techniques:
                techniques[tid]["detections"].append({
                    "id": det["id"], "description": det["description"],
                    "status": det["status"],
                })
    return {"signature": _index_signature(), "observables": observables,
            "techniques": techniques}


def _reverse_index() -> dict[str, Any]:
    """Return the reverse index, rebuilding it only if the cluster/registry
    fingerprint has changed since it was last cached."""
    sig = _index_signature()
    p = _index_path()
    if p.exists():
        try:
            cached = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            cached = None
        if cached and cached.get("signature") == sig:
            return cached
    idx = _build_reverse_index()
    try:
        _atomic_write_text(p, json.dumps(idx))
    except OSError:
        pass  # cache is best-effort; a read-only store still answers correctly
    return idx


def _detections_for_cluster(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Detections relevant to this cluster: anything in the shared
    registry whose technique_ids overlap this cluster's TTP table, or
    that explicitly names this cluster (e.g. filed before the TTP that
    justifies it was added). Each result is annotated with exactly
    which of this cluster's TTPs it covers."""
    registry = _load_detection_registry()
    ttp_ids = {t["id"].upper() for t in data["ttps"]}
    name = data["name"]
    result = []
    for det in registry["detections"]:
        covers = sorted({tid.upper() for tid in det["technique_ids"]} & ttp_ids)
        if covers or name in det.get("clusters", []):
            result.append({**det, "covers_ttps": covers})
    return result


@_synchronized
def add_detection(detection_id: str, description: str, technique_ids: list[str],
                   status: str = "draft", cluster_name: str | None = None) -> dict[str, Any]:
    """Upsert a detection into the shared, technique-keyed detection
    registry (data/clusters/_registry/detections.json) rather than into
    one cluster's own record - a Kerberoasting detection covers every
    adversary that does Kerberoasting, so it's modeled once per
    technique and joined onto clusters by technique_id, not
    hand-duplicated into each cluster that happens to use it.

    technique_ids is required (at least one) - that's what makes the
    detection discoverable from a cluster's TTP table and from
    get_technique_usage(). cluster_name is optional provenance (which
    investigation prompted writing this detection); pass it to also get
    the refreshed cluster view back.
    """
    if not technique_ids:
        raise ValueError("add_detection requires at least one technique_id")
    if cluster_name is not None:
        load_cluster(cluster_name)  # raises ClusterNotFound if it doesn't exist

    registry = _load_detection_registry()
    now = _now()
    for det in registry["detections"]:
        if det["id"] == detection_id:
            det["description"] = description
            det["status"] = status
            det["technique_ids"] = sorted(set(det["technique_ids"]) | set(technique_ids))
            if cluster_name and cluster_name not in det["clusters"]:
                det["clusters"].append(cluster_name)
            det["updated"] = now
            break
    else:
        registry["detections"].append({
            "id": detection_id, "description": description, "status": status,
            "technique_ids": sorted(set(technique_ids)),
            "clusters": [cluster_name] if cluster_name else [],
            "created": now, "updated": now,
        })
    _save_detection_registry(registry)

    # The cluster JSON's `detections` field (and its rendered markdown)
    # is a snapshot from the last time that cluster was saved - refresh
    # every cluster this detection now covers, not just cluster_name,
    # so an update here doesn't leave other clusters' .md views stale.
    technique_id_set = {tid.upper() for tid in technique_ids}
    for cname in list_clusters():
        data = load_cluster(cname)
        if technique_id_set & {t["id"].upper() for t in data["ttps"]}:
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
        "created": _now(),
    })
    save_cluster(data)
    return data


@_synchronized
def add_gap(name: str, description: str, priority: str = "medium") -> dict[str, Any]:
    data = load_cluster(name)
    data["gaps"].append({
        "description": description, "priority": priority, "created": _now(),
    })
    save_cluster(data)
    return data


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

    Matches the gap to update by its current exact description text -
    gaps have no separate id, same as add_gap/remove_gap. Raises if the
    cluster doesn't exist or no gap matches that text."""
    data = load_cluster(name)
    for g in data["gaps"]:
        if g["description"] == description:
            if new_description is not None:
                g["description"] = new_description
            if priority is not None:
                g["priority"] = priority
            g["updated"] = _now()
            save_cluster(data)
            return data
    raise ValueError(f"no gap matching that description in cluster {name!r}")


@_synchronized
def remove_gap(name: str, description: str) -> dict[str, Any]:
    """Remove a gap from a cluster's backlog outright - the counterpart
    to add_gap, for a gap that's fully closed and not worth keeping a
    record of (see update_gap instead if you'd rather revise it in
    place, e.g. downgrading priority with a note on what was tried).

    Matches by exact description text (case-sensitive) - gaps have no
    separate id, the description is the identifying content, same
    convention as remove_observable matching by value. Raises if the
    cluster doesn't exist or no gap matches. The returned cluster
    carries a transient `removed` gap dict (not persisted)."""
    data = load_cluster(name)
    kept: list[dict[str, Any]] = []
    removed: dict[str, Any] | None = None
    for g in data["gaps"]:
        if removed is None and g["description"] == description:
            removed = g
        else:
            kept.append(g)
    if removed is None:
        raise ValueError(f"no gap matching that description in cluster {name!r}")
    data["gaps"] = kept
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


def get_observables(name: str) -> dict[str, Any]:
    """Return just the observables block for a cluster (hashes, domains,
    ips, urls) plus the list of report sources they came from — the
    quick "what's tied to this cluster" view."""
    data = load_cluster(name)
    return {
        "name": data["name"],
        "observables": data["observables"],
        "report_sources": data["report_sources"],
    }


def find_observable(value: str) -> dict[str, Any]:
    """Reverse index from an observable value to the clusters that have
    seen it - the symmetric counterpart to get_technique_usage(), across
    every observable category. Backed by the cached reverse index, so it
    doesn't re-scan every cluster file per call.

    A hash value matches whether or not you include its algo prefix -
    passing either "sha256:abc..." or bare "abc..." finds the same
    entries, since callers often only have the bare hash on hand."""
    needle = value.strip().lower()
    matches = _reverse_index()["observables"].get(needle, [])
    return {"value": value, "matches": matches}


@_synchronized
def add_observable(name: str, category: str, value: str, source: str) -> dict[str, Any]:
    """Manually file a single observable (category is one of
    OBSERVABLE_CATEGORIES: hashes, domains, ips, urls, emails, cves,
    wallets, ja4, ja4s, ja4h, ja4l, ja4x, ja4t, ja4ts, ja4ssh, jarm) onto
    a cluster - the counterpart to ingest_report's automatic extraction,
    for an indicator that came from somewhere other than a parseable
    report (e.g. a pivot_observable finding, an actively-collected
    JA4+/JARM fingerprint, or something told to you directly). Reuses
    the exact same dedup/provenance logic as ingest_report: a value
    already tracked just gets `source` appended to its provenance list
    rather than creating a duplicate entry.

    A new domain/ip is still always tracked as an observable, but only
    queued for active fingerprinting if it passes _is_probe_worthy (not
    a private/reserved address, not a known-non-actor domain/resolver
    IP like a public DNS resolver or a major vendor's own site) - see
    that function's docstring. If it's skipped, the returned dict
    carries a transient (not persisted) `fingerprint_queue_skipped`
    list of {category, value, reason}; use requeue_fingerprint if you
    disagree with the call and want it probed anyway."""
    if category not in OBSERVABLE_CATEGORIES:
        raise ValueError("category must be one of " + ", ".join(OBSERVABLE_CATEGORIES))
    data = load_cluster(name)
    extracted = {c: ([value] if c == category else []) for c in OBSERVABLE_CATEGORIES}
    _, skipped = _merge_observables(data, extracted, source)
    save_cluster(data)
    if skipped:
        data = {**data, "fingerprint_queue_skipped": skipped}
    return data


@_synchronized
def remove_observable(name: str, category: str, value: str) -> dict[str, Any]:
    """Remove an observable from a cluster - the counterpart to
    add_observable, for pruning a false positive or a benign reference
    that the extractor over-matched (a legitimate service the malware
    merely contacts, a shared-hosting IP, etc.).

    Matches case-insensitively and, for hashes, with or without the algo
    prefix, removing every entry in `category` that matches - so removing
    "ukr.net" also clears a differently-cased "UKR.NET". Raises if the
    cluster doesn't exist or nothing matched. The returned cluster carries
    a transient `removed` list of the values dropped (not persisted)."""
    if category not in OBSERVABLE_CATEGORIES:
        raise ValueError("category must be one of " + ", ".join(OBSERVABLE_CATEGORIES))
    data = load_cluster(name)
    bucket = data["observables"][category]
    needle = value.strip().lower()
    kept: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    for o in bucket:
        stored = o["value"].lower()
        bare = stored.split(":", 1)[1] if category == "hashes" and ":" in stored else stored
        (removed if needle in (stored, bare) else kept).append(o)
    if not removed:
        raise ValueError(f"no {category} observable matching {value!r} in cluster {name!r}")
    data["observables"][category] = kept
    save_cluster(data)
    return {**data, "removed": [o["value"] for o in removed]}


# Pivot enrichment cache. VirusTotal's free tier is 4 req/min, 500/day,
# so refetching the same indicator on every pivot burns straight through
# it; RDAP/RIPEstat are also slow round-trips worth not repeating. This
# caches each source's answer for a value for a short TTL. It is NOT
# cluster data - just a transient enrichment cache under _registry -
# and only successful lookups are cached (never errors or the VT skip
# note). Set CTI_PIVOT_CACHE_TTL=0 to disable caching entirely.
_PIVOT_CACHE_TTL_ENV = "CTI_PIVOT_CACHE_TTL"
_PIVOT_CACHE_TTL_DEFAULT = 3600


def _pivot_cache_path() -> Path:
    return DATA_DIR / "_registry" / "pivot_cache.json"


def _pivot_cache_ttl() -> int:
    try:
        return int(os.environ.get(_PIVOT_CACHE_TTL_ENV, _PIVOT_CACHE_TTL_DEFAULT))
    except ValueError:
        return _PIVOT_CACHE_TTL_DEFAULT


def _load_pivot_cache() -> dict[str, Any]:
    p = _pivot_cache_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _cached_pivot(source: str, value: str, fetch) -> Any:
    """Return a cached source result for `value` if it's fresh, else call
    `fetch()`, cache a successful result, and return it. `fetch` may
    raise (e.g. VirusTotal) - exceptions propagate uncached so a transient
    outage isn't remembered as the answer."""
    import time
    ttl = _pivot_cache_ttl()
    if ttl <= 0:
        return fetch()
    key = f"{source}:{value}"
    cache = _load_pivot_cache()
    entry = cache.get(key)
    now = time.time()
    if entry and now - entry.get("ts", 0) < ttl:
        return entry["result"]
    result = fetch()
    # Don't cache soft failures (RDAP/RIPEstat return an "error" key rather
    # than raising); a later retry should be able to succeed.
    if not (isinstance(result, dict) and "error" in result):
        cache[key] = {"ts": now, "result": result}
        try:
            _atomic_write_text(_pivot_cache_path(), json.dumps(cache))
        except OSError:
            pass
    return result


def pivot_observable(value: str) -> dict[str, Any]:
    """On-demand infrastructure pivot for a single hash/domain/ip/url
    against free, no-recurring-cost public data sources - RDAP
    (registration data), RIPEstat (ASN/network context, IP only), and
    VirusTotal (reputation + resolution history, if VT_API_KEY is set
    in the environment). Display only: no cluster data is written, unlike
    ingest_report - though successful lookups are cached transiently
    under _registry to respect source rate limits (see CTI_PIVOT_CACHE_TTL).
    If a pivot surfaces something worth keeping, record it yourself via
    append_hunt_log, add_gap, or by filing the new indicator into a
    cluster.

    VirusTotal is skipped (with a note, not an error) if VT_API_KEY
    isn't configured - RDAP and RIPEstat need no key at all and always
    run for the observable types they apply to. Certificate-transparency
    history (Cert Spotter, for domains) and reverse-IP co-hosting
    (Hackertarget, for IPs) are also keyless and surface sibling
    infrastructure as new pivot leads.
    """
    kind = pivot.classify(value)
    result: dict[str, Any] = {"value": value, "kind": kind}

    if kind in ("domain", "ip"):
        result["rdap"] = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, kind))
    if kind == "ip":
        result["ripestat"] = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        result["reverse_ip"] = _cached_pivot(
            "reverse_ip", value, lambda: pivot.hackertarget_reverse_ip(value))
    if kind == "domain":
        result["certspotter"] = _cached_pivot(
            "certspotter", value, lambda: pivot.certspotter_lookup(value))

    api_key = os.environ.get(pivot.VT_API_KEY_ENV)
    if not api_key:
        result["virustotal"] = {
            "skipped": f"set {pivot.VT_API_KEY_ENV} to enable VirusTotal lookups"}
    else:
        try:
            result["virustotal"] = _cached_pivot(
                "virustotal", value, lambda: pivot.virustotal_lookup(value, kind, api_key))
        except pivot.PivotError as e:
            result["virustotal"] = {"error": str(e)}

    return result


_PIVOT_CLUSTER_WORKERS = 6


def _domain_lifecycle(value: str) -> tuple[str, dict[str, Any]]:
    rdap = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, "domain"))
    resolved = pivot.resolve_host(value)  # live, not cached — liveness is the point
    status = pivot.classify_domain_lifecycle(rdap, resolved)
    return status, {"resolved": resolved,
                    "nameservers": rdap.get("nameservers") if isinstance(rdap, dict) else None}


def _ip_lifecycle(value: str) -> tuple[str, dict[str, Any]]:
    ripe = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
    status = pivot.classify_ip_lifecycle(ripe)
    return status, {"asn": ripe.get("asn") if isinstance(ripe, dict) else None,
                    "prefix": ripe.get("prefix") if isinstance(ripe, dict) else None}


def pivot_cluster(name: str) -> dict[str, Any]:
    """Sweep every tracked domain and IP for a cluster through the free
    pivot sources and stamp a lifecycle status onto each, turning a
    static observable list into a live "what's still up" view. Domains
    are classified active/dead/sinkholed/expired/unknown (RDAP + a live
    resolution attempt); IPs routed/unrouted/unknown (RIPEstat). The
    status, the time it was checked, and the supporting detail are
    written back onto each observable (unlike pivot_observable, which is
    display-only), and a summary is returned. Successful source lookups
    are cached (see CTI_PIVOT_CACHE_TTL) so re-sweeping is cheap.

    The network lookups run concurrently and, crucially, OUTSIDE the data
    lock - a cluster with dozens of domains would otherwise serialize
    into minutes of blocking I/O with the whole store locked. Only the
    final write-back takes the lock, re-reading the cluster so it applies
    onto current on-disk state."""
    data = load_cluster(name)  # existence check + snapshot the values to check
    domains = [o["value"] for o in data["observables"]["domains"]]
    ips = [o["value"] for o in data["observables"]["ips"]]

    # Network phase: concurrent, no lock held.
    results: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
    jobs = ([("domains", v, _domain_lifecycle) for v in domains]
            + [("ips", v, _ip_lifecycle) for v in ips])
    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_PIVOT_CLUSTER_WORKERS) as ex:
            futures = {ex.submit(fn, v): (cat, v) for cat, v, fn in jobs}
            for fut in concurrent.futures.as_completed(futures):
                cat, v = futures[fut]
                try:
                    results[(cat, v)] = fut.result()
                except Exception as e:  # a single lookup blowing up shouldn't sink the sweep
                    results[(cat, v)] = ("unknown", {"error": str(e)})

    # Write phase: brief lock, applied onto a fresh read of the cluster.
    now = _now()
    with _data_lock():
        data = load_cluster(name)
        summary: dict[str, Any] = {"name": data["name"], "checked": now, "domains": [], "ips": []}
        for cat in ("domains", "ips"):
            for o in data["observables"][cat]:
                found = results.get((cat, o["value"]))
                if not found:
                    continue
                status, detail = found
                o["status"] = status
                o["status_checked"] = now
                o["status_detail"] = detail
                row = {"value": o["value"], "status": status}
                row["resolved" if cat == "domains" else "asn"] = \
                    detail.get("resolved") if cat == "domains" else detail.get("asn")
                summary[cat].append(row)
        save_cluster(data)
    return summary


def _safe_vt(value: str, kind: str, api_key: str) -> dict[str, Any]:
    """VirusTotal lookup that returns an {"error": ...} dict instead of
    raising, so it composes with _cached_pivot (which caches successes,
    never errors) inside a larger expansion."""
    try:
        return pivot.virustotal_lookup(value, kind, api_key)
    except pivot.PivotError as e:
        return {"error": str(e)}


def _file_new_observables(data: dict[str, Any], category: str, values: list[str],
                           source: str) -> list[str]:
    """Merge only values not already tracked on the cluster in `category`,
    returning the ones actually added (deduped, order-preserving)."""
    existing = {o["value"] for o in data["observables"][category]}
    new = [v for v in dict.fromkeys(values) if v and v not in existing]
    if new:
        extracted = {c: (new if c == category else []) for c in OBSERVABLE_CATEGORIES}
        _merge_observables(data, extracted, source)  # skip list unused - caller's own confidence filter already applies
    return new


@_synchronized
def pivot_and_expand(value: str, cluster_name: str,
                     include_cohosted: bool = False) -> dict[str, Any]:
    """Pivot a domain or IP and file the high-confidence new indicators it
    surfaces straight onto an existing cluster (with provenance and a
    hunt-log entry), instead of leaving you to copy each finding back by
    hand. What gets filed:

    - domain: sibling hostnames from certificate-transparency logs that
      sit under the queried name (same operator, high confidence), and
      the domain's historical resolution IPs from VirusTotal.
    - ip: the IP's historical resolutions (domains) from VirusTotal.

    Reverse-IP co-hosted domains are NOT filed by default (shared-hosting
    noise); pass include_cohosted=True to file them too, or read them from
    the returned `review` block and file the real ones yourself. Anything
    not filed (co-hosted domains, CT names outside the queried name) is
    returned under `review` for manual follow-up. Only genuinely new
    indicators are filed; ones already tracked are left as-is."""
    data = load_cluster(cluster_name)  # must already exist; expansion targets an investigation
    kind = pivot.classify(value)
    if kind not in ("domain", "ip"):
        raise ValueError(
            f"pivot_and_expand supports domain/ip values; got kind={kind!r} for {value!r}")
    now = _now()
    api_key = os.environ.get(pivot.VT_API_KEY_ENV)
    filed: dict[str, list[str]] = {}
    review: dict[str, Any] = {}

    def record(category: str, values: list[str], source: str) -> None:
        added = _file_new_observables(data, category, values, source)
        if added:
            filed.setdefault(category, []).extend(added)

    if kind == "domain":
        ct = _cached_pivot("certspotter", value, lambda: pivot.certspotter_lookup(value))
        if isinstance(ct, dict) and ct.get("error"):
            review["certspotter_error"] = ct["error"]
        elif isinstance(ct, dict):
            hostnames = ct.get("hostnames", [])
            siblings = [h for h in hostnames if h != value and h.endswith("." + value)]
            record("domains", siblings,
                   f"pivot_and_expand via Cert Spotter CT log, checked {now}")
            others = [h for h in hostnames if h != value and not h.endswith("." + value)]
            if others:
                review["certspotter_other_hostnames"] = others
        if api_key:
            vt = _cached_pivot("virustotal", value, lambda: _safe_vt(value, kind, api_key))
            ips = [r["ip"] for r in (vt.get("resolutions") or []) if r.get("ip")] \
                if isinstance(vt, dict) else []
            record("ips", ips,
                   f"pivot_and_expand via VirusTotal resolution history, checked {now}")
    else:  # ip
        if api_key:
            vt = _cached_pivot("virustotal", value, lambda: _safe_vt(value, kind, api_key))
            domains = [r["domain"] for r in (vt.get("resolutions") or []) if r.get("domain")] \
                if isinstance(vt, dict) else []
            record("domains", domains,
                   f"pivot_and_expand via VirusTotal resolution history, checked {now}")
        rev = _cached_pivot("reverse_ip", value, lambda: pivot.hackertarget_reverse_ip(value))
        cohosted = rev.get("domains", []) if isinstance(rev, dict) and not rev.get("error") else []
        if include_cohosted:
            record("domains", cohosted,
                   f"pivot_and_expand via Hackertarget reverse-IP, checked {now}")
        elif cohosted:
            review["cohosted_domains"] = cohosted

    filed = {c: sorted(set(v)) for c, v in filed.items() if v}
    total = sum(len(v) for v in filed.values())
    breakdown = ", ".join(f"{len(v)} {c}" for c, v in filed.items()) or "none"
    entry = f"pivot_and_expand on {value}: filed {total} new indicator(s) ({breakdown})"
    if review:
        n_review = sum(len(v) for v in review.values() if isinstance(v, list))
        if n_review:
            entry += f"; {n_review} candidate(s) left for review"
    data["hunt_log"].append({"date": now, "entry": entry})
    save_cluster(data)

    return {"value": value, "kind": kind, "cluster": cluster_name,
            "filed": filed, "review": review, "cluster_state": load_cluster(cluster_name)}


# Report-fetch cache. analyze_report (preview) and ingest_report (commit)
# are routinely called back-to-back on the same source - analyze first to
# pick a cluster_name, then ingest to file it - which would otherwise
# fetch identical content twice (a real cost for slow report sites, and
# a pointless repeat request either way). Same _registry/TTL-env pattern
# as the pivot cache above. Set CTI_REPORT_CACHE_TTL=0 to disable.
_REPORT_CACHE_TTL_ENV = "CTI_REPORT_CACHE_TTL"
_REPORT_CACHE_TTL_DEFAULT = 3600


def _report_cache_path() -> Path:
    return DATA_DIR / "_registry" / "report_fetch_cache.json"


def _report_cache_ttl() -> int:
    try:
        return int(os.environ.get(_REPORT_CACHE_TTL_ENV, _REPORT_CACHE_TTL_DEFAULT))
    except ValueError:
        return _REPORT_CACHE_TTL_DEFAULT


def _fetch_report_text(source: str) -> str:
    """report_ingest.fetch_text(source), cached briefly so analyze_report
    followed by ingest_report on the same source reuses one fetch instead
    of two. Keyed by source string (URL or local path) - a local file
    edited between the two calls within the TTL window would read stale,
    but that gap is normally seconds, not the file's edit cadence."""
    import time
    ttl = _report_cache_ttl()
    if ttl <= 0:
        return report_ingest.fetch_text(source)
    path = _report_cache_path()
    cache: dict[str, Any] = {}
    if path.exists():
        try:
            cache = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            cache = {}
    now = time.time()
    entry = cache.get(source)
    if entry and now - entry.get("ts", 0) < ttl:
        return entry["text"]
    text = report_ingest.fetch_text(source)
    cache[source] = {"ts": now, "text": text}
    try:
        _atomic_write_text(path, json.dumps(cache))
    except OSError:
        pass
    return text


def analyze_report(source: str) -> dict[str, Any]:
    """Fetch a report (URL or local file path) and extract observables,
    ATT&CK technique IDs, and candidate cluster names, WITHOUT writing
    anything. Use this to preview extraction — e.g. to pick the right
    cluster_name yourself — before committing with `ingest_report`."""
    text = _fetch_report_text(source)
    text = report_ingest.defang_normalize(text)
    observables = report_ingest.extract_observables(text)
    candidates = report_ingest.suggest_cluster_names(text)
    result = {
        "source": source,
        "observables": {k: v for k, v in observables.items() if k != "ttps"},
        "ttps": observables["ttps"],
        "candidate_cluster_names": candidates,
    }
    if _nothing_extracted(observables):
        result["warning"] = _EXTRACTION_EMPTY_WARNING
    return result


def _merge_observables(data: dict[str, Any], extracted: dict[str, list[str]],
                        source: str,
                        ip_ports: dict[str, int] | None = None,
                        ) -> tuple[dict[str, int], list[dict[str, str]]]:
    now = _now()
    counts = {}
    newly_tracked: list[tuple[str, str]] = []  # (category, value), for the fingerprint queue
    skipped: list[dict[str, str]] = []  # entries tracked but not queued, with why
    ip_ports = ip_ports or {}
    for category in OBSERVABLE_CATEGORIES:
        bucket = data["observables"][category]
        by_value = {o["value"]: o for o in bucket}
        added = 0
        for value in extracted[category]:
            if value in by_value:
                entry = by_value[value]
                if source not in entry["sources"]:
                    entry["sources"].append(source)
                entry["last_seen"] = now
            else:
                entry = {"value": value, "sources": [source],
                          "first_seen": now, "last_seen": now}
                bucket.append(entry)
                added += 1
                if category in _FINGERPRINTABLE_CATEGORIES:
                    ok, reason = _is_probe_worthy(category, value)
                    if ok:
                        newly_tracked.append((category, value))
                    else:
                        skipped.append({"category": category, "value": value, "reason": reason})
            # A report naming a C2/service port near this IP (see
            # report_ingest._extract_ip_ports) is stamped onto the IP's
            # own observable entry so active fingerprinting can probe
            # its real port instead of always defaulting to 443 - see
            # probe_pending_fingerprints.py's _lookup_port. Appended
            # (deduped), not overwritten, since a later report might
            # name a second port for the same IP without invalidating
            # the first.
            if category == "ips" and value in ip_ports:
                ports = entry.setdefault("ports", [])
                if ip_ports[value] not in ports:
                    ports.append(ip_ports[value])
        counts[category] = added
    if newly_tracked:
        _enqueue_pending_fingerprints(data["name"], newly_tracked)
    return counts, skipped


def _load_pending_fingerprints() -> list[dict[str, Any]]:
    path = _pending_fingerprints_path()
    if not path.exists():
        return []
    return json.loads(path.read_text())


def _enqueue_pending_fingerprints(cluster_name: str, items: list[tuple[str, str]]) -> None:
    # Called from inside _merge_observables, which only ever runs from a
    # caller already holding _data_lock (add_observable/ingest_report/
    # import_stix_bundle are all @_synchronized), so no lock of its own.
    entries = _load_pending_fingerprints()
    now = _now()
    entries.extend({"cluster": cluster_name, "category": category, "value": value,
                     "queued_at": now} for category, value in items)
    _atomic_write_text(_pending_fingerprints_path(), json.dumps(entries, indent=2))


def list_pending_fingerprints() -> list[dict[str, Any]]:
    """Peek at domains/ips newly tracked (via add_observable, ingest_report,
    or import_stix_bundle) since the last pop_pending_fingerprints call -
    i.e. infrastructure that hasn't been actively fingerprinted (JA4+/
    JARM) yet. Read-only; doesn't clear the queue. Each entry is
    {cluster, category, value, queued_at}."""
    return _load_pending_fingerprints()


@_synchronized
def pop_pending_fingerprints() -> list[dict[str, Any]]:
    """Return every queued entry and clear the queue in one step - the
    operation a fingerprinting script (e.g. running on an isolated VM)
    calls each cycle to claim everything waiting without racing another
    caller or re-processing the same entries next time. Use
    list_pending_fingerprints instead to check without consuming."""
    entries = _load_pending_fingerprints()
    if entries:
        _atomic_write_text(_pending_fingerprints_path(), "[]")
    return entries


@_synchronized
def requeue_fingerprint(name: str, category: str, value: str) -> list[dict[str, Any]]:
    """Force a domain/ip that's already tracked on a cluster back onto the
    JA4+/JARM pending queue, bypassing the dedup check that normally only
    enqueues genuinely new observables (_merge_observables only queues on
    first sight of a value - touching an already-tracked one again via
    add_observable does NOT re-queue it). The supported way to ask for a
    re-probe - after a prior attempt errored, timed out, or returned a
    null/placeholder result - without hand-editing pending_fingerprints.json
    or re-adding the observable under a throwaway value just to trigger
    the queue path.

    category must be one of FINGERPRINTABLE_CATEGORIES ("domains", "ips").
    Raises if the cluster doesn't exist or value isn't currently tracked
    in that category - requeuing something never filed doesn't make
    sense; file it with add_observable first. Returns the full pending
    queue after the addition."""
    if category not in _FINGERPRINTABLE_CATEGORIES:
        raise ValueError("category must be one of " + ", ".join(_FINGERPRINTABLE_CATEGORIES))
    data = load_cluster(name)
    needle = value.strip().lower()
    bucket = data["observables"][category]
    if not any(o["value"].lower() == needle for o in bucket):
        raise ValueError(f"no {category} observable matching {value!r} in cluster {name!r} - "
                          "use add_observable to file it first")
    _enqueue_pending_fingerprints(name, [(category, value)])
    return _load_pending_fingerprints()


def _merge_ttps(data: dict[str, Any], technique_ids: list[str], source: str) -> list[str]:
    """Add newly-seen technique IDs at status 0 (no coverage) so they
    show up in the coverage table. Never touches an already-tracked
    TTP's status/notes — automated extraction shouldn't clobber a
    curated coverage assessment."""
    existing = {t["id"] for t in data["ttps"]}
    added = []
    for tid in technique_ids:
        if tid in existing:
            continue
        data["ttps"].append({
            "id": tid, "name": attack.canonical_name(tid) or tid, "status": 0,
            "notes": f"auto-extracted from report: {source}",
            "updated": _now(),
        })
        added.append(tid)
    return added


@_synchronized
def ingest_report(source: str, cluster_name: str | None = None,
                   create_if_missing: bool = True) -> dict[str, Any]:
    """Fetch a report, extract observables/TTPs, and file them into a
    cluster — creating it if it doesn't exist yet.

    If cluster_name is omitted, this tries to infer one from the report
    text (Microsoft/CrowdStrike/Mandiant-style actor names, or a
    malware name next to a word like "ransomware"). That inference is a
    regex heuristic, not attribution: if it finds zero or multiple
    plausible candidates, this raises rather than guessing — re-run
    with an explicit cluster_name (an agent reading the report can
    almost always pick the right one). Prefer passing cluster_name
    explicitly whenever you know it.

    Existing TTP statuses/notes are never overwritten by extraction —
    only new technique IDs are added, at status 0. Observables are
    deduped by value; a repeated observable from a new source just adds
    that source to its provenance list.

    Every newly-tracked domain/ip is still filed as an observable, but
    only queued for active fingerprinting if it passes
    _is_probe_worthy — extraction is a blind regex over report text and
    will happily match a version string, a public DNS resolver, or a
    vendor's own site mentioned in passing, and none of those should
    turn into a live probe just because they matched. Anything skipped
    is listed (with why) under `fingerprint_queue_skipped` on both the
    return value and the persisted `report_sources` entry for this
    ingest; use requeue_fingerprint if a skip turns out to be wrong.

    If the report names a C2/service port near one of the extracted IPs
    (e.g. "TCP port 886 (IPs: 1.2.3.4, ...)" or a bare "1.2.3.4:8080"),
    that port is stamped onto the IP's own observable entry
    (`ports: [...]`, see report_ingest._extract_ip_ports). Active
    fingerprinting checks that field first and only falls back to 443
    if nothing was extracted — see probe_pending_fingerprints.py's
    _lookup_port.
    """
    text = _fetch_report_text(source)
    text = report_ingest.defang_normalize(text)
    extracted = report_ingest.extract_observables(text)

    if cluster_name is None:
        candidates = report_ingest.suggest_cluster_names(text)
        if len(candidates) == 1:
            cluster_name = candidates[0]
        elif not candidates:
            raise ValueError(
                "could not infer a cluster name from the report; "
                "re-run ingest_report with an explicit cluster_name")
        else:
            raise ValueError(
                "multiple possible cluster names found in the report "
                f"({candidates}); re-run ingest_report with an explicit cluster_name")

    if _path(cluster_name).exists():
        data = load_cluster(cluster_name)
    elif create_if_missing:
        data = _new_cluster(cluster_name, f"Auto-created from report ingestion: {source}")
    else:
        raise ClusterNotFound(f"No cluster named {cluster_name!r}")

    observable_counts, skipped = _merge_observables(
        data, extracted, source, ip_ports=extracted.get("ip_ports"))
    _merge_ttps(data, extracted["ttps"], source)
    data["report_sources"].append({
        "source": source, "ingested": _now(),
        "observables_found": observable_counts,
        "ttps_found": extracted["ttps"],
        "fingerprint_queue_skipped": skipped,
    })
    save_cluster(data)
    if _nothing_extracted(extracted):
        data = {**data, "warning": _EXTRACTION_EMPTY_WARNING}
    if skipped:
        data = {**data, "fingerprint_queue_skipped": skipped}
    return data


def export_stix_bundle(name: str) -> dict[str, Any]:
    """Export the cluster as a STIX 2.1 bundle (Intrusion Set + Attack
    Patterns + Indicators + Relationships + Notes) for sharing outside
    this tool. Tracked observables become Indicators tied to the
    Intrusion Set."""
    data = load_cluster(name)
    return stix.to_bundle(data)


def export_stix_ecosystem(name: str) -> dict[str, Any]:
    """Export this cluster and every cluster it's (transitively) related
    to via add_relationship as one self-contained STIX 2.1 bundle.

    export_stix_bundle only exports one cluster's own Intrusion Set, so
    a cross-cluster Relationship's target_ref points at a STIX id that
    isn't actually an object in that bundle - fine if the receiving
    system already tracks the target cluster, a dangling reference if
    not. This walks the relationship graph outward from `name` (via
    each visited cluster's own `relationships`) and merges every
    reachable cluster's bundle into one, so every Relationship's target
    is guaranteed to be present as an object. A relationship pointing
    at a since-renamed/deleted cluster is skipped rather than failing
    the whole export.
    """
    visited: dict[str, dict[str, Any]] = {}
    queue = [name]
    while queue:
        cname = queue.pop(0)
        if cname in visited:
            continue
        try:
            data = load_cluster(cname)
        except ClusterNotFound:
            continue
        visited[cname] = data
        for rel in data.get("relationships", []):
            target = rel["target_cluster"]
            if target not in visited:
                queue.append(target)

    if name not in visited:
        raise ClusterNotFound(f"No cluster named {name!r}")

    bundles = [stix.to_bundle(data) for data in visited.values()]
    return stix.merge_bundles(bundles)


@_synchronized
def import_stix_bundle(bundle: dict[str, Any], name: str | None = None,
                        overwrite: bool = False) -> dict[str, Any]:
    """Create or update a cluster from an external STIX 2.1 bundle
    containing an Intrusion Set (plus optional Attack Patterns /
    Indicators / Relationships / Notes). Indicators are reconstructed
    into the cluster's observables. Existing local fields not present in
    the bundle (hunt log, detections, gaps) are preserved on update.

    Same fingerprint-queue gating as add_observable/ingest_report: a
    domain/ip that fails _is_probe_worthy is still tracked but not
    queued for active probing; see `fingerprint_queue_skipped` on the
    return value if any were skipped."""
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
        existing_rels = {(r["relationship_type"], r["target_stix_id"]) for r in data["relationships"]}
        for rel in parsed["relationships"]:
            key = (rel["relationship_type"], rel["target_stix_id"])
            if key not in existing_rels:
                data["relationships"].append(rel)
    else:
        data = _new_cluster(cluster_name, parsed["description"])
        data["stix_id"] = parsed["stix_id"]
        data["aliases"] = parsed["aliases"]
        data["first_seen"] = parsed["first_seen"]
        data["last_seen"] = parsed["last_seen"]
        data["ttps"] = parsed["ttps"]
        data["hunt_log"] = parsed["notes"]
        data["relationships"] = parsed["relationships"]

    parsed_obs = parsed.get("observables", {})
    skipped: list[dict[str, str]] = []
    if parsed_obs:
        extracted = {c: parsed_obs.get(c, []) for c in OBSERVABLE_CATEGORIES}
        _, skipped = _merge_observables(data, extracted, f"STIX import ({parsed['stix_id']})")
    save_cluster(data)
    if skipped:
        data = {**data, "fingerprint_queue_skipped": skipped}
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
    lines += ["", "## Detection inventory (shared registry, joined by technique)",
              "| ID | Description | Status | Covers | Updated |", "|---|---|---|---|---|"]
    for det in data["detections"]:
        lines.append(f"| {det['id']} | {det['description']} | {det['status']} | "
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
            lines.append("| Value | Status | Sources | First seen | Last seen |")
            lines.append("|---|---|---|---|---|")
            for o in items:
                status = o.get("status", "")
                if status and o.get("status_checked"):
                    status = f"{status} ({o['status_checked'][:10]})"
                lines.append(f"| {o['value']} | {status} | {', '.join(o['sources'])} | "
                              f"{o['first_seen']} | {o['last_seen']} |")
        else:
            lines.append("none")
    lines += ["", "## Report sources"]
    for r in data["report_sources"]:
        lines.append(f"- **{r['ingested']}** — {r['source']} "
                      f"(TTPs: {', '.join(r['ttps_found']) or 'none'})")
    lines += ["", "## Hunt log (append-only)"]
    for h in data["hunt_log"]:
        lines.append(f"- **{h['date']}** — {h['entry']}")
    md_path = _path(data["name"]).with_suffix(".md")
    _atomic_write_text(md_path, "\n".join(lines) + "\n")
