"""Core business logic for threat cluster tracking.

Protocol-agnostic on purpose: server.py (MCP) calls these same
functions for every harness. No MCP imports belong in this file.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import duckdb

from . import attack, pivot, report_ingest, stix
from .tracking import store as tracking_store
from .tracking.enrich import STALE_BASELINE_DAYS as _ATTR_STALE_BASELINE_DAYS

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


def _is_ipv4(value: str) -> bool:
    """True only for a parseable IPv4 literal. Used to strip IPv6 out of
    pivot results before filing - functional rule: ignore IPv6 for
    pivoting and probing, since the probe VM has no IPv6 route."""
    try:
        return ipaddress.ip_address(value).version == 4
    except ValueError:
        return False


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
        if addr.version == 6:
            return False, "IPv6 - the probe VM has no IPv6 route, active fingerprinting would only ever time out"
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
    # Collapse anything that isn't filename-safe (notably "/" and "\", which
    # would otherwise turn into a stray subdirectory - e.g. "ITG27 / Mustang
    # Panda" silently landing at itg27-/-mustang-panda.json and never
    # showing up in list_clusters(), which only globs the top-level dir).
    safe = re.sub(r"[^a-z0-9._-]+", "-", safe).strip("-")
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
        # each entry: {value, sources: [...], first_seen, last_seen}, plus
        # for domains/ips: ports (ips), asn/netname (ips), cert (domains),
        # tags (both) - see _apply_enrichment_snapshot for how these get
        # populated, at add-time and on every pivot_cluster sweep.
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


def add_observable(name: str, category: str, value: str, source: str,
                   metadata: dict[str, Any] | None = None) -> dict[str, Any]:
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

    metadata, if given, is stamped onto the entry only if it's genuinely
    new (an already-tracked value only gets `source` appended, same as
    always) - e.g. filing a file hash pivoted via pivot_observable with
    its filenames: add_observable(cluster, "hashes", "sha256:<hex>",
    source, metadata={"hash_kind": "file", "filenames": [...]}), so the
    filename isn't lost the way it is when only reading
    pivot_observable's own VirusTotal result (display-only, never
    auto-filed).

    A new domain/ip is still always tracked as an observable, but only
    queued for active fingerprinting if it passes _is_probe_worthy (not
    a private/reserved address, not a known-non-actor domain/resolver
    IP like a public DNS resolver or a major vendor's own site) - see
    that function's docstring. If it's skipped, the returned dict
    carries a transient (not persisted) `fingerprint_queue_skipped`
    list of {category, value, reason}; use requeue_fingerprint if you
    disagree with the call and want it probed anyway.

    A genuinely new domain/ip also gets a live asn/ports/cert/tags
    enrichment lookup (see _apply_enrichment_snapshot) before it's filed
    - deliberately run here, unlocked, rather than inside the
    @_synchronized merge below (see _sweep_lifecycle's docstring for
    why); re-touching an already-tracked value skips this and just
    appends `source` as before."""
    if category not in OBSERVABLE_CATEGORIES:
        raise ValueError("category must be one of " + ", ".join(OBSERVABLE_CATEGORIES))
    data = load_cluster(name)  # existence check + snapshot to decide if this is genuinely new
    enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]] = {}
    already_tracked = value in {o["value"] for o in data["observables"][category]}
    if category in _FINGERPRINTABLE_CATEGORIES and not already_tracked:
        enrichment = _sweep_lifecycle(
            domains=[value] if category == "domains" else [],
            ips=[value] if category == "ips" else [])
    return _add_observable_locked(name, category, value, source, enrichment, metadata)


@_synchronized
def _add_observable_locked(name: str, category: str, value: str, source: str,
                           enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]],
                           metadata: dict[str, Any] | None = None,
                           ) -> dict[str, Any]:
    data = load_cluster(name)  # re-read fresh; another writer may have raced in above
    extracted = {c: ([value] if c == category else []) for c in OBSERVABLE_CATEGORIES}
    _, skipped = _merge_observables(data, extracted, source, enrichment=enrichment, metadata=metadata)
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
    history (Cert Spotter, for domains), reverse-IP co-hosting
    (Hackertarget, for IPs), and open-port/CPE data (Shodan InternetDB,
    for IPs) are also keyless and surface sibling infrastructure or
    context as new pivot leads. ThreatFox (abuse.ch, THREATFOX_API_KEY)
    checks every kind against known malware-C2 IOCs, and is likewise
    skipped with a note when unconfigured - abuse.ch's Auth Portal now
    requires a free Auth-Key on every ThreatFox call. HoneyLabs
    honeypot-fleet telemetry (IPs only, HONEYLABS_API_KEY) is likewise
    skipped with a note when unconfigured; see summarize_honeylabs for
    how to read it.
    """
    kind = pivot.classify(value)
    result: dict[str, Any] = {"value": value, "kind": kind}

    threatfox_key = os.environ.get(pivot.THREATFOX_API_KEY_ENV)
    if not threatfox_key:
        result["threatfox"] = {
            "skipped": f"set {pivot.THREATFOX_API_KEY_ENV} to enable ThreatFox lookups"}
    else:
        result["threatfox"] = _cached_pivot(
            "threatfox", value, lambda: pivot.threatfox_lookup(value, threatfox_key))

    if kind in ("domain", "ip"):
        result["rdap"] = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, kind))
    if kind == "ip":
        result["ripestat"] = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        result["reverse_ip"] = _cached_pivot(
            "reverse_ip", value, lambda: pivot.hackertarget_reverse_ip(value))
        result["shodan"] = _cached_pivot(
            "shodan", value, lambda: pivot.shodan_internetdb_lookup(value))
        result["honeylabs"] = honeylabs_context(value)
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


def honeylabs_context(ip: str) -> dict[str, Any]:
    """Cached HoneyLabs honeypot-telemetry lookup for an IP. Returns the
    normalized lookup dict, a {"skipped": ...} note if HONEYLABS_API_KEY
    is unset, or {"error": ...} on lookup failure - never raises, so
    pipeline callers can enrich opportunistically without wrapping it."""
    api_key = os.environ.get(pivot.HONEYLABS_API_KEY_ENV)
    if not api_key:
        return {"skipped":
                f"set {pivot.HONEYLABS_API_KEY_ENV} to enable HoneyLabs honeypot-telemetry lookups"}
    try:
        return _cached_pivot("honeylabs", ip, lambda: pivot.honeylabs_lookup(ip, api_key))
    except pivot.PivotError as e:
        return {"error": str(e)}


def summarize_honeylabs(result: dict[str, Any]) -> str | None:
    """One-line, provenance-ready reading of a honeylabs_context result,
    or None for skipped/error results (so callers write nothing).

    The interpretation cuts both ways, and the line should keep that
    legible to whoever reads the provenance list later: heavy presence
    in honeypot telemetry usually means a mass scanner / opportunistic
    background noise (a counter-signal for "dedicated C2"), while
    absence on an otherwise-active IP is the quiet-infrastructure
    signal."""
    if not isinstance(result, dict) or "skipped" in result or "error" in result:
        return None
    today = datetime.now(timezone.utc).date().isoformat()
    events = result.get("events")
    if not events:
        return (f"HoneyLabs telemetry {today}: no honeypot activity on record - "
                "quiet infrastructure, not a known mass scanner")
    parts = [f"{events} honeypot events"]
    detail = []
    if result.get("events_24h"):
        detail.append(f"{result['events_24h']} in 24h")
    first_seen, last_seen = result.get("first_seen"), result.get("last_seen")
    if first_seen and last_seen:
        detail.append(f"seen {first_seen[:10]} to {last_seen[:10]}")
    if detail:
        parts[0] += f" ({', '.join(detail)})"
    ports = [str(p.get("port")) for p in (result.get("ports") or [])[:3]
             if isinstance(p, dict) and p.get("port") is not None]
    if ports:
        parts.append(f"top ports {','.join(ports)}")
    # cve_matches item shape unconfirmed (always empty on live samples so
    # far) - accept either bare strings or dicts carrying an id.
    cves = [c if isinstance(c, str) else c.get("id")
            for c in (result.get("cves") or [])[:3]]
    cves = [c for c in cves if c]
    if cves:
        parts.append(f"probing {', '.join(cves)}")
    if result.get("verdict"):
        label = result.get("verdict_label") or result["verdict"]
        qualifiers = ", ".join(q for q in (result.get("verdict_detail"),
                                            result.get("verdict_confidence"))
                               if q)
        parts.append(f"verdict: {label}" + (f" ({qualifiers})" if qualifiers else ""))
        return f"HoneyLabs telemetry {today}: {', '.join(parts)}"
    return (f"HoneyLabs telemetry {today}: {', '.join(parts)} - "
            "opportunistic scanner profile, weigh against dedicated-C2 hypotheses")


_PIVOT_CLUSTER_WORKERS = 6


def _threatfox_enrichment(value: str) -> dict[str, Any] | None:
    """Cached ThreatFox lookup for pivot_cluster's sweep, or None if
    THREATFOX_API_KEY isn't configured - mirrors pivot_observable's own
    skip-gracefully behavior rather than raising or logging a skip note
    per observable."""
    api_key = os.environ.get(pivot.THREATFOX_API_KEY_ENV)
    if not api_key:
        return None
    return _cached_pivot("threatfox", value, lambda: pivot.threatfox_lookup(value, api_key))


def _domain_lifecycle(value: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    rdap = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, "domain"))
    resolved = pivot.resolve_host(value)  # live, not cached — liveness is the point
    status = pivot.classify_domain_lifecycle(rdap, resolved)
    detail = {"resolved": resolved,
             "nameservers": rdap.get("nameservers") if isinstance(rdap, dict) else None}
    enrichment: dict[str, Any] = {
        "certspotter": _cached_pivot("certspotter", value, lambda: pivot.certspotter_lookup(value)),
    }
    threatfox = _threatfox_enrichment(value)
    if threatfox is not None:
        enrichment["threatfox"] = threatfox
    return status, detail, enrichment


def _ip_lifecycle(value: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    ripe = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
    status = pivot.classify_ip_lifecycle(ripe)
    detail = {"asn": ripe.get("asn") if isinstance(ripe, dict) else None,
             "prefix": ripe.get("prefix") if isinstance(ripe, dict) else None,
             "as_holder": ripe.get("as_holder") if isinstance(ripe, dict) else None}
    enrichment: dict[str, Any] = {
        "shodan": _cached_pivot("shodan", value, lambda: pivot.shodan_internetdb_lookup(value)),
        # Free/keyless reverse-IP co-hosting - combined with Shodan's own
        # "hostnames" field in _log_cluster_enrichment_history to build
        # the day-over-day "new domain pointed at this IP" signal (the
        # bgp.he.net cert-transparency-tab equivalent), without VT.
        "hackertarget": _cached_pivot(
            "reverse_ip", value, lambda: pivot.hackertarget_reverse_ip(value)),
    }
    threatfox = _threatfox_enrichment(value)
    if threatfox is not None:
        enrichment["threatfox"] = threatfox
    return status, detail, enrichment


def _sweep_lifecycle(domains: list[str], ips: list[str]
                      ) -> dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]:
    """Concurrent, lock-free lifecycle+enrichment sweep for a batch of
    domains/ips - the network phase shared by pivot_cluster (rechecking
    already-tracked observables) and the add-time enrichment path
    (add_observable/ingest_report/pivot_and_expand, for genuinely new
    ones). Never call this while holding _data_lock: a batch of RDAP/
    RIPEstat/Shodan/Cert Spotter/ThreatFox round-trips can take a while,
    and every other MCP tool call would block behind the lock for the
    duration - see pivot_cluster's docstring for why its own network
    phase already runs unlocked. A single lookup blowing up is recorded
    as an ("unknown", {"error": ...}, {}) tuple rather than sinking the
    whole batch."""
    jobs = ([("domains", v, _domain_lifecycle) for v in domains]
            + [("ips", v, _ip_lifecycle) for v in ips])
    results: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]] = {}
    if jobs:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_PIVOT_CLUSTER_WORKERS) as ex:
            futures = {ex.submit(fn, v): (cat, v) for cat, v, fn in jobs}
            for fut in concurrent.futures.as_completed(futures):
                cat, v = futures[fut]
                try:
                    results[(cat, v)] = fut.result()
                except Exception as e:  # a single lookup blowing up shouldn't sink the sweep
                    results[(cat, v)] = ("unknown", {"error": str(e)}, {})
    return results


def _new_values(data: dict[str, Any], category: str, values: list[str]) -> list[str]:
    """Values in `values` not already tracked on the cluster in `category`,
    deduped, order-preserving - the "what actually needs an enrichment
    lookup" filter shared by add_observable/ingest_report/pivot_and_expand,
    kept in sync with _file_new_observables' own dedup logic."""
    existing = {o["value"] for o in data["observables"][category]}
    return [v for v in dict.fromkeys(values) if v and v not in existing]


def _apply_enrichment_snapshot(entry: dict[str, Any], category: str,
                                detail: dict[str, Any], enrichment: dict[str, Any]) -> None:
    """Stamp the latest known asn/netname/ports/cert/tags snapshot onto an
    observable entry from a (status, detail, enrichment) tuple - the shape
    _domain_lifecycle/_ip_lifecycle/_sweep_lifecycle already produce.
    Called both at add-time (for a genuinely new observable) and from
    pivot_cluster's write phase (to keep an already-tracked observable's
    snapshot current) - see _merge_observables and pivot_cluster.

    asn/netname/cert are overwritten (this is a point-in-time snapshot,
    not history - the history lives in the tracking-store attribute_changes
    table, see _log_cluster_enrichment_history). ports and tags are
    unioned, never dropped, mirroring tracking.store.upsert_actor's own
    "known values only ever widen" convention - a port or tag seen once
    stays recorded even if a later check doesn't re-see it."""
    tags = set(entry.get("tags") or [])
    if category == "ips":
        # detail["asn"] comes straight from RIPEstat's "asns" field
        # (see pivot.ripestat_lookup / _ip_lifecycle) - plural because a
        # prefix can technically have more than one announcing origin -
        # so it's a list here, not a bare int; take the first as the
        # observable's own asn, matching enrich.py's _registry_lookup
        # (_as_int(asns[0])) and the DuckDB observations.asn column.
        asn_list = detail.get("asn")
        if asn_list:
            entry["asn"] = asn_list[0] if isinstance(asn_list, list) else asn_list
        if detail.get("as_holder"):
            entry["netname"] = detail["as_holder"]
        shodan = enrichment.get("shodan")
        if isinstance(shodan, dict) and "error" not in shodan:
            new_ports = shodan.get("ports") or []
            if new_ports:  # don't stamp an empty ports:[] where nothing was there before
                ports = entry.setdefault("ports", [])
                for p in new_ports:
                    if p not in ports:
                        ports.append(p)
            tags |= {f"shodan:tag:{t}" for t in shodan.get("tags") or []}
    elif category == "domains":
        certspotter = enrichment.get("certspotter")
        if isinstance(certspotter, dict) and "error" not in certspotter:
            issuances = certspotter.get("issuances") or []
            if issuances:  # nothing in CT logs yet - don't stamp an empty/None cert block
                latest = issuances[0]
                entry["cert"] = {"issuer": latest.get("issuer"),
                                  "not_before": latest.get("not_before"),
                                  "not_after": latest.get("not_after"),
                                  "sibling_hostnames": certspotter.get("hostnames") or [],
                                  "sha256": latest.get("cert_sha256"),
                                  "revoked": latest.get("revoked"),
                                  "checked": _now()}
    threatfox = enrichment.get("threatfox")
    if isinstance(threatfox, dict) and "error" not in threatfox:
        for m in threatfox.get("matches") or []:
            if m.get("malware"):
                tags.add(f"threatfox:malware:{m['malware']}")
            tags |= {f"threatfox:tag:{t}" for t in (m.get("tags") or [])}
    if tags:
        entry["tags"] = sorted(tags)


_ATTRIBUTE_CONFIDENCE_BASE = {
    "cert_issuer_changed": "high", "ports_changed": "medium", "cert_sans_changed": "medium",
    "cert_new": "high", "hostnames_changed": "medium",
}


def _attribute_confidence(change_type: str, baseline_observed_at: datetime) -> str:
    """Port/cert confidence, adapted from tracking.enrich._confidence's
    shape: unlike ASN (which can be corroborated across RDAP+HoneyLabs),
    ports/cert each have only one source, so there's no corroboration
    branch - confidence starts from a per-change-type base and is
    downgraded one step if the baseline is older than
    _ATTR_STALE_BASELINE_DAYS, same staleness rule enrich.py uses for
    ASN changes (an old baseline re-checked for the first time in months
    shouldn't read as a confident 'changed since yesterday')."""
    conf = _ATTRIBUTE_CONFIDENCE_BASE[change_type]
    if datetime.now() - baseline_observed_at > timedelta(days=_ATTR_STALE_BASELINE_DAYS):
        conf = {"high": "medium", "medium": "low"}[conf]
    return conf


def _record_port_change(con: duckdb.DuckDBPyConnection, ip: str, actor: str | None,
                        observed_at: datetime, new_ports: list[int]) -> None:
    baseline = tracking_store.latest_ports_for(con, ip, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=ip, actor=actor,
            attribute="ports", change_type="first_seen", confidence="medium",
            old_value=None, new_value=new_ports)
        return
    if sorted(baseline["ports"]) == sorted(new_ports):
        return  # no change - the common case, nothing recorded
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=ip, actor=actor,
        attribute="ports", change_type="ports_changed",
        confidence=_attribute_confidence("ports_changed", baseline["observed_at"]),
        old_value=baseline["ports"], new_value=new_ports)


def _record_cert_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                        observed_at: datetime, latest_issuance: dict[str, Any],
                        hostnames: list[str]) -> None:
    new_issuer = latest_issuance.get("issuer")
    baseline = tracking_store.latest_cert_for(con, domain, observed_at)
    if baseline is None:
        if new_issuer is None:
            return
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="cert", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"issuer": new_issuer, "hostnames": hostnames})
        return
    if new_issuer and baseline["issuer"] and new_issuer != baseline["issuer"]:
        change_type = "cert_issuer_changed"
    elif set(hostnames) != set(baseline["sibling_hostnames"]):
        change_type = "cert_sans_changed"
    else:
        return  # same issuer, same siblings - routine renewal, not recorded
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="cert", change_type=change_type,
        confidence=_attribute_confidence(change_type, baseline["observed_at"]),
        old_value={"issuer": baseline["issuer"], "hostnames": baseline["sibling_hostnames"]},
        new_value={"issuer": new_issuer, "hostnames": hostnames})


def _record_cert_hash_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                             observed_at: datetime, latest_issuance: dict[str, Any]) -> None:
    """A separate diff from _record_cert_change: that one tracks issuer/SAN
    changes and deliberately treats a same-issuer/same-SANs renewal as
    routine (not recorded), but a renewal always mints a brand new
    certificate - and therefore a new cert_sha256 - so this tracks that
    pivot value on its own timeline instead of conflating it with the
    issuer/SANs signal."""
    new_sha256 = latest_issuance.get("cert_sha256")
    if not new_sha256:
        return
    baseline = tracking_store.latest_cert_for(con, domain, observed_at)
    if baseline is None or not baseline.get("sha256"):
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="cert_hash", change_type="first_seen", confidence="medium",
            old_value=None,
            new_value={"sha256": new_sha256, "revoked": latest_issuance.get("revoked")})
        return
    if new_sha256 == baseline["sha256"]:
        return  # same cert as last check - nothing to record
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="cert_hash", change_type="cert_new",
        confidence=_attribute_confidence("cert_new", baseline["observed_at"]),
        old_value={"sha256": baseline["sha256"], "revoked": baseline.get("revoked")},
        new_value={"sha256": new_sha256, "revoked": latest_issuance.get("revoked")})


def _record_hostname_change(con: duckdb.DuckDBPyConnection, ip: str, actor: str | None,
                            observed_at: datetime, new_hostnames: list[str]) -> None:
    """Day-over-day diff of domains discovered pointing at a tracked IP
    (Shodan InternetDB's own hostnames field, unioned with Hackertarget's
    reverse-IP lookup - see _log_cluster_enrichment_history) - the
    bgp.he.net cert-transparency-tab equivalent for an IP, built from
    free/keyless sources already in this module rather than VT passive-DNS
    or a paid platform. Mirrors _record_port_change's shape. When new
    hostnames actually appear, also runs a best-effort Cert Spotter lookup
    on each (see _candidate_hostname_certs) so the flagged note carries the
    same cert-transparency pivot info bgp.he.net's IP page shows - the
    hostnames themselves are still never auto-filed as tracked
    observables, per the flag-only-new-leads decision."""
    baseline = tracking_store.latest_hostnames_for(con, ip, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=ip, actor=actor,
            attribute="hostnames", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"hostnames": new_hostnames})
        return
    if sorted(baseline["hostnames"]) == sorted(new_hostnames):
        return  # no change - the common case, nothing recorded
    new_only = sorted(set(new_hostnames) - set(baseline["hostnames"]))
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=ip, actor=actor,
        attribute="hostnames", change_type="hostnames_changed",
        confidence=_attribute_confidence("hostnames_changed", baseline["observed_at"]),
        old_value=baseline["hostnames"],
        new_value={"hostnames": new_hostnames, "added": new_only,
                  "certs": _candidate_hostname_certs(new_only) if new_only else []})


def _candidate_hostname_certs(hostnames: list[str]) -> list[dict[str, Any]]:
    """Best-effort Cert Spotter lookup for each newly-discovered (not yet
    tracked) hostname found pointing at a monitored IP - gives the analyst
    the same cert-transparency pivot info bgp.he.net's IP page shows,
    without filing the hostname itself as a tracked observable (new leads
    are flag-only, per the threat-cluster-tracking skill). Kept to a small
    list since this only ever runs over genuinely new hostnames from one
    sweep, and Cert Spotter's own error handling (rate-limited without a
    token) already degrades a single failed lookup to {"error": ...}
    rather than raising."""
    out = []
    for h in hostnames:
        cs = _cached_pivot("certspotter", h, lambda h=h: pivot.certspotter_lookup(h))
        if isinstance(cs, dict) and "error" not in cs and cs.get("issuances"):
            latest = cs["issuances"][0]
            out.append({"hostname": h, "cert_issuer": latest.get("issuer"),
                       "cert_sha256": latest.get("cert_sha256"),
                       "revoked": latest.get("revoked")})
        else:
            out.append({"hostname": h, "cert_issuer": None, "cert_sha256": None, "revoked": None})
    return out


def _log_cluster_enrichment_history(
        actor: str, observed_at: datetime,
        results: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]) -> str | None:
    """Best-effort: write one dated observation row per ip/domain that got
    fresh Shodan/Cert Spotter/ThreatFox data this sweep, so the dashboard's
    per-observable timeline can show when these fields were seen or
    changed - and, for ports/cert, diff the fresh value against the prior
    baseline and record a change in attribute_changes when something
    actually moved (see _record_port_change/_record_cert_change). Returns
    an error note (never raises) on a tracking-store hiccup - pivot_cluster's
    cluster-JSON write already happened and a separate store's outage
    shouldn't undo or block reporting that success."""
    try:
        with tracking_store.connect(read_only=False) as con:
            for (category, value), (_status, _detail, enrichment) in results.items():
                indicator_type = "domain" if category == "domains" else "ipv4"
                shodan = enrichment.get("shodan")
                if isinstance(shodan, dict) and "error" not in shodan:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="shodan", actor=actor, indicator_type=indicator_type,
                        shodan_ports=shodan.get("ports") or None,
                        shodan_tags=shodan.get("tags") or None,
                        metadata={"hostnames": shodan.get("hostnames"),
                                 "cpes": shodan.get("cpes"), "vulns": shodan.get("vulns")})
                    _record_port_change(con, value, actor, observed_at,
                                        shodan.get("ports") or [])
                certspotter = enrichment.get("certspotter")
                if isinstance(certspotter, dict) and "error" not in certspotter:
                    issuances = certspotter.get("issuances") or []
                    latest = issuances[0] if issuances else {}
                    hostnames = certspotter.get("hostnames") or []
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="certspotter", actor=actor, indicator_type=indicator_type,
                        cert_issuer=latest.get("issuer"),
                        cert_not_before=latest.get("not_before"),
                        cert_not_after=latest.get("not_after"),
                        cert_sibling_hostnames=hostnames or None,
                        cert_sha256=latest.get("cert_sha256"),
                        cert_revoked=latest.get("revoked"))
                    _record_cert_change(con, value, actor, observed_at, latest, hostnames)
                    _record_cert_hash_change(con, value, actor, observed_at, latest)
                threatfox = enrichment.get("threatfox")
                if isinstance(threatfox, dict) and "error" not in threatfox:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="threatfox", actor=actor, indicator_type=indicator_type,
                        threatfox_matches=threatfox.get("matches") or None)
                # Domain-on-IP discovery (free/keyless): union Shodan's own
                # "hostnames" field with Hackertarget's reverse-IP domains -
                # the bgp.he.net cert-transparency-tab equivalent for an IP,
                # diffed day-over-day the same way ports are.
                hackertarget = enrichment.get("hackertarget")
                shodan_hostnames = (shodan.get("hostnames") or []) \
                    if isinstance(shodan, dict) and "error" not in shodan else []
                hackertarget_domains = (hackertarget.get("domains") or []) \
                    if isinstance(hackertarget, dict) and "error" not in hackertarget else []
                if shodan_hostnames or hackertarget_domains:
                    discovered = sorted(set(shodan_hostnames) | set(hackertarget_domains))
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="hostdiscovery", actor=actor, indicator_type=indicator_type,
                        discovered_hostnames=discovered)
                    _record_hostname_change(con, value, actor, observed_at, discovered)
    except (tracking_store.TrackingBusy, duckdb.IOException) as e:
        return f"enrichment history not recorded: {e}"
    return None


def _file_cert_hash(data: dict[str, Any], domain: str, sha256: str,
                    issuer: str | None, revoked: bool | None, now: str) -> None:
    """Auto-file a certificate's own SHA256 fingerprint onto the cluster's
    hashes list when pivot_cluster sees a new one for an already-tracked
    domain - an attribute of infrastructure already being tracked (like
    ASN/ports/cert issuer), not a new lead, so unlike a sibling hostname
    (see _record_hostname_change, flag-only) this auto-updates without
    analyst confirmation. The `cert-sha256:` value prefix (distinct from
    the existing `sha256:`/`sha1:`/`md5:` file-hash prefixes) plus the
    explicit hash_kind field make this unambiguous as a certificate hash,
    not a file hash; cert_for names the domain it belongs to."""
    value = f"cert-sha256:{sha256}"
    bucket = data["observables"]["hashes"]
    source = f"Cert Spotter CT log for {domain}, seen {now[:10]}"
    for entry in bucket:
        if entry["value"] == value:
            if source not in entry["sources"]:
                entry["sources"].append(source)
            entry["last_seen"] = now
            entry["cert_issuer"] = issuer
            entry["cert_revoked"] = revoked
            return
    bucket.append({
        "value": value, "sources": [source], "first_seen": now, "last_seen": now,
        "hash_kind": "certificate", "cert_for": domain,
        "cert_issuer": issuer, "cert_revoked": revoked,
    })


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

    Each ip is also enriched via Shodan InternetDB (keyless) and, for
    both ips and domains, ThreatFox (if THREATFOX_API_KEY is set) -
    domains additionally get Cert Spotter. This enrichment is stamped
    onto each observable's asn/netname/ports/cert/tags fields (see
    _apply_enrichment_snapshot) so the current-known-value snapshot stays
    fresh, AND a dated snapshot is recorded to the tracking-store history
    (mcp_tools.tracking.store), which also runs day-over-day diffing for
    ports/cert and records a change when something moved - see
    _log_cluster_enrichment_history. The dashboard's per-observable
    profile reads that history back - see get_observables/the dashboard.

    The network lookups run concurrently and, crucially, OUTSIDE the data
    lock - a cluster with dozens of domains would otherwise serialize
    into minutes of blocking I/O with the whole store locked. Only the
    final write-back takes the lock, re-reading the cluster so it applies
    onto current on-disk state."""
    data = load_cluster(name)  # existence check + snapshot the values to check
    domains = [o["value"] for o in data["observables"]["domains"]]
    ips = [o["value"] for o in data["observables"]["ips"]]

    # Network phase: concurrent, no lock held.
    results = _sweep_lifecycle(domains, ips)

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
                status, detail, enrichment = found
                o["status"] = status
                o["status_checked"] = now
                o["status_detail"] = detail
                _apply_enrichment_snapshot(o, cat, detail, enrichment)
                if cat == "domains":
                    new_cert = o.get("cert") or {}
                    new_sha256 = new_cert.get("sha256")
                    if new_sha256:
                        # Unconditional, not gated on "changed since last
                        # sweep": _file_cert_hash's own bucket lookup
                        # already dedupes by value (idempotent re-filing
                        # just bumps last_seen/sources), and gating here
                        # would miss the very first cert a domain ever
                        # gets - add_observable's own add-time enrichment
                        # sweep already stamps entry["cert"] before this
                        # sweep ever runs (see _merge_observables), so a
                        # "did it change from the cluster JSON's own
                        # snapshot" check would never fire for that first
                        # sighting.
                        _file_cert_hash(data, o["value"], new_sha256, new_cert.get("issuer"),
                                       new_cert.get("revoked"), now)
                row = {"value": o["value"], "status": status}
                shodan = enrichment.get("shodan")
                if isinstance(shodan, dict) and "error" not in shodan:
                    row["ports"] = shodan.get("ports")
                certspotter = enrichment.get("certspotter")
                if isinstance(certspotter, dict) and "error" not in certspotter:
                    row["cert_sibling_count"] = len(certspotter.get("hostnames") or [])
                threatfox = enrichment.get("threatfox")
                if isinstance(threatfox, dict) and "error" not in threatfox:
                    row["threatfox_matches"] = len(threatfox.get("matches") or [])
                row["resolved" if cat == "domains" else "asn"] = \
                    detail.get("resolved") if cat == "domains" else detail.get("asn")
                summary[cat].append(row)
        save_cluster(data)

    # Best-effort history logging to the separate tracking store, outside
    # the cluster-JSON lock above (a different store, its own locking) -
    # done after that write succeeds so a tracking-store hiccup can't
    # undo or block the cluster-JSON update that already landed.
    observed_at = datetime.fromisoformat(now).replace(tzinfo=None)
    history_error = _log_cluster_enrichment_history(data["name"], observed_at, results)
    if history_error:
        summary["history_note"] = history_error
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
                           source: str,
                           enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                           | None = None) -> list[str]:
    """Merge only values not already tracked on the cluster in `category`,
    returning the ones actually added (deduped, order-preserving).
    `enrichment`, if given, is a _sweep_lifecycle-shaped result keyed by
    (category, value) - passed through to _merge_observables so a newly
    filed indicator gets its own asn/ports/cert/tags snapshot, not just
    whatever the parent pivot happened to fetch."""
    existing = {o["value"] for o in data["observables"][category]}
    new = [v for v in dict.fromkeys(values) if v and v not in existing]
    if new:
        extracted = {c: (new if c == category else []) for c in OBSERVABLE_CATEGORIES}
        # skip list unused - caller's own confidence filter already applies
        _merge_observables(data, extracted, source, enrichment=enrichment)
    return new


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
    indicators are filed; ones already tracked are left as-is.

    Each newly-filed indicator also gets its own live asn/ports/cert/tags
    snapshot (see _apply_enrichment_snapshot) - a second, cheap (cached)
    lookup on the newly-discovered value itself, run in the same unlocked
    network phase as the rest of this pivot; see _sweep_lifecycle for why
    that lookup must not run under _data_lock."""
    data = load_cluster(cluster_name)  # must already exist; expansion targets an investigation
    kind = pivot.classify(value)
    if kind not in ("domain", "ip"):
        raise ValueError(
            f"pivot_and_expand supports domain/ip values; got kind={kind!r} for {value!r}")
    if kind == "ip" and ipaddress.ip_address(value).version == 6:
        # Functional rule: ignore IPv6 for pivoting and probing - the probe
        # VM has no IPv6 route, so neither a VT lookup here nor anything
        # downstream (fingerprinting) can act on the result.
        return _pivot_and_expand_ipv6_skip(value, cluster_name, kind)

    now = _now()
    api_key = os.environ.get(pivot.VT_API_KEY_ENV)
    candidates: list[tuple[str, list[str], str]] = []  # (category, values, source)
    review: dict[str, Any] = {}

    if kind == "domain":
        ct = _cached_pivot("certspotter", value, lambda: pivot.certspotter_lookup(value))
        if isinstance(ct, dict) and ct.get("error"):
            review["certspotter_error"] = ct["error"]
        elif isinstance(ct, dict):
            hostnames = ct.get("hostnames", [])
            siblings = [h for h in hostnames if h != value and h.endswith("." + value)]
            candidates.append(("domains", siblings,
                               f"pivot_and_expand via Cert Spotter CT log, checked {now}"))
            others = [h for h in hostnames if h != value and not h.endswith("." + value)]
            if others:
                review["certspotter_other_hostnames"] = others
        if api_key:
            vt = _cached_pivot("virustotal", value, lambda: _safe_vt(value, kind, api_key))
            ips = [r["ip"] for r in (vt.get("resolutions") or []) if r.get("ip")] \
                if isinstance(vt, dict) else []
            ips = [ip for ip in ips if _is_ipv4(ip)]  # ignore IPv6 for pivoting/probing - no route from the probe VM
            candidates.append(("ips", ips,
                               f"pivot_and_expand via VirusTotal resolution history, checked {now}"))
    else:  # ip
        if api_key:
            vt = _cached_pivot("virustotal", value, lambda: _safe_vt(value, kind, api_key))
            domains = [r["domain"] for r in (vt.get("resolutions") or []) if r.get("domain")] \
                if isinstance(vt, dict) else []
            candidates.append(("domains", domains,
                               f"pivot_and_expand via VirusTotal resolution history, checked {now}"))
        rev = _cached_pivot("reverse_ip", value, lambda: pivot.hackertarget_reverse_ip(value))
        cohosted = rev.get("domains", []) if isinstance(rev, dict) and not rev.get("error") else []
        if include_cohosted:
            candidates.append(("domains", cohosted,
                               f"pivot_and_expand via Hackertarget reverse-IP, checked {now}"))
        elif cohosted:
            review["cohosted_domains"] = cohosted

    new_domains = _new_values(data, "domains",
                              [v for cat, vs, _ in candidates if cat == "domains" for v in vs])
    new_ips = _new_values(data, "ips",
                          [v for cat, vs, _ in candidates if cat == "ips" for v in vs])
    enrichment = _sweep_lifecycle(new_domains, new_ips)  # unlocked - see docstring

    return _pivot_and_expand_merge(value, kind, cluster_name, now, candidates, review, enrichment)


@_synchronized
def _pivot_and_expand_ipv6_skip(value: str, cluster_name: str, kind: str) -> dict[str, Any]:
    data = load_cluster(cluster_name)
    entry = f"pivot_and_expand on {value}: skipped (IPv6, not pivoted)"
    data["hunt_log"].append({"date": _now(), "entry": entry})
    save_cluster(data)
    return {"value": value, "kind": kind, "cluster": cluster_name,
            "filed": {}, "review": {}, "cluster_state": load_cluster(cluster_name)}


@_synchronized
def _pivot_and_expand_merge(value: str, kind: str, cluster_name: str, now: str,
                            candidates: list[tuple[str, list[str], str]],
                            review: dict[str, Any],
                            enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                            ) -> dict[str, Any]:
    """Locked write phase: re-read the cluster fresh (another writer may
    have raced in while the network phase above ran unlocked) and file
    everything in one go."""
    data = load_cluster(cluster_name)
    filed: dict[str, list[str]] = {}
    for category, values, source in candidates:
        added = _file_new_observables(data, category, values, source, enrichment=enrichment)
        if added:
            filed.setdefault(category, []).extend(added)

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
                        ip_ports: dict[str, list[int]] | None = None,
                        enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                        | None = None,
                        metadata: dict[str, Any] | None = None,
                        ) -> tuple[dict[str, int], list[dict[str, str]]]:
    """enrichment, if given, is a _sweep_lifecycle-shaped result keyed by
    (category, value) - applied via _apply_enrichment_snapshot only onto
    entries genuinely new to this cluster (an already-tracked value just
    gets `source` appended, as before; its snapshot is pivot_cluster's job
    to refresh, not add-time's).

    metadata, if given, is stamped (via dict.update) onto any newly-created
    entry - e.g. add_observable's own metadata= param, for recording a
    file hash's filenames (see mcp-server/cti_tools/pivot.py's VirusTotal
    communicating/downloaded_files data, surfaced but never persisted
    until an analyst manually files one this way). Only meaningful when
    `extracted` names a single value (add_observable's own call shape) -
    a bulk multi-value call (ingest_report, import_stix_bundle) never
    passes this, since one metadata dict can't sensibly apply to every
    value being filed at once."""
    now = _now()
    counts = {}
    newly_tracked: list[tuple[str, str]] = []  # (category, value), for the fingerprint queue
    skipped: list[dict[str, str]] = []  # entries tracked but not queued, with why
    ip_ports = ip_ports or {}
    enrichment = enrichment or {}
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
                if metadata:
                    entry.update(metadata)
                found = enrichment.get((category, value))
                if found:
                    _, detail, enr = found
                    _apply_enrichment_snapshot(entry, category, detail, enr)
                    if category == "domains":
                        # A genuinely new domain's very first cert sighting
                        # happens right here (this add-time sweep), not on
                        # a later pivot_cluster pass - file it now so the
                        # sha256 is pivotable from the moment the domain is
                        # tracked (see pivot_cluster's own matching call for
                        # why this is unconditional, not gated on "changed").
                        new_cert = entry.get("cert") or {}
                        new_sha256 = new_cert.get("sha256")
                        if new_sha256:
                            _file_cert_hash(data, value, new_sha256, new_cert.get("issuer"),
                                           new_cert.get("revoked"), now)
                bucket.append(entry)
                added += 1
                if category in _FINGERPRINTABLE_CATEGORIES:
                    ok, reason = _is_probe_worthy(category, value)
                    if ok:
                        newly_tracked.append((category, value))
                    else:
                        skipped.append({"category": category, "value": value, "reason": reason})
            # Every C2/service port a report names near this IP (see
            # report_ingest._extract_ip_ports) is stamped onto the IP's
            # own observable entry so active fingerprinting can probe
            # its real port(s) instead of always defaulting to 443 - see
            # probe_pending_fingerprints.py's _lookup_ports. Appended
            # (deduped), not overwritten, since a later report might
            # name another port for the same IP (a genuinely multi-port
            # C2, or just a second report) without invalidating the
            # ones already recorded.
            if category == "ips" and value in ip_ports:
                ports = entry.setdefault("ports", [])
                for port in ip_ports[value]:
                    if port not in ports:
                        ports.append(port)
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
    if category == "ips" and not _is_ipv4(value):
        raise ValueError(f"refusing to requeue {value!r}: IPv6 is ignored for pivoting/probing "
                          "(no route from the probe VM)")
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
    every such port is stamped onto the IP's own observable entry
    (`ports: [...]`, see report_ingest._extract_ip_ports — usually one
    port, but a genuinely multi-port C2 can accumulate more than one).
    Active fingerprinting checks that field first and only falls back to
    443 if nothing was extracted — see probe_pending_fingerprints.py's
    _lookup_ports, which probes every recorded port, not just the first.

    Every genuinely new domain/ip extracted also gets a live asn/ports/
    cert/tags enrichment lookup (see _apply_enrichment_snapshot), run in
    an unlocked phase between the report fetch/extraction and the final
    write - see _sweep_lifecycle's docstring for why that has to happen
    outside _data_lock. The single report-URL fetch itself still runs
    under the lock, unchanged from before.
    """
    cluster_name, extracted, new_domains, new_ips = _ingest_report_phase1(
        source, cluster_name, create_if_missing)
    enrichment = _sweep_lifecycle(new_domains, new_ips)  # unlocked
    return _ingest_report_phase2(cluster_name, source, extracted, enrichment, create_if_missing)


@_synchronized
def _ingest_report_phase1(source: str, cluster_name: str | None, create_if_missing: bool
                          ) -> tuple[str, dict[str, Any], list[str], list[str]]:
    """Locked: fetch the report (one bounded URL fetch, as before) and
    extract/resolve the cluster name - no per-indicator network calls
    happen in this phase. Returns what phase 2 needs to finish the write,
    plus the genuinely-new domains/ips for the unlocked enrichment sweep
    that runs between the two phases."""
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

    new_domains = _new_values(data, "domains", extracted["domains"])
    new_ips = _new_values(data, "ips", extracted["ips"])
    return cluster_name, extracted, new_domains, new_ips


@_synchronized
def _ingest_report_phase2(cluster_name: str, source: str, extracted: dict[str, Any],
                          enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]],
                          create_if_missing: bool) -> dict[str, Any]:
    """Locked: re-resolve the cluster fresh (another writer may have
    raced in while the enrichment sweep ran unlocked between the two
    phases) and file extraction + enrichment in one write."""
    if _path(cluster_name).exists():
        data = load_cluster(cluster_name)
    elif create_if_missing:
        data = _new_cluster(cluster_name, f"Auto-created from report ingestion: {source}")
    else:
        raise ClusterNotFound(f"No cluster named {cluster_name!r}")

    observable_counts, skipped = _merge_observables(
        data, extracted, source, ip_ports=extracted.get("ip_ports"), enrichment=enrichment)
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


_DATE_ONLY_RE = re.compile(r"^(\d{4})-(\d{2})(?:-(\d{2}))?")


def _date_only(value: str | None) -> str | None:
    """Normalize an ISO-ish date/datetime/year-month string to plain
    YYYY-MM-DD, or return the value unchanged if it doesn't start with
    at least YYYY-MM. Observable-level first_seen/last_seen/
    status_checked are always machine-generated via _now() so this is a
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
    md_path = _path(data["name"]).with_suffix(".md")
    _atomic_write_text(md_path, "\n".join(lines) + "\n")
