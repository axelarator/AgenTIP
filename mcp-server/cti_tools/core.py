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

from . import attack, pivot, report_ingest, stix, vm_proxy, webamon
from .tracking import store as tracking_store
from .tracking.analytics import SHARED_HOSTING_ASNS
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
    filename isn't lost the way it is when only reading it off a
    display-only lookup.

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


# Pivot enrichment cache. Webamon calls count against a daily budget and
# HoneyLabs credits are metered, so refetching the same indicator on every
# pivot burns through both; RDAP/RIPEstat and the probe-VM round-trips are
# also slow and worth not repeating. This caches each source's answer for
# a value for a short TTL. It is NOT cluster data - just a transient
# enrichment cache under _registry - and only successful lookups are
# cached (never errors or a missing-key skip note). Set
# CTI_PIVOT_CACHE_TTL=0 to disable caching entirely.
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


_pivot_cache_lock = threading.Lock()


def _is_soft_failure(result: Any) -> bool:
    """True for a source result that reports failure instead of raising.

    Sources signal failure two ways: a top-level "error", or a per-sub-call
    "<name>_error" (pivot.ripestat_lookup returns one per sub-call so a
    partial answer still comes back). Only the first used to keep a result
    out of the cache, so a run where every RIPEstat sub-call failed cached
    {"network_info_error": ...} as if it were the answer - and for the whole
    TTL afterwards every sweep reported the IP as "unknown" with no error
    anywhere to explain it. Seen for real when the MCP server started
    without CTI_PROBE_* set.
    """
    if not isinstance(result, dict):
        return False
    return any(k == "error" or str(k).endswith("_error") for k in result)


def _cached_pivot(source: str, value: str, fetch) -> Any:
    """Return a cached source result for `value` if it's fresh, else call
    `fetch()`, cache a successful result, and return it. `fetch` may
    raise - exceptions propagate uncached so a transient outage isn't
    remembered as the answer.

    The read and the write are each taken under _pivot_cache_lock so the
    6-thread _sweep_lifecycle pool can't lose entries to an interleaved
    read-modify-write of the shared pivot_cache.json (the write re-reads
    the file so a concurrent writer's entry survives). fetch() itself runs
    OUTSIDE the lock - it's a network round trip and mustn't serialize the
    whole pool. Cross-process races (cron vs MCP server) still exist but
    _atomic_write_text keeps each write internally consistent, so the worst
    case is a dropped cache entry, not corruption."""
    import time
    ttl = _pivot_cache_ttl()
    if ttl <= 0:
        return fetch()
    key = f"{source}:{value}"
    now = time.time()
    with _pivot_cache_lock:
        entry = _load_pivot_cache().get(key)
    if entry and now - entry.get("ts", 0) < ttl:
        return entry["result"]
    result = fetch()
    # Don't cache soft failures; a later retry should be able to succeed.
    if not _is_soft_failure(result):
        with _pivot_cache_lock:
            cache = _load_pivot_cache()  # re-read so a concurrent writer isn't clobbered
            cache[key] = {"ts": now, "result": result}
            try:
                _atomic_write_text(_pivot_cache_path(), json.dumps(cache))
            except OSError:
                pass
    return result


def _norm_live(result: dict[str, Any] | Any) -> dict[str, Any]:
    """Normalize a vm_proxy live-grab response (tls_grab/http_probe/
    dns_lookup) - which always carries an `error` key, None on success -
    into the {...}|{"error": ...} shape the enrichment consumers gate on
    (`"error" not in result`). Drops the `error: None` key on success so a
    good result isn't misread as a failure or refused by _cached_pivot."""
    if not isinstance(result, dict):
        return {"error": "unexpected probe response"}
    if result.get("error"):
        return {"error": str(result["error"])}
    return {k: v for k, v in result.items() if k != "error"}


def _live_tls(host: str) -> dict[str, Any]:
    try:
        return _cached_pivot("tls_live", host, lambda: _norm_live(vm_proxy.tls_grab(host)))
    except vm_proxy.VMProxyError as e:
        return {"error": str(e)}


def _live_http(host: str) -> dict[str, Any]:
    try:
        return _cached_pivot("http_live", host,
                             lambda: _norm_live(vm_proxy.http_probe(f"https://{host}")))
    except vm_proxy.VMProxyError as e:
        return {"error": str(e)}


def _webamon_domain(domain: str) -> dict[str, Any]:
    return _cached_pivot("webamon", domain, lambda: webamon.search_domain(domain))


def _webamon_ip(ip: str) -> dict[str, Any]:
    return _cached_pivot("webamon_ip", ip, lambda: webamon.search_ip(ip))


def _webamon_infostealers(domain: str) -> dict[str, Any]:
    return _cached_pivot("webamon_is", domain, lambda: webamon.infostealers(domain))


def _subdomains_for(domain: str) -> dict[str, Any]:
    """Passive subdomain discovery for the automatic sweep: subfinder unioned
    with Wayback CDX, both run on the probe VM. Flag-only (never auto-filed
    here - see _record_subdomains_change). Returns {"subdomains": [...]} or
    {"error": ...}."""
    subs: set[str] = set()
    errors = []
    for source, fn in (("subfinder", vm_proxy.subfinder), ("wayback", vm_proxy.wayback_cdx)):
        try:
            r = _cached_pivot(source, domain, lambda fn=fn: _norm_live(fn(domain)))
        except vm_proxy.VMProxyError as e:
            errors.append(str(e))
            continue
        if isinstance(r, dict) and "error" not in r:
            subs |= {s.lower() for s in (r.get("subdomains") or [])}
    if not subs and errors:
        return {"error": "; ".join(errors)}
    return {"subdomains": sorted(subs)}


def pivot_observable(value: str) -> dict[str, Any]:
    """On-demand infrastructure pivot for a single hash/domain/ip/url.
    Display only: no cluster data is written, unlike ingest_report -
    though successful lookups are cached transiently under _registry to
    respect source rate limits (see CTI_PIVOT_CACHE_TTL). If a pivot
    surfaces something worth keeping, record it yourself via
    append_hunt_log, add_gap, or by filing the new indicator into a
    cluster.

    Sources: RDAP (registration data, domain/ip); RIPEstat (ASN/network
    context, ip); Webamon (a domain's latest scan - cert, DNS, ASN, tech,
    kit fingerprints - and its infostealer-log hits; an IP's hosted
    domains, the reverse-IP replacement); a live TLS grab and HTTP probe
    from the probe VM (a domain's current certificate and liveness);
    PTR (ip); ThreatFox known-malware-C2 IOC match (THREATFOX_API_KEY);
    and HoneyLabs honeypot telemetry (ip, HONEYLABS_API_KEY). ThreatFox/
    HoneyLabs are skipped with a note when their key is unset; the rest
    need no key (Webamon uses WEBAMON_API_KEY, surfacing an error dict if
    unset). See summarize_honeylabs for how to read the HoneyLabs result.
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
        result["webamon_ip"] = _webamon_ip(value)  # hosted domains (reverse-IP replacement)
        result["ptr"] = _cached_pivot("ptr", value, lambda: pivot.ptr_lookup(value))
        result["honeylabs"] = honeylabs_context(value)
    if kind == "domain":
        result["webamon"] = _webamon_domain(value)  # latest scan: cert, DNS, ASN, kit fingerprints
        result["webamon_infostealers"] = _webamon_infostealers(value)  # compromised creds (masked)
        result["tls"] = _live_tls(value)   # current certificate, live from the probe VM
        result["http"] = _live_http(value)  # live liveness/title/server

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
    # Live current-cert grab (replaces Cert Spotter's CT history), a live
    # HTTP probe, the domain's latest Webamon scan (ASN/tech/kit
    # fingerprints), its infostealer hits, and passive subdomain discovery
    # (subfinder + Wayback, flag-only). All day-over-day attribute diffs -
    # see _log_cluster_enrichment_history.
    enrichment: dict[str, Any] = {
        "tls": _live_tls(value),
        "http": _live_http(value),
        "webamon": _webamon_domain(value),
        "webamon_infostealers": _webamon_infostealers(value),
        "subdomains": _subdomains_for(value),
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
        # Domains Webamon has scanned resolving to this IP - the reverse-IP
        # / hosted-domain signal (replaces Shodan hostnames + Hackertarget).
        # Open ports are no longer discovered automatically here: that's
        # nmap, run on demand via active_scan (see the port-change signal).
        "webamon_ip": _webamon_ip(value),
        # Reverse-DNS PTR record - a day-over-day attribute diff like ASN
        # (see _record_ptr_change).
        "ptr": _cached_pivot("ptr", value, lambda: pivot.ptr_lookup(value)),
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
    RIPEstat/Webamon/probe-VM/ThreatFox round-trips can take a while,
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


def _stamp_webamon_summary(entry: dict[str, Any], webamon: dict[str, Any]) -> None:
    """Stamp a compact Webamon snapshot (report_id, last scan date, risk
    score, kit fingerprints) onto an observable. Accepts both a domain
    result (carries `latest`) and an IP result (carries only `total_hits`/
    `domains`)."""
    latest = webamon.get("latest")
    summary: dict[str, Any] = {"checked": _now(), "total_hits": webamon.get("total_hits")}
    if isinstance(latest, dict):
        summary.update({
            "report_id": latest.get("report_id"),
            "last_scan": latest.get("date"),
            "risk_score": latest.get("risk_score"),
            "fingerprint_dom": (latest.get("fingerprint") or {}).get("dom"),
            "fingerprint_ssl": (latest.get("fingerprint") or {}).get("ssl"),
        })
    entry["webamon"] = summary


def _asn_int(value: Any) -> int | None:
    """Normalize an ASN to int. RIPEstat reports ASNs as strings ("16509",
    occasionally "AS16509") and hands back a list when an IP is announced by
    more than one; SHARED_HOSTING_ASNS and the tracking store use ints.
    Coercing once, here, is what keeps `asn in SHARED_HOSTING_ASNS` honest -
    comparing the raw string never matched, so shared-hosting suppression
    silently did nothing and stamped 50 other tenants' domains onto tracked
    AWS IPs. Returns None for anything unparseable, so callers can keep the
    raw value instead."""
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return int(text) if text.isdigit() else None


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
            asn_value = _asn_int(asn_list)
            entry["asn"] = (asn_value if asn_value is not None else
                            (asn_list[0] if isinstance(asn_list, list) else asn_list))
        if detail.get("as_holder"):
            entry["netname"] = detail["as_holder"]
        webamon_ip = enrichment.get("webamon_ip")
        if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
            # Hosted domains Webamon has scanned on this IP. Suppress when the
            # IP sits in a known shared-hosting ASN - those are every other
            # tenant, not this actor's infra (same rationale as the retired
            # Hackertarget co-hosting signal; see SHARED_HOSTING_ASNS).
            asn = entry.get("asn")
            if asn not in SHARED_HOSTING_ASNS:
                hosts = webamon_ip.get("domains") or []
                if hosts:
                    entry["ip_hostnames"] = sorted(set(entry.get("ip_hostnames") or []) | set(hosts))
            _stamp_webamon_summary(entry, webamon_ip)
    elif category == "domains":
        tls = enrichment.get("tls")
        if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
            cert = tls["cert"]
            entry["cert"] = {"issuer": cert.get("issuer"), "subject": cert.get("subject"),
                              "sans": cert.get("sans") or [],
                              "not_before": cert.get("not_before"),
                              "not_after": cert.get("not_after"),
                              "sha256": cert.get("sha256"),
                              "checked": _now(), "source": "tls_live"}
        http = enrichment.get("http")
        if isinstance(http, dict) and "error" not in http and http.get("status") is not None:
            entry["http"] = {"status": http.get("status"), "title": http.get("title"),
                              "server": http.get("server"), "final_url": http.get("final_url")}
        webamon = enrichment.get("webamon")
        if isinstance(webamon, dict) and "error" not in webamon:
            _stamp_webamon_summary(entry, webamon)
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
    "ptr_changed": "medium", "resolved_ip_changed": "medium",
    "ip_hostnames_changed": "medium", "http_server_changed": "medium",
    "http_title_changed": "low", "webamon_fingerprint_changed": "high",
    "subdomains_changed": "low",
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
    # Baseline is the prior on-demand nmap scan (ports are no longer
    # discovered automatically now that Shodan InternetDB is retired).
    baseline = tracking_store.latest_nmap_ports_for(con, ip, observed_at)
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


def _record_ptr_change(con: duckdb.DuckDBPyConnection, ip: str, actor: str | None,
                       observed_at: datetime, new_hostname: str | None) -> None:
    """Day-over-day diff of an IP's reverse-DNS (PTR) record - mirrors
    _record_port_change's shape as a scalar diff instead of a list one.
    None is a legitimate value on either side (confirmed absent PTR
    record, see pivot.ptr_lookup) - only a change between two
    known/confirmed states is recorded, same "definitive answer either
    way" rule the rest of this module uses for lifecycle checks.

    old_value/new_value are explicitly json.dumps'd (unlike
    _record_port_change's bare list/dict, which store._json auto-
    serializes) because store._json passes a Python str straight
    through unmodified (so an already-JSON string caller isn't double-
    encoded) - a raw hostname or a bare `None` would otherwise hit the
    JSON-typed column as unquoted text ("host.example") or a dropped
    SQL NULL, either of which DuckDB's JSON column rejects or - for
    None - collapses into "no baseline row" instead of "confirmed no
    PTR", which is a real, distinct value here."""
    baseline = tracking_store.latest_ptr_for(con, ip, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=ip, actor=actor,
            attribute="ptr", change_type="first_seen", confidence="medium",
            old_value=None, new_value=json.dumps(new_hostname))
        return
    if baseline["hostname"] == new_hostname:
        return  # no change - the common case, nothing recorded
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=ip, actor=actor,
        attribute="ptr", change_type="ptr_changed",
        confidence=_attribute_confidence("ptr_changed", baseline["observed_at"]),
        old_value=json.dumps(baseline["hostname"]), new_value=json.dumps(new_hostname))


def _record_resolved_ip_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                               observed_at: datetime, new_ips: list[str]) -> None:
    """Day-over-day diff of a domain's resolved IP(s) - the "domain
    shifted hosting" signal, mirroring _record_port_change exactly
    (sorted-list equality). new_ips can legitimately be [] (a confirmed
    dead/sinkholed domain - see pivot.resolve_host's []-vs-None
    contract); this function is only ever called with a definitive
    result, never an inconclusive one (see
    core._log_cluster_enrichment_history's gate on `detail["resolved"]
    is not None`)."""
    baseline = tracking_store.latest_resolved_ip_for(con, domain, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="resolved_ip", change_type="first_seen", confidence="medium",
            old_value=None, new_value=new_ips)
        return
    if sorted(baseline["resolved_ip"]) == sorted(new_ips):
        return  # no change - the common case, nothing recorded
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="resolved_ip", change_type="resolved_ip_changed",
        confidence=_attribute_confidence("resolved_ip_changed", baseline["observed_at"]),
        old_value=baseline["resolved_ip"], new_value=new_ips)


def _record_cert_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                        observed_at: datetime, cert: dict[str, Any]) -> None:
    """Day-over-day diff of a domain's live certificate (issuer / SANs),
    from the probe-VM TLS grab that replaced Cert Spotter. A same-issuer,
    same-SANs renewal is routine and not recorded (the sha256 rotation is
    tracked separately by _record_cert_hash_change)."""
    new_issuer = cert.get("issuer")
    sans = sorted(cert.get("sans") or [])
    baseline = tracking_store.latest_tls_cert_for(con, domain, observed_at)
    if baseline is None:
        if new_issuer is None and not sans:
            return
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="cert", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"issuer": new_issuer, "sans": sans})
        return
    base_sans = sorted(baseline.get("sans") or [])
    if new_issuer and baseline["issuer"] and new_issuer != baseline["issuer"]:
        change_type = "cert_issuer_changed"
    elif set(sans) != set(base_sans):
        change_type = "cert_sans_changed"
    else:
        return  # same issuer, same SANs - routine renewal, not recorded
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="cert", change_type=change_type,
        confidence=_attribute_confidence(change_type, baseline["observed_at"]),
        old_value={"issuer": baseline["issuer"], "sans": base_sans},
        new_value={"issuer": new_issuer, "sans": sans})


def _record_cert_hash_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                             observed_at: datetime, cert: dict[str, Any]) -> None:
    """A separate diff from _record_cert_change: that one tracks issuer/SAN
    changes and treats a same-issuer/same-SANs renewal as routine, but a
    renewal always mints a brand new certificate - and therefore a new
    sha256 - so this tracks that pivot value on its own timeline."""
    new_sha256 = cert.get("sha256")
    if not new_sha256:
        return
    baseline = tracking_store.latest_tls_cert_for(con, domain, observed_at)
    if baseline is None or not baseline.get("sha256"):
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="cert_hash", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"sha256": new_sha256})
        return
    if new_sha256 == baseline["sha256"]:
        return  # same cert as last check - nothing to record
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="cert_hash", change_type="cert_new",
        confidence=_attribute_confidence("cert_new", baseline["observed_at"]),
        old_value={"sha256": baseline["sha256"]}, new_value={"sha256": new_sha256})


def _record_ip_hostnames_change(con: duckdb.DuckDBPyConnection, ip: str, actor: str | None,
                                observed_at: datetime, new_hostnames: list[str]) -> None:
    """Day-over-day diff of the domains Webamon reports resolving to a
    tracked IP (search_ip) - the reverse-IP / hosted-domain signal. Flag
    only: the new hostnames are surfaced (`added`) but never auto-filed as
    tracked observables (that's a reviewed pivot_and_expand decision)."""
    baseline = tracking_store.latest_ip_hostnames_for(con, ip, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=ip, actor=actor,
            attribute="ip_hostnames", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"hostnames": new_hostnames})
        return
    if sorted(baseline["hostnames"]) == sorted(new_hostnames):
        return
    added = sorted(set(new_hostnames) - set(baseline["hostnames"]))
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=ip, actor=actor,
        attribute="ip_hostnames", change_type="ip_hostnames_changed",
        confidence=_attribute_confidence("ip_hostnames_changed", baseline["observed_at"]),
        old_value=baseline["hostnames"],
        new_value={"hostnames": new_hostnames, "added": added})


def _record_http_change(con: duckdb.DuckDBPyConnection, host: str, actor: str | None,
                        observed_at: datetime, title: str | None, server: str | None) -> None:
    """Day-over-day diff of a host's HTTP title / Server header (from the
    live probe) - a served-content change on already-tracked infra."""
    baseline = tracking_store.latest_http_for(con, host, observed_at)
    if baseline is None:
        if title is None and server is None:
            return
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=host, actor=actor,
            attribute="http", change_type="first_seen", confidence="low",
            old_value=None, new_value={"title": title, "server": server})
        return
    if title == baseline["title"] and server == baseline["server"]:
        return
    change_type = "http_server_changed" if server != baseline["server"] else "http_title_changed"
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=host, actor=actor,
        attribute="http", change_type=change_type,
        confidence=_attribute_confidence(change_type, baseline["observed_at"]),
        old_value={"title": baseline["title"], "server": baseline["server"]},
        new_value={"title": title, "server": server})


def _record_fingerprint_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                               observed_at: datetime, dom: str | None, ssl: str | None) -> None:
    """Day-over-day diff of a domain's Webamon kit fingerprints (dom/ssl) -
    a rebuilt phishing kit or changed TLS config on already-tracked infra."""
    baseline = tracking_store.latest_fingerprint_for(con, domain, observed_at)
    if baseline is None:
        if dom is None and ssl is None:
            return
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=domain, actor=actor,
            attribute="webamon_fingerprint", change_type="first_seen", confidence="medium",
            old_value=None, new_value={"dom": dom, "ssl": ssl})
        return
    if dom == baseline["dom"] and ssl == baseline["ssl"]:
        return
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="webamon_fingerprint", change_type="webamon_fingerprint_changed",
        confidence=_attribute_confidence("webamon_fingerprint_changed", baseline["observed_at"]),
        old_value={"dom": baseline["dom"], "ssl": baseline["ssl"]},
        new_value={"dom": dom, "ssl": ssl})


def _record_subdomains_change(con: duckdb.DuckDBPyConnection, apex: str, actor: str | None,
                              observed_at: datetime, new_subdomains: list[str]) -> None:
    """Day-over-day diff of an apex's discovered subdomains (subfinder +
    Wayback) - flag only, surfacing the newly-appeared names for review."""
    baseline = tracking_store.latest_subdomains_for(con, apex, observed_at)
    if baseline is None:
        tracking_store.record_attribute_change(
            con, detected_at=observed_at, indicator_value=apex, actor=actor,
            attribute="subdomains", change_type="first_seen", confidence="low",
            old_value=None, new_value={"subdomains": new_subdomains})
        return
    if sorted(baseline["subdomains"]) == sorted(new_subdomains):
        return
    added = sorted(set(new_subdomains) - set(baseline["subdomains"]))
    if not added:
        return  # only removals - not a lead
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=apex, actor=actor,
        attribute="subdomains", change_type="subdomains_changed",
        confidence=_attribute_confidence("subdomains_changed", baseline["observed_at"]),
        old_value=baseline["subdomains"],
        new_value={"subdomains": new_subdomains, "added": added})


def _record_infostealer_change(con: duckdb.DuckDBPyConnection, domain: str, actor: str | None,
                               observed_at: datetime, count: int, urls: list[str]) -> None:
    """Day-over-day diff of a domain's Webamon infostealer-log hit count -
    a new/growing credential-leak footprint. Every hit is notable, so the
    first sighting of a non-zero count is itself recorded (not first_seen
    baseline)."""
    baseline = tracking_store.latest_infostealer_for(con, domain, observed_at)
    prev = baseline["count"] if baseline else 0
    if count <= (prev or 0):
        return  # no new hits since last check
    tracking_store.record_attribute_change(
        con, detected_at=observed_at, indicator_value=domain, actor=actor,
        attribute="infostealer_hits", change_type="infostealer_hits",
        confidence="medium", old_value={"count": prev},
        new_value={"count": count, "sample_urls": urls[:10]})


def _log_cluster_enrichment_history(
        actor: str, observed_at: datetime,
        results: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]) -> str | None:
    """Best-effort: write one dated observation row per ip/domain that got
    fresh live-enrichment data this sweep (TLS/HTTP/Webamon/infostealer/
    subdomains/ThreatFox/PTR/resolved-IP), so the dashboard's per-observable
    timeline can show when these fields were seen or changed - and diff the
    fresh value against the prior baseline, recording a change in
    attribute_changes when something actually moved (see the _record_*
    functions). Returns an error note (never raises) on a tracking-store
    hiccup - pivot_cluster's cluster-JSON write already happened and a
    separate store's outage shouldn't undo or block reporting that success."""
    try:
        with tracking_store.connect(read_only=False) as con:
            for (category, value), (_status, detail, enrichment) in results.items():
                if category == "domains":
                    indicator_type = "domain"
                else:
                    indicator_type = "ipv6" if ":" in value else "ipv4"

                threatfox = enrichment.get("threatfox")
                if isinstance(threatfox, dict) and "error" not in threatfox:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="threatfox", actor=actor, indicator_type=indicator_type,
                        threatfox_matches=threatfox.get("matches") or None)

                if category == "ips":
                    webamon_ip = enrichment.get("webamon_ip")
                    if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
                        hosts = webamon_ip.get("domains") or []
                        tracking_store.upsert_observation(
                            con, observed_at=observed_at, indicator_value=value,
                            source="webamon", actor=actor, indicator_type=indicator_type,
                            ip_hostnames=hosts or None)
                        _record_ip_hostnames_change(con, value, actor, observed_at, hosts)
                    ptr = enrichment.get("ptr")
                    if isinstance(ptr, dict) and "error" not in ptr:
                        tracking_store.upsert_observation(
                            con, observed_at=observed_at, indicator_value=value,
                            source="ptr", actor=actor, indicator_type=indicator_type,
                            ptr_hostname=ptr.get("hostname"))
                        _record_ptr_change(con, value, actor, observed_at, ptr.get("hostname"))
                    continue

                # --- domains ---
                tls = enrichment.get("tls")
                if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
                    cert = tls["cert"]
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="tls_live", actor=actor, indicator_type="domain",
                        tls_sha256=cert.get("sha256"), tls_issuer=cert.get("issuer"),
                        tls_subject=cert.get("subject"), tls_sans=cert.get("sans") or None,
                        tls_not_before=cert.get("not_before"), tls_not_after=cert.get("not_after"))
                    _record_cert_change(con, value, actor, observed_at, cert)
                    _record_cert_hash_change(con, value, actor, observed_at, cert)

                http = enrichment.get("http")
                if isinstance(http, dict) and "error" not in http and http.get("status") is not None:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="http_live", actor=actor, indicator_type="domain",
                        http_status=http.get("status"), http_title=http.get("title"),
                        http_server=http.get("server"), http_final_url=http.get("final_url"))
                    _record_http_change(con, value, actor, observed_at,
                                        http.get("title"), http.get("server"))

                webamon = enrichment.get("webamon")
                if isinstance(webamon, dict) and "error" not in webamon:
                    latest = webamon.get("latest") or {}
                    fp = latest.get("fingerprint") or {}
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="webamon", actor=actor, indicator_type="domain",
                        webamon_report_id=latest.get("report_id"),
                        webamon_risk_score=latest.get("risk_score"),
                        webamon_fingerprint_dom=fp.get("dom"),
                        webamon_fingerprint_ssl=fp.get("ssl"),
                        webamon_last_scan=latest.get("date"))
                    _record_fingerprint_change(con, value, actor, observed_at,
                                               fp.get("dom"), fp.get("ssl"))

                infostealers = enrichment.get("webamon_infostealers")
                if isinstance(infostealers, dict) and "error" not in infostealers:
                    hits = infostealers.get("results") or []
                    urls = sorted({h.get("url") for h in hits if h.get("url")})
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="webamon_infostealers", actor=actor, indicator_type="domain",
                        infostealer_count=len(hits), infostealer_urls=urls or None)
                    _record_infostealer_change(con, value, actor, observed_at, len(hits), urls)

                subdomains = enrichment.get("subdomains")
                if isinstance(subdomains, dict) and "error" not in subdomains:
                    subs = subdomains.get("subdomains") or []
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="subdomains", actor=actor, indicator_type="domain",
                        subdomains=subs or None)
                    _record_subdomains_change(con, value, actor, observed_at, subs)

                # Domain-hosting-shift detection: detail["resolved"] is the
                # same live A-record lookup _domain_lifecycle already runs.
                # None = inconclusive (skip); [] = confirmed dead/sinkholed
                # (a real, recordable answer).
                resolved = detail.get("resolved")
                if resolved is not None:
                    tracking_store.upsert_observation(
                        con, observed_at=observed_at, indicator_value=value,
                        source="dns_resolve", actor=actor, indicator_type="domain",
                        resolved_ip=resolved)
                    _record_resolved_ip_change(con, value, actor, observed_at, resolved)
    except (tracking_store.TrackingBusy, duckdb.IOException) as e:
        return f"enrichment history not recorded: {e}"
    return None


def _file_cert_hash(data: dict[str, Any], domain: str, sha256: str,
                    issuer: str | None, revoked: bool | None, now: str) -> None:
    """Auto-file a certificate's own SHA256 fingerprint onto the cluster's
    hashes list when pivot_cluster sees a new one for an already-tracked
    domain - an attribute of infrastructure already being tracked (like
    ASN/ports/cert issuer), not a new lead, so unlike a discovered
    subdomain or hosted domain (flag-only) this auto-updates without
    analyst confirmation. The `cert-sha256:` value prefix (distinct from
    the existing `sha256:`/`sha1:`/`md5:` file-hash prefixes) plus the
    explicit hash_kind field make this unambiguous as a certificate hash,
    not a file hash; cert_for names the domain it belongs to."""
    value = f"cert-sha256:{sha256}"
    bucket = data["observables"]["hashes"]
    source = f"live TLS grab for {domain}, seen {now[:10]}"
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

    Domains are also enriched via a live TLS grab + HTTP probe from the
    probe VM, Webamon (latest scan, kit fingerprints, infostealer hits),
    and subfinder/Wayback subdomain discovery (flag-only here); ips via
    Webamon hosted-domains and PTR; both via ThreatFox (if
    THREATFOX_API_KEY is set). This enrichment is stamped onto each
    observable's asn/netname/cert/http/webamon/ip_hostnames/tags fields
    (see _apply_enrichment_snapshot) so the current-known-value snapshot
    stays fresh, AND a dated snapshot is recorded to the tracking-store
    history (cti_tools.tracking.store), which also runs day-over-day
    diffing and records a change when something moved - see
    _log_cluster_enrichment_history. Open ports are not discovered here
    (nothing passive replaced Shodan's); they come from report text and
    the on-demand active_scan. The dashboard's per-observable
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
                tls = enrichment.get("tls")
                if isinstance(tls, dict) and "error" not in tls and tls.get("cert"):
                    row["cert_sha256"] = tls["cert"].get("sha256")
                webamon_ip = enrichment.get("webamon_ip")
                if isinstance(webamon_ip, dict) and "error" not in webamon_ip:
                    row["hosted_domains"] = len(webamon_ip.get("domains") or [])
                webamon = enrichment.get("webamon")
                if isinstance(webamon, dict) and "error" not in webamon and webamon.get("latest"):
                    row["webamon_risk"] = webamon["latest"].get("risk_score")
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

    - domain: sibling subdomains under the queried name (subfinder +
      Wayback, same operator, high confidence). Webamon kit-fingerprint
      siblings (other scanned domains sharing this domain's dom/ssl
      fingerprint) are surfaced under `review`, not auto-filed.
    - ip: the domains Webamon has scanned resolving to this IP.

    Co-hosted domains on a shared-hosting IP are noise; when the queried
    IP sits in a known shared-hosting ASN (see SHARED_HOSTING_ASNS) they
    are suppressed and a `review["cohosted_domains_suppressed"]` note
    explains why. Otherwise, by default they go to `review` rather than
    being filed; pass include_cohosted=True to file them. Only genuinely
    new indicators are filed; ones already tracked are left as-is.

    Each newly-filed indicator also gets its own live asn/cert/tags
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
        # VM has no IPv6 route, so nothing downstream can act on the result.
        return _pivot_and_expand_ipv6_skip(value, cluster_name, kind)

    now = _now()
    candidates: list[tuple[str, list[str], str]] = []  # (category, values, source)
    review: dict[str, Any] = {}

    if kind == "domain":
        # Sibling subdomains under the queried name (subfinder + Wayback).
        subs = _subdomains_for(value)
        if isinstance(subs, dict) and subs.get("error"):
            review["subdomain_discovery_error"] = subs["error"]
        else:
            all_subs = (subs.get("subdomains") or []) if isinstance(subs, dict) else []
            siblings = [h for h in all_subs if h != value and h.endswith("." + value)]
            candidates.append(("domains", siblings,
                               f"pivot_and_expand via subfinder/Wayback, checked {now}"))
            others = [h for h in all_subs if h != value and not h.endswith("." + value)]
            if others:
                review["other_hostnames"] = others
        # Webamon kit-fingerprint siblings - the campaign-cluster signal,
        # surfaced for review rather than auto-filed (a shared kit isn't
        # proof of the same operator).
        wm = _webamon_domain(value)
        latest = wm.get("latest") if isinstance(wm, dict) and "error" not in wm else None
        if isinstance(latest, dict):
            fp = latest.get("fingerprint") or {}
            fp_siblings: dict[str, list[str]] = {}
            for kindfp in ("dom", "ssl"):
                if fp.get(kindfp):
                    sib = webamon.fingerprint_siblings(fp[kindfp], kind=kindfp)
                    doms = [d for d in (sib.get("domains") or []) if d != value] \
                        if isinstance(sib, dict) and "error" not in sib else []
                    if doms:
                        fp_siblings[kindfp] = doms
            if fp_siblings:
                review["webamon_fingerprint_siblings"] = fp_siblings
    else:  # ip
        wm = _webamon_ip(value)
        hosted = wm.get("domains", []) if isinstance(wm, dict) and "error" not in wm else []
        # Same shared-hosting guard the automatic sweep uses: a shared-
        # hosting ASN's hosted domains are every other tenant, not this
        # actor's infra - suppress before they can be filed or reviewed.
        ripe = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))
        asn_list = ripe.get("asn") if isinstance(ripe, dict) else None
        asn = _asn_int(asn_list)  # RIPEstat gives strings; see _asn_int
        if hosted and asn in SHARED_HOSTING_ASNS:
            review["cohosted_domains_suppressed"] = (
                f"{len(hosted)} co-hosted domains suppressed - "
                f"{value} is in a shared-hosting ASN ({asn})")
            hosted = []
        if include_cohosted:
            candidates.append(("domains", hosted,
                               f"pivot_and_expand via Webamon hosted-domains, checked {now}"))
        elif hosted:
            review["cohosted_domains"] = hosted

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


# --------------------------------------------------------------------------- #
# active_scan - on-demand loud probing (nmap + dirsearch/open-directory)
# --------------------------------------------------------------------------- #
_ACTIVE_SCAN_TOOLS = ("nmap", "dirsearch")


def _opensearch_max_ts() -> float | None:
    """Best-effort snapshot of the newest `ts` indexed in the lab's Zeek/
    OpenSearch, used to bracket an active scan's captured traffic (the same
    provenance anchor probe_pending_fingerprints uses). None if OpenSearch
    isn't reachable - provenance is nice-to-have, never blocks the scan."""
    try:
        from .opensearch_client import OpenSearchClient
        return OpenSearchClient().current_max_ts()
    except Exception:
        return None


def _ts_to_dt(ts: float | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


def active_scan(target: str, cluster: str | None = None,
                tools: list[str] | None = None) -> dict[str, Any]:
    """On-demand, LOUD active scan of a domain/ip - explicitly separate
    from the automatic light-touch enrichment sweep. Runs nmap (top-ports
    -sV) and/or dirsearch (web path map + recursive open-directory file
    listing) from the probe VM, so the target's own infrastructure
    receives the traffic; only call when explicitly asked. Open ports feed
    the port-change signal; open-directory files are diffed day over day
    (new files flagged). Results are written to the tracking store (and,
    if `cluster` is given and the target is tracked there, stamped onto its
    observable), and the run is audited in active_scans with the Zeek
    timestamp window its traffic falls in, so the captured packets can be
    found later in OpenSearch/Arkime."""
    kind = pivot.classify(target)
    if kind not in ("domain", "ip"):
        raise ValueError(f"active_scan supports domain/ip; got kind={kind!r} for {target!r}")
    if kind == "ip" and ipaddress.ip_address(target).version == 6:
        return {"target": target, "kind": kind, "skipped": "IPv6 (no route from the probe VM)"}
    requested = list(tools) if tools else list(_ACTIVE_SCAN_TOOLS)
    unknown = [t for t in requested if t not in _ACTIVE_SCAN_TOOLS]
    if unknown:
        raise ValueError(f"unknown active_scan tool(s): {unknown}; valid: {_ACTIVE_SCAN_TOOLS}")

    ran_at = _now()
    observed_at = datetime.fromisoformat(ran_at).replace(tzinfo=None)
    before_ts = _opensearch_max_ts()

    # Network phase - unlocked (nmap/dirsearch take minutes).
    summary: dict[str, Any] = {"target": target, "kind": kind, "cluster": cluster,
                               "tools": requested, "ran_at": ran_at}
    nmap_ports: list[int] = []
    if "nmap" in requested:
        try:
            nres = vm_proxy.nmap(target)
        except vm_proxy.VMProxyError as e:
            nres = {"error": str(e)}
        if isinstance(nres, dict) and not nres.get("error"):
            nmap_ports = sorted({p["port"] for p in (nres.get("ports") or []) if p.get("port")})
            summary["nmap"] = {"ports": nres.get("ports") or [], "resolved_ip": nres.get("resolved_ip")}
        else:
            summary["nmap"] = {"error": nres.get("error")}

    opendirs: list[dict[str, Any]] = []
    if "dirsearch" in requested:
        url = target if target.startswith(("http://", "https://")) else f"http://{target}/"
        try:
            dres = vm_proxy.dirsearch(url)
        except vm_proxy.VMProxyError as e:
            dres = {"error": str(e)}
        if isinstance(dres, dict) and not dres.get("error"):
            opendirs = dres.get("opendirs") or []
            summary["dirsearch"] = {"hits": len(dres.get("hits") or []),
                                    "opendirs": len(opendirs),
                                    "baseline_404": dres.get("baseline_404")}
        else:
            summary["dirsearch"] = {"error": dres.get("error")}

    after_ts = _opensearch_max_ts()

    # Tracking-store write (own locking) - records observations, port/opendir
    # diffs, and the active_scans audit row.
    new_files: list[dict[str, Any]] = []
    indicator_type = "domain" if kind == "domain" else ("ipv6" if ":" in target else "ipv4")
    try:
        with tracking_store.connect(read_only=False) as con:
            if nmap_ports:
                tracking_store.upsert_observation(
                    con, observed_at=observed_at, indicator_value=target,
                    source="nmap", actor=cluster, indicator_type=indicator_type,
                    nmap_ports=nmap_ports)
                _record_port_change(con, target, cluster, observed_at, nmap_ports)
            for listing in opendirs:
                url = listing.get("url")
                files = listing.get("files") or []
                if not url:
                    continue
                had_prior = con.execute(
                    "SELECT 1 FROM opendir_files WHERE indicator_value = ? LIMIT 1",
                    [target]).fetchone()
                added = tracking_store.upsert_opendir_files(
                    con, indicator_value=target, url=url, files=files,
                    observed_at=observed_at, actor=cluster)
                # First-ever scan is a baseline (every file is "new") - only
                # flag genuinely new files against an existing baseline.
                if had_prior and added:
                    new_files.extend(added)
                    tracking_store.record_attribute_change(
                        con, detected_at=observed_at, indicator_value=target, actor=cluster,
                        attribute="opendir_files", change_type="opendir_files",
                        confidence="medium", old_value=None,
                        new_value={"url": url, "added": [f["path"] for f in added]})
            tracking_store.record_active_scan(
                con, ran_at=observed_at, indicator_value=target, actor=cluster,
                tools=requested, summary=summary,
                zeek_first_ts=_ts_to_dt(before_ts), zeek_last_ts=_ts_to_dt(after_ts))
    except (tracking_store.TrackingBusy, duckdb.IOException) as e:
        summary["history_note"] = f"active-scan history not recorded: {e}"

    summary["new_open_dir_files"] = new_files
    if cluster is not None:
        summary["cluster_state"] = _active_scan_file(target, kind, cluster, ran_at,
                                                      nmap_ports, opendirs, new_files)
    return summary


@_synchronized
def _active_scan_file(target: str, kind: str, cluster: str, now: str,
                      nmap_ports: list[int], opendirs: list[dict[str, Any]],
                      new_files: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Locked write phase: stamp nmap ports and any open-directory listing
    onto the target's observable in `cluster` (if it's tracked there) and
    log the scan to the hunt log. Returns the fresh cluster state, or None
    if the cluster doesn't exist."""
    try:
        data = load_cluster(cluster)
    except ClusterNotFound:
        return None
    category = "domains" if kind == "domain" else "ips"
    entry = next((o for o in data["observables"][category] if o["value"] == target), None)
    if entry is not None:
        if nmap_ports:
            ports = entry.setdefault("ports", [])
            for p in nmap_ports:
                if p not in ports:
                    ports.append(p)
        if opendirs:
            entry["opendir"] = [{"url": d.get("url"), "file_count": len(d.get("files") or [])}
                                for d in opendirs]
    parts = []
    if nmap_ports:
        parts.append(f"nmap: {len(nmap_ports)} open port(s)")
    if opendirs:
        parts.append(f"{len(opendirs)} open director{'y' if len(opendirs) == 1 else 'ies'}"
                     + (f", {len(new_files)} new file(s)" if new_files else ""))
    if parts:
        data["hunt_log"].append({"date": now, "entry": f"active_scan on {target}: " + "; ".join(parts)})
    save_cluster(data)
    return load_cluster(cluster)


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
    file hash's filenames when an analyst manually files one. Only
    meaningful when
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
