"""Cluster files on disk: where they live, the lock that serialises writes,
loading, saving, and the registries beside them (detections, the reverse
index of observables).

Everything else in this package reads and writes clusters through here.
`DATA_DIR` is read from the environment once, at import; tests patch
`cti.clusters.storage.DATA_DIR`.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from typing import Iterator

from .. import attack
from .. import stix
from ..clusters_render import write_markdown
from ..errors import ClusterNotFound      # the one such class; see cti/errors.py
from ..report import ingest as report_ingest
from ..util import atomic_write_text
from ..util import now_iso
from ..util import repo_root

try:
    import fcntl  # POSIX-only; the lock degrades to a no-op elsewhere.
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]


# Data lives at the repo root (`<repo>/data/clusters`) so it's shared
# across every harness surface (MCP server, CLI, any future UI) rather
# than nested inside a package. Override with CTI_DATA_DIR for tests
# or alternate deployments (e.g. a separate private data repo).
log = logging.getLogger(__name__)

_REPO_ROOT = repo_root()
# `or`, not a default argument: CTI_DATA_DIR set but empty must mean the
# default. Path("") is the current directory, and every *.json in it would
# be read as a cluster.
DATA_DIR = Path(os.environ.get("CTI_DATA_DIR") or _REPO_ROOT / "data" / "clusters")

# The observable categories a cluster tracks. Single source of truth
# lives in report_ingest (the extractor); re-exported here so the rest
# of core, the CLI, and callers can reference core.OBSERVABLE_CATEGORIES
# without reaching across modules.
OBSERVABLE_CATEGORIES = report_ingest.OBSERVABLE_CATEGORIES




def _slug(data_or_name: dict[str, Any] | str) -> str:
    """The cluster's key in the membership store: its file stem."""
    name = data_or_name["name"] if isinstance(data_or_name, dict) else data_or_name
    return _path(name).stem


def _path(name: str) -> Path:
    safe = name.strip().lower().replace(" ", "-")
    # Collapse anything that isn't filename-safe (notably "/" and "\", which
    # would otherwise turn into a stray subdirectory - e.g. "ITG27 / Mustang
    # Panda" silently landing at itg27-/-mustang-panda.json and never
    # showing up in list_clusters(), which only globs the top-level dir).
    safe = re.sub(r"[^a-z0-9._-]+", "-", safe).strip("-")
    return DATA_DIR / f"{safe}.json"




# _atomic_write_text moved to cti/util.py (webamon had its own inline copy).


# Serializes mutating operations across processes (the MCP server and
# the CLI both write the same store) so two read-modify-write sequences
# can't interleave and clobber each other. Reads (load/list/find) don't
# take it. Reentrant within a thread so a locked op calling another
# locked helper won't deadlock on flock.
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
        "created": now_iso(),
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
        "denylist": [],  # [{value, reason, date}] - rejected candidates, never re-filed
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
    for key in ("ttps", "hunt_log", "detections", "gaps", "report_sources", "relationships",
                "denylist"):
        data.setdefault(key, [])
    data.setdefault("observables", {})
    for category in OBSERVABLE_CATEGORIES:
        data["observables"].setdefault(category, [])
    return data


def load_cluster(name: str, *, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    """Read one cluster, with its detections joined from the registry.

    `registry` is for an operation that loads many clusters: read the
    registry once and pass it, instead of each load reading it again."""
    p = _path(name)
    if not p.exists():
        raise ClusterNotFound(f"No cluster named {name!r}")
    data = _migrate(json.loads(p.read_text()))
    # Detections live in the shared registry, keyed by technique - not
    # duplicated per cluster - so what a cluster "has" is always a live
    # join against its current TTP table, computed on every load rather
    # than trusted from whatever was last written to disk.
    data["detections"] = _detections_for_cluster(data, registry)
    return data


def save_cluster(data: dict[str, Any]) -> None:
    p = _path(data["name"])
    atomic_write_text(p, json.dumps(data, indent=2))
    # Rendering takes the destination path rather than computing it, so
    # clusters_render stays pure and cannot be caught out by DATA_DIR
    # being patched to one directory while CTI_DATA_DIR names another.
    write_markdown(data, _path(data["name"]).with_suffix(".md"))


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
    atomic_write_text(_registry_path(), json.dumps(registry, indent=2))


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
        data = load_cluster(cname, registry=registry)
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
                    "status": det["status"], "scope": _detection_scope(det),
                    "clusters": det.get("clusters", []),
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
        atomic_write_text(p, json.dumps(idx))
    except OSError:
        pass  # cache is best-effort; a read-only store still answers correctly
    return idx


DETECTION_SCOPES = ("cluster", "technique")


def _detection_scope(det: dict[str, Any]) -> str:
    # Entries written before scoping existed carry no field; they keep the
    # original technique-wide join so nothing silently drops off a cluster.
    return det.get("scope", "technique")


def _detections_for_cluster(data: dict[str, Any],
                            registry: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Detections relevant to this cluster. A technique-scoped detection
    (generic behavior - one Kerberoasting rule catches every adversary
    that Kerberoasts) joins onto any cluster whose TTP table shares one
    of its technique_ids. A cluster-scoped detection (keyed to one
    actor's artifacts - a C2 port, a signer, a YARA rule for their
    loader) appears only on the clusters it names, even when another
    cluster logs the same technique, so it isn't shown as coverage it
    doesn't provide. Either kind appears on a cluster it explicitly
    names (e.g. filed before the TTP that justifies it was added). Each
    result is annotated with which of this cluster's TTPs it covers."""
    if registry is None:
        registry = _load_detection_registry()
    ttp_ids = {t["id"].upper() for t in data["ttps"]}
    name = data["name"]
    result = []
    for det in registry["detections"]:
        covers = sorted({tid.upper() for tid in det["technique_ids"]} & ttp_ids)
        scope = _detection_scope(det)
        if name in det.get("clusters", []) or (covers and scope == "technique"):
            result.append({**det, "scope": scope, "covers_ttps": covers})
    return result
