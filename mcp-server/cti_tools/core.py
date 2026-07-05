"""Core business logic for threat cluster tracking.

Protocol-agnostic on purpose: server.py (MCP) and cli.py (Pi / any Bash
tool) both call these same functions so the two invocation surfaces stay
identical. No MCP or argparse imports belong in this file.
"""
from __future__ import annotations

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
    wallets) onto a cluster - the counterpart to ingest_report's
    automatic extraction, for an indicator that came from somewhere
    other than a parseable report
    (e.g. a pivot_observable finding, or something told to you
    directly). Reuses the exact same dedup/provenance logic as
    ingest_report: a value already tracked just gets `source` appended
    to its provenance list rather than creating a duplicate entry."""
    if category not in OBSERVABLE_CATEGORIES:
        raise ValueError("category must be one of " + ", ".join(OBSERVABLE_CATEGORIES))
    data = load_cluster(name)
    extracted = {c: ([value] if c == category else []) for c in OBSERVABLE_CATEGORIES}
    _merge_observables(data, extracted, source)
    save_cluster(data)
    return data


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
    run for the observable types they apply to.
    """
    kind = pivot.classify(value)
    result: dict[str, Any] = {"value": value, "kind": kind}

    if kind in ("domain", "ip"):
        result["rdap"] = _cached_pivot("rdap", value, lambda: pivot.rdap_lookup(value, kind))
    if kind == "ip":
        result["ripestat"] = _cached_pivot("ripestat", value, lambda: pivot.ripestat_lookup(value))

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


def analyze_report(source: str) -> dict[str, Any]:
    """Fetch a report (URL or local file path) and extract observables,
    ATT&CK technique IDs, and candidate cluster names, WITHOUT writing
    anything. Use this to preview extraction — e.g. to pick the right
    cluster_name yourself — before committing with `ingest_report`."""
    text = report_ingest.fetch_text(source)
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
                        source: str) -> dict[str, int]:
    now = _now()
    counts = {}
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
                bucket.append({"value": value, "sources": [source],
                                "first_seen": now, "last_seen": now})
                added += 1
        counts[category] = added
    return counts


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
    """
    text = report_ingest.fetch_text(source)
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

    observable_counts = _merge_observables(data, extracted, source)
    _merge_ttps(data, extracted["ttps"], source)
    data["report_sources"].append({
        "source": source, "ingested": _now(),
        "observables_found": observable_counts,
        "ttps_found": extracted["ttps"],
    })
    save_cluster(data)
    if _nothing_extracted(extracted):
        data = {**data, "warning": _EXTRACTION_EMPTY_WARNING}
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
    the bundle (hunt log, detections, gaps) are preserved on update."""
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
    if parsed_obs:
        extracted = {c: parsed_obs.get(c, []) for c in OBSERVABLE_CATEGORIES}
        _merge_observables(data, extracted, f"STIX import ({parsed['stix_id']})")
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
            lines.append("| Value | Sources | First seen | Last seen |")
            lines.append("|---|---|---|---|")
            for o in items:
                lines.append(f"| {o['value']} | {', '.join(o['sources'])} | "
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
