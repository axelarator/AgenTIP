"""Getting intelligence in and out as documents: threat-report ingest and
STIX import and export.
"""
from __future__ import annotations

from typing import Any

from .. import stix
from ..report import ingest as report_ingest
from ..sources import cache
from ..store import entities
from ..util import now_iso
from .storage import (
    ClusterNotFound, OBSERVABLE_CATEGORIES, _new_cluster, _path, _synchronized,
    load_cluster, save_cluster,
)
from .lifecycle import _without_inactive
from .enrich import _new_values, _record_enrichment, _sweep_lifecycle
from .observables import _merge_observables, _merge_ttps


_EXTRACTION_EMPTY_WARNING = (
    "no observables or TTPs were extracted from this source - the page may "
    "keep IOCs/techniques in a table, image, or PDF appendix the plain-text "
    "extractor can't reach, or it may genuinely contain none. Don't treat "
    "this the same as a clean report with nothing to report; check the "
    "source manually if that seems unlikely."
)


def _nothing_extracted(extracted: dict[str, list[str]]) -> bool:
    return not any(extracted[c] for c in (*OBSERVABLE_CATEGORIES, "ttps"))


# Report-fetch cache. analyze_report (preview) and ingest_report (commit)
# are routinely called back-to-back on the same source - analyze first to
# pick a cluster_name, then ingest to file it - which would otherwise
# fetch identical content twice (a real cost for slow report sites, and
# a pointless repeat request either way). Same _registry/TTL-env pattern
# as the pivot cache above. Set CTI_REPORT_CACHE_TTL=0 to disable.
_REPORT_CACHE_TTL_ENV = "CTI_REPORT_CACHE_TTL"
_REPORT_CACHE_TTL_DEFAULT = 3600


def _fetch_report_text(source: str) -> str:
    """Fetched report body, cached so analyze_report and a following
    ingest_report share one fetch. Was a third hand-rolled TTL cache; now
    sources/cache.py like the other two."""
    if not source.startswith(("http://", "https://")):
        return report_ingest.fetch_text(source)
    return cache.cached_text("report", source,
                             lambda: report_ingest.fetch_text(source))

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


def ingest_report(source: str, cluster_name: str | None = None,
                   create_if_missing: bool = True,
                   exclude: list[str] | None = None) -> dict[str, Any]:
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

    Every newly-tracked domain/ip is filed as an observable, and netwatch
    scans it unless it fails _is_probe_worthy — extraction is a blind
    regex over report text and will happily match a version string, a
    public DNS resolver, or a vendor's own site mentioned in passing, and
    none of those should turn into a live probe just because they matched.
    Anything skipped is listed (with why) under `scan_skipped` on both the
    return value and the persisted `report_sources` entry for this ingest.

    If the report names a C2/service port near one of the extracted IPs
    (e.g. "TCP port 886 (IPs: 1.2.3.4, ...)" or a bare "1.2.3.4:8080"),
    every such port is stamped onto the IP's own observable entry
    (`ports: [...]`, see report_ingest._extract_ip_ports — usually one
    port, but a genuinely multi-port C2 can accumulate more than one).
    netwatch scans every recorded port, beside its own port discovery.

    Every genuinely new domain/ip extracted also gets a live asn/ports/
    cert/tags enrichment lookup (see _apply_enrichment_snapshot), run in
    an unlocked phase between the report fetch/extraction and the final
    write - see _sweep_lifecycle's docstring for why that has to happen
    outside _data_lock. The report fetch runs before the lock is taken.

    `exclude` drops extracted values BEFORE anything else happens to them,
    which matters more than it sounds. Extraction over-matches - a vendor's
    own domain, a hosting provider named in the prose, the contact email in
    the footer - and every new domain and IP gets a live TLS/HTTP grab from
    the probe VM. The fingerprint-queue guard above only stops the
    *fingerprint* probe; without this, filing the report would still send
    lookups and a live connection at the vendor's and the provider's own
    servers, which is not what the probe VM is for. Pruning afterwards with
    remove_observable is too late: the traffic has already left. Matching is
    case-insensitive on the value as shown by analyze_report, and a hash may
    be given with or without its algorithm prefix. What was dropped comes
    back under `excluded` so the exclusion can be recorded in the hunt log.
    """
    # Unlocked, like analyze_report's fetch: the cluster lock is global, and
    # held through this it made every other cluster write wait on a third
    # party's web server.
    text = report_ingest.defang_normalize(_fetch_report_text(source))
    cluster_name, extracted, new_domains, new_ips, excluded = _ingest_report_phase1(
        source, cluster_name, create_if_missing, exclude, text)
    enrichment = _sweep_lifecycle(new_domains, new_ips)  # unlocked
    result = _ingest_report_phase2(cluster_name, source, extracted, enrichment, create_if_missing)
    result["excluded"] = excluded   # the returned dict only; it is not re-saved
    # After phase 2's write, outside its lock. A report is the moment a
    # domain becomes tracked, and until now that moment produced no
    # observation row at all - so the indicator had no baseline to diff
    # against and no selectors to link on until a later sweep found it.
    note = _record_enrichment(result.get("name") or cluster_name, enrichment)
    if note:
        result["history_note"] = note
    return result


def _apply_exclusions(extracted: dict[str, Any], exclude: list[str] | None
                      ) -> tuple[dict[str, Any], list[str]]:
    """Remove `exclude`d values from an extraction. Returns (kept, removed)."""
    wanted = {e.strip().lower() for e in (exclude or []) if e and e.strip()}
    if not wanted:
        return extracted, []
    kept: dict[str, Any] = {}
    removed: list[str] = []
    for category, values in extracted.items():
        if not isinstance(values, list):
            kept[category] = values
            continue
        survivors = []
        for value in values:
            if not isinstance(value, str):
                survivors.append(value)
                continue
            bare = value.split(":", 1)[1] if category == "hashes" and ":" in value else value
            if value.lower() in wanted or bare.lower() in wanted:
                removed.append(value)
            else:
                survivors.append(value)
        kept[category] = survivors
    return kept, removed


@_synchronized
def _ingest_report_phase1(source: str, cluster_name: str | None, create_if_missing: bool,
                          exclude: list[str] | None, text: str
                          ) -> tuple[str, dict[str, Any], list[str], list[str], list[str]]:
    """Locked: extract from the already-fetched report `text` and resolve
    the cluster name - no network calls happen in this phase. Returns what
    phase 2 needs to finish the write, plus the genuinely-new domains/ips
    for the unlocked enrichment sweep that runs between the two phases."""
    extracted, excluded = _apply_exclusions(report_ingest.extract_observables(text), exclude)

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
    return cluster_name, extracted, new_domains, new_ips, excluded


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
        data, extracted, source, ip_ports=extracted.get("ip_ports"), enrichment=enrichment,
        decided_by=entities.REPORT)
    _merge_ttps(data, extracted["ttps"], source)
    data["report_sources"].append({
        "source": source, "ingested": now_iso(),
        "observables_found": observable_counts,
        "ttps_found": extracted["ttps"],
        "scan_skipped": skipped,
    })
    save_cluster(data)
    if _nothing_extracted(extracted):
        data = {**data, "warning": _EXTRACTION_EMPTY_WARNING}
    if skipped:
        data = {**data, "scan_skipped": skipped}
    return data


def export_stix_bundle(name: str, include_inactive: bool = False) -> dict[str, Any]:
    """Export the cluster as a STIX 2.1 bundle (Intrusion Set + Attack
    Patterns + Indicators + Relationships + Notes) for sharing outside
    this tool. Tracked observables become Indicators tied to the
    Intrusion Set. Retired and candidate observables are left out unless
    include_inactive=True."""
    data = load_cluster(name)
    return stix.to_bundle(data if include_inactive else _without_inactive(data))


def export_stix_ecosystem(name: str, include_inactive: bool = False) -> dict[str, Any]:
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

    bundles = [stix.to_bundle(data if include_inactive else _without_inactive(data))
               for data in visited.values()]
    return stix.merge_bundles(bundles)


@_synchronized
def import_stix_bundle(bundle: dict[str, Any], name: str | None = None,
                        overwrite: bool = False) -> dict[str, Any]:
    """Create or update a cluster from an external STIX 2.1 bundle
    containing an Intrusion Set (plus optional Attack Patterns /
    Indicators / Relationships / Notes). Indicators are reconstructed
    into the cluster's observables. Existing local fields not present in
    the bundle (hunt log, detections, gaps) are preserved on update.

    Same scan gating as add_observable/ingest_report: a domain/ip that
    fails _is_probe_worthy is still tracked but never scanned; see
    `scan_skipped` on the return value if any were skipped."""
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
        _, skipped = _merge_observables(data, extracted, f"STIX import ({parsed['stix_id']})",
                                        decided_by=entities.REPORT)
    save_cluster(data)
    if skipped:
        data = {**data, "scan_skipped": skipped}
    return data
