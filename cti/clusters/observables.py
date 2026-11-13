"""Adding, removing and deciding observables: the cluster's indicators, its
candidates, and the merge used by report and STIX ingest.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .. import attack
from .. import membership
from .. import store as tracking_store
from ..errors import ok
from ..sources import pivot
from ..store import entities
from ..util import now_iso
from .storage import (
    OBSERVABLE_CATEGORIES, _reverse_index, _slug, _synchronized, load_cluster,
    save_cluster,
)
from .lifecycle import (
    _find_entry, _is_live, _without_inactive, lifecycle_of, member_values,
)
from .enrich import (
    _FINGERPRINTABLE_CATEGORIES, _apply_enrichment_snapshot, _is_probe_worthy,
    _record_enrichment, _sweep_lifecycle,
)


def get_observables(name: str, include_inactive: bool = False) -> dict[str, Any]:
    """Return just the observables block for a cluster (hashes, domains,
    ips, urls) plus the list of report sources they came from — the
    quick "what's tied to this cluster" view. Retired and candidate
    entries are left out unless include_inactive=True."""
    data = load_cluster(name)
    if not include_inactive:
        data = _without_inactive(data)
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

    A new domain/ip is always tracked as an observable, and netwatch scans
    it on its next pass unless it fails _is_probe_worthy (a private or
    reserved address, or a known non-actor domain/resolver such as a
    public DNS resolver or a major vendor's own site). If it fails, the
    returned dict carries a transient (not persisted) `scan_skipped` list
    of {category, value, reason}.

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
    result = _add_observable_locked(name, category, value, source, enrichment,
                                    metadata)
    # The enrichment above is a full sweep result; without this it reached
    # the cluster JSON as a snapshot and the tracking store not at all.
    note = _record_enrichment(name, enrichment)
    if note:
        result = {**result, "history_note": note}
    return result


@_synchronized
def _add_observable_locked(name: str, category: str, value: str, source: str,
                           enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]],
                           metadata: dict[str, Any] | None = None,
                           ) -> dict[str, Any]:
    data = load_cluster(name)  # re-read fresh; another writer may have raced in above
    extracted = {c: ([value] if c == category else []) for c in OBSERVABLE_CATEGORIES}
    _, skipped = _merge_observables(data, extracted, source, enrichment=enrichment,
                                    metadata=metadata, decided_by=entities.ANALYST)
    save_cluster(data)
    if skipped:
        data = {**data, "scan_skipped": skipped}
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
    # The cluster's claim goes with the entry; the entity and its evidence
    # stay in the store, where a later pivot can still find and score it.
    for o in removed:
        if membership.member_value(category, o["value"]):
            membership.forget(_slug(data), o["value"])
    return {**data, "removed": [o["value"] for o in removed]}


# --------------------------------------------------------------------------- #
# Candidates - hosts the weekly expansion sweep found, awaiting a decision
# --------------------------------------------------------------------------- #
# Auto-reject a candidate with no live evidence for this long - see
# expire_candidates.
CANDIDATE_QUIET_DAYS = 30


@_synchronized
def file_candidate(name: str, value: str, source: str, metadata: dict[str, Any],
                   enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                   | None = None, links: list[dict[str, Any]] | None = None
                   ) -> dict[str, Any] | bool:
    """File a host a pivot, scan or rule surfaced as a scored `candidate`.

    Candidates live in the membership store, not the cluster JSON: the JSON
    lists members, and a candidate becomes one only through
    accept_candidate. Returns the relatedness score (truthy), or False,
    filing nothing, when the cluster already tracks the value, has a
    verdict on it, or (legacy) lists it on the JSON deny list.

    `links` are the dated selectors that surfaced the host - see
    membership.file_candidate. `enrichment` is accepted for the old call
    shape; the sweep that produced it has already recorded it to the store.
    """
    data = load_cluster(name)
    needle = value.strip().lower()
    if _find_entry(data, needle) or needle in {d["value"].lower() for d in data["denylist"]}:
        return False
    via = str(metadata.get("discovered_via") or "?")[:96]
    scored = membership.file_candidate(
        _slug(data), value, origin=source, decided_by="pivot",
        reason=metadata.get("candidate_reason") or f"found via {via}", links=links or (),
        members=member_values(data))
    if scored is None:
        return False
    data["hunt_log"].append({"date": now_iso(), "entry": (
        f"candidate {value} filed via {via}: {scored['band']} "
        f"({scored['score']:.2f}); {metadata.get('candidate_reason', '')}".rstrip("; "))})
    save_cluster(data)
    return scored


@_synchronized
def accept_candidate(name: str, value: str, note: str = "") -> dict[str, Any]:
    """Promote a candidate to a member: it joins the cluster JSON, starts
    exporting and is queued for fingerprinting. Raises if `value` is not a
    candidate on this cluster."""
    data = load_cluster(name)
    found = _find_entry(data, value)
    now = now_iso()
    if found and lifecycle_of(found[1]) == "candidate":
        # A candidate filed before the membership store: it is already in
        # the JSON, so promote it there and record the verdict beside it.
        category, entry = found
        entry["lifecycle"] = "active"
        entry["lifecycle_since"] = now
        entry["accepted"] = now
        _set_role_analyst(_slug(data), entry["value"], "accepted",
                          origin=(entry.get("sources") or [None])[0], reason=note or None)
        reason = entry.get("candidate_reason", "")
    else:
        decided = membership.decide(_slug(data), value, "accepted", reason=note or None)
        entry_value = decided["entity"]
        category = "ips" if pivot.classify(entry_value) == "ip" else "domains"
        extracted = {c: ([entry_value] if c == category else []) for c in OBSERVABLE_CATEGORIES}
        _merge_observables(data, extracted, decided.get("origin") or "accepted candidate")
        reason = decided.get("reason") or ""
        entry = {"value": entry_value}
    data["hunt_log"].append({"date": now, "entry": (
        f"accepted candidate {entry['value']} ({reason})" + (f": {note}" if note else ""))})
    save_cluster(data)
    return {"name": data["name"], "accepted": entry["value"], "category": category}


@_synchronized
def reject_candidate(name: str, value: str, reason: str) -> dict[str, Any]:
    """Refuse a candidate for good: the membership store records the
    rejection and the cluster never re-files it. Raises if `value` is not a
    candidate on this cluster - a member is pruned with remove_observable."""
    if not reason.strip():
        raise ValueError("a reason is required - it is what stops the next analyst re-adding it")
    data = load_cluster(name)
    found = _find_entry(data, value)
    if found and lifecycle_of(found[1]) == "candidate":
        category, entry = found
        _reject(data, category, entry, reason)
        _set_role_analyst(_slug(data), entry["value"], "rejected", reason=reason)
        rejected = entry["value"]
    else:
        rejected = membership.decide(_slug(data), value, "rejected", reason=reason)["entity"]
        data["hunt_log"].append({"date": now_iso(),
                                 "entry": f"rejected candidate {rejected}: {reason}"})
    save_cluster(data)
    return {"name": data["name"], "rejected": rejected, "reason": reason}


def _set_role_analyst(cluster: str, value: str, role: str, *, origin: str | None = None,
                      reason: str | None = None) -> None:
    with tracking_store.connect_retry(read_only=False) as con:
        entities.set_role(con, cluster, value, role, decided_by=entities.ANALYST,
                          origin=origin, reason=reason)


def _reject(data: dict[str, Any], category: str, entry: dict[str, Any], reason: str) -> None:
    now = now_iso()
    data["observables"][category] = [o for o in data["observables"][category]
                                     if o is not entry]
    data["denylist"].append({"value": entry["value"], "reason": reason, "date": now,
                             "discovered_via": entry.get("discovered_via")})
    data["hunt_log"].append({"date": now, "entry": f"rejected candidate {entry['value']}: {reason}"})


@_synchronized
def expire_candidates(name: str, now: str | None = None) -> list[str]:
    """Reject candidates with no live evidence for CANDIDATE_QUIET_DAYS -
    never seen live since being filed, or gone quiet since. A candidate
    nobody has decided on in that time is not going to become a lead.
    Returns the values rejected."""
    now = now or now_iso()
    data = load_cluster(name)
    expired = []
    for cat in ("domains", "ips"):
        for o in list(data["observables"][cat]):
            if lifecycle_of(o) != "candidate":
                continue
            since = o.get("last_live") or o.get("first_seen") or now
            try:
                quiet = (datetime.fromisoformat(now) - datetime.fromisoformat(since)).days
            except (ValueError, TypeError):
                continue
            if quiet >= CANDIDATE_QUIET_DAYS:
                _reject(data, cat, o, (f"no live evidence in {quiet} days as a candidate"
                                       + ("" if o.get("last_live") else " (never live)")))
                expired.append(o["value"])
    stored = membership.expire(_slug(data), CANDIDATE_QUIET_DAYS, now)
    for value in stored:
        data["hunt_log"].append({"date": now, "entry": (
            f"candidate {value} expired: no evidence in {CANDIDATE_QUIET_DAYS}+ days")})
    if expired or stored:
        save_cluster(data)
    return expired + stored


def _merge_observables(data: dict[str, Any], extracted: dict[str, list[str]],
                        source: str,
                        ip_ports: dict[str, list[int]] | None = None,
                        enrichment: dict[tuple[str, str], tuple[str, dict[str, Any], dict[str, Any]]]
                        | None = None,
                        metadata: dict[str, Any] | None = None,
                        decided_by: str | None = None,
                        ) -> tuple[dict[str, int], list[dict[str, str]]]:
    """Merge extracted values into the cluster JSON, and record what they are.

    `decided_by` names the authority filing them - `entities.REPORT` for a
    report or STIX import, `entities.ANALYST` for add_observable - and the
    indicator values are mirrored into the store as `seed` memberships.
    Left None, nothing is mirrored (a caller that only refreshes JSON).

    A server fingerprint (JARM, JA4S, JA4TS, JA4X) whose source names the
    host it was measured on is not a cluster indicator: it is recorded as a
    dated selector on that host and kept out of the JSON. One with no host
    in its source stays an observable, as before.

    enrichment, if given, is a _sweep_lifecycle-shaped result keyed by
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
    now = now_iso()
    counts = {}
    skipped: list[dict[str, str]] = []  # entries tracked but never scanned, with why
    ip_ports = ip_ports or {}
    enrichment = enrichment or {}
    extracted = dict(extracted)
    fingerprint_rows = []
    for category in membership.SERVER_FINGERPRINTS:
        keep = []
        for value in extracted.get(category) or []:
            row = membership.fingerprint_selector(category, value, source)
            (fingerprint_rows.append(row) if row else keep.append(value))
        extracted[category] = keep
    if fingerprint_rows:
        membership.record_fingerprints(fingerprint_rows, actor=data.get("name"))
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
                # New reporting on a dormant or retired host is evidence it
                # matters again; put it back in the sweep. A candidate is
                # left alone - only accept_candidate promotes one.
                if (lifecycle_of(entry) in ("dormant", "retired")
                        and (metadata or {}).get("lifecycle") != "candidate"):
                    entry["lifecycle"] = "active"
                    entry["lifecycle_since"] = now
                # Refresh the snapshot if this call actually fetched one.
                # It used to be dropped, on the reasoning that refreshing a
                # tracked value is pivot_cluster's job - but the caller has
                # already paid for the lookup by the time it gets here, and
                # discarding it left a stale asn/cert/tags snapshot beside
                # a fresh result that was thrown away. Only ever an
                # overwrite with NEWER data; first_seen is not touched.
                found = enrichment.get((category, value))
                if found:
                    _, detail, enr = found
                    _apply_enrichment_snapshot(entry, category, detail, enr)
            else:
                entry = {"value": value, "sources": [source],
                          "first_seen": now, "last_seen": now}
                if metadata:
                    entry.update(metadata)
                found = enrichment.get((category, value))
                if found:
                    status, detail, enr = found
                    _apply_enrichment_snapshot(entry, category, detail, enr)
                    if status != "unknown" and _is_live(category, status, enr):
                        entry["last_live"] = now
                bucket.append(entry)
                added += 1
                if category in _FINGERPRINTABLE_CATEGORIES:
                    ok, reason = _is_probe_worthy(category, value)
                    if not ok:
                        skipped.append({"category": category, "value": value, "reason": reason})
            # Every C2/service port a report names near this IP (see
            # report_ingest._extract_ip_ports) is stamped onto the IP's
            # own observable entry, which the netwatch watchlist hands the
            # probe as known ports beside its own discovery. Appended
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
    # A candidate is not probed until it is accepted: the fingerprints the
    # probe files would otherwise export ahead of the host they belong to.
    if decided_by:
        membership.mirror_seeds(
            _slug(data), [(c, v) for c in OBSERVABLE_CATEGORIES for v in extracted.get(c) or []],
            origin=source, decided_by=decided_by)
    return counts, skipped


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
            "updated": now_iso(),
        })
        added.append(tid)
    return added
