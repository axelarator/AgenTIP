"""`active_scan`: the on-demand, loud probe of one target (nmap and the
path/open-directory search) and the filing of what it finds.
"""
from __future__ import annotations

import duckdb
import ipaddress
from datetime import datetime
from datetime import timezone
from typing import Any

from .. import store as tracking_store
from ..probe import vm_proxy
from ..sources import pivot
from ..tracking.history import _record_opendir
from ..util import now_iso
from .storage import ClusterNotFound, _synchronized, load_cluster, log, save_cluster


# --------------------------------------------------------------------------- #
# active_scan - on-demand loud probing (nmap + dirsearch/open-directory)
# --------------------------------------------------------------------------- #
_ACTIVE_SCAN_TOOLS = ("nmap", "dirsearch")


def _opensearch_max_ts() -> float | None:
    """Best-effort snapshot of the newest `ts` indexed in the lab's Zeek/
    OpenSearch, used to bracket an active scan's captured traffic (the same
    provenance anchor the fingerprint queue used). None if OpenSearch
    isn't reachable - provenance is nice-to-have, never blocks the scan.

    Only the sensor being unreachable is swallowed. This used to catch
    Exception, and when the client module moved to cti/sources/ the
    resulting ImportError was swallowed with it: 51 of 52 recorded scans
    have no window."""
    from ..sources.opensearch import OpenSearchClient, OpenSearchError
    try:
        return OpenSearchClient().current_max_ts()
    except (OpenSearchError, OSError, ValueError, KeyError) as e:
        log.info("no Zeek window for this scan: %s", e)
        return None


def _ts_to_dt(ts: float | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)


_MAX_EXTRA_DIRSEARCH = 8
_TLS_SERVICES = {"https", "https-alt", "ssl/http", "ssl/https"}


def active_scan(target: str, cluster: str | None = None,
                tools: list[str] | None = None,
                ports: list[int] | None = None) -> dict[str, Any]:
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
    found later in OpenSearch/Arkime.

    `ports` adds specific TCP ports - a report's console or open-directory
    ports, say - to nmap's top-100 list rather than replacing it, so the
    recorded port set stays comparable with earlier scans. With dirsearch,
    each extra port nmap found open (every extra port, if nmap is not run)
    is also mapped, up to eight."""
    kind = pivot.classify(target)
    if kind not in ("domain", "ip"):
        raise ValueError(f"active_scan supports domain/ip; got kind={kind!r} for {target!r}")
    extra = sorted({int(p) for p in ports}) if ports else []
    bad = [p for p in extra if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"active_scan ports out of range: {bad}")
    if kind == "ip" and ipaddress.ip_address(target).version == 6:
        return {"target": target, "kind": kind, "skipped": "IPv6 (no route from the probe VM)"}
    requested = list(tools) if tools else list(_ACTIVE_SCAN_TOOLS)
    unknown = [t for t in requested if t not in _ACTIVE_SCAN_TOOLS]
    if unknown:
        raise ValueError(f"unknown active_scan tool(s): {unknown}; valid: {_ACTIVE_SCAN_TOOLS}")

    ran_at = now_iso()
    observed_at = datetime.fromisoformat(ran_at).replace(tzinfo=None)
    before_ts = _opensearch_max_ts()

    # Network phase - unlocked (nmap/dirsearch take minutes).
    summary: dict[str, Any] = {"target": target, "kind": kind, "cluster": cluster,
                               "tools": requested, "ran_at": ran_at}
    if extra:
        summary["extra_ports"] = extra
    nmap_ports: list[int] = []
    open_services: dict[int, str | None] = {}
    if "nmap" in requested:
        try:
            nres = (vm_proxy.nmap(target, ports=extra) if extra else vm_proxy.nmap(target))
        except vm_proxy.VMProxyError as e:
            nres = {"error": str(e)}
        if isinstance(nres, dict) and not nres.get("error"):
            nmap_ports = sorted({p["port"] for p in (nres.get("ports") or []) if p.get("port")})
            open_services = {p["port"]: p.get("service") for p in (nres.get("ports") or [])
                             if p.get("port")}
            summary["nmap"] = {"ports": nres.get("ports") or [], "resolved_ip": nres.get("resolved_ip")}
            if extra and nres.get("extra_ports") is None:
                # An older helper ignores the key and scans the top list only.
                # Say so rather than let "8787 not open" read as a finding.
                summary["nmap"]["warning"] = (
                    "the probe helper predates the ports option: only the top-100 "
                    "ports were scanned, NOT the extra ports - redeploy it with "
                    "setup_probe_vm.sh")
        else:
            summary["nmap"] = {"error": nres.get("error")}

    opendirs: list[dict[str, Any]] = []
    if "dirsearch" in requested:
        base = target if target.startswith(("http://", "https://")) else f"http://{target}/"
        urls = [base]
        if extra and not target.startswith(("http://", "https://")):
            mapped = [p for p in extra if p in open_services] if "nmap" in requested else extra
            for p in mapped[:_MAX_EXTRA_DIRSEARCH]:
                scheme = "https" if (open_services.get(p) or "") in _TLS_SERVICES else "http"
                urls.append(f"{scheme}://{target}:{p}/")
        runs: list[dict[str, Any]] = []
        for url in urls:
            try:
                dres = vm_proxy.dirsearch(url)
            except vm_proxy.VMProxyError as e:
                dres = {"error": str(e)}
            if isinstance(dres, dict) and not dres.get("error"):
                found = dres.get("opendirs") or []
                opendirs.extend(found)
                run = {"url": url, "hits": len(dres.get("hits") or []),
                       "opendirs": len(found),
                       "baseline_404": dres.get("baseline_404")}
                # The crawl still ran; only the wordlist search failed. Zero
                # hits then means "did not look", not "nothing there".
                if dres.get("dirsearch_error"):
                    run["path_search_error"] = dres["dirsearch_error"]
                runs.append(run)
            else:
                runs.append({"url": url, "error": dres.get("error")})
        if len(runs) == 1:
            run = dict(runs[0])
            run.pop("url")
            summary["dirsearch"] = run
        else:
            summary["dirsearch"] = {"hits": sum(r.get("hits", 0) for r in runs),
                                    "opendirs": len(opendirs), "urls": runs}

    after_ts = _opensearch_max_ts()

    # Tracking-store write (own locking) - records observations, port/opendir
    # diffs, and the active_scans audit row.
    new_files: list[dict[str, Any]] = []
    indicator_type = "domain" if kind == "domain" else ("ipv6" if ":" in target else "ipv4")
    try:
        with tracking_store.connect_retry(read_only=False) as con:
            if nmap_ports:
                tracking_store.upsert_observation(
                    con, observed_at=observed_at, indicator_value=target,
                    source="nmap", actor=cluster, indicator_type=indicator_type,
                    nmap_ports=nmap_ports)
                tracking_store.detect(con, "ports", indicator_value=target,
                                      actor=cluster, observed_at=observed_at,
                                      new=nmap_ports)
                # The port SET as a selector, not just a per-host diff. This
                # is the only path that discovers ports: the observe pass
                # takes known ports as input and never scans, so without
                # this line `net.port_set` only ever appeared in backfills
                # and the report's high-port pivot (RDP on 64350/65111,
                # which no top-100 scan reaches) had no live source at all.
                tracking_store.selectors.record(
                    con, selector_type="net.port_set", selector_value=nmap_ports,
                    indicator_value=target, indicator_type=indicator_type,
                    actor=cluster, source="nmap", observed_at=observed_at)
            for listing in opendirs:
                new_files.extend(_record_opendir(
                    con, indicator_value=target, listing=listing,
                    observed_at=observed_at, actor=cluster,
                    indicator_type=indicator_type))
            tracking_store.record_active_scan(
                con, ran_at=observed_at, indicator_value=target, actor=cluster,
                tools=requested, summary=summary,
                zeek_first_ts=_ts_to_dt(before_ts), zeek_last_ts=_ts_to_dt(after_ts))
    except (tracking_store.TrackingBusy, duckdb.Error) as e:
        summary["history_note"] = f"active-scan history not recorded: {type(e).__name__}: {e}"

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
