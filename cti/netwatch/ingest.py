"""Load scan results, join the passive fingerprints, diff, record.

For each (target, port) a scan produced this is: upsert the snapshot, diff
it against the previous scan's snapshot (port opened/closed, cert swap,
JARM/JA4S move, header-order or title change, a C2 template hit), derive
the same selectors the observe pass does so the host is pivotable, and
write an observation for the time series.

The passive half comes from Zeek via Wazuh: our probe opened these
sessions on the mirrored bridge, so ssl.log carries their ja4s and conn.log
their ja4ts/ja4l. We match on (probe IP -> target IP:port) inside a time
window around the scan, filling the fields tlsx alone cannot.

Writes go through connect_retry, so the hourly ingest simply waits on
DuckDB's own file lock if the daily run is mid-write - no bespoke lock.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import store
from ..sources import ja4x as ja4x_mod
from ..sources import observe as observe_source
from ..sources.opensearch import OpenSearchClient, OpenSearchError
from .jobs import spool_dir

log = logging.getLogger(__name__)

# Zeek sees the probe by its bridge IP, not the "vantage" label. Default to
# the probe host; a Windows vantage maps through the same env the lab uses.
_VANTAGE_IP = {
    "probe": os.environ.get("CTI_PROBE_ZEEK_IP") or os.environ.get("CTI_PROBE_HOST"),
    "win116": os.environ.get("CTI_WIN_ZEEK_IP"),
}

# Zeek -> Wazuh ingest lags capture; widen the window on both sides.
_JOIN_LOOKBACK = 120.0
_JOIN_LOOKAHEAD = 900.0

# (field on the snapshot) -> change_type when it differs from the baseline.
_DIFF_FIELDS = {
    "cert_sha256": "cert_changed",
    "jarm": "jarm_changed",
    "ja4s": "ja4s_changed",
    "header_order": "header_order_changed",
    "http_title": "title_changed",
    "banner_sha256": "banner_changed",
    "app_proto": "app_proto_changed",
}


def _parse_ts(value: Any) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).replace(tzinfo=None)
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


# Which of our clients' sessions the server-side fingerprints are read from.
# A server answers each client hello differently - measured 2026-10-17, 74 of
# 130 servers gave httpx and tlsx different JA4S, while every client got a
# stable answer of its own - so a JA4S only means something per client.
# Pinned to tlsx: the dedicated TLS client, used by both the sweep and
# netwatch, stable on all 88 servers it reached. The value is the cipher-hash
# part of tlsx's own JA4 (the middle field), which holds across SNI/no-SNI.
DEFAULT_JA4S_CLIENT_HASH = "e8f1e7e78f70"


def ja4s_client_hash() -> str:
    return os.environ.get("CTI_JA4S_CLIENT_HASH", DEFAULT_JA4S_CLIENT_HASH)


def _pinned_client(ja4: str | None) -> bool:
    parts = (ja4 or "").split("_")
    return len(parts) == 3 and parts[1] == ja4s_client_hash()


def _passive_fingerprints(client: OpenSearchClient | None, vantage: str,
                          ip: str, port: int, scan_epoch: float) -> dict[str, Any]:
    """ja4s/ja4x (ssl.log) and ja4ts/ja4l (conn.log) for the pinned client's
    session to ip:port around scan time. Unreachable Zeek is a skip.

    The TCP fingerprints come from the same session (joined on Zeek's uid):
    a server's SYN-ACK also depends on the client's SYN.
    """
    probe_ip = _VANTAGE_IP.get(vantage)
    if client is None or not probe_ip or not ip:
        return {}
    out: dict[str, Any] = {}
    base = [{"term": {client.field("src_ip"): probe_ip}},
            {"term": {client.field("dst_ip"): ip}},
            {"term": {client.field("dst_port"): port}},
            client.ts_range(gte=scan_epoch - _JOIN_LOOKBACK,
                            lt=scan_epoch + _JOIN_LOOKAHEAD)]
    try:
        hits = client.sources({"bool": {"filter": base}}, size=200)
    except OpenSearchError as e:
        log.warning("passive join unavailable: %s", e)
        return out
    ssl = [h for h in hits if h.get("log_file", "").endswith("ssl.log")]
    pinned = [h for h in ssl if _pinned_client(h.get("ja4"))]
    if ssl and not pinned:
        log.warning("no session from the pinned TLS client (JA4 cipher hash %s) to %s:%s "
                    "among %d - if tlsx was upgraded, set CTI_JA4S_CLIENT_HASH",
                    ja4s_client_hash(), ip, port, len(ssl))
    for hit in pinned:
        for f in ("ja4s", "ja4x"):
            if hit.get(f) and not out.get(f):
                out[f] = hit[f]
    uids = {h.get("uid") for h in pinned if h.get("uid")}
    for hit in hits:
        if hit.get("log_file", "").endswith("conn.log") and hit.get("uid") in uids:
            for f in ("ja4ts", "ja4l"):
                if hit.get(f) and not out.get(f):
                    out[f] = hit[f]
    return out


def intercepted_ports() -> set[int]:
    """Ports something on the probe's egress path answers for every target.

    Measured 2026-10-16: TCP/53 to five unrelated hosts on four providers
    completed the handshake, sent 0 bytes and closed at an identical 0.48 s
    or 2.47 s, while real resolvers on the same path answered with 48-300
    bytes. naabu reports that as open on every host it touches. A port in
    this set counts as open only with an application answer behind it.
    """
    raw = os.environ.get("CTI_NETWATCH_INTERCEPTED_PORTS", "53")
    return {int(p) for p in raw.split(",") if p.strip().isdigit()}


def _intercepted(rec: dict[str, Any]) -> bool:
    return (bool(rec.get("open")) and int(rec.get("port") or 0) in intercepted_ports()
            and not (rec.get("http") or rec.get("tls") or rec.get("banner_sha256")
                     or rec.get("app_proto")))


def _flatten(rec: dict[str, Any], passive: dict[str, Any]) -> dict[str, Any]:
    """A scan record (+ passive fingerprints) -> a service_snapshots row.

    JA4X is computed here from the certificate's PEM, which is then dropped
    from the stored record: it is ~2 KB per port per scan, and the digest it
    yields (with cert_sha256 beside it) is what anything reads back."""
    http = rec.get("http") or {}
    tls = rec.get("tls") or {}
    ja4x = passive.get("ja4x") or ja4x_mod.for_tls(tls)
    if tls.get("pem"):
        rec = {**rec, "tls": {k: v for k, v in tls.items() if k != "pem"}}
    return {
        "scan_id": rec["scan_id"], "scanned_at": _parse_ts(rec.get("ts")),
        "vantage": rec.get("vantage") or "probe", "profile": rec.get("profile"),
        "target": rec["target"], "ip": rec.get("ip"), "port": int(rec.get("port") or 0),
        "open": bool(rec.get("open")), "actor": rec.get("actor"),
        "banner_sha256": rec.get("banner_sha256"),
        "cert_sha256": tls.get("cert_sha256"), "spki_sha256": tls.get("spki_sha256"),
        "tls_issuer": tls.get("issuer"), "ja3s": tls.get("ja3s"),
        "ja4s": passive.get("ja4s"), "ja4ts": passive.get("ja4ts"),
        "ja4x": ja4x,
        "jarm": http.get("jarm"), "http_status": http.get("status"),
        "http_title": http.get("title"), "http_server": http.get("server"),
        "header_order": observe_source.header_order(http.get("raw_header")),
        "body_sha256": http.get("body_sha256"),
        "favicon_mmh3": (str(http["favicon_mmh3"])
                         if http.get("favicon_mmh3") not in (None, "", 0) else None),
        "hassh_server": None, "app_proto": None,
        "c2_hits": rec.get("c2_hits") or None,
        "record": rec,
    }


def _diff(con, row: dict[str, Any]) -> int:
    """Record what moved on this (target, port) since the last scan."""
    base = store.latest_service_snapshot(
        con, row["target"], row["port"], before_scan_id=row["scan_id"])
    changes: list[tuple[str, str, Any, Any]] = []

    if base is not None and bool(base.get("open")) != row["open"]:
        changes.append(("open", "port_opened" if row["open"] else "port_closed",
                        base.get("open"), row["open"]))
    if row["open"]:
        for field, change_type in _DIFF_FIELDS.items():
            new = row.get(field)
            old = base.get(field) if base else None
            if new and old and new != old:
                changes.append((field, change_type, old, new))
    new_hits = set(row.get("c2_hits") or [])
    old_hits = set((base or {}).get("c2_hits") and
                   json.loads(base["c2_hits"]) if base and base.get("c2_hits") else [])
    if new_hits - old_hits:
        changes.append(("c2_hits", "c2_signature_hit",
                        sorted(old_hits) or None, sorted(new_hits)))

    for field, change_type, old, new in changes:
        store.record_service_change(
            con, detected_at=row["scanned_at"], scan_id=row["scan_id"],
            target=row["target"], port=row["port"], actor=row.get("actor"),
            field=field, change_type=change_type, old_value=old, new_value=new)
    return len(changes)


def _observe_result(records: list[dict[str, Any]], passive_by_port: dict[int, dict]) -> dict:
    """Aggregate a target's per-port records into one observe-shaped result,
    so observe.selectors_from applies its own rules (one copy of the
    extraction logic, same as the backfill does)."""
    http, tls = {}, {}
    open_ports = []
    for rec in sorted(records, key=lambda r: r.get("port") or 0):
        if rec.get("port"):
            if rec.get("open"):
                open_ports.append(rec["port"])
        if rec.get("http") and not http:
            http = dict(rec["http"])
        if rec.get("tls") and not tls.get("cert_sha256"):
            tls = {**dict(rec["tls"]), **({"ja4s": tls["ja4s"]} if tls.get("ja4s") else {})}
        # Zeek's JA4S is the server's own answer, recorded whether or not the
        # active TLS grab produced a certificate - it was only ever attached
        # beside one, so while tlsx failed no JA4S became a selector at all.
        passive = passive_by_port.get(rec.get("port"), {})
        for field in ("ja4s", "ja4ts", "ja4x"):
            if passive.get(field) and field not in tls:
                tls[field] = passive[field]
    return {"http": http, "tls": tls, "dns": {}, "whois": {},
            "cdn": {}, "ports": open_ports or None, "errors": {}}


_UNSET = object()


def ingest(*, client: Any = _UNSET, purge: bool = True) -> dict[str, Any]:
    """Load every spooled scan, join, diff, record. Returns a summary.

    `client` left unset builds the default Zeek backend for the passive
    join; pass None to skip the join entirely (tests, or a run with no
    sensor)."""
    files = sorted(spool_dir().glob("*.jsonl"))
    if not files:
        return {"files": 0, "snapshots": 0, "changes": 0, "selectors": 0}

    if client is _UNSET:
        try:
            client = OpenSearchClient()
        except Exception as e:
            log.warning("no Zeek backend for passive join: %s", e)
            client = None

    by_target: dict[tuple[str, str], list[dict]] = {}
    for path in files:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            by_target.setdefault((rec.get("scan_id"), rec.get("target")), []).append(rec)

    snapshots = changes = selectors = 0
    with store.connect_retry(read_only=False) as con:
        for (scan_id, target), records in by_target.items():
            # Before anything reads `open`: the snapshot, the diff and the
            # port-set selector must all see an intercepted port as closed.
            records = [{**r, "open": False, "intercepted": True} if _intercepted(r) else r
                       for r in records]
            passive_by_port: dict[int, dict] = {}
            for rec in records:
                if not rec.get("open") or not rec.get("ip"):
                    continue
                passive_by_port[rec["port"]] = _passive_fingerprints(
                    client, rec.get("vantage") or "probe", rec["ip"],
                    rec["port"], _parse_ts(rec.get("ts")).replace(
                        tzinfo=timezone.utc).timestamp())
            actor = next((r.get("actor") for r in records if r.get("actor")), None)
            kind = "ip" if records and records[0].get("ip") == target else "domain"
            observed_at = _parse_ts(records[0].get("ts"))

            for rec in records:
                row = _flatten(rec, passive_by_port.get(rec.get("port"), {}))
                store.upsert_service_snapshot(con, row=row)
                changes += _diff(con, row)
                snapshots += 1

            result = _observe_result(records, passive_by_port)
            if result["http"] or result["tls"] or result["ports"]:
                found = observe_source.selectors_from(result, target=target, kind=kind)
                selectors += len(store.selectors.record_many(
                    con, indicator_value=target, found=found,
                    observed_at=observed_at, indicator_type=kind, actor=actor,
                    source="netwatch",
                    vantage=records[0].get("vantage") or "probe"))

    if purge:
        for path in files:
            path.unlink(missing_ok=True)
    return {"files": len(files), "snapshots": snapshots,
            "changes": changes, "selectors": selectors}
