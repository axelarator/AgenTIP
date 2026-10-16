"""The Windows-client pass: what a Windows machine is served.

The probe answers "what is running there". This answers "what would a
victim's machine get" - .NET over Schannel with an Edge User-Agent, from
win116 - and records where the two disagree.

## Which hosts, and when

Coverage-driven, not a fixed list. Each run takes the watchlist's members
(and candidates at CTI_WIN_CANDIDATE_BAND, default `probable`, or better),
skips CDN edges, and keeps the ones win116 has not seen within
CTI_WIN_REFRESH_DAYS (default 7) - never-seen first, then the stalest. At
most CTI_WIN_TARGETS_PER_RUN (default 30) hosts per run, so a full profile
for every seed is built up over runs rather than in one burst.

## What is recorded

* a `service_snapshots` row per URL, vantage `win116`, so the client view
  has history and change detection like the scanner view;
* the selectors `observe.selectors_from` derives from it - body, title,
  certificate - as spans with vantage `win116`;
* `http.client_divergence` when the answer differs from the probe's latest
  snapshot of the same host and port: a different status class, title,
  certificate or landing host - or a TLS session the scanner negotiated and
  Schannel could not (legacy-only ciphers, or a filter on the client
  hello). The value names what diverged ("status:404>200", "title", "cert",
  "redirect", "tls"), so hosts that gate the same way share it. A timeout
  is not divergence: it could be anything. Body hashes alone are not compared: a dynamic page
  differs on every load, and that is not gating.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from .. import membership, store
from ..probe import win_proxy
from ..sources import observe as observe_source
from ..store import entities
from . import watchlist

log = logging.getLogger(__name__)

WEB_PORTS = {80: "http", 443: "https", 8080: "http", 8443: "https", 8000: "http",
             8888: "http", 2052: "http", 2053: "https", 2082: "http", 2083: "https",
             2086: "http", 2087: "https", 2095: "http", 2096: "https", 8880: "http"}
EXTRA_PORTS_PER_HOST = 2
BASELINE_DAYS = 14
# Schannel's own words for a failed negotiation, as .NET reports them.
_TLS_FAILURE = re.compile(r"SSL/TLS|secure channel|handshake", re.I)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _urls(value: str, ports: list[int]) -> list[tuple[int, str]]:
    host = f"[{value}]" if ":" in value else value
    out = [(443, f"https://{host}/"), (80, f"http://{host}/")]
    extra = [p for p in ports if p in WEB_PORTS and p not in (80, 443)]
    for port in extra[:EXTRA_PORTS_PER_HOST]:
        out.append((port, f"{WEB_PORTS[port]}://{host}:{port}/"))
    return out


def plan(*, now: datetime | None = None) -> list[dict[str, Any]]:
    """The hosts this run should fetch, most overdue first."""
    now = now or _now()
    refresh = timedelta(days=_int_env("CTI_WIN_REFRESH_DAYS", 7))
    cap = _int_env("CTI_WIN_TARGETS_PER_RUN", 30)
    floor = os.environ.get("CTI_WIN_CANDIDATE_BAND", "probable")

    chosen = []
    for t in watchlist.build():
        if t.get("lifecycle") == "candidate" and not membership.band_at_least(
                t.get("band") or "noise", floor):
            continue
        if t["kind"] == "ip" and entities.entity_type(t["value"]) != "ipv4":
            continue
        chosen.append(t)
    if not chosen:
        return []

    with store.connect_retry(read_only=True) as con:
        last = dict(con.execute(
            "SELECT target, max(scanned_at) FROM service_snapshots "
            f"WHERE vantage = ? AND target IN ({', '.join('?' for _ in chosen)}) GROUP BY 1",
            [win_proxy.VANTAGE, *[t["value"] for t in chosen]]).fetchall())
    due = [t for t in chosen if last.get(t["value"]) is None
           or now - last[t["value"]] >= refresh]
    due.sort(key=lambda t: (last.get(t["value"]) is not None,
                            last.get(t["value"]) or datetime.min,
                            t.get("lifecycle") == "candidate"))
    return [{**t, "last_win116": last.get(t["value"])} for t in due[:cap]]


def _baseline(con, target: str, port: int, now: datetime) -> dict[str, Any] | None:
    found = con.execute(
        "SELECT http_status, http_title, cert_sha256, record FROM service_snapshots "
        "WHERE target = ? AND port = ? AND vantage <> ? AND open AND scanned_at >= ? "
        "ORDER BY scanned_at DESC LIMIT 1",
        [target, port, win_proxy.VANTAGE, now - timedelta(days=BASELINE_DAYS)]).fetchone()
    if not found:
        return None
    status, title, cert, record = found
    final = None
    try:
        rec = json.loads(record) if isinstance(record, str) else (record or {})
        final = (rec.get("http") or {}).get("final_url") or (rec.get("http") or {}).get("url")
    except (ValueError, TypeError):
        pass
    return {"status": status, "title": title, "cert": cert, "final_url": final}


def _host(url: str | None) -> str | None:
    if not url:
        return None
    return (urlsplit(url).hostname or "").lower().rstrip(".") or None


def divergence(base: dict[str, Any] | None, seen: dict[str, Any], target: str) -> str | None:
    """What a Windows client was served differently, as a shareable value."""
    if not base:
        return None
    http, tls = seen.get("http") or {}, seen.get("tls") or {}
    if not http and not tls:
        error = str(seen.get("error") or "")
        scanner_negotiated = base.get("status") is not None or base.get("cert")
        return "tls" if scanner_negotiated and _TLS_FAILURE.search(error) else None
    parts = []
    ws, ps = http.get("status"), base.get("status")
    if isinstance(ws, int) and isinstance(ps, int) and ws // 100 != ps // 100:
        parts.append(f"status:{ps}>{ws}")
    wt, pt = (http.get("title") or "").strip().lower(), (base.get("title") or "").strip().lower()
    if wt and pt and wt != pt:
        parts.append("title")
    wc, pc = tls.get("cert_sha256"), base.get("cert")
    if wc and pc and wc.lower() != pc.lower():
        parts.append("cert")
    landed, probe_landed = _host(http.get("final_url")), _host(base.get("final_url"))
    target_host = target.lower().rstrip(".")
    if landed and landed != target_host and landed != (probe_landed or target_host):
        parts.append("redirect")
    return ",".join(sorted(parts)) or None


def run(*, targets: list[dict[str, Any]] | None = None,
        now: datetime | None = None) -> dict[str, Any]:
    """Fetch the planned hosts from win116 and record what it was served."""
    if not win_proxy.configured():
        return {"skipped": "win116 is not configured (CTI_WIN_HOST / CTI_WIN_USER)"}
    now = now or _now()
    targets = plan(now=now) if targets is None else targets
    if not targets:
        return {"targets": 0, "fetched": 0, "answered": 0, "divergent": []}

    requests, meta = [], {}
    for t in targets:
        for port, url in _urls(t["value"], t.get("ports") or []):
            requests.append({"target": t["value"], "url": url})
            meta[url] = (t, port)
    results = win_proxy.fetch(requests)

    scan_id = f"win116-{int(time.time())}"
    answered, divergent, selectors_written = 0, [], 0
    with store.connect_retry(read_only=False) as con:
        for seen in results:
            t, port = meta.get(seen.get("url"), (None, None))
            if t is None:
                continue
            http, tls = seen.get("http") or {}, seen.get("tls") or {}
            is_open = http.get("status") is not None or bool(tls)
            answered += is_open
            kind = "ip" if t["kind"] == "ip" else "domain"
            diverged = divergence(_baseline(con, t["value"], port, now), seen, t["value"])
            store.upsert_service_snapshot(con, row={
                "scan_id": scan_id, "scanned_at": now, "vantage": win_proxy.VANTAGE,
                "profile": "client", "target": t["value"], "ip": None, "port": port,
                "open": is_open, "actor": t.get("actor"),
                "cert_sha256": tls.get("cert_sha256"), "tls_issuer": tls.get("issuer"),
                "http_status": http.get("status"), "http_title": http.get("title"),
                "http_server": http.get("server"), "body_sha256": http.get("body_sha256"),
                "record": seen})
            if is_open:
                selectors_written += len(store.selectors.record_many(
                    con, indicator_value=t["value"],
                    found=observe_source.selectors_from(seen, target=t["value"], kind=kind),
                    observed_at=now, indicator_type=kind, actor=t.get("actor"),
                    source=win_proxy.VANTAGE, vantage=win_proxy.VANTAGE))
            if diverged:
                store.selectors.record(
                    con, indicator_value=t["value"], selector_type="http.client_divergence",
                    selector_value=diverged, observed_at=now, indicator_type=kind,
                    actor=t.get("actor"), source=win_proxy.VANTAGE, vantage=win_proxy.VANTAGE)
                store.record_service_change(
                    con, detected_at=now, scan_id=scan_id, target=t["value"], port=port,
                    actor=t.get("actor"), field="client_divergence",
                    change_type="client_divergence", old_value=None, new_value=diverged)
                divergent.append({"target": t["value"], "port": port, "diverged": diverged})
    return {"scan_id": scan_id, "targets": len(targets), "fetched": len(results),
            "answered": answered, "selectors": selectors_written, "divergent": divergent}
