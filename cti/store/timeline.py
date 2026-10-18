"""What moved, over a window: the daily digest's view of change over time.

Three kinds of movement, all read from what the store already keeps:

* **Band moves** - a candidate's relatedness band changing between the last
  score before the window and the last inside it (`relatedness_scores` is
  append-only). New evidence lifting a `weak` host to `probable` is the
  signal the score exists to deliver; a fall is worth seeing too.
* **Value changes** - on a tracked or candidate host, a selector span that
  opened in the window replacing an earlier value of the same type FROM THE
  SAME SOURCE AND VANTAGE: a new JARM, a re-keyed TLS stack, a changed
  header order, a new registrant. Comparing across tools read every
  difference between scanners as a change - each client's hello draws a
  different JA4S, and two JARM implementations disagree - so it is not
  done. A value the host has shown before is alternation, not change.
  Types the attribute change-detectors already report (certificate hash,
  resolved IP, PTR, title, server, ports, Webamon fingerprints) are left to
  them, and body hashes are left out - dynamic pages change on every load.
* **Client divergences** - the first time a host served the Windows client
  something different from the scanner, per divergence value.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import duckdb

from ..util import rows
from . import cdn
from .selectors import selector_class
from .spans import PASSIVE_SOURCES

BAND_ORDER = ("noise", "weak", "probable", "strong")

# Span types worth a line when they change on a host, beyond what the
# attribute change-detectors already report.
TIMELINE_TYPES = (
    "tls.jarm", "tls.ja4s", "tls.ja4x", "tls.ja4ts", "tls.ja3s", "tls.spki_sha256",
    # Not tls.san: a certificate names several at once, so one opening
    # replaces nothing.
    "tls.subject_cn", "tls.default_subject", "tls.serial",
    "http.favicon_mmh3", "http.header_set", "http.header_order",
    "ssh.hassh_server", "flow.app_proto",
    "dns.ns_set", "dns.mx_set", "dns.soa_email",
    "whois.registrar", "whois.registrant_email",
)


def _tracked(con, clusters: list[str] | None) -> dict[str, list[str]]:
    """entity -> ["cluster:role", ...] for seeds, accepted and candidates."""
    params: list[Any] = []
    where = "role IN ('seed', 'accepted', 'candidate')"
    if clusters:
        where += f" AND cluster IN ({', '.join('?' for _ in clusters)})"
        params.extend(clusters)
    out: dict[str, list[str]] = {}
    for entity, cluster, role in con.execute(
            f"SELECT entity, cluster, role FROM memberships WHERE {where}", params).fetchall():
        out.setdefault(entity, []).append(f"{cluster}:{role}")
    return out


def band_moves(con: duckdb.DuckDBPyConnection, *, since: datetime, until: datetime,
               clusters: list[str] | None = None) -> list[dict[str, Any]]:
    params: list[Any] = [since, until]
    scope = ""
    if clusters:
        scope = f" AND cluster IN ({', '.join('?' for _ in clusters)})"
        params.extend(clusters)
    current = rows(con, f"""
        SELECT cluster, entity, arg_max(score, scored_at) AS score,
               arg_max(band, scored_at) AS band
        FROM relatedness_scores WHERE scored_at >= ? AND scored_at <= ? {scope}
        GROUP BY 1, 2""", params)
    out = []
    for row in current:
        prior = con.execute(
            "SELECT score, band FROM relatedness_scores WHERE cluster = ? AND entity = ? "
            "AND scored_at < ? ORDER BY scored_at DESC LIMIT 1",
            [row["cluster"], row["entity"], since]).fetchone()
        role = con.execute("SELECT role FROM memberships WHERE cluster = ? AND entity = ?",
                           [row["cluster"], row["entity"]]).fetchone()
        if not role or role[0] != "candidate":
            continue
        if prior and prior[1] == row["band"]:
            continue
        # A newly scored candidate is news only if it scored something.
        if not prior and row["band"] == "noise":
            continue
        before = prior[1] if prior else None
        direction = ("new" if before is None else
                     "up" if BAND_ORDER.index(row["band"]) > BAND_ORDER.index(before) else "down")
        out.append({"cluster": row["cluster"], "entity": row["entity"],
                    "from_band": before, "to_band": row["band"],
                    "from_score": round(prior[0], 3) if prior else None,
                    "to_score": round(row["score"], 3), "direction": direction})
    rank = {"up": 0, "new": 1, "down": 2}
    out.sort(key=lambda m: (rank[m["direction"]], -BAND_ORDER.index(m["to_band"]),
                            m["cluster"], m["entity"]))
    return out


def _behind_cdn(con, indicator: str) -> bool:
    """A CDN edge, or a name the observe pass last saw behind one. Its TLS
    and HTTP are the CDN's, and rotate on the CDN's schedule.

    Read from the observation history, not selectors: the observe pass
    deliberately records no address selector for a CDN edge, so a
    Cloudflare-fronted name has no `net.resolved_ip` to look at.
    """
    if cdn.is_cdn(indicator):
        return True
    latest = con.execute(
        "SELECT cdn_provider, resolved_ip FROM observations_wide WHERE indicator_value = ? "
        "AND (cdn_provider IS NOT NULL OR resolved_ip IS NOT NULL) "
        "ORDER BY observed_at DESC LIMIT 1", [indicator]).fetchone()
    if not latest:
        return False
    provider, resolved = latest
    if provider:
        return True
    try:
        addresses = [a for a in json.loads(resolved or "[]") if ":" not in a]
    except (TypeError, ValueError):
        return False
    return bool(addresses) and all(cdn.is_cdn(a) for a in addresses)


def value_changes(con: duckdb.DuckDBPyConnection, *, since: datetime, until: datetime,
                  clusters: list[str] | None = None) -> list[dict[str, Any]]:
    tracked = _tracked(con, clusters)
    if not tracked:
        return []
    types = ", ".join("?" for _ in TIMELINE_TYPES)
    passive = ", ".join("?" for _ in PASSIVE_SOURCES)
    opened = rows(con, f"""
        SELECT n.indicator_value, n.selector_type, n.selector_value, n.start_at, n.vantage,
               (SELECT o.selector_value FROM selector_spans o
                 WHERE o.indicator_value = n.indicator_value
                   AND o.selector_type = n.selector_type
                   AND o.selector_value <> n.selector_value
                   AND o.source = n.source
                   AND coalesce(o.vantage, '') = coalesce(n.vantage, '')
                   AND o.start_at < n.start_at
                 ORDER BY o.end_at DESC LIMIT 1) AS previous
        FROM selector_spans n
        WHERE n.start_at >= ? AND n.start_at <= ?
          AND n.selector_type IN ({types})
          AND n.source NOT IN ({passive})
          -- A value this host has shown before, from anywhere, is a host
          -- alternating between values (two certificates behind a balancer),
          -- not a change.
          AND NOT EXISTS (SELECT 1 FROM selector_spans r
                          WHERE r.indicator_value = n.indicator_value
                            AND r.selector_type = n.selector_type
                            AND r.selector_value = n.selector_value
                            AND r.start_at < n.start_at)""",
        [since, until, *TIMELINE_TYPES, *sorted(PASSIVE_SOURCES)])
    out = []
    fronted: dict[str, bool] = {}
    for row in opened:
        if row["previous"] is None or row["indicator_value"] not in tracked:
            continue
        if row["selector_type"].startswith(("tls.", "http.")):
            host = row["indicator_value"]
            if host not in fronted:
                fronted[host] = _behind_cdn(con, host)
            if fronted[host]:
                continue
        out.append({"indicator": row["indicator_value"],
                    "memberships": tracked[row["indicator_value"]],
                    "selector_type": row["selector_type"],
                    "class": selector_class(row["selector_type"]),
                    "old_value": row["previous"], "new_value": row["selector_value"],
                    "at": row["start_at"], "vantage": row["vantage"]})
    out.sort(key=lambda c: (c["indicator"], c["selector_type"]))
    return out


def divergences(con: duckdb.DuckDBPyConnection, *, since: datetime, until: datetime,
                clusters: list[str] | None = None) -> list[dict[str, Any]]:
    tracked = _tracked(con, clusters)
    found = rows(con, """
        SELECT c.target, c.port, c.new_value, c.detected_at
        FROM service_changes c
        WHERE c.field = 'client_divergence' AND c.detected_at >= ? AND c.detected_at <= ?
          AND NOT EXISTS (SELECT 1 FROM service_changes p
                          WHERE p.field = 'client_divergence' AND p.target = c.target
                            AND p.new_value = c.new_value AND p.detected_at < ?)
        ORDER BY c.target, c.port""", [since, until, since])
    out = []
    for row in found:
        if row["target"] not in tracked:
            continue
        value = row["new_value"]
        if isinstance(value, str) and value.startswith('"'):
            value = value.strip('"')
        out.append({"target": row["target"], "port": row["port"], "diverged": value,
                    "memberships": tracked[row["target"]], "at": row["detected_at"]})
    return out


def changes(con: duckdb.DuckDBPyConnection, *, since: datetime, until: datetime,
            clusters: list[str] | None = None) -> dict[str, Any]:
    def plain(items):
        return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in i.items()}
                for i in items]
    return {"since": since.isoformat(), "until": until.isoformat(),
            "band_moves": plain(band_moves(con, since=since, until=until, clusters=clusters)),
            "value_changes": plain(value_changes(con, since=since, until=until,
                                                 clusters=clusters)),
            "client_divergences": plain(divergences(con, since=since, until=until,
                                                    clusters=clusters))}
