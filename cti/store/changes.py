"""Day-over-day attribute change detection, as data.

## What this replaces

The old tree had ten `_record_*_change` functions in core.py
(lines 1387-1633) paired with twelve `latest_*_for` query functions in
tracking/store.py (lines 368-574). Every one of the ten had the same
four-step body - fetch baseline, emit a `first_seen` row if there is
none, return early if nothing changed, otherwise record the change - and
every one of the twelve was the same query with a different column list:

    SELECT observed_at, <cols> FROM observations
    WHERE indicator_value = ? AND source = ?
      [AND <guard> IS NOT NULL] AND observed_at < ?
    ORDER BY observed_at DESC LIMIT 1

Twenty-two functions, roughly 500 lines, to express ten table rows'
worth of difference. Adding an attribute meant writing two more.

Now an attribute is an `AttributeSpec` entry and one driver runs them
all. Every behavioural quirk the old comments documented is preserved
and annotated on the spec that carries it - they were all load-bearing,
and several encode a real incident.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

import duckdb

from ..util import is_stale
from .selectors import canonical_dn

# A baseline this old is re-checked for the first time in months; a
# change against it shouldn't read as a confident "changed since
# yesterday". Same rule the ASN path uses.
STALE_BASELINE_DAYS = 90

# Per-change-type prior. High = the change is hard to explain innocently
# (a new issuer, a rebuilt kit); low = it moves for routine reasons.
CONFIDENCE_BASE = {
    "cert_issuer_changed": "high",
    "cert_sans_changed": "medium",
    "cert_new": "high",
    "ports_changed": "medium",
    "hostnames_changed": "medium",
    "ptr_changed": "medium",
    "resolved_ip_changed": "medium",
    "ip_hostnames_changed": "medium",
    "http_server_changed": "medium",
    "http_title_changed": "low",
    "webamon_fingerprint_changed": "high",
    "subdomains_changed": "low",
    "infostealer_hits": "medium",
}

_DOWNGRADE = {"high": "medium", "medium": "low", "low": "low"}


def confidence(change_type: str, baseline_observed_at: datetime | None) -> str:
    """Confidence for a recorded change.

    Replaces two implementations that ended in the identical downgrade
    line: core._attribute_confidence and tracking.enrich._confidence.
    Unlike ASN - which can be corroborated across RDAP and HoneyLabs -
    these attributes each have a single source, so there is no
    corroboration branch: start from the per-change-type prior and
    downgrade one step if the baseline is stale.
    """
    conf = CONFIDENCE_BASE[change_type]
    if baseline_observed_at is not None and is_stale(baseline_observed_at, STALE_BASELINE_DAYS):
        conf = _DOWNGRADE[conf]
    return conf


def asn_confidence(new_source: str, baseline: dict[str, Any], corroborated: bool) -> str:
    """The ASN variant, which *does* have a corroboration branch. Kept
    beside the others so the staleness rule lives in one place."""
    conf = "high" if (new_source == "rdap"
                      and (baseline["source"] == "rdap" or corroborated)) else "medium"
    if is_stale(baseline["observed_at"], STALE_BASELINE_DAYS):
        conf = _DOWNGRADE[conf]
    return conf


# --------------------------------------------------------------------------- #
# Specs
# --------------------------------------------------------------------------- #

_NO_BASELINE = object()

# "this value is not worth recording" - distinct from None, which is a
# legitimate observed value for ptr ("confirmed no PTR record"). Using
# None for both made a tracked host losing its PTR silently invisible.
SKIP = object()


@dataclass(frozen=True)
class AttributeSpec:
    """One tracked attribute.

    attribute        value written to attribute_changes.attribute
    source           observations.source holding this attribute's rows - or
                     a tuple of them, newest-format first. A spec that
                     changes tool keeps the old source in the tuple so its
                     baseline stays continuous across the switch
    columns          observations_wide columns making up the baseline
    guard            column that must be non-NULL for a row to count as a
                     usable baseline, or None when NULL is itself a
                     meaningful observed value
    json_columns     columns to json.loads out of the view
    classify         (old, new) -> change_type, or None for "no change"
    shape_old        old -> the JSON written to old_value
    shape_new        (new, old) -> the JSON written to new_value
    first_seen_confidence / emit_first_seen / first_seen_empty
                     baseline-row behaviour
    baseline_default a value to compare against when no baseline row
                     exists, instead of emitting first_seen
    bare             compare the single column's raw value rather than a
                     dict keyed by column name
    json_encode      double-encode old/new before storing (see `ptr`)
    fixed_confidence bypass the prior/staleness calculation
    """
    attribute: str
    source: str | tuple[str, ...]
    columns: tuple[str, ...]
    bare: bool
    classify: Callable[[Any, Any], str | None]
    guard: str | None = None
    json_columns: frozenset[str] = frozenset()
    shape_old: Callable[[Any], Any] = lambda old: old
    shape_new: Callable[[Any, Any], Any] = lambda new, old: new
    normalize_new: Callable[[Any], Any] = lambda new: new
    first_seen_confidence: str = "medium"
    first_seen_empty: Callable[[Any], bool] = lambda new: False
    baseline_default: Any = _NO_BASELINE
    json_encode: bool = False
    fixed_confidence: str | None = None
    note: str = ""


def _sorted_list_changed(old: Any, new: Any, change_type: str) -> str | None:
    return None if sorted(old or []) == sorted(new or []) else change_type


def _classify_cert(old: dict, new: dict) -> str | None:
    """A same-issuer, same-SANs renewal is routine and deliberately not
    recorded - the sha256 rotation it produces is tracked separately by
    the cert_hash spec, on its own timeline."""
    # Compared as canonical DNs. The baseline may be an openssl row ("C = US,
    # O = Let's Encrypt, CN = YE1") and the new value tlsx's ("CN=YE1, O=Let's
    # Encrypt, C=US"): the same issuer, spelled two ways. Compared as strings
    # the first observation after the switch would report a certificate
    # issuer change for every domain that has one.
    if (new["issuer"] and old["issuer"]
            and canonical_dn(new["issuer"]) != canonical_dn(old["issuer"])):
        return "cert_issuer_changed"
    if set(new["sans"] or []) != set(old["sans"] or []):
        return "cert_sans_changed"
    return None


def _classify_http(old: dict, new: dict) -> str | None:
    if new["title"] == old["title"] and new["server"] == old["server"]:
        return None
    return "http_server_changed" if new["server"] != old["server"] else "http_title_changed"


def _classify_subdomains(old: list, new: list) -> str | None:
    if sorted(old or []) == sorted(new or []):
        return None
    if not set(new or []) - set(old or []):
        return None  # only removals - not a lead
    return "subdomains_changed"


def _added(new: list, old: list, key: str) -> dict:
    return {key: new, "added": sorted(set(new or []) - set(old or []))}


# The certificate now comes from the observe pass (tlsx) and the separate
# openssl grab that used to write `tls_live` is gone. Both stay in the tuple:
# 310 tls_live rows are the baseline for 22 domains, and dropping them would
# turn every one of those domains' next observation into a "first_seen".
# Verified before the switch: on all 73 same-day pairs the two sources agree
# exactly on sha256 and on the SAN set, and every domain that has tls_live
# history already has observe_tls history.
CERT_SOURCES = ("observe_tls", "tls_live")


SPECS: dict[str, AttributeSpec] = {
    "ports": AttributeSpec(
        attribute="ports", bare=True, source="nmap", guard="nmap_ports",
        columns=("nmap_ports",), json_columns=frozenset({"nmap_ports"}),
        classify=lambda old, new: _sorted_list_changed(old, new, "ports_changed"),
        note="Ports come from on-demand nmap now that Shodan InternetDB is "
             "retired, so a change here means someone actively rescanned the "
             "host - not routine daily churn.",
    ),
    "ptr": AttributeSpec(
        attribute="ptr", bare=True, source="ptr", guard=None,
        columns=("ptr_hostname",),
        classify=lambda old, new: None if old == new else "ptr_changed",
        json_encode=True,
        note="guard is deliberately None: a NULL ptr_hostname is a "
             "legitimate, confirmed 'no PTR record' observation, not a "
             "missing one - a 'ptr' row only exists when the lookup "
             "succeeded. Excluding NULLs would silently drop 'went from "
             "having a PTR to having none' as a usable future baseline. "
             "json_encode is on because a bare hostname or None would "
             "otherwise reach a JSON column as unquoted text or a dropped "
             "SQL NULL, and NULL here collapses into 'no baseline' rather "
             "than the distinct value 'confirmed no PTR'.",
    ),
    "resolved_ip": AttributeSpec(
        attribute="resolved_ip", bare=True, source="dns_resolve", guard="resolved_ip",
        columns=("resolved_ip",), json_columns=frozenset({"resolved_ip"}),
        classify=lambda old, new: _sorted_list_changed(old, new, "resolved_ip_changed"),
        note="new value can legitimately be [] - a confirmed dead or "
             "sinkholed domain. Only called with a definitive result, never "
             "an inconclusive one. An empty list serializes to '[]', not "
             "SQL NULL, so the guard excludes only never-written rows.",
    ),
    "cert": AttributeSpec(
        attribute="cert", bare=False, source=CERT_SOURCES, guard="tls_sha256",
        columns=("tls_issuer", "tls_sans"),
        json_columns=frozenset({"tls_sans"}),
        classify=_classify_cert,
        normalize_new=lambda c: {"issuer": c.get("issuer"),
                                 "sans": sorted(c.get("sans") or [])},
        shape_old=lambda old: {"issuer": old["issuer"], "sans": sorted(old["sans"] or [])},
        first_seen_empty=lambda new: new["issuer"] is None and not new["sans"],
    ),
    "cert_hash": AttributeSpec(
        attribute="cert_hash", bare=False, source=CERT_SOURCES, guard="tls_sha256",
        columns=("tls_sha256",),
        classify=lambda old, new: None if old["sha256"] == new["sha256"] else "cert_new",
        normalize_new=lambda c: ({"sha256": c["sha256"]} if c.get("sha256") else SKIP),
        note="A renewal always mints a new certificate and therefore a new "
             "sha256, which the `cert` spec treats as routine - so the hash "
             "gets its own timeline. This is the one attribute whose change "
             "is a genuine first-ever discovery rather than a changed value "
             "on known infrastructure, and the only one auto-filed onto the "
             "cluster's own hash list.",
    ),
    "ip_hostnames": AttributeSpec(
        attribute="ip_hostnames", bare=True, source="webamon", guard="ip_hostnames",
        columns=("ip_hostnames",), json_columns=frozenset({"ip_hostnames"}),
        classify=lambda old, new: _sorted_list_changed(old, new, "ip_hostnames_changed"),
        shape_new=lambda new, old: _added(new, old, "hostnames"),
        first_seen_confidence="medium",
        note="Flag only: new hostnames are surfaced but never auto-filed as "
             "tracked observables - that is a reviewed pivot_and_expand "
             "decision. Suppressed entirely on shared-hosting ASNs.",
    ),
    "http": AttributeSpec(
        attribute="http", bare=False, source="http_live", guard=None,
        columns=("http_title", "http_server"),
        classify=_classify_http,
        normalize_new=lambda h: {"title": h.get("title"), "server": h.get("server")},
        first_seen_confidence="low",
        first_seen_empty=lambda new: new["title"] is None and new["server"] is None,
    ),
    "webamon_fingerprint": AttributeSpec(
        attribute="webamon_fingerprint", bare=False, source="webamon",
        guard="webamon_fingerprint_dom",
        columns=("webamon_fingerprint_dom", "webamon_fingerprint_ssl"),
        classify=lambda old, new: (None if old["dom"] == new["dom"] and old["ssl"] == new["ssl"]
                                   else "webamon_fingerprint_changed"),
        normalize_new=lambda f: {"dom": f.get("dom"), "ssl": f.get("ssl")},
        first_seen_empty=lambda new: new["dom"] is None and new["ssl"] is None,
        note="A rebuilt phishing kit or changed TLS config on already-tracked "
             "infrastructure - the strongest shared_fingerprint lead.",
    ),
    "subdomains": AttributeSpec(
        attribute="subdomains", bare=True, source="subdomains", guard="subdomains",
        columns=("subdomains",), json_columns=frozenset({"subdomains"}),
        classify=_classify_subdomains,
        shape_new=lambda new, old: _added(new, old, "subdomains"),
        first_seen_confidence="low",
    ),
    "infostealer_hits": AttributeSpec(
        attribute="infostealer_hits", bare=False, source="webamon_infostealers",
        guard="infostealer_count", columns=("infostealer_count",),
        classify=lambda old, new: ("infostealer_hits"
                                   if (new["count"] or 0) > (old["count"] or 0) else None),
        normalize_new=lambda v: {"count": v["count"], "urls": v.get("urls") or []},
        shape_old=lambda old: {"count": old["count"]},
        shape_new=lambda new, old: {"count": new["count"],
                                    "sample_urls": new["urls"][:10]},
        baseline_default={"count": 0},
        fixed_confidence="medium",
        note="The one spec with no first_seen baseline: every hit is "
             "notable, so the first sighting of a non-zero count is itself "
             "recorded. Only growth counts - a shrinking footprint is not a "
             "signal. Webamon caps the page at 25, so treat a flat 25 as "
             "'at least 25'.",
    ),
}


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #

_BASELINE_SQL = ("SELECT observed_at, {cols} FROM observations_wide "
                 "WHERE indicator_value = ? AND source IN ({marks}) {guard} "
                 "AND observed_at < ? ORDER BY observed_at DESC LIMIT 1")

# observations_wide column -> the key the specs and old code use.
_KEY_ALIASES = {
    "nmap_ports": "ports", "ptr_hostname": "hostname",
    "tls_issuer": "issuer", "tls_sans": "sans", "tls_sha256": "sha256",
    "http_title": "title", "http_server": "server",
    "webamon_fingerprint_dom": "dom", "webamon_fingerprint_ssl": "ssl",
    "infostealer_count": "count",
}


def baseline(con: duckdb.DuckDBPyConnection, spec: AttributeSpec,
             indicator_value: str, before) -> dict[str, Any] | None:
    """The most recent prior observation of this attribute, strictly
    before `before`. Replaces all twelve `latest_*_for` functions."""
    guard = f"AND {spec.guard} IS NOT NULL" if spec.guard else ""
    sources = (spec.source,) if isinstance(spec.source, str) else tuple(spec.source)
    sql = _BASELINE_SQL.format(cols=", ".join(spec.columns), guard=guard,
                               marks=", ".join("?" for _ in sources))
    row = con.execute(sql, [indicator_value, *sources, before]).fetchone()
    if row is None:
        return None
    out: dict[str, Any] = {"observed_at": row[0]}
    for col, value in zip(spec.columns, row[1:]):
        if col in spec.json_columns:
            value = json.loads(value) if value else []
        out[_KEY_ALIASES.get(col, col)] = value
    return out


def record_attribute_change(con: duckdb.DuckDBPyConnection, *, detected_at,
                            indicator_value: str, actor: str | None,
                            attribute: str, change_type: str,
                            old_value: Any, new_value: Any,
                            confidence: str) -> None:
    con.execute(
        """INSERT INTO attribute_changes
             (detected_at, indicator_value, actor, attribute, change_type,
              old_value, new_value, confidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (indicator_value, attribute, detected_at) DO NOTHING""",
        [detected_at, indicator_value, actor, attribute, change_type,
         _as_json(old_value), _as_json(new_value), confidence])


def _as_json(value: Any) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value)


def detect(con: duckdb.DuckDBPyConnection, attribute: str, *,
           indicator_value: str, actor: str | None, observed_at,
           new: Any) -> str | None:
    """Diff `new` against the stored baseline and record any change.

    Returns the change_type written, or None when nothing was recorded -
    which is the common case, and deliberately so: the digest would be
    unreadable if every unchanged re-check produced a row.

    This is the single driver that replaces the ten `_record_*_change`
    functions. Each of them was this function with one spec inlined.
    """
    spec = SPECS[attribute]
    normalized = spec.normalize_new(new)
    if normalized is SKIP:
        return None  # nothing worth recording (e.g. a cert with no sha256)

    row = baseline(con, spec, indicator_value, observed_at)

    if row is None and spec.baseline_default is _NO_BASELINE:
        if spec.first_seen_empty(normalized):
            return None
        _emit(con, spec, detected_at=observed_at, indicator_value=indicator_value,
              actor=actor, change_type="first_seen",
              confidence=spec.first_seen_confidence,
              old_value=None, new_value=spec.shape_new(normalized, None))
        return "first_seen"

    old = row if row is not None else dict(spec.baseline_default)
    old_cmp = _comparable(spec, old)
    new_cmp = normalized
    change_type = spec.classify(old_cmp, new_cmp)
    if change_type is None:
        return None

    conf = spec.fixed_confidence or confidence(
        change_type, row["observed_at"] if row else None)
    _emit(con, spec, detected_at=observed_at, indicator_value=indicator_value,
          actor=actor, change_type=change_type, confidence=conf,
          old_value=spec.shape_old(old_cmp),
          new_value=spec.shape_new(new_cmp, old_cmp))
    return change_type


def _comparable(spec: AttributeSpec, row: dict[str, Any]) -> Any:
    """The baseline reduced to what `classify` compares.

    `bare` is an explicit spec field rather than something inferred from
    len(columns): cert_hash has one column but its classify reads
    old["sha256"], so inferring "one column means a bare value" silently
    handed it a string and raised TypeError on the first cert rotation.
    """
    keys = [_KEY_ALIASES.get(c, c) for c in spec.columns]
    if spec.bare:
        return row[keys[0]]
    return {k: row.get(k) for k in keys}


def _emit(con, spec: AttributeSpec, **kw) -> None:
    if spec.json_encode:
        kw["old_value"] = json.dumps(kw["old_value"])
        kw["new_value"] = json.dumps(kw["new_value"])
    record_attribute_change(con, attribute=spec.attribute, **kw)
