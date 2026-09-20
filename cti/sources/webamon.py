"""Webamon threat-intelligence client - the passive-enrichment layer that
replaces the retired scan platforms (Shodan InternetDB, VirusTotal,
Hackertarget, Cert Spotter). Webamon continuously scans and indexes the
web; we query that index for a domain's latest scan (certificate, DNS,
ASN, tech stack, kit fingerprints), an IP's hosted domains (the reverse-IP
/ passive-hostname replacement), and infostealer-log hits, and can submit
a fresh scan when the index has nothing recent.

Unlike pivot.py's sources, these calls are made **directly from this host**
rather than through the probe VM: they hit Webamon's SaaS, not the tracked
indicator's own infrastructure, so there's no adversary-facing traffic to
keep off the analyst's host - the same deliberate exception already made
for the HoneyLabs MCP server.

Every function returns a plain dict, or `{"error": "..."}` on failure -
never raises into the enrichment sweep - so `_cached_pivot` and the
snapshot/history consumers can gate on `"error" not in result` exactly as
they do for the pivot sources.

Auth: header `x-api-key: <WEBAMON_API_KEY>`. Base `https://pro.webamon.com`.
A soft daily budget (CTI_WEBAMON_DAILY_BUDGET, default 1000) is tracked in
a small JSON counter next to the pivot cache and checked before each call,
so a runaway sweep can't blow the plan's quota. The counter is a file (not
the DuckDB store) on purpose: this is called from core._sweep_lifecycle's
6-thread pool, and a per-call DuckDB read-write connection would contend on
DuckDB's single-writer-per-process file lock. A file counter with an
in-process lock is racy across the cron and MCP-server processes, but the
budget is only a soft guard, so a small over/undercount is acceptable.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from datetime import date
from typing import Any

from . import budget, http

BASE_URL = os.environ.get("CTI_WEBAMON_BASE", "https://pro.webamon.com")
USER_AGENT = "cti-agent"
WEBAMON_API_KEY_ENV = "WEBAMON_API_KEY"
HTTP_TIMEOUT = 30

_DAILY_BUDGET_ENV = "CTI_WEBAMON_DAILY_BUDGET"
_DAILY_BUDGET_DEFAULT = 1000
_RESCAN_DAYS_ENV = "CTI_WEBAMON_RESCAN_DAYS"
_RESCAN_DAYS_DEFAULT = 7

# Curated field list for scan-index queries: everything useful for
# enrichment, deliberately excluding `dom` (full page HTML) and
# `page_scripts` (both large and never stored).
_SCAN_FIELDS = ("report_id,date,scan_status,resolved_url,resolved_domain,"
                "page_title,meta,certificate,domain,server,technology,fingerprint,tag")

# Mirror core.DATA_DIR without importing core (core imports this module).
def _api_key() -> str | None:
    return os.environ.get(WEBAMON_API_KEY_ENV)


def rescan_days() -> int:
    try:
        return int(os.environ.get(_RESCAN_DAYS_ENV, _RESCAN_DAYS_DEFAULT))
    except ValueError:
        return _RESCAN_DAYS_DEFAULT


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
# The daily counter that used to live here - its own JSON file, its own
# read-modify-write, its own inline atomic write - is now
# sources/budget.py, shared with RDAP and HoneyLabs and safe under the
# parallel fan-out. The urllib transport is now sources/http.py.
#
# Webamon is one of the two documented via="direct" exceptions: it queries
# the vendor's own scan index, not the indicator's own infrastructure, so
# routing it through the probe VM would spend that host's egress allowance
# for no OPSEC benefit.

def quota_used_today() -> int:
    return budget.used_today("webamon")


def _daily_budget() -> int:
    return budget.cap("webamon")


def _get(path: str, params: dict[str, Any]) -> Any:
    key = _api_key()
    if not key:
        return {"error": f"no {WEBAMON_API_KEY_ENV} configured"}
    try:
        budget.spend("webamon", 1)
    except budget.BudgetExhausted:
        return {"error": "webamon daily budget exhausted"}

    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{BASE_URL.rstrip('/')}/{path.lstrip('/')}?{query}"
    try:
        return http.get_json(url, via="direct", headers={"x-api-key": key},
                             timeout=HTTP_TIMEOUT)
    except http.HttpError as e:
        # These three are worth naming rather than collapsing into one
        # error: they are the difference between "fix your key", "upgrade
        # your plan" and "wait a minute".
        if e.status == 401:
            return {"error": "webamon auth failed (check WEBAMON_API_KEY)"}
        if e.status == 403:
            return {"error": "webamon forbidden (plan/quota)"}
        if e.status == 429:
            return {"error": "webamon rate limited"}
        if e.status is not None:
            return {"error": f"webamon HTTP {e.status}"}
        return {"error": f"failed to reach webamon: {e}"}




def _search(params: dict[str, Any]) -> Any:
    """GET /search, returning the parsed response dict or {"error": ...}."""
    result = _get("/search", params)
    if isinstance(result, dict) and "error" in result:
        return result
    if not isinstance(result, dict):
        return {"error": "webamon returned a non-object response"}
    return result


# --------------------------------------------------------------------------- #
# normalization
# --------------------------------------------------------------------------- #
def _cert(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "issuer": entry.get("issuer"),
        "subject": entry.get("subject_name"),
        "sans": entry.get("san_list") or [],
        "not_before": entry.get("valid_from_utc"),
        "not_after": entry.get("valid_to_utc"),
        "protocol": entry.get("protocol"),
    }


def normalize_scan(doc: dict[str, Any]) -> dict[str, Any]:
    """Pull the enrichment-relevant fields out of a Webamon scan document.
    Drops `dom`/`page_scripts` (large, never stored)."""
    if not isinstance(doc, dict):
        return {}
    meta = doc.get("meta") or {}
    fp = doc.get("fingerprint") or {}
    certs = [_cert(c) for c in (doc.get("certificate") or []) if isinstance(c, dict)]
    ips = []
    for d in (doc.get("domain") or []):
        if not isinstance(d, dict):
            continue
        asn = d.get("asn") or {}
        ips.append({"name": d.get("name"), "ip": d.get("ip"),
                    "server": d.get("server"),
                    "asn": asn.get("number"), "asn_name": asn.get("name"),
                    "asn_network": asn.get("network"),
                    "country": (d.get("country") or {}).get("iso")})
    return {
        "report_id": doc.get("report_id"),
        "date": doc.get("date"),
        "scan_status": doc.get("scan_status"),
        "resolved_url": doc.get("resolved_url"),
        "resolved_domain": doc.get("resolved_domain"),
        "page_title": doc.get("page_title"),
        "risk_score": meta.get("risk_score"),
        "certificates": certs,
        "ips": ips,
        "technology": doc.get("technology") or [],
        "fingerprint": {k: fp.get(k) for k in
                        ("dom", "ssl", "tech", "cookies", "asn", "scripts", "links", "domains")},
    }


# --------------------------------------------------------------------------- #
# public lookups
# --------------------------------------------------------------------------- #
def search_domain(domain: str, size: int = 5) -> dict[str, Any]:
    """Latest Webamon scan(s) for a domain (scans index). Returns
    {"total_hits", "results": [normalized...], "latest": normalized|None}."""
    resp = _search({"lucene_query": f'domain.name:"{domain}"', "index": "scans",
                    "fields": _SCAN_FIELDS, "size": size})
    if "error" in resp:
        return resp
    results = [normalize_scan(r) for r in (resp.get("results") or [])]
    # A scan matches `domain.name:"X"` whenever ANY domain it loaded equals X
    # - including a malicious page that merely fetched X as a resource. For
    # enrichment we want a scan actually *of* X, so prefer the newest result
    # whose submission resolved to the queried domain; fall back to the
    # newest result only when none does.
    own = [r for r in results if r.get("resolved_domain") == domain]
    latest = (own or results)[0] if results else None
    return {"total_hits": resp.get("total_hits"), "results": results, "latest": latest}


def search_ip(ip: str, size: int = 50) -> dict[str, Any]:
    """Domains Webamon has scanned resolving to this IP (server.ip on the
    scans index) - the reverse-IP / passive-hostname replacement. Returns
    {"total_hits", "domains": [...], "results": [{resolved_domain,date,page_title}]}."""
    resp = _search({"lucene_query": f'server.ip:"{ip}"', "index": "scans",
                    "fields": "resolved_domain,date,page_title", "size": size})
    if "error" in resp:
        return resp
    results = resp.get("results") or []
    domains = sorted({r.get("resolved_domain") for r in results if r.get("resolved_domain")})
    return {"total_hits": resp.get("total_hits"), "domains": domains, "results": results}


def infostealers(term: str, size: int = 25) -> dict[str, Any]:
    """Infostealer-log hits for a domain. The plaintext `password` field is
    dropped at this boundary - only the masked `password_peek` is kept.

    Both clauses are phrase-quoted, and every returned row is re-checked
    against `term` before it counts. Unquoted, `username:@example.com` gets
    analyzed into tokens and ORs into a match against most of the index: a
    deliberately nonsense domain came back with 572k "hits" on aarp.org /
    canva.com / netflix.com, so every tracked domain looked compromised.
    Re-checking client-side keeps that from depending on how the index
    happens to analyze a field.

    `total_hits` is how many rows actually matched `term`; `raw_total_hits`
    is what the index claimed for the query, and `capped` means the page
    came back full, so the real total may be higher than what was counted.
    """
    quoted = f'"{term}"'
    resp = _search({"lucene_query": f'domain:{quoted} OR username:"@{term}"',
                    "index": "infostealers", "size": size})
    if "error" in resp:
        return resp
    raw = [r for r in (resp.get("results") or []) if isinstance(r, dict)]
    needle = term.lower()
    out = []
    for r in raw:
        domain = (r.get("domain") or "").lower()
        username = (r.get("username") or "").lower()
        if not (domain == needle or domain.endswith("." + needle)
                or f"@{needle}" in username):
            continue
        out.append({k: r.get(k) for k in
                    ("domain", "url", "username", "password_peek", "source",
                     "file_name", "file_sha256", "ingest_date")})
    return {"total_hits": len(out), "raw_total_hits": resp.get("total_hits"),
            "capped": len(raw) >= size, "results": out}


def fingerprint_siblings(fp_hash: str, kind: str = "dom", size: int = 25) -> dict[str, Any]:
    """Other scanned domains sharing a Webamon kit fingerprint
    (fingerprint.dom / fingerprint.ssl) - the campaign-cluster signal that
    stands in for the plan-gated /clusters endpoint. Returns
    {"total_hits", "domains": [...]}."""
    resp = _search({"lucene_query": f'fingerprint.{kind}:"{fp_hash}"', "index": "scans",
                    "fields": "resolved_domain,date", "size": size})
    if "error" in resp:
        return resp
    domains = sorted({r.get("resolved_domain") for r in (resp.get("results") or [])
                      if r.get("resolved_domain")})
    return {"total_hits": resp.get("total_hits"), "domains": domains}


# --------------------------------------------------------------------------- #
# Reverse lookup: from a selector value to the indicators that share it
# --------------------------------------------------------------------------- #

# selector type -> (queried field, path within the root domain entry or None)
#
# One map instead of a wrapper per field. The alternative - search_by_title,
# search_by_subject, search_by_san, twenty more - is the duplication this
# rewrite exists to remove: each would be the same three lines with a
# different f-string, and the interesting part (which field, and what a match
# is worth) belongs in a table beside the taxonomy that classes it.
#
# The second element is the scope, and getting it wrong is the difference
# between a lead and noise. A scan document holds every certificate, resource
# and address the page touched, so `certificate.san_list:"www.example.com"`
# matches a site that merely loaded an image from a host with that
# certificate. When the path is set, the value is re-checked inside the
# `domain[]` entry marked `root` - the scanned host itself. Verified on the
# live index: that check rejects kiratlimimarlik.com, whose own certificate
# names only itself, and keeps formthirtythree.com, which really is served
# under example.com's certificate.
#
# None means the field is scan-wide and the distinction does not arise:
# page_title, the fingerprints and lexical features describe the scan.
#
# Absences are deliberate:
#   tls.cert_sha256   Webamon publishes no leaf-certificate SHA-256. Their
#                     fingerprint.ssl is their own digest - webamon.fp_ssl.
#   whois.*           domain.whois.registrar matches zero documents; the
#                     index carries no registration data, so `whois` on the
#                     probe VM is the only source for those selectors.
#   net.port_set      not in the index. That is naabu and nmap.
#   dns.*             no resolver records; dnsx is the source.
REVERSE_FIELDS: dict[str, tuple[str, str | None]] = {
    # --- our own selectors, as Webamon stores the same fact ---------------
    # domain.resource.sha256 is the raw body digest, verified byte-for-byte:
    # example.com's body hashes to ff67a9d7... and so does this field. It is
    # therefore comparable with httpx's -hash sha256, which fingerprint.dom
    # is not.
    "http.body_sha256":   ("domain.resource.sha256", "resource.sha256"),
    # Scan-wide on purpose: the question a staged payload asks is "who else
    # served this file", and a sub-resource is exactly where it would be.
    "file.sha256":        ("domain.resource.sha256", None),
    "tls.subject_cn":     ("certificate.subject_name", "certificate.subject_name"),
    "tls.san":            ("certificate.san_list", "certificate.san_list"),
    "tls.issuer":         ("certificate.issuer", "certificate.issuer"),
    "net.resolved_ip":    ("server.ip", "ip"),
    "http.server":        ("domain.server", "server"),
    "net.asn":            ("domain.asn.number", "asn.number"),
    "http.title":         ("page_title", None),
    "http.tech":          ("technology.name", None),
    # --- Webamon's own digests, scan-wide by nature ------------------------
    "webamon.fp_dom":            ("fingerprint.dom", None),
    "webamon.fp_dom_structure":  ("fingerprint.dom_structure", None),
    "webamon.fp_ssl":            ("fingerprint.ssl", None),
    "webamon.fp_cert_san":       ("fingerprint.cert_san", None),
    "webamon.fp_cert_config":    ("fingerprint.cert_config", None),
    "webamon.fp_cert_issuer":    ("fingerprint.cert_issuer", None),
    "webamon.fp_header_order":   ("fingerprint.header_order", None),
    "webamon.fp_cookie_names":   ("fingerprint.cookie_names", None),
    "webamon.fp_domains":        ("fingerprint.domains", None),
    "webamon.fp_ns_set":         ("fingerprint.ns_set", None),
    "webamon.fp_mx_set":         ("fingerprint.mx_set", None),
    "webamon.fp_links":          ("fingerprint.links", None),
    "webamon.fp_scripts":        ("fingerprint.scripts", None),
    "webamon.fp_cookies":        ("fingerprint.cookies", None),
    "webamon.fp_tech":           ("fingerprint.tech", None),
    "webamon.fp_asn":            ("fingerprint.asn", None),
    "brand.impersonated":        ("lexical.brand_match", None),
}

# Fields whose matching is token-based rather than exact. A quoted phrase is
# not enough on these: the analyzer splits the value and matches the pieces,
# so total_hits counts documents that do not carry it. The re-check below is
# what makes a result trustworthy; this set only says whether total_hits is
# a count or an upper bound. The digest and address fields were confirmed
# exact against the live index.
_ANALYZED = frozenset({
    "certificate.subject_name", "certificate.san_list", "certificate.issuer",
    "page_title", "domain.server", "technology.name", "lexical.brand_match",
})


def reversible(selector_type: str) -> bool:
    """Whether Webamon can answer "who else has this?" for this selector."""
    return selector_type in REVERSE_FIELDS


# Lucene's reserved characters. Quoting a phrase is not enough on its own:
# the API answers HTTP 400 for `certificate.san_list:"*.sharepoint.com"`,
# because the parser still sees the wildcard inside the quotes. Every
# wildcard SAN in this repo's own data - and most certificates carry one -
# failed to price until these were escaped.
_LUCENE_RESERVED = '+-&|!(){}[]^"~*?:\\/'


def _lucene_literal(value: Any) -> str:
    """A phrase-quoted Lucene term with reserved characters escaped.

    Quoting is not cosmetic: `infostealers` documents what an unquoted value
    does, where a nonsense domain came back with 572k hits. Escaping is not
    either - a value must not be able to end the phrase early and add a
    clause of its own, and a wildcard must be matched rather than expanded.
    """
    text = "".join("\\" + c if c in _LUCENE_RESERVED else c for c in str(value))
    return f'"{text}"'


def _field_values(doc: Any, path: str) -> list[str]:
    """Every leaf value at a dotted path, descending through lists.

    A scan document nests: `domain` is a list, each entry has its own
    `certificate` (sometimes a list, sometimes one object), each of those a
    `san_list`. A match can come from any of them, so the whole subtree has
    to be collected before a value can be confirmed or rejected.
    """
    nodes: list[Any] = [doc]
    for part in path.split("."):
        nxt: list[Any] = []
        for node in nodes:
            for n in (node if isinstance(node, list) else [node]):
                if isinstance(n, dict) and part in n:
                    nxt.append(n[part])
        nodes = nxt
    out: list[str] = []
    stack = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            stack.extend(node.values())
        elif node is not None and not isinstance(node, bool):
            out.append(str(node))
    return out


def _root_entry(doc: dict[str, Any]) -> dict[str, Any] | None:
    """The `domain[]` entry for the host that was scanned.

    `root: True` marks it. Falling back to a name match on resolved_domain
    covers documents where the flag is absent; returning None when neither
    identifies an entry is deliberate, because a root-scoped check that
    cannot find the root must reject rather than pass.
    """
    entries = [d for d in (doc.get("domain") or []) if isinstance(d, dict)]
    for entry in entries:
        if entry.get("root") is True:
            return entry
    resolved = (doc.get("resolved_domain") or "").lower().rstrip(".")
    for entry in entries:
        if (entry.get("name") or "").lower().rstrip(".") == resolved and resolved:
            return entry
    return None


def _carries(doc: dict[str, Any], field: str, root_path: str | None,
             needle: str) -> bool:
    if root_path is None:
        values = _field_values(doc, field)
    else:
        root = _root_entry(doc)
        if root is None:
            return False
        values = _field_values(root, root_path)
    return needle in {v.lower().rstrip(".") for v in values}


def reverse_selector(selector_type: str, selector_value: Any, *,
                     size: int = 25) -> dict[str, Any]:
    """Indicators Webamon has scanned that carry this selector value.

    Returns {"field", "total_hits", "indicators", "sampled", "rejected",
    "exact", "capped"} or {"error": ...}.

    Two corrections are applied to what the API returns, and both were needed
    to make it usable.

    `total_hits` counts SCANS, not indicators. example.com's DOM digest
    returns 4388 hits and one indicator, because the index has scanned that
    page 4388 times, so `indicators` is counted from the page instead. A
    caller seeing capped=True with one indicator is looking at a heavily
    rescanned single site, not a widely shared value.

    Every result is then re-checked, scoped per REVERSE_FIELDS, and
    `rejected` counts the ones that did not really carry the value.
    """
    mapped = REVERSE_FIELDS.get(selector_type)
    if not mapped:
        return {"error": f"{selector_type} has no reverse field on webamon"}
    field, root_path = mapped
    value = str(selector_value).strip()
    if not value:
        return {"error": "empty selector value"}

    # A root-scoped check needs the whole domain[] array to find the root
    # entry; a scan-wide one needs only the field it queried.
    projection = "resolved_domain,date," + ("domain" if root_path else field)
    resp = _search({"lucene_query": f"{field}:{_lucene_literal(value)}",
                    "index": "scans", "fields": projection, "size": size})
    if "error" in resp:
        return resp

    results = [r for r in (resp.get("results") or []) if isinstance(r, dict)]
    needle = value.lower().rstrip(".")
    confirmed = [r for r in results if _carries(r, field, root_path, needle)]
    indicators = sorted({r.get("resolved_domain") for r in confirmed
                         if r.get("resolved_domain")})
    return {"field": field, "total_hits": resp.get("total_hits"),
            "indicators": indicators, "sampled": len(results),
            "rejected": len(results) - len(confirmed),
            "exact": field not in _ANALYZED, "capped": len(results) >= size}


def global_count(selector_type: str, selector_value: Any) -> dict[str, Any]:
    """How common this selector value is across Webamon's whole index.

    This is the `global_count` the rarity table was built for and had no
    source: crt.sh stopped ingesting, and urlscan needs a key and caps its
    total at 10,000. Webamon answers for one budget unit on a key that is
    already configured, and the spread is the whole point - 48.8 million
    scans share example.com's cookie fingerprint and 2 share its SSL
    fingerprint. One of those is a pivot and the other is a wasted sweep.

    `size` is 1 because only the count is wanted. `exact` is False on an
    analyzed field, where the count includes documents that do not carry the
    value; that is still the safe direction for a rarity gate, since it can
    overstate how common a value is but never understate it.
    """
    mapped = REVERSE_FIELDS.get(selector_type)
    if not mapped:
        return {"error": f"{selector_type} has no reverse field on webamon"}
    field, _ = mapped
    resp = _search({"lucene_query": f"{field}:{_lucene_literal(selector_value)}",
                    "index": "scans", "fields": "resolved_domain", "size": 1})
    if "error" in resp:
        return resp
    return {"field": field, "count": resp.get("total_hits"), "source": "webamon",
            "exact": field not in _ANALYZED}



def submit_scan(submission_url: str) -> dict[str, Any]:
    """Submit a fresh Webamon scan (their infrastructure, not ours).
    Returns {"report_id": ...} or {"error": ...}."""
    resp = _get("/scan", {"submission_url": submission_url})
    if isinstance(resp, dict) and "error" in resp:
        return resp
    if isinstance(resp, dict) and resp.get("report_id"):
        return {"report_id": resp["report_id"]}
    return {"error": f"unexpected scan response: {resp!r}"[:200]}


def poll_scan(report_id: str) -> dict[str, Any] | None:
    """Fetch a submitted scan's result by polling the scans index for its
    report_id. Returns the normalized scan, or None if not indexed yet."""
    resp = _search({"lucene_query": f'report_id:"{report_id}"', "index": "scans",
                    "fields": _SCAN_FIELDS, "size": 1})
    if "error" in resp:
        return None
    results = resp.get("results") or []
    return normalize_scan(results[0]) if results else None


def status() -> dict[str, Any]:
    """Cheap connectivity/quota check for --check-access style callers."""
    if not _api_key():
        return {"ok": False, "error": f"no {WEBAMON_API_KEY_ENV} configured"}
    resp = _search({"search": "example.com", "results": "domain.name", "size": 1})
    return {"ok": "error" not in resp, "used_today": quota_used_today(),
            "budget": _daily_budget(), **({"error": resp["error"]} if "error" in resp else {})}
