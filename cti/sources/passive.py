"""Two free, keyless, passive sources: Shodan InternetDB and mnemonic PDNS.

## Why these two, and why "passive" is the whole point

Neither sends a packet to the indicator. That is the distinction that
earns them a place beside naabu and nmap, which do, and which are
therefore opt-in and on request only.

**InternetDB** (`internetdb.shodan.io`) is Shodan. Not a second opinion on
Shodan - the same scan database, served as a free keyless subset: ports,
CPEs, hostnames, tags, vulns. This repo retired Shodan InternetDB once
already, on a rule that still holds - `docs/architecture.md`: "the design
favors live interaction over scan platforms... a scan platform's record of
a host can be weeks old."

It is back for the half of that rule which does not hold. Staleness is a
reason not to trust it for LIVENESS. It is not a reason to refuse
COVERAGE: after the retirement there was no passive port source at all,
and `changes.py` still says so ("Ports come from on-demand nmap now that
Shodan InternetDB is gone"). A port set nobody had to scan for is worth
having, as long as nothing mistakes it for one we confirmed - which is why
it gets its own source name, its own selector type, and a class that
cannot promote anything.

**mnemonic PDNS** (`api.mnemonic.no/pdns/v3`) answers what a name resolved
to BEFORE, and which names resolved to an address, with first- and
last-seen timestamps on every record. Nothing else here can do that:
dnsx answers what resolves now, Webamon's index carries no resolution
history, and Validin can but costs one of fifty lookups a month.

## The trap this module is built around

A historical resolution is not a current one. Two domains that pointed at
one address four years apart share nothing; the same two pointing at it in
the same week are a lead. `net.resolved_ip` means the present tense, so
nothing here is allowed to write it - historical answers get
`net.historical_ip`, which is behavioural and corroborates only.
"""
from __future__ import annotations

import urllib.parse
from typing import Any

from . import budget, http

INTERNETDB_URL = "https://internetdb.shodan.io"
MNEMONIC_URL = "https://api.mnemonic.no/pdns/v3"
HTTP_TIMEOUT = 20


def _get(provider: str, url: str) -> Any:
    try:
        budget.spend(provider, 1)
    except budget.BudgetExhausted as e:
        return {"error": str(e)}
    budget.pace(provider)
    try:
        return http.get_json(url, via="direct", timeout=HTTP_TIMEOUT)
    except http.HttpError as e:
        # 404 is the documented "nothing indexed for this address" answer,
        # which is a result, not a failure - reporting it as an error would
        # make an unknown host indistinguishable from an unreachable API.
        if e.status == 404:
            return {"not_found": True}
        if e.status == 429:
            return {"error": f"{provider} rate limited"}
        if e.status is not None:
            return {"error": f"{provider} HTTP {e.status}"}
        return {"error": f"failed to reach {provider}: {e}"}


# --------------------------------------------------------------------------- #
# Shodan InternetDB
# --------------------------------------------------------------------------- #

def internetdb(ip: str) -> dict[str, Any]:
    """Shodan's free keyless view of one address.

    Returns {"ports", "cpes", "hostnames", "tags", "vulns", "passive": True}
    or {"error": ...}. `passive` is on every result because the caller must
    not be able to forget it: these ports were observed by somebody else at
    an unknown time, and treating them as current is the one way to misuse
    this source.
    """
    value = str(ip).strip()
    if not value:
        return {"error": "no address given"}
    resp = _get("internetdb", f"{INTERNETDB_URL}/{urllib.parse.quote(value, safe='')}")
    if isinstance(resp, dict) and "error" in resp:
        return resp
    if isinstance(resp, dict) and resp.get("not_found"):
        return {"ip": value, "passive": True, "indexed": False,
                "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}
    if not isinstance(resp, dict):
        return {"error": "internetdb returned a non-object response"}
    return {
        "ip": resp.get("ip") or value,
        "passive": True, "indexed": True,
        "ports": sorted({int(p) for p in (resp.get("ports") or [])
                         if str(p).isdigit()}),
        "cpes": list(resp.get("cpes") or []),
        "hostnames": list(resp.get("hostnames") or []),
        "tags": list(resp.get("tags") or []),
        "vulns": list(resp.get("vulns") or []),
    }


# --------------------------------------------------------------------------- #
# mnemonic passive DNS
# --------------------------------------------------------------------------- #

# Record types worth keeping. mnemonic returns plenty more; these are the
# ones an infrastructure question is ever asked about.
PDNS_TYPES = ("a", "aaaa", "cname", "ns", "mx")


def pdns(value: str, *, limit: int = 100) -> dict[str, Any]:
    """Resolution history for a domain, or reverse history for an address.

    One endpoint serves both directions: given a name it returns what that
    name resolved to, given an address it returns the names that resolved
    to it. Returns {"query", "records": [...], "total", "truncated"}.

    Every record carries `first_seen` and `last_seen` as epoch seconds,
    because that is what makes the answer usable: whether two indicators
    pointed at one address AT THE SAME TIME is the question, and a source
    that only said "at some point" would not be able to answer it.
    """
    query = str(value).strip()
    if not query:
        return {"error": "no query given"}
    url = (f"{MNEMONIC_URL}/{urllib.parse.quote(query, safe='')}"
           f"?limit={int(limit)}")
    resp = _get("mnemonic", url)
    if isinstance(resp, dict) and "error" in resp:
        return resp
    if not isinstance(resp, dict):
        return {"error": "mnemonic returned a non-object response"}
    if resp.get("not_found"):
        return {"query": query, "passive": True, "records": [], "total": 0,
                "truncated": False}

    rows = [r for r in (resp.get("data") or []) if isinstance(r, dict)]
    records = []
    for r in rows:
        rrtype = str(r.get("rrtype") or "").lower()
        if rrtype not in PDNS_TYPES:
            continue
        answer = r.get("answer")
        if not isinstance(answer, str) or not answer.strip():
            continue
        records.append({
            "query": r.get("query"), "answer": answer.strip(),
            "rrtype": rrtype,
            # Milliseconds on the wire; seconds everywhere in this repo.
            "first_seen": _seconds(r.get("firstSeenTimestamp")),
            "last_seen": _seconds(r.get("lastSeenTimestamp")),
            "times": r.get("times"),
        })
    return {"query": query, "passive": True, "records": records,
            "total": resp.get("count"), "truncated": len(rows) >= limit}


def _seconds(value: Any) -> int | None:
    """mnemonic timestamps are epoch milliseconds."""
    try:
        return int(value) // 1000
    except (TypeError, ValueError):
        return None


def overlapping(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two passive-DNS records were live at the same time.

    The question a shared historical address actually poses. Two domains on
    one address four years apart share nothing; the same two in one week
    are a lead, and only the timestamps can tell them apart. Unknown
    timestamps return False - an unanswerable question is not a yes.
    """
    a_first, a_last = a.get("first_seen"), a.get("last_seen")
    b_first, b_last = b.get("first_seen"), b.get("last_seen")
    if None in (a_first, a_last, b_first, b_last):
        return False
    return a_first <= b_last and b_first <= a_last


def status() -> dict[str, Any]:
    """Neither source needs a key, so this only reports the courtesy caps."""
    return {"internetdb": {"used_today": budget.used_today("internetdb"),
                           "cap": budget.cap("internetdb")},
            "mnemonic": {"used_today": budget.used_today("mnemonic"),
                         "cap": budget.cap("mnemonic")}}
