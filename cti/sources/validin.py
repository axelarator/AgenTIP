"""Validin - a metered reverse-lookup index, callable only on your say-so.

## Why this module is different from every other source

Every other source here is called by the sweep. This one must not be. The
instruction that created it was explicit: a key may be configured, but the
source is never reachable from the sweep, the graph, or any automatic path,
and it is used for specific lookups on request.

That is not a comment, because a comment is not a gate. Two independent
checks enforce it and both must pass:

* an explicit `manual_invocation(reason)` scope, which nothing automatic
  enters - if a lookup is attempted outside one it raises;
* a call-stack check that refuses if any frame belongs to the graph or to
  the sweep, even inside such a scope. The scope alone would be defeated by
  someone wrapping automatic code in it, which is exactly the mistake a
  future change is most likely to make.

The second check is the one that earns its keep, and it fails closed: an
unreadable stack is treated as automatic.

## Why the budget is two numbers

The free tier meters daily AND monthly, and the monthly is the binding one:
ten a day would be three hundred a month against a ceiling of fifty. The
API reports both (`remaining.daily`, `remaining.monthly`), so `budget_state`
can reconcile our local count against the provider's - the local count is
the gate, because it works before a call is made, and the provider's is the
truth.

Every response carries what is left. A source this scarce should never make
you go and look up what it cost.

## What it is for

Validin covers the two gaps nothing else here can. Webamon's index holds no
registration data at all, and no CLI on the probe VM does passive history.
Validin does both, and it reverse-looks-up `tls.cert_sha256`, which Webamon
cannot because it publishes no leaf-certificate digest.

Not everything maps. Validin's body digest is SHA-1 and ours is SHA-256, so
`http.body_sha256` is absent from the map below rather than quietly wrong.
"""
from __future__ import annotations

import os
import sys
import threading
import urllib.parse
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Iterator

from . import budget, http

BASE_URL = os.environ.get("CTI_VALIDIN_BASE", "https://app.validin.com")
API_KEY_ENV = "CTI_VALIDIN_API_KEY"
HTTP_TIMEOUT = 30
PROVIDER = "validin"

# This source is manual-only. Nothing in this repo may import it into an
# automatic path; the checks below are what make that true rather than
# aspirational.
MANUAL_ONLY = True


class ManualOnly(RuntimeError):
    """A Validin lookup was attempted from somewhere it is not allowed.

    Deliberately NOT a return value. Every other failure here becomes
    {"error": ...} so a sweep degrades instead of crashing - but this one
    means an automatic path reached a source that must never be automatic,
    and turning it into a skippable note is how that gets missed.
    """


# Any frame whose file lives under one of these is automatic by definition.
# The repo root, resolved at import, because the package layout is not what
# a reading of the imports suggests: the graph is a TOP-LEVEL `graph`
# package, not `cti.graph`, so a guard written as "/cti/graph/" matched
# nothing and the graph could have called straight through it.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_AUTOMATIC_DIRS = tuple(str(_REPO_ROOT / name) + os.sep
                        for name in ("graph", "dashboard"))

# cti/mcp/ is deliberately NOT here. An MCP tool runs because somebody asked
# for it by name, which is the condition this source is allowed under - it
# is the manual path, not an automatic one. The dashboard is blocked because
# a page load is not a request for a metered lookup.

# Function names that ARE the automatic pipeline. Split in two because the
# test has to differ: a function called `_sweep_lifecycle` anywhere is ours,
# while `collect` or `run` is a name any library might use, so the generic
# ones only count inside this repo.
# Checked against cti/core.py by a test, because a list that has drifted
# from the code guards nothing: the first version of this named four
# functions that do not exist.
_AUTOMATIC_FUNCTIONS = frozenset({
    "_sweep_lifecycle", "_domain_lifecycle", "_ip_lifecycle",
    "pivot_cluster", "pivot_and_expand", "pivot_observable",
})
_AUTOMATIC_FUNCTIONS_IN_REPO = frozenset({"collect", "observe", "_observe",
                                          "rank", "analyze", "enrich"})

_scope = threading.local()


@contextmanager
def manual_invocation(reason: str) -> Iterator[None]:
    """Mark the calling scope as a deliberate, human-requested lookup.

    `reason` is required and is not decoration: this source is capped at
    fifty calls a month, so a call with no stated purpose is a call that
    should not have been made. It appears in the response.
    """
    if not (reason or "").strip():
        raise ManualOnly("a manual Validin lookup needs a stated reason")
    previous = getattr(_scope, "reason", None)
    _scope.reason = reason.strip()
    try:
        yield
    finally:
        _scope.reason = previous


def _automatic_caller() -> str | None:
    """The name of the automatic frame in the current stack, if any.

    Fails closed: if the stack cannot be walked, the caller is treated as
    automatic. An unreadable stack is not evidence of innocence.
    """
    try:
        frame = sys._getframe(1)
    except Exception:
        return "unreadable stack"
    repo = str(_REPO_ROOT) + os.sep
    try:
        while frame is not None:
            code = frame.f_code
            filename = os.path.abspath(code.co_filename)
            if filename.startswith(_AUTOMATIC_DIRS):
                return f"{os.path.relpath(filename, _REPO_ROOT)}:{code.co_name}"
            if code.co_name in _AUTOMATIC_FUNCTIONS:
                return f"{filename}:{code.co_name}"
            if (code.co_name in _AUTOMATIC_FUNCTIONS_IN_REPO
                    and filename.startswith(repo)):
                return f"{os.path.relpath(filename, _REPO_ROOT)}:{code.co_name}"
            frame = frame.f_back
    except Exception:
        return "unreadable stack"
    return None


def _require_manual() -> str:
    """Both gates. Returns the stated reason."""
    automatic = _automatic_caller()
    if automatic:
        raise ManualOnly(
            f"validin is manual-only and was called from {automatic}. "
            "It is capped at 50 lookups a month and must never be reached "
            "from the sweep or the graph.")
    reason = getattr(_scope, "reason", None)
    if not reason:
        raise ManualOnly(
            "validin is manual-only: wrap the lookup in "
            'validin.manual_invocation("why you are spending a lookup")')
    return reason


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #

def budget_state(remote: dict[str, Any] | None = None) -> dict[str, Any]:
    """What is left, locally and - when a response says so - remotely.

    The local count is the gate: it is knowable before a call is made, which
    is the only moment a gate can act. The provider's count is the truth,
    and `drift` records where the two disagree so a miscount is visible
    rather than inferred from a sudden run of refusals.
    """
    state = {
        "daily_remaining": max(0, budget.cap(PROVIDER) - budget.used_today(PROVIDER)),
        "daily_cap": budget.cap(PROVIDER),
        "monthly_remaining": budget.remaining_monthly(PROVIDER),
        "monthly_cap": budget.monthly_cap(PROVIDER),
        "spendable_now": budget.remaining(PROVIDER),
    }
    if isinstance(remote, dict):
        state["provider_reported"] = {
            "daily": remote.get("daily"), "monthly": remote.get("monthly")}
        drift = {}
        for period in ("daily", "monthly"):
            theirs, ours = remote.get(period), state[f"{period}_remaining"]
            if isinstance(theirs, int) and isinstance(ours, int) and theirs != ours:
                drift[period] = {"ours": ours, "theirs": theirs}
        if drift:
            state["drift"] = drift
    return state


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #

def _api_key() -> str | None:
    return os.environ.get(API_KEY_ENV)


def _get(path: str, params: dict[str, Any] | None = None, *,
         metered: bool = True) -> Any:
    """One API call. `metered=False` is only for endpoints that cost nothing.

    Verified against the live API: /api/ping, /api/paths and
    /api/profile/usage leave the usage counters unchanged, so spending
    budget on them would make the gate stricter than the provider is.
    """
    key = _api_key()
    if not key:
        return {"error": f"no {API_KEY_ENV} configured"}
    if metered:
        try:
            budget.spend(PROVIDER, 1)
        except budget.BudgetExhausted as e:
            return {"error": str(e), "budget": budget_state()}

    url = f"{BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    if params:
        query = urllib.parse.urlencode(
            {k: v for k, v in params.items() if v is not None})
        url = f"{url}?{query}"
    try:
        return http.get_json(url, via="direct",
                             headers={"Authorization": f"Bearer {key}"},
                             timeout=HTTP_TIMEOUT)
    except http.HttpError as e:
        if e.status == 401:
            return {"error": f"validin auth failed (check {API_KEY_ENV})"}
        if e.status == 403:
            return {"error": "validin forbidden - this key's tier does not "
                             "include that endpoint"}
        if e.status == 429:
            return {"error": "validin rate limited"}
        if e.status is not None:
            return {"error": f"validin HTTP {e.status}"}
        return {"error": f"failed to reach validin: {e}"}


def _segment(value: Any) -> str:
    """A path segment. Escaped, because these values come from certificates
    and page titles and can contain anything at all."""
    return urllib.parse.quote(str(value), safe="")


# --------------------------------------------------------------------------- #
# Unmetered: is the key alive, and what is left
# --------------------------------------------------------------------------- #

def status() -> dict[str, Any]:
    """Key, quota and drift. Costs nothing, so it is not gated as manual.

    A read-only check that spends no budget cannot be the automation risk
    this module exists to prevent, and refusing it from the sweep would
    only mean the sweep cannot report its own quota.
    """
    if not _api_key():
        return {"ok": False, "error": f"no {API_KEY_ENV} configured",
                "budget": budget_state()}
    resp = _get("/api/profile/usage", metered=False)
    if isinstance(resp, dict) and "error" in resp:
        return {"ok": False, **resp, "budget": budget_state()}
    remote = (resp or {}).get("remaining") if isinstance(resp, dict) else None
    return {"ok": True, "budget": budget_state(remote),
            "usage": (resp or {}).get("usage")}


def sync() -> dict[str, Any]:
    """Adopt the provider's monthly count. Costs nothing, so not gated.

    Run this before relying on the budget. The local counter starts at zero
    and the account does not: this key had already spent 5 of its 50
    monthly lookups through the web UI, so without reconciling, the local
    gate would have authorised 50 more and met a 429 on the 46th.
    """
    if not _api_key():
        return {"ok": False, "error": f"no {API_KEY_ENV} configured"}
    resp = _get("/api/profile/usage", metered=False)
    if isinstance(resp, dict) and "error" in resp:
        return {"ok": False, **resp}
    remote = (resp or {}).get("remaining") or {}
    monthly_left = remote.get("monthly")
    month_cap = budget.monthly_cap(PROVIDER)
    if not isinstance(monthly_left, int) or month_cap is None:
        return {"ok": False, "error": "validin reported no monthly remaining",
                "budget": budget_state(remote)}
    adjustment = budget.reconcile(PROVIDER, month_cap - monthly_left)
    return {"ok": True, "adjustment": adjustment, "budget": budget_state(remote)}


# --------------------------------------------------------------------------- #
# The reverse map: our selector types, on Validin's pivot categories
# --------------------------------------------------------------------------- #

# selector type -> (endpoint kind, category). Taken from the live
# /api/paths response for this key, not from documentation.
#
# "hash"   -> /api/axon/hash/pivots/{value}/{category}
# "string" -> /api/axon/string/pivots2/{category}?string=...
# "reg"    -> /api/axon/string/registration/history2/{field}?string=...
#
# The two that matter most are the ones nothing else here can do:
# tls.cert_sha256, which Webamon cannot reverse because it publishes no leaf
# digest, and the whois.* fields, which Webamon's index does not carry at
# all.
#
# http.body_sha256 is deliberately absent. Validin's body digest is
# BODY_SHA1 - a different algorithm over the same bytes - so our value could
# never match it, and mapping the two would invent a lookup that silently
# returns nothing forever.
REVERSE_FIELDS: dict[str, tuple[str, str]] = {
    "tls.cert_sha256":         ("hash", "CERT_FINGERPRINT_SHA256"),
    "http.favicon_mmh3":       ("hash", "FAVICON_HASH"),
    "tls.subject_cn":          ("string", "CERT_CN"),
    "tls.san":                 ("string", "CERT_SUBJECTALTNAME"),
    "tls.issuer":              ("string", "CERT_ISSUER"),
    "tls.serial":              ("string", "CERT_SERIALNUMBER"),
    "tls.jarm":                ("string", "JARM"),
    "http.server":             ("string", "SERVER"),
    "http.title":              ("string", "TITLE"),
    "whois.registrant_email":  ("reg", "REGISTRANT_EMAIL"),
    "whois.registrar":         ("reg", "REGISTRAR"),
}

_ENDPOINTS = {
    "hash":   "/api/axon/hash/pivots/{value}/{category}",
    "string": "/api/axon/string/pivots2/{category}",
    "reg":    "/api/axon/string/registration/history2/{category}",
}


def reversible(selector_type: str) -> bool:
    return selector_type in REVERSE_FIELDS


# --------------------------------------------------------------------------- #
# Metered lookups - every one of these needs manual_invocation()
# --------------------------------------------------------------------------- #

def reverse_selector(selector_type: str, selector_value: Any, *,
                     limit: int = 100) -> dict[str, Any]:
    """Indicators Validin has seen carrying this selector value.

    Same shape as `webamon.reverse_selector` on purpose: a caller choosing
    between them should not have to learn two result formats. One lookup.
    """
    reason = _require_manual()
    mapped = REVERSE_FIELDS.get(selector_type)
    if not mapped:
        return {"error": f"{selector_type} has no reverse category on validin",
                "budget": budget_state()}
    kind, category = mapped
    value = str(selector_value).strip()
    if not value:
        return {"error": "empty selector value", "budget": budget_state()}

    path = _ENDPOINTS[kind].format(value=_segment(value),
                                   category=_segment(category))
    params = {"limit": limit}
    if kind != "hash":
        params["string"] = value
    resp = _get(path, params)
    if isinstance(resp, dict) and "error" in resp:
        return {**resp, "reason": reason}
    records = parse_records(resp, query_key=value)
    return {"category": category, "reason": reason, "records": records,
            "indicators": sorted({r["value"] for r in records}),
            "truncated": len(records) >= limit,
            "raw": resp, "budget": budget_state()}


def parse_records(resp: Any, *, query_key: str | None = None) -> list[dict[str, Any]]:
    """Flatten Validin's `records` map into typed, dated rows.

    The shape is {"<CATEGORY>-<TYPE>": [{key, value, value_type, first_seen,
    last_seen}]}, and all of it matters: `value_type` separates the IP a
    certificate was served from from the hosts that served it, and the
    timestamps are the passive history that is the reason to come here at
    all. An earlier version walked the JSON blindly for anything that looked
    like a hostname and returned the queried hash as one of its own results.

    Unix timestamps are left as integers rather than parsed. They come from
    the provider and this module does not own their meaning; a caller that
    wants dates can convert, and a wrong guess here would be invisible.
    """
    records = resp.get("records") if isinstance(resp, dict) else None
    if not isinstance(records, dict):
        return []
    out: list[dict[str, Any]] = []
    for bucket, entries in records.items():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()
            # The query key comes back as `key` on every row; if it also
            # appears as a value the result is the thing we asked about.
            if query_key and value == query_key:
                continue
            out.append({"value": value,
                        "type": entry.get("value_type"),
                        "bucket": bucket,
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen")})
    return out


def dns_history(indicator: str, *, is_ip: bool = False,
                limit: int = 100) -> dict[str, Any]:
    """Passive resolution history for a domain or an IP. One lookup.

    The gap no CLI on the probe VM can fill: dnsx answers what resolves
    now, and this answers what resolved before.
    """
    reason = _require_manual()
    path = (f"/api/axon/ip/dns/history/{_segment(indicator)}" if is_ip
            else f"/api/axon/domain/dns/history/{_segment(indicator)}")
    resp = _get(path, {"limit": limit})
    if isinstance(resp, dict) and "error" in resp:
        return {**resp, "reason": reason}
    records = parse_records(resp, query_key=indicator)
    return {"indicator": indicator, "reason": reason, "records": records,
            "values": sorted({r["value"] for r in records}),
            "raw": resp, "budget": budget_state()}


def certificates(domain: str, *, limit: int = 100) -> dict[str, Any]:
    """Certificate Transparency history for a domain. One lookup.

    This is the crt.sh replacement. crt.sh answers HTTP 200 and serves a
    frozen archive - its newest entry is weeks old - so it is not a source
    any more, and subfinder only returns names, not certificates.
    """
    reason = _require_manual()
    resp = _get(f"/api/axon/domain/certificates/{_segment(domain)}",
                {"limit": limit})
    if isinstance(resp, dict) and "error" in resp:
        return {**resp, "reason": reason}
    records = parse_records(resp, query_key=domain)
    return {"domain": domain, "reason": reason, "records": records,
            "values": sorted({r["value"] for r in records}),
            "raw": resp, "budget": budget_state()}


def registration_history(domain: str, *, limit: int = 100) -> dict[str, Any]:
    """Normalized WHOIS/RDAP history. One lookup.

    Webamon's index carries no registration data - domain.whois.registrar
    matches zero documents - and the probe VM's `whois` sees only the
    record as it stands today. Registration history is where a registrant
    who has since gone private is still visible.
    """
    reason = _require_manual()
    resp = _get(f"/api/axon/domain/registration/history/{_segment(domain)}",
                {"limit": limit})
    if isinstance(resp, dict) and "error" in resp:
        return {**resp, "reason": reason}
    records = parse_records(resp, query_key=domain)
    return {"domain": domain, "reason": reason, "records": records,
            "values": sorted({r["value"] for r in records}),
            "raw": resp, "budget": budget_state()}
