"""Validin: the gates, the budget, and the record parsing.

No network anywhere in this file. The transport is stubbed in every test
that reaches it, because a gate that fails open must not be able to spend a
lookup while proving it - the source is capped at fifty a month.
"""
from __future__ import annotations

import os
import pathlib

import pytest

from cti.sources import budget, validin

REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(validin.API_KEY_ENV, "test-key")
    budget.reset("validin")
    yield
    budget.reset("validin")


@pytest.fixture
def no_transport(monkeypatch):
    """Replace the HTTP layer and record what it was asked for."""
    calls: list = []

    def fake(path, params=None, *, metered=True):
        calls.append({"path": path, "params": params, "metered": metered})
        if metered:
            try:
                budget.spend("validin", 1)
            except budget.BudgetExhausted as e:
                return {"error": str(e)}
        return {"records": {}}

    monkeypatch.setattr(validin, "_get", fake)
    return calls


# --------------------------------------------------------------------------- #
# The gate: manual-only means manual-only
# --------------------------------------------------------------------------- #

def test_a_lookup_outside_a_manual_scope_is_refused(no_transport):
    with pytest.raises(validin.ManualOnly, match="manual-only"):
        validin.reverse_selector("tls.cert_sha256", "a" * 64)
    assert no_transport == [], "nothing may reach the network"


def test_the_refusal_is_an_exception_not_an_error_dict(no_transport):
    """Every other failure here degrades to {"error": ...} so a sweep does
    not crash. This one must not: it means an automatic path reached a
    source that may never be automatic, and a skippable note is how that
    gets missed."""
    with pytest.raises(validin.ManualOnly):
        validin.dns_history("example.com")


def test_a_scope_needs_a_stated_reason():
    """Fifty lookups a month: a call with no stated purpose is a call that
    should not have been made."""
    for empty in ("", "   ", None):
        with pytest.raises(validin.ManualOnly, match="reason"):
            with validin.manual_invocation(empty):  # type: ignore[arg-type]
                pass


def test_the_stated_reason_is_returned_with_the_result(no_transport):
    with validin.manual_invocation("chasing the 7-Eleven certificate"):
        result = validin.reverse_selector("tls.cert_sha256", "a" * 64)
    assert result["reason"] == "chasing the 7-Eleven certificate"


def test_the_scope_does_not_outlive_the_with_block(no_transport):
    with validin.manual_invocation("done now"):
        pass
    with pytest.raises(validin.ManualOnly):
        validin.reverse_selector("tls.cert_sha256", "a" * 64)


def test_a_nested_scope_restores_the_outer_reason(no_transport):
    with validin.manual_invocation("outer"):
        with validin.manual_invocation("inner"):
            pass
        assert validin.reverse_selector("tls.cert_sha256", "a" * 64)["reason"] == "outer"


# --------------------------------------------------------------------------- #
# The gate that catches the mistake a future change will actually make
# --------------------------------------------------------------------------- #

def _write_caller(path: pathlib.Path) -> None:
    path.write_text(
        "from cti.sources import validin\n"
        "def anything():\n"
        "    with validin.manual_invocation('wrapped, but automatic'):\n"
        "        return validin.reverse_selector('tls.cert_sha256', 'a' * 64)\n")


@pytest.mark.parametrize("package", ["graph", "dashboard"])
def test_an_automatic_package_is_refused_even_inside_a_scope(package, no_transport,
                                                             monkeypatch):
    """The scope alone would be defeated by wrapping automatic code in it,
    which is the likeliest future mistake. The path check is what stops it."""
    import importlib
    import sys

    module = REPO / package / "_validin_gate_probe.py"
    _write_caller(module)
    monkeypatch.syspath_prepend(str(REPO))
    try:
        caller = importlib.import_module(f"{package}._validin_gate_probe")
        with pytest.raises(validin.ManualOnly, match="manual-only"):
            caller.anything()
    finally:
        sys.modules.pop(f"{package}._validin_gate_probe", None)
        module.unlink()
    assert no_transport == []


def test_the_automatic_directories_exist():
    """The guard was first written as "/cti/graph/" and matched nothing at
    all, because the graph is a top-level package. A path gate that names a
    directory which does not exist is not a gate."""
    for directory in validin._AUTOMATIC_DIRS:
        assert pathlib.Path(directory).is_dir(), directory
    assert any(d.endswith(f"graph{os.sep}") for d in validin._AUTOMATIC_DIRS)


def test_a_function_named_like_the_sweep_is_refused_wherever_it_lives(no_transport):
    def _sweep_lifecycle():
        with validin.manual_invocation("looks deliberate, is not"):
            return validin.reverse_selector("tls.cert_sha256", "a" * 64)

    with pytest.raises(validin.ManualOnly, match="_sweep_lifecycle"):
        _sweep_lifecycle()


def test_the_sweep_function_names_are_real():
    """A name list that has drifted from the code guards nothing.

    The first version of this list named sweep_cluster, sweep_all,
    run_daily and daily_digest. None of them exist; the gate they were
    supposed to provide was four dead strings.
    """
    core = (REPO / "cti" / "core.py").read_text()
    for name in validin._AUTOMATIC_FUNCTIONS:
        assert f"def {name}(" in core, f"{name} is no longer a function in core.py"


def test_an_unreadable_stack_is_treated_as_automatic(monkeypatch):
    """Fails closed. An unreadable stack is not evidence of innocence."""
    def boom(_depth):
        raise RuntimeError("no stack for you")

    monkeypatch.setattr(validin.sys, "_getframe", boom)
    assert validin._automatic_caller() == "unreadable stack"


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #

def test_the_eleventh_lookup_in_a_day_is_blocked(no_transport):
    with validin.manual_invocation("burning the daily budget"):
        for i in range(10):
            result = validin.reverse_selector("tls.cert_sha256", f"{i:064d}")
            assert "error" not in result, f"call {i + 1} should have succeeded"
        blocked = validin.reverse_selector("tls.cert_sha256", "f" * 64)
    assert "daily budget exhausted" in blocked["error"]
    assert len(no_transport) == 11, "the gate runs inside _get, which was reached"
    assert budget.used_today("validin") == 10, "the blocked call cost nothing"


def test_the_monthly_cap_binds_before_the_daily_one_would(monkeypatch):
    """Ten a day is three hundred a month against a ceiling of fifty, so the
    monthly cap is the one that actually stops anything."""
    monkeypatch.setenv("CTI_VALIDIN_MONTHLY_BUDGET", "3")
    for _ in range(3):
        budget.spend("validin", 1)
    with pytest.raises(budget.BudgetExhausted, match="monthly"):
        budget.spend("validin", 1)
    assert budget.remaining("validin") == 0
    assert budget.cap("validin") - budget.used_today("validin") == 7, \
        "the daily cap alone would still have allowed seven more"


def test_every_response_says_what_is_left(no_transport):
    with validin.manual_invocation("checking the budget is reported"):
        result = validin.reverse_selector("tls.cert_sha256", "a" * 64)
    assert result["budget"]["daily_remaining"] == 9
    assert result["budget"]["monthly_remaining"] == 49


def test_reconciling_adopts_spend_this_counter_never_saw():
    """The live key had already spent 5 of its 50 monthly lookups through
    the web UI. Without this the local gate would have authorised 50 more
    and met a 429 on the 46th."""
    assert budget.remaining_monthly("validin") == 50
    budget.reconcile("validin", 5)
    assert budget.remaining_monthly("validin") == 45
    assert budget.used_today("validin") == 0, "carried spend is not today's"


def test_reconciling_never_hands_budget_back():
    """The provider is the authority on what has been spent, but a lower
    remote figure - a lagging counter, a reset - must not return budget we
    believe is gone."""
    budget.spend("validin", 4)
    before = budget.remaining_monthly("validin")
    budget.reconcile("validin", 1)
    assert budget.remaining_monthly("validin") == before


def test_reconciling_is_idempotent():
    budget.reconcile("validin", 5)
    budget.reconcile("validin", 5)
    assert budget.remaining_monthly("validin") == 45


def test_the_unmetered_endpoints_spend_nothing(monkeypatch):
    """Verified against the live API: ping, paths and profile/usage leave
    the provider's own counters unchanged."""
    seen: list = []
    monkeypatch.setattr(validin.http, "get_json",
                        lambda url, **kw: seen.append(url) or
                        {"remaining": {"daily": 10, "monthly": 50}})
    validin.status()
    assert budget.used_today("validin") == 0
    assert seen and seen[0].endswith("/api/profile/usage")


def test_status_is_not_gated_because_it_costs_nothing(monkeypatch):
    """A read-only check that spends no budget is not the automation risk
    this module guards against, and refusing it from the sweep would only
    stop the sweep reporting its own quota."""
    monkeypatch.setattr(validin.http, "get_json",
                        lambda url, **kw: {"remaining": {"daily": 10, "monthly": 50}})

    def _sweep_lifecycle():
        return validin.status()

    assert _sweep_lifecycle()["ok"] is True


def test_drift_between_our_count_and_the_providers_is_reported(monkeypatch):
    monkeypatch.setattr(validin.http, "get_json",
                        lambda url, **kw: {"remaining": {"daily": 10, "monthly": 45}})
    state = validin.status()["budget"]
    assert state["drift"]["monthly"] == {"ours": 50, "theirs": 45}
    assert "daily" not in state["drift"], "only the period that disagrees"


# --------------------------------------------------------------------------- #
# The map, and what it deliberately omits
# --------------------------------------------------------------------------- #

def test_every_mapped_type_is_in_the_taxonomy():
    from cti.store.selectors import TYPES
    assert sorted(t for t in validin.REVERSE_FIELDS if t not in TYPES) == []


def test_the_body_hash_is_not_mapped():
    """Validin's body digest is BODY_SHA1 and ours is SHA-256 - a different
    algorithm over the same bytes. Mapping them would invent a lookup that
    returns nothing forever and looks like an absence of results."""
    assert not validin.reversible("http.body_sha256")


def test_it_covers_the_two_gaps_webamon_cannot(no_transport):
    """Registration data, which Webamon's index does not carry at all, and
    the leaf certificate digest, which it does not publish."""
    from cti.sources import webamon
    for selector_type in ("tls.cert_sha256", "whois.registrant_email",
                          "whois.registrar"):
        assert validin.reversible(selector_type), selector_type
        assert not webamon.reversible(selector_type), selector_type


def test_an_unmapped_type_costs_nothing(no_transport):
    with validin.manual_invocation("asking for something it cannot answer"):
        result = validin.reverse_selector("dns.apex", "evil.example")
    assert "error" in result
    assert no_transport == [], "refused before the transport, so before the spend"


def test_a_value_cannot_escape_its_path_segment(no_transport):
    """These values come from certificates and page titles and can contain
    anything, including a slash."""
    with validin.manual_invocation("path escaping"):
        validin.reverse_selector("tls.cert_sha256", "../../profile/token")
    assert no_transport[0]["path"] == \
        "/api/axon/hash/pivots/..%2F..%2Fprofile%2Ftoken/CERT_FINGERPRINT_SHA256"


# --------------------------------------------------------------------------- #
# Parsing the response
# --------------------------------------------------------------------------- #

_LIVE_SHAPE = {
    "query_key": "36fe8f7d" + "0" * 56,
    "records": {
        "CERT_FINGERPRINT_SHA256-IP": [
            {"key": "36fe8f7d" + "0" * 56, "value": "37.1.220.158",
             "value_type": "ip4", "first_seen": 1789862400, "last_seen": 1789862400}],
        "CERT_FINGERPRINT_SHA256-HOST": [
            {"key": "36fe8f7d" + "0" * 56, "value": "d42p3b.top",
             "value_type": "dom", "first_seen": 1789862400, "last_seen": 1789862400},
            {"key": "36fe8f7d" + "0" * 56, "value": "36fe8f7d" + "0" * 56,
             "value_type": "dom", "first_seen": 1, "last_seen": 2}],
    },
}


def test_records_are_parsed_with_their_type_and_dates():
    rows = validin.parse_records(_LIVE_SHAPE, query_key="36fe8f7d" + "0" * 56)
    by_value = {r["value"]: r for r in rows}
    assert by_value["37.1.220.158"]["type"] == "ip4"
    assert by_value["d42p3b.top"]["type"] == "dom"
    # the timestamps ARE the reason to come here - passive history
    assert by_value["d42p3b.top"]["first_seen"] == 1789862400


def test_the_queried_value_is_not_returned_as_its_own_result():
    """An earlier version walked the JSON for anything hostname-shaped and
    returned the queried hash among its own results."""
    rows = validin.parse_records(_LIVE_SHAPE, query_key="36fe8f7d" + "0" * 56)
    assert all(r["value"] != "36fe8f7d" + "0" * 56 for r in rows)


def test_a_response_with_no_records_parses_to_nothing():
    for empty in ({}, {"records": None}, {"records": []}, None, "nonsense"):
        assert validin.parse_records(empty) == []


# --------------------------------------------------------------------------- #
# The only door in
# --------------------------------------------------------------------------- #

def test_nothing_automatic_imports_validin_at_all():
    """The cheapest guard: a source that is never imported into the
    pipeline cannot be called from it whatever the stack says."""
    offenders = []
    for path in list((REPO / "graph").rglob("*.py")) + [REPO / "cti" / "core.py"]:
        if "validin" in path.read_text():
            offenders.append(str(path.relative_to(REPO)))
    assert offenders == []


def test_the_mcp_tools_are_the_manual_path(monkeypatch):
    """cti/mcp/ must NOT be gated: a tool runs because somebody asked for it
    by name, which is exactly the condition this source is allowed under."""
    from cti.mcp import server

    monkeypatch.setattr(validin, "_get", lambda *a, **k: {"records": {}})
    # It got past both gates - no ManualOnly - and carried the reason
    # through. The budget is untouched only because the transport is stubbed.
    result = server.validin_reverse_selector(
        "tls.cert_sha256", "a" * 64, "an analyst asked")
    assert result["reason"] == "an analyst asked"
    assert "error" not in result


def test_the_mcp_history_tool_rejects_an_unknown_kind(monkeypatch):
    from cti.mcp import server
    monkeypatch.setattr(validin, "_get", lambda *a, **k: {"records": {}})
    assert "error" in server.validin_history("example.com", kind="nonsense",
                                             reason="typo")
    assert budget.used_today("validin") == 0, "an unknown kind costs nothing"
