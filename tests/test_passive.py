"""Shodan InternetDB and mnemonic passive DNS.

No network: `http.get_json` is stubbed everywhere. The response shapes are
taken from live calls made while writing this, including the ones that
matter most - a 404 for an unindexed address, and millisecond timestamps.
"""
from __future__ import annotations

import pytest

from cti.sources import budget, http, passive


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    for provider in ("internetdb", "mnemonic"):
        budget.reset(provider)
        monkeypatch.setenv(f"CTI_{provider.upper()}_MIN_INTERVAL", "0")
    yield


def _stub(monkeypatch, payload):
    seen: list[str] = []

    def fake(url, **kw):
        seen.append(url)
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(http, "get_json", fake)
    return seen


# --------------------------------------------------------------------------- #
# InternetDB
# --------------------------------------------------------------------------- #

_IDB = {"cpes": ["cpe:/a:cloudflare:cloudflare"],
        "hostnames": ["one.one.one.one"], "ip": "1.1.1.1",
        "ports": [443, 53, 80], "tags": [], "vulns": []}


def test_internetdb_returns_the_ports_nobody_had_to_scan_for(monkeypatch):
    _stub(monkeypatch, _IDB)
    result = passive.internetdb("1.1.1.1")
    assert result["ports"] == [53, 80, 443], "sorted, numeric"
    assert result["cpes"] == ["cpe:/a:cloudflare:cloudflare"]


def test_every_internetdb_result_is_marked_passive(monkeypatch):
    """The caller must not be able to forget it. These ports were observed
    by somebody else at an unknown time, and treating them as current is
    the one way to misuse this source."""
    _stub(monkeypatch, _IDB)
    assert passive.internetdb("1.1.1.1")["passive"] is True


def test_an_unindexed_address_is_a_result_not_a_failure(monkeypatch):
    """404 is the documented "nothing indexed" answer. Reporting it as an
    error would make an unknown host indistinguishable from an API
    outage."""
    _stub(monkeypatch, http.HttpError("not found", status=404))
    result = passive.internetdb("203.0.113.9")
    assert "error" not in result
    assert result["indexed"] is False and result["ports"] == []


def test_a_real_failure_is_still_an_error(monkeypatch):
    _stub(monkeypatch, http.HttpError("boom", status=500))
    assert "error" in passive.internetdb("1.1.1.1")


# --------------------------------------------------------------------------- #
# mnemonic
# --------------------------------------------------------------------------- #

_PDNS = {"responseCode": 200, "count": 998, "data": [
    {"query": "evil.example", "answer": "203.0.113.9", "rrtype": "a",
     "firstSeenTimestamp": 1604074362891, "lastSeenTimestamp": 1789919937736,
     "times": 23443},
    {"query": "evil.example", "answer": "ns1.evil.example", "rrtype": "ns",
     "firstSeenTimestamp": 1604074362891, "lastSeenTimestamp": 1789919937736},
    {"query": "evil.example", "answer": "junk", "rrtype": "txt",
     "firstSeenTimestamp": 1, "lastSeenTimestamp": 2},
]}


def test_pdns_timestamps_are_converted_to_seconds(monkeypatch):
    """Milliseconds on the wire, seconds everywhere in this repo. Left
    unconverted they would read as dates fifty thousand years out."""
    _stub(monkeypatch, _PDNS)
    record = passive.pdns("evil.example")["records"][0]
    assert record["first_seen"] == 1604074362
    assert record["last_seen"] == 1789919937


def test_pdns_keeps_only_the_record_types_worth_pivoting_on(monkeypatch):
    _stub(monkeypatch, _PDNS)
    types = {r["rrtype"] for r in passive.pdns("evil.example")["records"]}
    assert types == {"a", "ns"}, "txt is not an infrastructure answer"


def test_pdns_reports_the_full_total_not_the_page(monkeypatch):
    _stub(monkeypatch, _PDNS)
    assert passive.pdns("evil.example")["total"] == 998


def test_pdns_serves_both_directions(monkeypatch):
    """One endpoint: a name returns what it resolved to, an address returns
    the names that resolved to it."""
    seen = _stub(monkeypatch, _PDNS)
    passive.pdns("193.29.58.192")
    assert seen[0].endswith("/193.29.58.192?limit=100")


# --------------------------------------------------------------------------- #
# The trap the module is built around
# --------------------------------------------------------------------------- #

def test_overlapping_windows_are_a_lead_and_distant_ones_are_not():
    """Two domains on one address four years apart share nothing; the same
    two in one week are a lead. Only the timestamps can tell them apart."""
    week_one = {"first_seen": 1_700_000_000, "last_seen": 1_700_600_000}
    same_week = {"first_seen": 1_700_300_000, "last_seen": 1_700_900_000}
    years_later = {"first_seen": 1_800_000_000, "last_seen": 1_800_600_000}
    assert passive.overlapping(week_one, same_week) is True
    assert passive.overlapping(week_one, years_later) is False


def test_an_unanswerable_overlap_is_not_a_yes():
    assert passive.overlapping({"first_seen": None, "last_seen": None},
                               {"first_seen": 1, "last_seen": 2}) is False


def test_a_historical_address_cannot_be_recorded_as_a_current_one():
    """net.resolved_ip means the present tense. A passive answer gets
    net.historical_ip, which is behavioural and corroborates only."""
    from cti.store.selectors import selector_class
    assert selector_class("net.resolved_ip") == "structural"
    assert selector_class("net.historical_ip") == "behavioural"


def test_a_passive_port_set_cannot_be_confused_with_a_scanned_one():
    from cti.store.selectors import artefact, selector_class
    assert selector_class("net.passive_port_set") == "behavioural"
    assert artefact("net.passive_port_set") != artefact("net.port_set")


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #

def test_both_sources_are_metered_despite_being_free(monkeypatch):
    """A source we pay nothing for is the one we have least right to
    hammer."""
    _stub(monkeypatch, _IDB)
    passive.internetdb("1.1.1.1")
    assert budget.used_today("internetdb") == 1
    _stub(monkeypatch, _PDNS)
    passive.pdns("evil.example")
    assert budget.used_today("mnemonic") == 1


def test_an_exhausted_budget_stops_the_call(monkeypatch):
    monkeypatch.setenv("CTI_INTERNETDB_BUDGET", "1")
    seen = _stub(monkeypatch, _IDB)
    passive.internetdb("1.1.1.1")
    result = passive.internetdb("1.1.1.2")
    assert "error" in result and "exhausted" in result["error"]
    assert len(seen) == 1, "the second call never reached the network"


def test_neither_source_needs_a_key():
    """The whole reason they are here. status() reports caps, not auth."""
    assert set(passive.status()) == {"internetdb", "mnemonic"}


def test_the_case_this_module_was_built_around():
    """Not hypothetical - it is the first real query this module made.

    192.252.186.62 currently serves JadeProx's EDR-impersonation domains.
    Passive DNS says kakatown.com - also tracked under JadeProx - lived
    there from 2019-12 to 2020-06. Same actor, same address, six years
    apart. Written as net.resolved_ip that is a confident false link
    between a live cluster and a domain that left before it arrived.
    """
    kakatown = {"first_seen": 1_575_936_000, "last_seen": 1_593_000_000}
    edr = {"first_seen": 1_787_000_000, "last_seen": 1_789_900_000}
    assert passive.overlapping(kakatown, edr) is False
