"""The weekly expansion sweep - cti/tracking/expand_coverage.py.

No network: Webamon's reverse lookup and the per-host sweep are stubbed.
The sweep stub writes the new host's selectors the way the real
_record_enrichment would, so the corroboration rule runs for real.
"""
from __future__ import annotations

from datetime import date, datetime

import pytest

from cti import core, membership, store
from cti.store import selectors
from cti.tracking import expand_coverage as X

DAY = datetime(2026, 10, 5)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path / "clusters")
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "t.duckdb"))


def _select(indicator, selector_type, value, global_count=None):
    with store.connect() as con:
        selectors.record(con, indicator_value=indicator, selector_type=selector_type,
                         selector_value=value, observed_at=DAY, indicator_type="domain",
                         actor="Kit" if indicator.startswith("known") else None)
        if global_count is not None:
            con.execute("INSERT INTO selector_stats VALUES (?, ?, 1, ?, 'webamon', ?) "
                        "ON CONFLICT DO NOTHING",
                        [selector_type, selectors.normalize(selector_type, value),
                         global_count, DAY])


@pytest.fixture
def cluster(monkeypatch):
    core.create_cluster("Kit")
    data = core.load_cluster("Kit")
    data["observables"]["domains"].append(
        {"value": "known.example", "sources": ["r"], "first_seen": "2026-09-01T00:00:00+00:00",
         "last_seen": "2026-09-01T00:00:00+00:00"})
    data["denylist"].append({"value": "denied.example", "reason": "parked", "date": "x"})
    core.save_cluster(data)
    _select("known.example", "webamon.fp_ssl", "fp-rare", global_count=12)
    _select("known.example", "webamon.fp_dom", "fp-common", global_count=5_000_000)

    reversed_ = []

    def reverse(selector_type, value, size=25):
        reversed_.append((selector_type, value))
        return {"indicators": ["known.example", "denied.example", "new.example",
                               "weak.example"]}

    def sweep(domains, ips, *a, **k):
        return {("domains", d): ("active", {"resolved": ["198.51.100.7"]}, {}) for d in domains}

    def record(actor, results, **k):
        # new.example really serves the same TLS stack; weak.example only
        # shares a structural fact, which is not enough on its own.
        _select("new.example", "webamon.fp_ssl", "fp-rare")
        _select("weak.example", "tls.san", "shared.example")
        _select("known.example", "tls.san", "shared.example")
        return None

    monkeypatch.setattr(X.webamon, "reverse_selector", reverse)
    monkeypatch.setattr(core, "_sweep_lifecycle", sweep)
    monkeypatch.setattr(core, "_record_enrichment", record)
    return reversed_


def test_seeds_are_promotable_priced_and_below_provider_scale(cluster):
    with store.connect() as con:
        seeds = X.seeds_for(con, core.load_cluster("Kit"))
    assert [(s["selector_type"], s["selector_value"]) for s in seeds] == [
        ("webamon.fp_ssl", "fp-rare")]


def test_swept_hosts_are_filed_as_scored_candidates(cluster):
    report = X.expand_cluster("Kit")
    assert cluster == [("webamon.fp_ssl", "fp-rare")]
    filed = {f["value"]: f for f in report["filed"]}
    # new.example shares a rare identity fact; weak.example one structural
    # fact. Both clear the default `weak` floor - as scored candidates, not
    # members - and the identity link scores higher.
    assert set(filed) == {"new.example", "weak.example"}
    assert filed["new.example"]["score"] > filed["weak.example"]["score"]
    assert filed["new.example"]["discovered_via"] == "webamon.fp_ssl:fp-rare"
    assert filed["new.example"]["candidate_linked_to"] == "known.example"
    # Candidates live in the membership store; the cluster JSON lists members.
    assert {o["value"] for o in core.load_cluster("Kit")["observables"]["domains"]} == {
        "known.example"}
    assert {c["entity"] for c in membership.candidates("kit")} == {"new.example",
                                                                   "weak.example"}


def test_the_band_floor_decides_what_is_filed(cluster, monkeypatch):
    monkeypatch.setenv("CTI_CANDIDATE_MIN_BAND", "strong")
    report = X.expand_cluster("Kit")
    assert report["filed"] == [] and report["rejected_links"] == 2
    assert membership.candidates("kit") == []


def test_a_filed_candidate_is_not_swept_again(cluster, monkeypatch):
    X.expand_cluster("Kit")
    swept = []
    real = core._sweep_lifecycle
    monkeypatch.setattr(core, "_sweep_lifecycle",
                        lambda d, i, *a, **k: swept.extend(d) or real(d, i))
    X.expand_cluster("Kit")
    assert swept == []


def test_denied_and_tracked_hosts_are_never_swept(cluster, monkeypatch):
    swept = []
    real = core._sweep_lifecycle
    monkeypatch.setattr(core, "_sweep_lifecycle",
                        lambda d, i, *a, **k: swept.extend(d) or real(d, i))
    X.expand_cluster("Kit")
    assert sorted(swept) == ["new.example", "weak.example"]


def test_a_host_another_cluster_tracks_is_reported_not_filed(cluster):
    core.create_cluster("Other")
    data = core.load_cluster("Other")
    data["observables"]["domains"].append(
        {"value": "new.example", "sources": ["r"], "first_seen": "x", "last_seen": "x"})
    core.save_cluster(data)
    report = X.expand_cluster("kit")
    assert "new.example" not in {f["value"] for f in report["filed"]}
    assert report["owned_elsewhere"] == [{"value": "new.example", "cluster": "Other"}]


def test_the_budget_caps_reverse_lookups(cluster, monkeypatch):
    monkeypatch.setenv("CTI_WEBAMON_EXPAND_BUDGET", "0")
    out = X.run(date(2026, 10, 5), forced=True, clusters=["kit"])
    assert cluster == []
    assert out["budget_exhausted"] and out["filed_total"] == 0


def test_it_only_runs_on_the_expansion_day(monkeypatch):
    monkeypatch.setenv("CTI_EXPAND_WEEKDAY", "0")
    assert "skipped" in X.run(date(2026, 10, 6), clusters=[])     # a Tuesday
    assert "skipped" not in X.run(date(2026, 10, 5), clusters=[])  # a Monday
    assert "skipped" not in X.run(date(2026, 10, 6), forced=True, clusters=[])


def test_a_pdns_neighbour_is_scored_on_its_dated_link(cluster, monkeypatch):
    """The link that surfaced a host is recorded before it is scored, so a
    name that sat on our address two years ago scores on that gap - not on
    nothing at all."""
    from cti.netwatch.candidates import Candidate
    _select("known.example", "net.resolved_ip", "198.51.100.40")
    monkeypatch.setattr(X, "_live_indicators", lambda data: ["198.51.100.40"])
    monkeypatch.setattr(X.pdns_source, "host_candidates", lambda ind, kind: [
        Candidate("old-tenant.example", "domain", "net.cohosted_domain:198.51.100.40",
                  "198.51.100.40", "pdns", first_seen=1680000000, last_seen=1680500000)])
    monkeypatch.setattr(X.webamon, "reverse_selector", lambda *a, **k: {"indicators": []})
    X.expand_cluster("Kit")
    score = membership.score("kit", "old-tenant.example", members=["known.example"])
    [pair] = [e for e in score["evidence"] if e["type"] == "net.historical_ip"]
    assert pair["gap_days"] > 900 and score["band"] == "noise"
