"""Change over time - cti/store/timeline.py and its digest section."""
from __future__ import annotations

from datetime import date, datetime, timedelta

import duckdb
import pytest

from cti import store
from cti.store import entities as E
from cti.store import selectors as S
from cti.store import timeline as T
from cti.store.schema import init_schema
from cti.tracking import digest

NOW = datetime(2026, 10, 16, 6, 15)
SINCE = NOW - timedelta(days=1)


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    E.set_role(c, "jadeprox", "c2.example", "seed", decided_by=E.REPORT)
    yield c
    c.close()


def add(con, indicator, stype, value, when, source="netwatch", vantage="probe"):
    S.record(con, indicator_value=indicator, selector_type=stype, selector_value=value,
             observed_at=when, source=source, vantage=vantage)


def candidate(con, entity, *scores):
    E.file_candidate(con, "jadeprox", entity, origin="t", decided_by="pivot")
    for when, score, band in scores:
        E.record_score(con, "jadeprox", entity, score=score, band=band, evidence=[],
                       scored_at=when)


def test_a_band_move_up_down_and_new(con):
    old = NOW - timedelta(days=2)
    candidate(con, "rising.example", (old, 0.3, "weak"), (NOW, 0.62, "probable"))
    candidate(con, "falling.example", (old, 0.62, "probable"), (NOW, 0.3, "weak"))
    candidate(con, "steady.example", (old, 0.3, "weak"), (NOW, 0.31, "weak"))
    candidate(con, "fresh.example", (NOW, 0.85, "strong"))
    moves = T.band_moves(con, since=SINCE, until=NOW)
    assert [(m["entity"], m["direction"]) for m in moves] == [
        ("rising.example", "up"), ("fresh.example", "new"), ("falling.example", "down")]
    assert moves[0]["from_band"] == "weak" and moves[0]["to_band"] == "probable"


def test_a_new_candidate_scored_noise_is_not_news(con):
    candidate(con, "stranger.example", (NOW, 0.05, "noise"))
    assert T.band_moves(con, since=SINCE, until=NOW) == []


def test_tls_changes_behind_a_cdn_are_the_cdns(con, monkeypatch):
    monkeypatch.setattr(T.cdn, "is_cdn", lambda ip: ip.startswith("104.21."))
    E.set_role(con, "jadeprox", "worker.example", "seed", decided_by=E.REPORT)
    store.upsert_observation(con, observed_at=NOW - timedelta(hours=1),
                             indicator_value="worker.example", source="dns_resolve",
                             actor=None, indicator_type="domain", resolved_ip=["104.21.1.1"])
    add(con, "worker.example", "tls.serial", "01", NOW - timedelta(days=10))
    add(con, "worker.example", "tls.serial", "02", NOW - timedelta(hours=3))
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_a_name_the_observe_pass_saw_behind_a_cdn(con):
    E.set_role(con, "jadeprox", "edge.example", "seed", decided_by=E.REPORT)
    store.upsert_observation(con, observed_at=NOW - timedelta(hours=1),
                             indicator_value="edge.example", source="observe_dns",
                             actor=None, indicator_type="domain", cdn_provider="cloudflare")
    add(con, "edge.example", "tls.serial", "01", NOW - timedelta(days=10))
    add(con, "edge.example", "tls.serial", "02", NOW - timedelta(hours=3))
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_an_accepted_or_rejected_host_is_not_a_band_move(con):
    candidate(con, "done.example", (NOW - timedelta(days=2), 0.3, "weak"),
              (NOW, 0.62, "probable"))
    E.set_role(con, "jadeprox", "done.example", "accepted", decided_by=E.ANALYST)
    assert T.band_moves(con, since=SINCE, until=NOW) == []


def test_a_fingerprint_that_changed_on_a_tracked_host(con):
    add(con, "c2.example", "tls.jarm", "1" * 62, NOW - timedelta(days=10))
    add(con, "c2.example", "tls.jarm", "2" * 62, NOW - timedelta(hours=3))
    [change] = T.value_changes(con, since=SINCE, until=NOW)
    assert change["old_value"] == "1" * 62 and change["new_value"] == "2" * 62
    assert change["memberships"] == ["jadeprox:seed"]


def test_two_tools_disagreeing_is_not_a_change(con):
    """2026-10-17: Zeek's JA4S differs by which scanner opened the session,
    and the old Windows JARM tool and httpx's JARM disagree."""
    add(con, "c2.example", "tls.ja4s", "t130200_1301_aaa", NOW - timedelta(days=10), source="observe")
    add(con, "c2.example", "tls.ja4s", "t130200_1303_aaa", NOW - timedelta(hours=3), source="netwatch")
    add(con, "c2.example", "tls.jarm", "1" * 62, NOW - timedelta(days=10), source="migration:jarm", vantage="win116")
    add(con, "c2.example", "tls.jarm", "3" * 62, NOW - timedelta(hours=3), source="netwatch", vantage="probe")
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_a_host_alternating_between_two_values_is_not_a_change(con):
    add(con, "c2.example", "tls.serial", "aa", NOW - timedelta(days=10))
    add(con, "c2.example", "tls.serial", "bb", NOW - timedelta(days=5))
    add(con, "c2.example", "tls.serial", "aa", NOW - timedelta(hours=3))
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_a_first_sighting_is_not_a_change(con):
    add(con, "c2.example", "tls.jarm", "1" * 62, NOW - timedelta(hours=3))
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_untracked_hosts_and_detector_owned_types_are_left_out(con):
    for host in ("c2.example", "stranger.example"):
        add(con, host, "tls.cert_sha256", "a" * 64, NOW - timedelta(days=10))
        add(con, host, "tls.cert_sha256", "b" * 64, NOW - timedelta(hours=3))
    add(con, "stranger.example", "tls.jarm", "1" * 62, NOW - timedelta(days=10))
    add(con, "stranger.example", "tls.jarm", "2" * 62, NOW - timedelta(hours=3))
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_passive_history_is_not_a_change_today(con):
    add(con, "c2.example", "dns.ns_set", "ns1.a.example", NOW - timedelta(days=10),
        source="validin")
    add(con, "c2.example", "dns.ns_set", "ns1.b.example", NOW - timedelta(hours=3),
        source="validin")
    assert T.value_changes(con, since=SINCE, until=NOW) == []


def test_a_divergence_is_reported_the_first_time_only(con):
    def change(scan, when, value):
        store.record_service_change(con, detected_at=when, scan_id=scan, target="c2.example",
                                    port=443, actor=None, field="client_divergence",
                                    change_type="client_divergence", old_value=None,
                                    new_value=value)
    change("a", NOW - timedelta(days=3), "tls")
    change("b", NOW - timedelta(hours=2), "tls")
    change("c", NOW - timedelta(hours=1), "status:404>200")
    assert [d["diverged"] for d in T.divergences(con, since=SINCE, until=NOW)] == [
        "status:404>200"]


def test_the_digest_renders_what_moved(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_TRACKING_DIGESTS", str(tmp_path))
    timeline = {
        "band_moves": [{"cluster": "jadeprox", "entity": "rising.example", "from_band": "weak",
                        "to_band": "probable", "from_score": 0.3, "to_score": 0.62,
                        "direction": "up"}],
        "value_changes": [{"indicator": "c2.example", "memberships": ["jadeprox:seed"],
                           "selector_type": "tls.jarm", "old_value": "1" * 62,
                           "new_value": "2" * 62, "vantage": "probe"}],
        "client_divergences": [{"target": "c2.example", "port": 443, "diverged": "tls",
                                "memberships": ["jadeprox:seed"]}]}
    text = digest.write(date(2026, 10, 16), {"timeline": timeline}).read_text()
    assert "## Candidate relatedness moved" in text and "↑ **rising.example**" in text
    assert "## Fingerprints changed on tracked hosts" in text and "`tls.jarm`" in text
    assert "## Served Windows clients something different" in text


def test_a_band_falling_alone_does_not_wake_the_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_TRACKING_DIGESTS", str(tmp_path))
    timeline = {"band_moves": [{"cluster": "j", "entity": "x", "from_band": "probable",
                                "to_band": "weak", "from_score": 0.6, "to_score": 0.3,
                                "direction": "down"}]}
    assert not digest._has_signals({"timeline": timeline})
