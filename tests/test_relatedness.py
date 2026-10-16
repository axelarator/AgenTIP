"""Spans, memberships and the relatedness score.

The regression cases at the bottom are the 2026-10-16 JadeProx cleanup,
replayed with the dates Validin returned for 192.252.186.62. They are why
this module exists: a co-resolution five years apart must score as noise,
and the old promote rule must still score as strong.
"""
from __future__ import annotations

from datetime import datetime

import duckdb
import pytest

from cti.store import entities as E
from cti.store import relatedness as R
from cti.store import selectors as S
from cti.store import spans as SP
from cti.store.schema import init_schema

DAY = datetime(2026, 10, 1)


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    yield c
    c.close()


def add(con, indicator, selector_type, value, when=DAY, first=None, last=None,
        source="observe"):
    S.record(con, indicator_value=indicator, selector_type=selector_type,
             selector_value=value, observed_at=when, first_seen=first,
             last_seen=last, indicator_type=E.entity_type(indicator), source=source)


def seed(con, cluster, *values):
    for v in values:
        E.set_role(con, cluster, v, "seed", decided_by=E.REPORT, origin="report")


# --------------------------------------------------------------------------- #
# Spans
# --------------------------------------------------------------------------- #

def test_observations_within_the_gap_extend_one_span(con):
    for day in (1, 2, 4):
        add(con, "a.example", "tls.jarm", "x" * 62, when=datetime(2026, 10, day))
    spans = SP.spans_for(con, indicator_value="a.example")
    assert len(spans) == 1
    assert spans[0]["start_at"] == datetime(2026, 10, 1)
    assert spans[0]["end_at"] == datetime(2026, 10, 4)
    assert spans[0]["observations"] == 3


def test_a_value_that_goes_away_and_returns_is_two_spans(con):
    add(con, "a.example", "tls.jarm", "x" * 62, when=datetime(2026, 9, 1))
    add(con, "a.example", "tls.jarm", "x" * 62, when=datetime(2026, 10, 1))
    assert len(SP.spans_for(con, indicator_value="a.example")) == 2
    # The fold in `selectors` still spans the whole history.
    row = con.execute("SELECT first_seen, last_seen FROM selectors").fetchone()
    assert row == (datetime(2026, 9, 1), datetime(2026, 10, 1))


def test_an_observation_between_two_spans_merges_them(con):
    for day in (1, 5, 3):           # 1 and 5 are apart; 3 bridges them
        add(con, "a.example", "tls.jarm", "x" * 62, when=datetime(2026, 10, day))
    spans = SP.spans_for(con, indicator_value="a.example")
    assert len(spans) == 1 and spans[0]["observations"] == 3


def test_passive_windows_are_kept_as_given(con):
    """The pDNS bug: every historical address was stamped with the day we
    asked. A 2019 window must stay a 2019 window."""
    add(con, "kakatown.com", "net.historical_ip", "192.252.186.62", when=DAY,
        first=1566777600, last=1596326400, source="mnemonic_pdns")
    span = SP.spans_for(con, indicator_value="kakatown.com")[0]
    assert span["start_at"].year == 2019 and span["end_at"].year == 2020
    row = con.execute("SELECT first_seen, last_seen FROM selectors").fetchone()
    assert row[1].year == 2020


def test_passive_windows_do_not_bridge_a_gap(con):
    add(con, "a.example", "net.historical_ip", "198.51.100.1", first="2020-01-01",
        last="2020-02-01", source="mnemonic_pdns")
    add(con, "a.example", "net.historical_ip", "198.51.100.1", first="2020-02-03",
        last="2020-03-01", source="mnemonic_pdns")
    assert len(SP.spans_for(con, indicator_value="a.example")) == 2


def test_epoch_milliseconds_are_read_as_milliseconds():
    assert SP.to_ts(1566777600000) == SP.to_ts(1566777600)


# --------------------------------------------------------------------------- #
# Memberships: who may set what
# --------------------------------------------------------------------------- #

def test_an_automatic_path_cannot_seed_or_accept(con):
    for role in ("seed", "accepted", "rejected"):
        with pytest.raises(E.RoleError):
            E.set_role(con, "c", "x.example", role, decided_by="pivot",
                       reason="r")


def test_an_automatic_path_cannot_overwrite_a_human_verdict(con):
    seed(con, "c", "x.example")
    assert E.file_candidate(con, "c", "x.example", origin="pdns",
                            decided_by="pivot") is None
    assert E.membership(con, "c", "x.example")["role"] == "seed"


def test_a_rejection_holds_against_refiling(con):
    E.set_role(con, "c", "kakatown.com", "rejected", decided_by=E.ANALYST,
               reason="2019 tenant")
    assert E.file_candidate(con, "c", "KAKATOWN.COM.", origin="pdns",
                            decided_by="pivot") is None


def test_a_rejection_needs_a_reason(con):
    with pytest.raises(ValueError):
        E.set_role(con, "c", "x.example", "rejected", decided_by=E.ANALYST)


def test_only_seeds_and_accepted_are_members(con):
    seed(con, "c", "a.example")
    E.file_candidate(con, "c", "b.example", origin="pdns", decided_by="pivot")
    assert [m["entity"] for m in E.members(con, "c")] == ["a.example"]


def test_scores_are_appended_and_mirrored(con):
    E.file_candidate(con, "c", "b.example", origin="pdns", decided_by="pivot")
    E.record_score(con, "c", "b.example", score=0.1, band="noise", evidence=[],
                   scored_at="2026-10-01")
    E.record_score(con, "c", "b.example", score=0.6, band="probable", evidence=[],
                   scored_at="2026-10-02")
    assert [h["score"] for h in E.score_history(con, "c", "b.example")] == [0.1, 0.6]
    assert E.membership(con, "c", "b.example")["band"] == "probable"


def test_entity_types():
    assert E.entity_type("192.0.2.1") == "ipv4"
    assert E.entity_type("cert-sha256:" + "a" * 64) == "cert"
    assert E.entity_type("https://x.example/a") == "url"
    assert E.entity_type("md5:" + "a" * 32) == "hash"
    assert E.entity_type("x.example") == "domain"
    assert E.entity_type("CVE-2025-12345") == "cve"
    assert E.canonical("cve-2025-12345") == "CVE-2025-12345"
    assert E.entity_type("ops@evil.example") == "email"


# --------------------------------------------------------------------------- #
# The invariant: the old promote rule lands in "strong"
# --------------------------------------------------------------------------- #

def test_one_rare_overlapping_identity_fact_is_strong(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "http.body_sha256", "b" * 64)
    assert R.score_candidate(con, "c", "c.example").band == "strong"


def test_two_independent_structural_facts_are_strong(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "dns.soa_email", "ops@evil.example")
        add(con, host, "whois.registrant_email", "reg@evil.example")
    result = R.score_candidate(con, "c", "c.example")
    assert result.band == "strong", result.to_dict()


def test_one_structural_fact_is_not_strong(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "dns.soa_email", "ops@evil.example")
    assert R.score_candidate(con, "c", "c.example").band == "probable"


def test_two_sans_off_one_certificate_are_one_fact(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "tls.san", "one.evil.example")
        add(con, host, "tls.san", "two.evil.example")
    assert R.score_candidate(con, "c", "c.example").band != "strong"


def test_an_asn_adds_nothing(con):
    seed(con, "c", "198.51.100.1")
    for host in ("198.51.100.1", "198.51.100.2"):
        add(con, host, "net.asn", "64500")
        add(con, host, "net.country", "US")
    result = R.score_candidate(con, "c", "198.51.100.2")
    assert result.score == 0.0 and result.pairs, "shown as evidence, worth nothing"


def test_a_provider_scale_value_adds_nothing(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "http.body_sha256", "c" * 64)
    con.execute("INSERT INTO selector_stats VALUES ('http.body_sha256', ?, 2, 50000, "
                "'webamon', NULL)", ["c" * 64])
    assert R.score_candidate(con, "c", "c.example").score == 0.0


def test_a_priced_value_counts_for_less_the_commoner_it_is(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "http.body_sha256", "d" * 64)
    unpriced = R.score_candidate(con, "c", "c.example").score
    con.execute("INSERT INTO selector_stats VALUES ('http.body_sha256', ?, 2, 500, "
                "'webamon', NULL)", ["d" * 64])
    assert R.score_candidate(con, "c", "c.example").score < unpriced


# --------------------------------------------------------------------------- #
# Demotions
# --------------------------------------------------------------------------- #

def test_a_default_certificate_is_not_identity(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        add(con, host, "tls.cert_sha256", "e" * 64)
        add(con, host, "tls.default_subject", "CN=localhost, O=MyOrg, C=RU")
    result = R.score_candidate(con, "c", "c.example")
    cert = [p for p in result.pairs if p.selector_type == "tls.cert_sha256"][0]
    assert cert.cls == "behavioural" and result.band != "strong"


def test_a_catch_all_certificate_is_the_address_not_a_deployment(con):
    """37.1.220.158 served one self-signed cert for 248 unrelated names."""
    seed(con, "c", "myship.7-11.com.tw.v4n.top")
    hosts = ["myship.7-11.com.tw.v4n.top", "myship.7-11.com.tw.5u6.top",
             "t5yvdrf.bond", "g1u9hm.top", "nldwmxll.bond", "rsd41r.top"]
    for host in hosts:
        add(con, host, "tls.cert_sha256", "36fe" + "0" * 60)
        add(con, host, "net.resolved_ip", "37.1.220.158")
    result = R.score_candidate(con, "c", "myship.7-11.com.tw.5u6.top")
    cert = [p for p in result.pairs if p.selector_type == "tls.cert_sha256"][0]
    assert cert.cls == "behavioural" and "catch-all" in cert.note
    assert result.band != "strong"


# --------------------------------------------------------------------------- #
# Regression: JadeProx, 192.252.186.62, dates from Validin 2026-10-16
# --------------------------------------------------------------------------- #

TRIO_WINDOW = ("2026-04-09", "2026-10-16")


@pytest.fixture
def jadeprox(con):
    seed(con, "jadeprox", "update-trellix.com")
    add(con, "update-trellix.com", "net.historical_ip", "192.252.186.62",
        first=TRIO_WINDOW[0], last=TRIO_WINDOW[1], source="validin_dns")
    add(con, "update-trellix.com", "net.resolved_ip", "192.252.186.62")
    add(con, "update-trellix.com", "tls.jarm", "0" * 62)
    return con


def test_kakatown_a_2019_tenant_is_noise(jadeprox):
    add(jadeprox, "kakatown.com", "net.historical_ip", "192.252.186.62",
        first="2019-08-26", last="2020-08-02", source="validin_dns")
    result = R.score_candidate(jadeprox, "jadeprox", "kakatown.com")
    assert result.band == "noise" and result.score < 0.001
    assert result.pairs[0].gap_days > 2000


def test_the_7_eleven_pair_adjacent_tenancy_is_below_weak(jadeprox):
    add(jadeprox, "myship.7-11.com.tw.v4n.top", "net.historical_ip", "192.252.186.62",
        first="2026-03-13", last="2026-03-20", source="validin_dns")
    add(jadeprox, "kakatown.com", "net.historical_ip", "192.252.186.62",
        first="2019-08-26", last="2020-08-02", source="validin_dns")
    seven = R.score_candidate(jadeprox, "jadeprox", "myship.7-11.com.tw.v4n.top")
    kaka = R.score_candidate(jadeprox, "jadeprox", "kakatown.com")
    assert seven.band in ("noise", "weak")
    assert seven.score > kaka.score, "adjacent beats five years apart"


def test_a_vendor_trio_sibling_is_at_least_probable(jadeprox):
    add(jadeprox, "update-crowdstrike.com", "net.historical_ip", "192.252.186.62",
        first=TRIO_WINDOW[0], last=TRIO_WINDOW[1], source="validin_dns")
    add(jadeprox, "update-crowdstrike.com", "net.resolved_ip", "192.252.186.62")
    add(jadeprox, "update-crowdstrike.com", "tls.jarm", "0" * 62)
    result = R.score_candidate(jadeprox, "jadeprox", "update-crowdstrike.com")
    assert result.band in ("probable", "strong"), result.to_dict()


def test_rescore_records_every_candidate(jadeprox):
    add(jadeprox, "kakatown.com", "net.historical_ip", "192.252.186.62",
        first="2019-08-26", last="2020-08-02", source="validin_dns")
    E.file_candidate(jadeprox, "jadeprox", "kakatown.com", origin="validin",
                     decided_by="pivot")
    [result] = R.rescore_cluster(jadeprox, "jadeprox")
    assert E.membership(jadeprox, "jadeprox", "kakatown.com")["band"] == result.band


def test_pairs_between_names_what_two_indicators_share_and_when(jadeprox):
    add(jadeprox, "kakatown.com", "net.historical_ip", "192.252.186.62",
        first="2019-08-26", last="2020-08-02", source="validin_dns")
    result = R.pairs_between(jadeprox, "kakatown.com", "update-trellix.com")
    [pair] = result.pairs
    assert pair.selector_type == "net.historical_ip" and pair.gap_days > 2000


# --------------------------------------------------------------------------- #
# Fixes from the first dry run against live data (2026-10-16)
# --------------------------------------------------------------------------- #

def test_sharing_an_address_is_not_a_catch_all_of_that_address(con):
    """Every holder of an IP sits on that IP. The first dry run demoted the
    vendor trio's shared address to behavioural on exactly that logic."""
    seed(con, "c", "update-trellix.com")
    for host in ("update-trellix.com", "update-crowdstrike.com", "update-sentinelone.com",
                 "www.update-trellix.com", "www.update-crowdstrike.com", "x.example"):
        add(con, host, "net.resolved_ip", "192.252.186.62")
    pair = R.score_candidate(con, "c", "update-crowdstrike.com").pairs[0]
    assert pair.cls == "structural" and pair.note is None


def test_anything_measured_on_a_cdn_edge_weighs_nothing(con, monkeypatch):
    monkeypatch.setattr(R.cdn, "is_cdn", lambda ip: ip.startswith("104.21."))
    seed(con, "c", "m.example")
    for host in ("m.example", "104.21.60.187"):
        add(con, host, "tls.jarm", "1" * 62)
        add(con, host, "net.port_set", [80, 443, 2052, 8443])
    result = R.score_candidate(con, "c", "104.21.60.187")
    assert result.score == 0.0 and all("CDN" in p.note for p in result.pairs)


def test_behavioural_facts_alone_stay_inside_weak(con):
    seed(con, "c", "m.example")
    for host in ("m.example", "c.example"):
        for stype, value in (("tls.jarm", "2" * 62), ("tls.ja4s", "t130200_1302_a"),
                             ("tls.ja4ts", "65535_2-1-3_1460_8"), ("ssh.hassh_server", "h" * 32),
                             ("http.title", "Login"), ("net.port_set", [22, 443, 8443])):
            add(con, host, stype, value)
    result = R.score_candidate(con, "c", "c.example")
    assert result.score <= R.BEHAVIOURAL_CAP + 1e-9 and result.band == "weak"


def test_a_subdomain_of_a_seed_apex_carries_the_registration_link(con):
    seed(con, "c", "update-trellix.com")
    add(con, "www.update-trellix.com", "dns.apex", "update-trellix.com")
    for host in ("update-trellix.com", "www.update-trellix.com"):
        add(con, host, "net.resolved_ip", "192.252.186.62")
    result = R.score_candidate(con, "c", "www.update-trellix.com")
    assert "dns.apex" in result.artefacts and result.band == "strong", result.to_dict()


# --------------------------------------------------------------------------- #
# A selector whose value is itself a member
# --------------------------------------------------------------------------- #

def test_a_2019_tenant_of_a_seed_ip_is_noise(con):
    """The report seeds the IP; update-trellix.com shows it in use in 2026."""
    seed(con, "c", "192.252.186.62")
    add(con, "update-trellix.com", "net.resolved_ip", "192.252.186.62",
        first="2026-04-09", last="2026-10-16", source="validin_dns")
    add(con, "kakatown.com", "net.historical_ip", "192.252.186.62",
        first="2019-08-26", last="2020-08-02", source="validin_dns")
    result = R.score_candidate(con, "c", "kakatown.com")
    assert result.band == "noise" and result.pairs[0].member == "192.252.186.62"


def test_a_current_name_on_a_seed_ip_is_linked(con):
    seed(con, "c", "192.252.186.62")
    add(con, "192.252.186.62", "net.port_set", [8080], when=datetime(2026, 10, 10))
    add(con, "new-lure.example", "net.resolved_ip", "192.252.186.62",
        when=datetime(2026, 10, 12))
    assert R.score_candidate(con, "c", "new-lure.example").band == "probable"


def test_an_ip_a_seed_domain_resolves_to_is_linked(con):
    seed(con, "c", "turnkeyaiagents.com")
    add(con, "turnkeyaiagents.com", "net.resolved_ip", "75.98.162.139",
        when=datetime(2026, 9, 22))
    add(con, "75.98.162.139", "net.port_set", [80, 443], when=datetime(2026, 9, 24))
    result = R.score_candidate(con, "c", "75.98.162.139")
    assert result.band == "probable"
    assert any(p.member == "turnkeyaiagents.com" for p in result.pairs)
