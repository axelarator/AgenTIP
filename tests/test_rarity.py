"""Rarity and expansion: what a particular VALUE is worth, and the rule.

Class caps what a selector TYPE can prove. These cover the part class cannot
express - `ns1.evil-actor.com` and `ns1.cloudflare.com` are the same type and
mean entirely different things - and the corroboration rule that decides
whether a link is actionable.
"""
from __future__ import annotations

from datetime import datetime

import duckdb
import pytest

from cti.store import expand, rarity
from cti.store import selectors as S
from cti.store.schema import init_schema

DAY = datetime(2026, 9, 20, 6, 0)


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    yield c
    c.close()


def add(con, indicator, selector_type, value, actor="A"):
    S.record(con, indicator_value=indicator, selector_type=selector_type,
             selector_value=value, observed_at=DAY, actor=actor,
             indicator_type="domain", source="test")


# --------------------------------------------------------------------------- #
# Provider-scale values
# --------------------------------------------------------------------------- #

def test_the_provider_list_is_vendored():
    assert rarity._mass_providers()


@pytest.mark.parametrize("nameservers", [
    "ns1.dnsowl.com,ns2.dnsowl.com,ns3.dnsowl.com",   # NameSilo's free DNS
    "hera.ns.cloudflare.com,elliott.ns.cloudflare.com",
    "ns-1.awsdns.com,ns-2.awsdns.com",
])
def test_mass_provider_nameservers_are_not_a_link(nameservers):
    assert rarity.is_mass_dns(nameservers)


def test_a_custom_nameserver_set_is_a_link():
    assert not rarity.is_mass_dns("ns1.evil-actor.com,ns2.evil-actor.com")


def test_one_mass_provider_member_taints_the_whole_set():
    """A set is only a registration link if every member is custom."""
    assert rarity.is_mass_dns("ns1.custom.com,hera.ns.cloudflare.com")


def test_a_provider_scale_value_cannot_promote_even_though_its_type_can(con):
    """dns.ns_set is structural, and Cloudflare's nameservers are still not a
    link. Class alone cannot express this."""
    add(con, "a.example", "dns.ns_set", ["hera.ns.cloudflare.com"])
    add(con, "b.example", "dns.ns_set", ["hera.ns.cloudflare.com"])
    rarity.refresh(con)
    verdict = rarity.assess(con, "dns.ns_set", ["hera.ns.cloudflare.com"])
    assert not verdict["can_promote"] and verdict["provider_scale"]
    assert S.shared(con) == []


def test_a_custom_nameserver_set_does_promote(con):
    add(con, "a.example", "dns.ns_set", ["ns1.evil-actor.com", "ns2.evil-actor.com"])
    add(con, "b.example", "dns.ns_set", ["ns2.evil-actor.com", "ns1.evil-actor.com"])
    assert [r["selector_type"] for r in S.shared(con)] == ["dns.ns_set"]


def test_registrar_is_corroboration_only():
    """Its own description said "useful only as the second selector beside a
    stronger one" while it was classed structural, and NameSilo duly appeared
    as a six-indicator link in a live sweep."""
    assert S.selector_class("whois.registrar") == "behavioural"
    assert not S.can_promote("whois.registrar")


# --------------------------------------------------------------------------- #
# selector_stats
# --------------------------------------------------------------------------- #

def test_refresh_counts_indicators_per_value(con):
    for host in ("a.example", "b.example", "c.example"):
        add(con, host, "tls.cert_sha256", "shared")
    add(con, "d.example", "tls.cert_sha256", "lonely")
    rarity.refresh(con)
    assert rarity.assess(con, "tls.cert_sha256", "shared")["local_count"] == 3
    assert rarity.assess(con, "tls.cert_sha256", "lonely")["local_count"] == 1


def test_refresh_does_not_clobber_a_global_count(con):
    """A local refresh must not erase what a global source filled in."""
    add(con, "a.example", "tls.cert_sha256", "x")
    rarity.refresh(con)
    con.execute("UPDATE selector_stats SET global_count = 42, global_source = 'test'")
    rarity.refresh(con)
    assert rarity.assess(con, "tls.cert_sha256", "x")["global_count"] == 42


def test_apex_spread_counts_registered_domains_not_hosts(con):
    """Six hosts under one apex is one operator's infrastructure; six hosts
    under six apexes sharing a value is a statement about the value."""
    for host in ("a.one.example", "b.one.example", "c.one.example"):
        add(con, host, "whois.registrar", "R")
    assert rarity.apexes_for(con, "whois.registrar", "R") == 1
    for host in ("x.two.example", "y.three.example"):
        add(con, host, "whois.registrar", "R")
    assert rarity.apexes_for(con, "whois.registrar", "R") == 3


# --------------------------------------------------------------------------- #
# The corroboration rule
# --------------------------------------------------------------------------- #

def test_one_identity_selector_promotes(con):
    """A shared content digest means both hosts were configured from the same
    source. That is enough on its own."""
    for host in ("a.example", "b.example"):
        add(con, host, "http.body_sha256", "a" * 64)
    [candidate] = expand.candidates_for(con, "a.example")
    assert candidate.promoted and "identity" in candidate.reason


def test_two_independent_structural_selectors_promote(con):
    for host in ("a.example", "b.example"):
        add(con, host, "dns.apex", "shared.example")
        add(con, host, "tls.serial", "0A:1B")
    [candidate] = expand.candidates_for(con, "a.example")
    assert candidate.promoted and "independent structural" in candidate.reason


def test_one_structural_selector_does_not_promote(con):
    """Co-residency alone can be shared hosting we failed to detect."""
    for host in ("a.example", "b.example"):
        add(con, host, "net.resolved_ip", "193.29.58.192")
    [candidate] = expand.candidates_for(con, "a.example")
    assert not candidate.promoted
    assert "needs a second" in candidate.reason


def test_two_selectors_of_the_same_type_are_one_fact(con):
    """Two SANs off one certificate are one fact, not two."""
    for host in ("a.example", "b.example"):
        add(con, host, "tls.san", "first.example")
        add(con, host, "tls.san", "second.example")
    [candidate] = expand.candidates_for(con, "a.example")
    assert not candidate.promoted, "same-type selectors must not stack"


def test_corroborating_selectors_never_promote_however_many(con):
    for host in ("a.example", "b.example"):
        add(con, host, "http.server", "nginx")
        add(con, host, "tls.issuer", "CN = Test CA")
        add(con, host, "http.title", "Panel")
        add(con, host, "whois.registrar", "NameSilo, LLC")
    assert expand.candidates_for(con, "a.example") == [] or not any(
        c.promoted for c in expand.candidates_for(con, "a.example"))


def test_a_promoted_candidate_still_reports_its_corroboration(con):
    """The weak signals describe the finding even though they cannot make it."""
    for host in ("a.example", "b.example"):
        add(con, host, "http.body_sha256", "a" * 64)
        add(con, host, "http.server", "nginx")
    [candidate] = expand.candidates_for(con, "a.example")
    assert candidate.promoted
    assert ("http.server", "nginx") in candidate.corroborating


def test_expansion_reports_why_a_value_is_unusable(con):
    add(con, "a.example", "whois.registrar", "NameSilo, LLC")
    add(con, "b.example", "whois.registrar", "NameSilo, LLC")
    rarity.refresh(con)
    [hit] = expand.from_selector(con, "whois.registrar", "NameSilo, LLC",
                                 exclude="a.example")
    assert not hit["usable_as_lead"] and "corroboration-only" in hit["why_not"]


def test_expansion_is_local_and_contacts_nothing(con, monkeypatch):
    """The cheapest expansion, and the one that should always run first."""
    import socket

    def blocked(*a, **k):
        raise AssertionError("local expansion must not touch the network")
    monkeypatch.setattr(socket.socket, "connect", blocked)

    for host in ("a.example", "b.example"):
        add(con, host, "http.body_sha256", "a" * 64)
    assert expand.candidates_for(con, "a.example")[0].promoted
