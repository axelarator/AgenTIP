"""Tests for the graph layer that need no model.

Everything here is the deterministic half: ranking, suppression, budget
allocation, actor resolution, finding parsing, tracing. The specialists
themselves are exercised by running the graph for real - see the README's
verification section - because what they decide is the part a stub cannot
check.
"""
from __future__ import annotations

import json
from datetime import datetime

import duckdb
import pytest

from cti.store.observations import upsert_observation
from cti.store.schema import init_schema
from graph.nodes.analyze import _resolve_actor
from graph.nodes.rank import ITEMS_PER_FAMILY, rank
from graph.sdk import load_prompt, parse_findings
from graph.state import ATTRIBUTE_FAMILY, FAMILY_ATTRIBUTES


def _digest(**sections):
    base = {"attribute_changes": [], "asn_pivots": [], "open_directories": []}
    base.update(sections)
    return base


def _change(indicator, attribute, change_type, actor="A", confidence="medium", **kw):
    row = {"indicator_value": indicator, "attribute": attribute,
           "change_type": change_type, "actor": actor, "confidence": confidence,
           "detected_at": "2026-09-18 06:00:00", "old_value": None, "new_value": None}
    row.update(kw)
    return row


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #

def test_every_attribute_has_exactly_one_owning_specialist():
    """A row routed to two specialists would be analyzed twice and could
    produce two contradictory findings about the same change."""
    seen = set()
    for attributes in FAMILY_ATTRIBUTES.values():
        overlap = seen & set(attributes)
        assert not overlap, f"attributes owned by two families: {overlap}"
        seen |= set(attributes)


def test_every_specialist_has_a_prompt_and_every_prompt_mentions_its_attributes():
    for family, attributes in FAMILY_ATTRIBUTES.items():
        prompt = load_prompt(family)
        assert len(prompt) > 500, f"{family} prompt looks empty"
        for attribute in attributes:
            assert attribute in prompt, f"{family} prompt never mentions {attribute}"


def test_every_family_has_an_item_budget():
    for family in FAMILY_ATTRIBUTES:
        assert family in ITEMS_PER_FAMILY, f"{family} has no item budget"


# --------------------------------------------------------------------------- #
# Suppression
# --------------------------------------------------------------------------- #

def test_shared_hosting_rows_are_dropped_before_any_model_sees_them(monkeypatch, tmp_path):
    """The whole point of ranking in code: a Cloudflare address listing
    other tenants' domains is not a signal, and used to be paid for in
    context anyway."""
    db = tmp_path / "t.duckdb"
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(db))
    con = duckdb.connect(str(db))
    init_schema(con)
    upsert_observation(con, observed_at=datetime(2026, 9, 1), source="rdap",
                       indicator_value="104.21.60.187", asn=13335, netname="CLOUDFLARENET")
    upsert_observation(con, observed_at=datetime(2026, 9, 1), source="rdap",
                       indicator_value="208.91.112.55", asn=40934, netname="FORTINET")
    con.close()

    digest = _digest(attribute_changes=[
        _change("104.21.60.187", "ip_hostnames", "ip_hostnames_changed"),
        _change("208.91.112.55", "ip_hostnames", "ip_hostnames_changed"),
    ])
    items = {i.indicator: i for i in rank({"digest_json": digest})["items"]}
    assert items["104.21.60.187"].suppressed, "CDN row should be suppressed"
    assert not items["208.91.112.55"].suppressed, (
        "a dedicated host is not shared hosting - suppressing it would drop "
        "the exact kind of co-tenancy lead this signal exists for")


def test_hostname_half_of_the_shared_hosting_rule_is_wired_up():
    """pivot.is_shared_hosting_hostname had no caller at all, so a PTR
    flip on something plainly named like a CDN edge was weighed the same
    as one on dedicated infrastructure."""
    digest = _digest(attribute_changes=[
        _change("1.2.3.4", "ptr", "ptr_changed",
                old_value=json.dumps("server-1.cloudfront.net"),
                new_value=json.dumps("server-2.cloudfront.net")),
    ])
    item = rank({"digest_json": digest})["items"][0]
    assert item.suppressed


def test_first_seen_rows_are_not_changes():
    digest = _digest(attribute_changes=[_change("x.com", "cert", "first_seen")])
    assert rank({"digest_json": digest})["items"][0].suppressed


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #

def test_one_indicator_does_not_consume_the_whole_budget():
    """The digest window is days wide, so a domain that moves daily
    contributes one row per day."""
    digest = _digest(attribute_changes=[
        _change("x.com", "resolved_ip", "resolved_ip_changed", detected_at=f"2026-09-1{d} 06:00:00")
        for d in range(1, 8)
    ])
    selected = rank({"digest_json": digest})["ranked"]["infra_change"]
    assert len(selected) == 1
    assert selected[0].detected_at.startswith("2026-09-17")


def test_open_directory_files_are_not_collapsed_into_one():
    """Every file in a directory shares the indicator and the attribute,
    so keying dedup on those alone loses the whole directory but one."""
    digest = _digest(open_directories=[
        {"indicator_value": "1.2.3.4", "actor": "A", "url": "http://1.2.3.4/",
         "path": name, "first_seen": "2026-09-18 06:00:00"}
        for name in ("beacon.pem", "cmd1.txt", "backup.tar.gz")
    ])
    selected = rank({"digest_json": digest})["ranked"]["opendir"]
    assert len(selected) == 3


def test_a_wide_family_gets_a_wider_budget():
    """hosting owns four attribute types. A flat budget spent both its
    slots on fingerprints and never showed it a hosted-domain lead."""
    digest = _digest(attribute_changes=[
        _change("a.com", "webamon_fingerprint", "webamon_fingerprint_changed", confidence="high"),
        _change("b.com", "webamon_fingerprint", "webamon_fingerprint_changed", confidence="high"),
        _change("1.2.3.4", "ip_hostnames", "ip_hostnames_changed"),
        _change("c.com", "subdomains", "subdomains_changed", confidence="low"),
    ])
    selected = rank({"digest_json": digest})["ranked"]["hosting"]
    assert {i.attribute for i in selected} == {
        "webamon_fingerprint", "ip_hostnames", "subdomains"}


def test_a_family_with_nothing_to_do_is_given_nothing():
    digest = _digest(attribute_changes=[_change("x.com", "cert", "cert_issuer_changed")])
    ranked = rank({"digest_json": digest})["ranked"]
    assert ranked["cert_tls"] and not ranked["opendir"] and not ranked["hosting"]


# --------------------------------------------------------------------------- #
# Actor attribution
# --------------------------------------------------------------------------- #

def test_actor_comes_from_the_indicators_not_the_first_item():
    """Defaulting to items[0].actor filed a DragonForce finding under
    JadeProx. persist() writes this into save_correlation, so the result
    is a durable correlation against the wrong threat actor."""
    by = {"a.com": "DragonForce", "b.com": "JadeProx"}
    assert _resolve_actor("JadeProx", ["a.com"], by) == "DragonForce"
    assert _resolve_actor(None, ["a.com"], by) == "DragonForce"


def test_a_finding_spanning_two_actors_gets_no_actor():
    by = {"a.com": "DragonForce", "b.com": "JadeProx"}
    assert _resolve_actor("JadeProx", ["a.com", "b.com"], by) is None


def test_a_claimed_actor_is_kept_when_nothing_contradicts_it():
    assert _resolve_actor("STAC4749", ["unknown.com"], {}) == "STAC4749"


# --------------------------------------------------------------------------- #
# Reply parsing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("reply,expected", [
    ('[{"headline": "a"}]', 1),
    ('```json\n[{"headline": "a"}]\n```', 1),
    ('Here you go:\n[{"headline": "a"}]\nhope that helps', 1),
    ('[]', 0),
    ('{"headline": "a"}', 1),
])
def test_findings_are_parsed_from_the_shapes_models_actually_emit(reply, expected):
    parsed, error = parse_findings(reply)
    assert error is None and len(parsed) == expected


def test_a_reply_with_no_json_is_an_error_not_a_silent_empty():
    parsed, error = parse_findings("I could not find anything of note today.")
    assert parsed == [] and error
