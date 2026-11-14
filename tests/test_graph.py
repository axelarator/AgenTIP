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
from graph.state import FAMILY_ATTRIBUTES


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


# --------------------------------------------------------------------------- #
# Lifecycle and renewal suppression
# --------------------------------------------------------------------------- #

def test_a_routine_renewal_never_reaches_a_specialist():
    out = rank({"digest_json": _digest(attribute_changes=[
        _change("a.example", "cert_hash", "cert_renewed", confidence="low"),
        _change("b.example", "cert_hash", "cert_new", confidence="high")])})
    assert [i.indicator for i in out["ranked"]["cert_tls"]] == ["b.example"]
    renewal = next(i for i in out["items"] if i.indicator == "a.example")
    assert "renewal" in renewal.suppressed


def test_changes_on_dormant_hosts_are_dropped_but_links_are_not():
    digest = _digest(
        attribute_changes=[_change("quiet.example", "resolved_ip", "resolved_ip_changed"),
                           _change("live.example", "resolved_ip", "resolved_ip_changed")],
        lifecycle={"inactive": {"quiet.example": "dormant"}},
        infrastructure_links={"promoted": [
            {"seed": "quiet.example", "linked_to": "z.example", "reason": "r",
             "identity": [["tls.cert_sha256", "c"]], "structural": [], "corroborating": []}]})
    out = rank({"digest_json": digest})
    assert [i.indicator for i in out["ranked"]["infra_change"]] == ["live.example"]
    assert [i.indicator for i in out["ranked"]["infrastructure"]] == ["quiet.example"]


def test_lifecycle_moves_are_grouped_for_the_digest():
    from graph.nodes.collect import _lifecycle_moves
    moves = _lifecycle_moves([
        {"cluster": "kit", "ok": True, "result": {"lifecycle": [
            {"category": "domains", "value": "a", "from": "dormant", "to": "active"},
            {"category": "domains", "value": "b", "from": "active", "to": "dormant"},
            {"category": "ips", "value": "c", "from": "dormant", "to": "retired"}]}},
        {"cluster": "bad", "ok": False, "error": "x"}])
    assert [m["value"] for m in moves["reactivated"]] == ["a"]
    assert [m["value"] for m in moves["dormant"]] == ["b"]
    assert [m["value"] for m in moves["retired"]] == ["c"]


def test_the_digest_leads_with_reactivations_and_new_candidates():
    from datetime import date
    from cti.tracking import digest
    sections = {
        "lifecycle": {"reactivated": [{"cluster": "kit", "value": "back.example",
                                       "from": "retired", "to": "active"}],
                      "dormant": [{"cluster": "kit", "value": "q.example"}],
                      "retired": [], "inactive": {"q.example": "dormant"}},
        "coverage_expansion": {"filed_total": 1, "clusters": {"kit": {"filed": [
            {"value": "new.example", "candidate_linked_to": "known.example",
             "candidate_reason": "1 identity fact(s) (webamon.fp_ssl)",
             "discovered_via": "webamon.fp_ssl:abc"}]}}},
    }
    assert digest._has_signals(sections)
    body = digest.write(date(2026, 10, 5), sections).read_text()
    assert "Reactivated infrastructure" in body and "back.example" in body
    assert "New candidates" in body and "new.example" in body
    assert "- kit: 1 dormant" in body


def test_a_quiet_hosts_only_day_stays_quiet():
    """Hosts going dormant is routine; it must not wake Stage B on its own."""
    from cti.tracking import digest
    assert not digest._has_signals({"lifecycle": {"dormant": [{"cluster": "k", "value": "v"}]}})


# --------------------------------------------------------------------------- #
# A specialist that runs out of turns still answers (2026-10-17)
# --------------------------------------------------------------------------- #

def test_a_specialist_out_of_turns_answers_without_tools(monkeypatch):
    import asyncio

    from graph import sdk
    from graph.nodes import analyze
    from graph.state import Item

    calls = []

    async def fake_run_turn(**kw):
        calls.append(kw)
        if kw["allowed_tools"]:
            return sdk.TurnResult(text="", error="ResultError: Claude Code returned an error "
                                                 "result: Reached maximum number of turns (6)")
        return sdk.TurnResult(text='[{"headline": "cert rotated", "detail": "d", '
                                   '"indicators": ["x.example"], "confidence": "low"}]')

    monkeypatch.setattr(analyze, "run_turn", fake_run_turn)
    monkeypatch.setattr(analyze, "load_prompt", lambda family: "prompt")
    node = analyze.make_specialist("cert_tls")
    item = Item(family="cert_tls", attribute="cert_hash", actor="A", indicator="x.example",
                change_type="cert_new", confidence="medium", detected_at=None,
                old_value=None, new_value=None)
    out = asyncio.run(node({"day": "2026-10-17", "ranked": {"cert_tls": [item]}}))
    assert [f.headline for f in out["findings"]] == ["cert rotated"]
    assert "6-turn limit" in out["errors"][0]
    assert calls[1]["allowed_tools"] == [] and calls[1]["max_turns"] == 1


# --------------------------------------------------------------------------- #
# The timeline's rows reach a specialist
# --------------------------------------------------------------------------- #

def _timeline_digest(**timeline):
    return {"digest_json": _digest(day="2026-11-13", timeline=timeline)}


def _port_row(target, **kw):
    row = {"target": target, "actor": "A", "memberships": ["a:seed"], "opened": [],
           "closed": [], "flapped": [], "open_now": [], "at": "2026-11-13T06:03:00"}
    row.update(kw)
    return row


def test_port_changes_from_the_scheduled_scans_reach_a_specialist():
    """72 closures were recorded on 2026-11-13 and no specialist was shown
    one: only an on-demand rescan produced a `ports` row."""
    out = rank(_timeline_digest(port_changes=[
        _port_row("pulled.example", closed=[8080], open_now=[22, 443]),
        _port_row("dark.example", closed=[80, 443]),
        _port_row("listener.example", opened=[4444], open_now=[22, 4444])]))

    items = out["ranked"]["infra_change"]
    kinds = {i.indicator: i.change_type for i in items}
    assert kinds == {"pulled.example": "service_ports_closed",
                     "dark.example": "service_went_dark",
                     "listener.example": "service_ports_opened"}
    assert all(i.attribute == "service_ports" and i.actor == "A" for i in items)
    # One service pulled among several is the weakest of the three.
    assert items[-1].indicator == "pulled.example"
    assert items[0].new_value["open_now"] is not None


def test_a_dormant_host_that_opens_a_port_is_not_suppressed():
    digest = _digest(day="2026-11-13",
                     lifecycle={"inactive": {"woke.example": "dormant",
                                             "asleep.example": "dormant"}},
                     timeline={"port_changes": [
                         _port_row("woke.example", opened=[8443], open_now=[8443]),
                         _port_row("asleep.example", closed=[80])]})
    ranked = rank({"digest_json": digest})["ranked"]["infra_change"]
    assert [i.indicator for i in ranked] == ["woke.example"]


def test_fingerprint_changes_and_divergences_go_to_the_presentation_specialist():
    out = rank(_timeline_digest(
        value_changes=[
            {"indicator": "c2.example", "actor": "A", "selector_type": "tls.spki_sha256",
             "class": "identity", "old_value": "a" * 64, "new_value": "b" * 64,
             "at": "2026-11-13T05:00:00", "vantage": "probe"},
            {"indicator": "c2.example", "actor": "A", "selector_type": "http.header_order",
             "class": "behavioural", "old_value": "a,b", "new_value": "b,a",
             "at": "2026-11-13T05:00:00", "vantage": "probe"}],
        client_divergences=[{"target": "kit.example", "actor": "A", "port": 443,
                             "diverged": "status:404>200", "at": "2026-11-13T05:00:00"}]))

    items = out["ranked"]["cert_tls"]
    # Two fingerprints changing on one host are two items, not one.
    assert [(i.indicator, i.attribute) for i in items] == [
        ("kit.example", "client_divergence"),
        ("c2.example", "fingerprint"), ("c2.example", "fingerprint")]
    key, order = items[1], items[2]
    assert key.new_value["selector_type"] == "tls.spki_sha256" and key.score > order.score
    assert key.old_value["value"] == "a" * 64


def test_a_candidate_band_move_is_read_even_on_a_day_full_of_links():
    from graph.nodes.rank import ATTRIBUTE_CAP

    links = [{"seed": f"a{n}.example", "linked_to": f"b{n}.example", "actor": "A",
              "score": 0.9, "band": "strong", "reason": "r", "identity": [],
              "structural": [], "corroborating": []} for n in range(30)]
    digest = _digest(day="2026-11-13",
                     infrastructure_links={"promoted": links, "held_back_total": 0},
                     timeline={"band_moves": [
                         {"cluster": "a", "entity": "rising.example", "actor": "A",
                          "from_band": "weak", "to_band": "strong", "from_score": 0.3,
                          "to_score": 0.86, "direction": "up"}]})

    items = rank({"digest_json": digest})["ranked"]["infrastructure"]

    assert sum(i.attribute == "selector_link" for i in items) == ATTRIBUTE_CAP["selector_link"]
    (move,) = [i for i in items if i.attribute == "candidate_band"]
    assert move.change_type == "candidate_band_up" and move.indicator == "rising.example"
    assert move.old_value == {"band": "weak", "score": 0.3}
    assert move.new_value == {"cluster": "a", "band": "strong", "score": 0.86}


def test_a_block_of_hosts_going_dark_does_not_crowd_out_the_address_that_moved():
    """On 2026-11-13, 31 tracked hosts had nothing left open."""
    from graph.nodes.rank import ATTRIBUTE_CAP

    dark = [_port_row(f"h{n:02d}.example", closed=[80]) for n in range(31)]
    digest = _digest(day="2026-11-13",
                     attribute_changes=[_change("moved.example", "resolved_ip",
                                                "resolved_ip_changed")],
                     timeline={"port_changes": dark + [
                         _port_row("z-listener.example", opened=[4444], open_now=[4444])]})

    items = rank({"digest_json": digest})["ranked"]["infra_change"]

    assert sum(i.attribute == "service_ports" for i in items) == ATTRIBUTE_CAP["service_ports"]
    assert items[0].indicator == "z-listener.example", "the new listener is shown first"
    assert "moved.example" in [i.indicator for i in items]


def test_an_intermediate_rotation_already_on_record_is_not_shown():
    le = "CN={}, O=Let's Encrypt, C=US"
    digest = _digest(attribute_changes=[
        _change("rotated.example", "cert", "cert_issuer_changed", confidence="high",
                old_value={"issuer": le.format("YR2"), "sans": ["rotated.example"]},
                new_value={"issuer": le.format("YR1"), "sans": ["rotated.example"]}),
        _change("rebuilt.example", "cert", "cert_issuer_changed", confidence="high",
                old_value={"issuer": le.format("YR2"), "sans": ["rebuilt.example"]},
                new_value={"issuer": "CN=Abcde, O=Fghijklm, C=ZZ",
                           "sans": ["rebuilt.example"]})])

    out = rank({"digest_json": digest})

    assert [i.indicator for i in out["ranked"]["cert_tls"]] == ["rebuilt.example"]
    (dropped,) = [i for i in out["items"] if i.suppressed]
    assert "intermediate rotation" in dropped.suppressed
