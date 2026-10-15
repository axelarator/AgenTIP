"""Phase 3: hunt rules, the scan-target queue, and candidate sources."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import yaml

from cti import store
from cti.netwatch import queue, rules
from cti.netwatch.candidates import ct, neighbourhood, pdns

NOW = datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# loading and validation
# --------------------------------------------------------------------------- #

def _write_rule(doc: dict, name: str = "r.yaml") -> None:
    (rules.rules_dir() / name).write_text(yaml.safe_dump(doc))


def test_load_filters_disabled_by_default():
    _write_rule({"id": "on", "enabled": True, "scope": ["snapshots"],
                 "where": {"all": [{"tls.jarm": "abc"}]}}, "on.yaml")
    _write_rule({"id": "off", "enabled": False, "scope": ["snapshots"],
                 "where": {"all": [{"tls.jarm": "def"}]}}, "off.yaml")
    assert [r.id for r in rules.load()] == ["on"]
    assert {r.id for r in rules.load(enabled_only=False)} == {"on", "off"}


def test_bad_rules_are_dropped_not_raised():
    _write_rule({"enabled": True, "where": {"all": [{"tls.jarm": "x"}]}}, "noid.yaml")
    _write_rule({"id": "noscope", "enabled": True, "scope": ["bogus"],
                 "where": {"all": [{"tls.jarm": "x"}]}}, "noscope.yaml")
    _write_rule({"id": "empty", "enabled": True, "scope": ["snapshots"],
                 "where": {}}, "empty.yaml")
    assert rules.load(enabled_only=False) == []


# --------------------------------------------------------------------------- #
# snapshot matching: compile to SQL over selectors + snapshots
# --------------------------------------------------------------------------- #

def _selector(con, indicator, stype, value, actor="APT-W"):
    store.selectors.record(con, indicator_value=indicator, selector_type=stype,
                           selector_value=value, observed_at=NOW, actor=actor,
                           source="test")


def _snapshot(con, target, port, open=True):
    store.upsert_service_snapshot(con, row={
        "scan_id": "s1", "scanned_at": NOW, "vantage": "probe", "profile": "hot",
        "target": target, "ip": target, "port": port, "open": open,
        "actor": "APT-W", "record": {}})


def test_rule_matches_on_all_terms_and_ports():
    with store.connect() as con:
        _selector(con, "203.0.113.1", "tls.jarm", "JARMVALUE")
        _selector(con, "203.0.113.1", "http.header_order", "server,date")
        _snapshot(con, "203.0.113.1", 443)
        # a decoy that shares only the JARM, on a port the rule excludes
        _selector(con, "203.0.113.9", "tls.jarm", "JARMVALUE")
        _snapshot(con, "203.0.113.9", 22)

    rule = rules.Rule(id="r", where={
        "all": [{"tls.jarm": "JARMVALUE"}, {"http.header_order": "server,date"}],
        "ports": [443, 8443]}, scope=["snapshots"], cluster="c")
    with store.connect(read_only=True) as con:
        hits = rules.evaluate(con, [rule])
    assert [h["indicator"] for h in hits] == ["203.0.113.1"]


def test_any_block_is_a_union():
    with store.connect() as con:
        _selector(con, "a", "tls.cert_sha256", "c" * 64)
        _selector(con, "a", "tls.subject_cn", "panel.evil")
        _selector(con, "b", "tls.cert_sha256", "c" * 64)   # no subject_cn
    rule = rules.Rule(id="r", where={
        "all": [{"tls.cert_sha256": "c" * 64}],
        "any": [{"tls.subject_cn": "panel.evil"}, {"tls.subject_cn": "other"}]},
        scope=["snapshots"])
    with store.connect(read_only=True) as con:
        hits = {h["indicator"] for h in rules.evaluate(con, [rule])}
    assert hits == {"a"}        # b lacks any of the `any` terms


def test_snapshot_scope_is_required_to_evaluate():
    with store.connect() as con:
        _selector(con, "a", "tls.jarm", "j")
    rule = rules.Rule(id="ct-only", where={"all": [{"tls.jarm": "j"}]},
                      scope=["ct"])
    with store.connect(read_only=True) as con:
        assert rules.evaluate(con, [rule]) == []


# --------------------------------------------------------------------------- #
# CT matching: a cert pre-filter
# --------------------------------------------------------------------------- #

def test_match_ct_on_san_regex_and_apex():
    entry = {"sans": ["mail3.evil.com", "www.evil.com"],
             "subject": "CN=mail3.evil.com", "issuer": "C=US, O=Let's Encrypt"}
    san_rule = rules.Rule(id="san", where={"all": [{"tls.san": r"^mail\d+\."}]},
                          scope=["ct"])
    apex_rule = rules.Rule(id="apex", where={"all": [{"dns.apex": "evil.com"}]},
                           scope=["ct"])
    miss = rules.Rule(id="miss", where={"all": [{"tls.san": r"^smtp\."}]},
                      scope=["ct"])
    hits = rules.match_ct(entry, [san_rule, apex_rule, miss])
    assert {h["rule"] for h in hits} == {"san", "apex"}
    assert hits[0]["names"] == ["mail3.evil.com", "www.evil.com"]


def test_match_ct_skips_rules_with_no_cert_term():
    entry = {"sans": ["x.evil.com"], "subject": "", "issuer": ""}
    jarm_only = rules.Rule(id="j", where={"all": [{"tls.jarm": "abc"}]},
                           scope=["ct"])
    assert rules.match_ct(entry, [jarm_only]) == []


# --------------------------------------------------------------------------- #
# suggestion
# --------------------------------------------------------------------------- #

def test_suggest_builds_a_draft_from_shared_rare_selectors():
    with store.connect() as con:
        for host in ("203.0.113.1", "203.0.113.2"):
            _selector(con, host, "tls.jarm", "RAREJARM")
            _selector(con, host, "http.server", "nginx")   # contextual: excluded
            _snapshot(con, host, 8443)
        store.selectors.record  # keep import used
    with store.connect(read_only=True) as con:
        out = rules.suggest(con, ["203.0.113.1", "203.0.113.2"], cluster="c")
    draft = out["draft"]
    assert draft is not None
    terms = [next(iter(t)) for t in draft["where"]["all"]]
    assert "tls.jarm" in terms and "http.server" not in terms
    assert draft["where"]["ports"] == [8443]
    assert draft["enabled"] is False


def test_suggest_needs_enough_hosts():
    with store.connect() as con:
        _selector(con, "203.0.113.1", "tls.jarm", "j")
    with store.connect(read_only=True) as con:
        out = rules.suggest(con, ["203.0.113.1"], cluster="c", min_hosts=2)
    assert out["draft"] is None


# --------------------------------------------------------------------------- #
# the scan-target queue
# --------------------------------------------------------------------------- #

def test_queue_drain_takes_matching_tiers_and_leaves_the_rest():
    queue.enqueue([{"value": "a.evil", "tier": "hot", "ports": [443]},
                   {"value": "10.0.0.5", "tier": "sweep", "ports": [443]}],
                  source="ct")
    hot = queue.drain(tiers={"hot"})
    assert [t["value"] for t in hot] == ["a.evil"]
    # the sweep target is still queued for the weekly pass
    assert queue.pending() == 1
    rest = queue.drain(tiers={"sweep"})
    assert [t["value"] for t in rest] == ["10.0.0.5"]
    assert queue.pending() == 0


def test_queue_drain_unions_ports_on_duplicate_values():
    queue.enqueue([{"value": "a.evil", "tier": "hot", "ports": [443]}], source="x")
    queue.enqueue([{"value": "a.evil", "tier": "hot", "ports": [8443]}], source="y")
    drained = queue.drain(tiers={"hot"})
    assert len(drained) == 1
    assert drained[0]["ports"] == [443, 8443]


# --------------------------------------------------------------------------- #
# CT candidate source: match -> resolve -> queue
# --------------------------------------------------------------------------- #

def test_ct_ingest_queues_resolvable_hits_only():
    rule = rules.Rule(id="san", cluster="c",
                      where={"all": [{"tls.san": r"\.evil\.com$"}]}, scope=["ct"])
    entries = [{"sans": ["live.evil.com", "dead.evil.com"], "subject": "", "issuer": ""},
               {"sans": ["unrelated.good.com"], "subject": "", "issuer": ""}]

    def resolve(name):
        return ["1.2.3.4"] if name == "live.evil.com" else None

    out = ct.ingest_entries(entries, rules=[rule], resolve=resolve)
    assert out["matched"] == 1
    assert [t["value"] for t in out["targets"]] == ["live.evil.com"]
    assert out["targets"][0]["tier"] == "hot"
    assert queue.pending() == 1


# --------------------------------------------------------------------------- #
# neighbourhood range maths
# --------------------------------------------------------------------------- #

def test_neighbourhood_range_narrows_to_a_slash24():
    import ipaddress
    # a /22 announcement narrows to the /24 holding the address
    net = neighbourhood._range_for("185.100.87.133", "185.100.84.0/22")
    assert net == ipaddress.ip_network("185.100.87.0/24")
    # a more specific announcement is kept
    net = neighbourhood._range_for("185.100.87.133", "185.100.87.128/25")
    assert net == ipaddress.ip_network("185.100.87.128/25")
    # ipv6 is not swept
    assert neighbourhood._range_for("2001:db8::1", "2001:db8::/48") is None
