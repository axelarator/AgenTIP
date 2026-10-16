"""The key:value hunt language - cti/store/hunt_query.py."""
from __future__ import annotations

from datetime import datetime

import duckdb
import pytest

from cti.netwatch import rules as hunt_rules
from cti.store import entities as E
from cti.store import hunt_query as H
from cti.store import selectors as S
from cti.store.schema import init_schema

NOW = datetime(2026, 10, 16)
JARM = "27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c"


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    add = lambda i, t, v, **k: S.record(c, indicator_value=i, selector_type=t,  # noqa: E731
                                        selector_value=v, observed_at=k.pop("when", NOW),
                                        source=k.pop("source", "observe"), **k)
    add("update-trellix.com", "net.resolved_ip", "192.252.186.62",
        first_seen="2026-04-09", last_seen="2026-10-16")
    add("kakatown.com", "net.historical_ip", "192.252.186.62",
        first_seen="2019-08-26", last_seen="2020-08-02", source="validin_dns")
    add("claude-pro.com", "tls.jarm", JARM.upper())
    add("claude-pro.com", "net.asn", "13335")
    add("c2.example", "tls.jarm", JARM, vantage="win116")
    add("c2.example", "net.port_set", [22, 443, 8443])
    add("c2.example", "tls.default_subject", "C = RU, ST = Default, CN = localhost")
    add("x.top", "tls.default_subject", "CN=localhost, ST=Default, C=RU")
    add("cert.example", "tls.cert_sha256", "a" * 64, when=datetime(2026, 9, 1))
    add("cert.example", "tls.cert_sha256", "b" * 64, when=datetime(2026, 10, 14))
    E.set_role(c, "jadeprox", "update-trellix.com", "seed", decided_by=E.REPORT)
    E.set_role(c, "jadeprox", "kakatown.com", "rejected", decided_by=E.ANALYST, reason="2019")
    E.file_candidate(c, "jadeprox", "c2.example", origin="t", decided_by="pivot")
    E.record_score(c, "jadeprox", "c2.example", score=0.6, band="probable", evidence=[])
    yield c
    c.close()


def hits(con, query):
    return sorted(r["indicator"] for r in H.run(con, query, now=NOW)["results"])


def test_a_selector_value_is_normalized_like_the_store(con):
    assert hits(con, f"tls.jarm:{JARM.upper()}") == ["c2.example", "claude-pro.com"]


def test_not_and_implicit_and(con):
    assert hits(con, f"tls.jarm:{JARM} NOT net.asn:13335") == ["c2.example"]
    assert hits(con, f"tls.jarm:{JARM} AND NOT net.asn:13335") == ["c2.example"]


def test_or_and_parentheses_and_precedence(con):
    assert hits(con, "net.asn:13335 OR net.port:8443") == ["c2.example", "claude-pro.com"]
    # AND binds tighter than OR
    assert hits(con, "net.asn:13335 OR tls.jarm:* AND net.port:8443") == [
        "c2.example", "claude-pro.com"]
    assert hits(con, "(net.asn:13335 OR tls.jarm:*) AND net.port:8443") == ["c2.example"]


def test_a_distinguished_name_matches_in_any_order(con):
    assert hits(con, 'tls.default_subject:"C=RU, ST=Default, CN=localhost"') == [
        "c2.example", "x.top"]


def test_regex_and_wildcard(con):
    assert hits(con, 'indicator:~"\\.top$"') == ["x.top"]
    assert hits(con, 'tls.default_subject:~"localhost"') == ["c2.example", "x.top"]
    assert hits(con, "tls.cert_sha256:*") == ["cert.example"]


def test_a_port_inside_a_port_set(con):
    assert hits(con, "net.port:8443") == ["c2.example"]
    assert hits(con, "net.port:3389") == []


def test_a_window_separates_a_2019_tenant_from_a_2026_one(con):
    both = "(net.resolved_ip:192.252.186.62 OR net.historical_ip:192.252.186.62)"
    assert hits(con, both) == ["kakatown.com", "update-trellix.com"]
    assert hits(con, both + " during:[2026-01-01,2026-12-31]") == ["update-trellix.com"]
    assert hits(con, both + " seen:<2021-01-01") == ["kakatown.com"]


def test_membership_terms(con):
    assert hits(con, "cluster:jadeprox") == ["c2.example", "kakatown.com",
                                             "update-trellix.com"]
    assert hits(con, "cluster:JadeProx role:candidate band:weak") == ["c2.example"]
    assert hits(con, "cluster:jadeprox band:strong") == []
    assert hits(con, "cluster:jadeprox NOT role:rejected") == ["c2.example",
                                                               "update-trellix.com"]


def test_vantage_and_type(con):
    assert hits(con, "vantage:win116") == ["c2.example"]
    assert "update-trellix.com" in hits(con, "type:domain")


def test_changed_finds_a_rotation_since(con):
    assert hits(con, "changed:tls.cert_sha256 since:7d") == ["cert.example"]
    assert hits(con, "changed:tls.cert_sha256 since:2026-10-15") == []


def test_hits_show_the_dated_spans_they_matched(con):
    out = H.run(con, "net.historical_ip:192.252.186.62", now=NOW)
    [hit] = out["results"]
    assert hit["matched"][0]["from"].startswith("2019-08-26")
    assert hit["memberships"] == [{"cluster": "jadeprox", "role": "rejected",
                                   "band": None, "score": None}]


@pytest.mark.parametrize("bad", [
    "foo:bar", "tls.jarm:", "role:boss", "band:great", "net.port:https",
    "(tls.jarm:*", "tls.jarm:* OR during:[2026-01-01,2026-02-01]",
    'indicator:~"("', "", "AND",
])
def test_bad_queries_say_why(con, bad):
    with pytest.raises(H.QueryError):
        H.run(con, bad, now=NOW)


def test_pairs_between_two_shows_the_gap(con):
    out = H.pairs(con, "kakatown.com", "update-trellix.com")
    [pair] = out["evidence"]
    assert pair["gap_days"] > 2000 and out["band"] == "noise"


def test_pairs_ranks_what_an_indicator_is_most_like(con):
    out = H.pairs(con, "claude-pro.com")
    assert [r["other"] for r in out["related"]] == ["c2.example"]
    assert out["related"][0]["memberships"][0]["role"] == "candidate"


# --------------------------------------------------------------------------- #
# A hunt rule can carry a query
# --------------------------------------------------------------------------- #

def test_a_rule_with_a_query_runs_the_same_engine(con, tmp_path):
    (tmp_path / "r.yaml").write_text(
        "id: localhost-c2\ncluster: jadeprox\nenabled: true\n"
        "query: 'tls.default_subject:~\"localhost\" AND NOT role:rejected'\n"
        "where: {ports: [8443]}\n")
    rules = hunt_rules.load(directory=tmp_path)
    assert rules[0].query
    service = {"scan_id": "s", "scanned_at": NOW, "vantage": "probe", "target": "c2.example",
               "port": 8443, "open": True}
    con.execute("INSERT INTO service_snapshots (scan_id, scanned_at, vantage, target, port, open) "
                "VALUES (?, ?, ?, ?, ?, ?)", list(service.values()))
    found = hunt_rules.evaluate(con, rules)
    assert [h["indicator"] for h in found] == ["c2.example"]
    assert found[0]["terms"][0][0] == "query"


def test_a_rule_whose_query_does_not_parse_is_skipped(tmp_path):
    (tmp_path / "r.yaml").write_text("id: broken\nenabled: true\nquery: 'nope:1'\n")
    assert hunt_rules.load(directory=tmp_path) == []
