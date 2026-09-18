"""Behavioural tests for the table-driven change detector.

These pin the quirks that the ten hand-written `_record_*_change`
functions encoded in prose, because collapsing them into one driver is
only safe if the quirks survive. Each test names the rule it protects.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import duckdb
import pytest

from cti.store.changes import SPECS, detect
from cti.store.observations import upsert_observation
from cti.store.schema import init_schema

DAY1 = datetime(2026, 9, 17, 6, 0)
DAY2 = datetime(2026, 9, 18, 6, 0)


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    init_schema(c)
    yield c
    c.close()


def changes(con):
    return [dict(zip([d[0] for d in con.description], r)) for r in con.execute(
        "SELECT attribute, change_type, old_value, new_value, confidence "
        "FROM attribute_changes ORDER BY id").fetchall()]


def seed(con, source, value, observed_at=DAY1, **fields):
    upsert_observation(con, observed_at=observed_at, indicator_value=value,
                       source=source, actor="A", **fields)


# --------------------------------------------------------------------------- #
# Every spec: first_seen, then no-change, then change
# --------------------------------------------------------------------------- #

CASES = {
    #  attribute            seed fields (day 1)                 new (day 2) same / different
    "ports": (dict(nmap_ports=[22, 443]), [22, 443], [22, 443, 8080]),
    "ptr": (dict(ptr_hostname="a.example"), "a.example", "b.example"),
    "resolved_ip": (dict(resolved_ip=["1.1.1.1"]), ["1.1.1.1"], ["2.2.2.2"]),
    "ip_hostnames": (dict(ip_hostnames=["x.com"]), ["x.com"], ["x.com", "y.com"]),
    "subdomains": (dict(subdomains=["a.x.com"]), ["a.x.com"], ["a.x.com", "b.x.com"]),
    "cert": (dict(tls_sha256="h1", tls_issuer="LE", tls_sans=["x.com"]),
             {"issuer": "LE", "sans": ["x.com"], "sha256": "h1"},
             {"issuer": "DigiCert", "sans": ["x.com"], "sha256": "h1"}),
    "cert_hash": (dict(tls_sha256="h1", tls_issuer="LE", tls_sans=["x.com"]),
                  {"sha256": "h1"}, {"sha256": "h2"}),
    "http": (dict(http_title="T", http_server="nginx"),
             {"title": "T", "server": "nginx"}, {"title": "T", "server": "Apache"}),
    "webamon_fingerprint": (dict(webamon_fingerprint_dom="d1", webamon_fingerprint_ssl="s1"),
                            {"dom": "d1", "ssl": "s1"}, {"dom": "d2", "ssl": "s1"}),
}


@pytest.mark.parametrize("attribute", sorted(CASES))
def test_no_baseline_emits_first_seen(con, attribute):
    _, same, _ = CASES[attribute]
    assert detect(con, attribute, indicator_value="t", actor="A",
                  observed_at=DAY2, new=same) == "first_seen"


@pytest.mark.parametrize("attribute", sorted(CASES))
def test_unchanged_records_nothing(con, attribute):
    fields, same, _ = CASES[attribute]
    seed(con, SPECS[attribute].source, "t", **fields)
    assert detect(con, attribute, indicator_value="t", actor="A",
                  observed_at=DAY2, new=same) is None
    assert changes(con) == []


@pytest.mark.parametrize("attribute", sorted(CASES))
def test_changed_records_a_row(con, attribute):
    fields, _, different = CASES[attribute]
    seed(con, SPECS[attribute].source, "t", **fields)
    change_type = detect(con, attribute, indicator_value="t", actor="A",
                         observed_at=DAY2, new=different)
    assert change_type not in (None, "first_seen")
    rows = changes(con)
    assert len(rows) == 1 and rows[0]["attribute"] == attribute


# --------------------------------------------------------------------------- #
# The documented quirks
# --------------------------------------------------------------------------- #

def test_same_issuer_same_sans_renewal_is_not_a_cert_change(con):
    """A routine renewal mints a new sha256 but keeps issuer and SANs.
    `cert` must stay silent; `cert_hash` must fire. Recording the renewal
    as a cert change is what would flood the digest."""
    seed(con, "tls_live", "x.com", tls_sha256="h1", tls_issuer="LE", tls_sans=["x.com"])
    renewed = {"issuer": "LE", "sans": ["x.com"], "sha256": "h2"}
    assert detect(con, "cert", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new=renewed) is None
    assert detect(con, "cert_hash", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new=renewed) == "cert_new"


def test_issuer_change_outranks_sans_change(con):
    seed(con, "tls_live", "x.com", tls_sha256="h1", tls_issuer="LE", tls_sans=["x.com"])
    assert detect(con, "cert", indicator_value="x.com", actor="A", observed_at=DAY2,
                  new={"issuer": "DigiCert", "sans": ["x.com", "y.com"], "sha256": "h2"}
                  ) == "cert_issuer_changed"


def test_cert_without_sha256_records_nothing(con):
    assert detect(con, "cert_hash", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"issuer": "LE", "sans": []}) is None


def test_subdomain_removals_alone_are_not_a_lead(con):
    """Names disappearing from subfinder/Wayback output is churn, not a
    signal. Only additions are recorded."""
    seed(con, "subdomains", "x.com", subdomains=["a.x.com", "b.x.com"])
    assert detect(con, "subdomains", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new=["a.x.com"]) is None


def test_subdomain_addition_surfaces_the_added_names(con):
    seed(con, "subdomains", "x.com", subdomains=["a.x.com"])
    detect(con, "subdomains", indicator_value="x.com", actor="A",
           observed_at=DAY2, new=["a.x.com", "b.x.com"])
    assert json.loads(changes(con)[0]["new_value"])["added"] == ["b.x.com"]


def test_ip_hostnames_surfaces_only_what_was_added(con):
    seed(con, "webamon", "1.2.3.4", ip_hostnames=["x.com"])
    detect(con, "ip_hostnames", indicator_value="1.2.3.4", actor="A",
           observed_at=DAY2, new=["x.com", "y.com"])
    assert json.loads(changes(con)[0]["new_value"])["added"] == ["y.com"]


def test_ptr_null_is_a_real_value_not_a_missing_baseline(con):
    """A 'ptr' row exists only when the lookup succeeded, so a NULL
    hostname means 'confirmed no PTR record'. Losing a PTR must register
    as a change, which is why the ptr spec has no non-NULL guard."""
    seed(con, "ptr", "1.2.3.4", ptr_hostname="host.example")
    assert detect(con, "ptr", indicator_value="1.2.3.4", actor="A",
                  observed_at=DAY2, new=None) == "ptr_changed"
    row = changes(con)[0]
    assert json.loads(row["old_value"]) == "host.example"
    assert json.loads(row["new_value"]) is None


def test_ptr_gaining_a_record_from_none_is_a_change(con):
    seed(con, "ptr", "1.2.3.4", ptr_hostname=None)
    assert detect(con, "ptr", indicator_value="1.2.3.4", actor="A",
                  observed_at=DAY2, new="new.example") == "ptr_changed"


def test_empty_resolved_ip_is_definitive_not_missing(con):
    """A domain going dead resolves to []. That is a change, not an
    inconclusive lookup."""
    seed(con, "dns_resolve", "x.com", resolved_ip=["1.1.1.1"])
    assert detect(con, "resolved_ip", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new=[]) == "resolved_ip_changed"


def test_infostealer_only_growth_counts(con):
    seed(con, "webamon_infostealers", "x.com", infostealer_count=10)
    assert detect(con, "infostealer_hits", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"count": 4, "urls": []}) is None
    assert detect(con, "infostealer_hits", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"count": 12, "urls": []}) == "infostealer_hits"


def test_infostealer_first_nonzero_is_recorded_not_baselined(con):
    """No first_seen for this one: the first hit is itself the news."""
    assert detect(con, "infostealer_hits", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"count": 3, "urls": ["u"]}) == "infostealer_hits"
    assert changes(con)[0]["change_type"] == "infostealer_hits"


def test_infostealer_sample_urls_are_capped_at_ten(con):
    detect(con, "infostealer_hits", indicator_value="x.com", actor="A",
           observed_at=DAY2, new={"count": 30, "urls": [f"u{i}" for i in range(30)]})
    assert len(json.loads(changes(con)[0]["new_value"])["sample_urls"]) == 10


def test_http_server_change_outranks_title_change(con):
    seed(con, "http_live", "x.com", http_title="T", http_server="nginx")
    assert detect(con, "http", indicator_value="x.com", actor="A", observed_at=DAY2,
                  new={"title": "T2", "server": "Apache"}) == "http_server_changed"


def test_http_title_only_change_is_low_confidence(con):
    seed(con, "http_live", "x.com", http_title="T", http_server="nginx")
    detect(con, "http", indicator_value="x.com", actor="A", observed_at=DAY2,
           new={"title": "T2", "server": "nginx"})
    assert changes(con)[0]["confidence"] == "low"


def test_empty_first_observation_is_not_worth_a_baseline_row(con):
    """An HTTP probe that got neither a title nor a Server header, and a
    cert grab with neither issuer nor SANs, are nothing - not a baseline."""
    assert detect(con, "http", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"title": None, "server": None}) is None
    assert detect(con, "cert", indicator_value="x.com", actor="A",
                  observed_at=DAY2, new={"issuer": None, "sans": []}) is None
    assert changes(con) == []


def test_stale_baseline_downgrades_confidence(con):
    """A baseline re-checked for the first time in months shouldn't read
    as a confident 'changed since yesterday'."""
    old_day = DAY2 - timedelta(days=200)
    seed(con, "webamon", "x.com", observed_at=old_day,
         webamon_fingerprint_dom="d1", webamon_fingerprint_ssl="s1")
    detect(con, "webamon_fingerprint", indicator_value="x.com", actor="A",
           observed_at=DAY2, new={"dom": "d2", "ssl": "s1"})
    assert changes(con)[0]["confidence"] == "medium"   # high, downgraded once


def test_fresh_baseline_keeps_the_base_confidence(con):
    seed(con, "webamon", "x.com", webamon_fingerprint_dom="d1", webamon_fingerprint_ssl="s1")
    detect(con, "webamon_fingerprint", indicator_value="x.com", actor="A",
           observed_at=DAY2, new={"dom": "d2", "ssl": "s1"})
    assert changes(con)[0]["confidence"] == "high"


def test_baseline_ignores_observations_at_or_after_the_detection_time(con):
    """`observed_at < ?`, strictly. A row written earlier in the same run
    must not become its own baseline."""
    seed(con, "nmap", "1.2.3.4", observed_at=DAY2, nmap_ports=[22])
    assert detect(con, "ports", indicator_value="1.2.3.4", actor="A",
                  observed_at=DAY2, new=[22, 443]) == "first_seen"


def test_rerunning_the_same_detection_does_not_duplicate(con):
    seed(con, "nmap", "1.2.3.4", nmap_ports=[22])
    for _ in range(3):
        detect(con, "ports", indicator_value="1.2.3.4", actor="A",
               observed_at=DAY2, new=[22, 443])
    assert len(changes(con)) == 1


def test_every_spec_has_a_confidence_prior_for_every_change_type(con):
    """Guards against adding a spec whose change_type is missing from
    CONFIDENCE_BASE - which would raise KeyError only on the day that
    attribute first moved."""
    from cti.store.changes import CONFIDENCE_BASE
    for name, spec in SPECS.items():
        if spec.fixed_confidence:
            continue
        fields, _, different = CASES[name]
        c = duckdb.connect(":memory:")
        init_schema(c)
        upsert_observation(c, observed_at=DAY1, indicator_value="t",
                           source=spec.source, actor="A", **fields)
        detect(c, name, indicator_value="t", actor="A", observed_at=DAY2, new=different)
        ct = c.execute("SELECT change_type FROM attribute_changes").fetchone()
        assert ct and ct[0] in CONFIDENCE_BASE, f"{name}: {ct}"
        c.close()
