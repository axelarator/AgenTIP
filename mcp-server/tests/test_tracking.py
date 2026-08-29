"""Tests for the cti_tools.tracking actor-tracking layer. Run with:

    cd mcp-server && source .venv/bin/activate && pip install -e '.[test]'
    pytest tests/test_tracking.py
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta

import duckdb
import pytest

from contextlib import asynccontextmanager

from cti_tools import core, pivot
from cti_tools.tracking import analytics, digest, enrich, hl_mcp, ingest, store
from cti_tools.tracking import opensearch_xref


# Anchored to the real clock, not a hardcoded date: several tests below
# (see the NOW/TODAY-tracks-real-clock note further down) compare stored
# timestamps against a real datetime.now()/current_date inside
# store.py/analytics.py, so a fixed literal here would silently drift out
# of every freshness window as real time passes.
TODAY = date.today()
NOW = datetime.combine(TODAY, datetime.min.time())


@pytest.fixture(autouse=True)
def isolated_tracking(tmp_path, monkeypatch):
    """Never touch the real data/tracking/ tree from tests."""
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "t.duckdb"))
    monkeypatch.setenv("CTI_TRACKING_INBOX", str(tmp_path / "inbox"))
    monkeypatch.setenv("CTI_TRACKING_ARCHIVE", str(tmp_path / "archive"))
    monkeypatch.setenv("CTI_TRACKING_DIGESTS", str(tmp_path / "digests"))
    yield tmp_path


@pytest.fixture(autouse=True)
def default_lifecycle_stubs(monkeypatch):
    """core.add_observable now runs a live asn/ports/cert enrichment
    sweep (core._sweep_lifecycle) for every genuinely new domain/ip it
    files - a handful of tests here seed a cluster observable via
    core.add_observable purely to exercise ingest/register logic, with
    no interest in enrichment content. Stub the sweep's network sources
    to fast, empty, no-network defaults so those stay hermetic; a test
    that does care (none currently in this file) can override the
    specific pivot.* function itself on top of this, same pattern as
    test_core.py's identically-named fixture."""
    monkeypatch.setattr(pivot, "rdap_lookup",
                        lambda value, kind: {"nameservers": [], "status": [], "events": []})
    monkeypatch.setattr(pivot, "resolve_host", lambda host: [])
    monkeypatch.setattr(pivot, "ripestat_lookup", lambda ip: {"asn": []})
    monkeypatch.setattr(pivot, "certspotter_lookup", lambda domain: {"hostnames": []})
    monkeypatch.setattr(pivot, "shodan_internetdb_lookup",
                        lambda ip: {"ports": [], "hostnames": [], "cpes": [], "tags": [], "vulns": []})


def _obs(con, ip, day, source="honeylabs", **kw):
    store.upsert_observation(
        con, observed_at=datetime.combine(day, datetime.min.time()),
        indicator_value=ip, source=source, **kw)


def test_schema_init_idempotent():
    with store.connect() as con:
        pass
    with store.connect() as con:
        tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    assert {"observations", "asn_changes", "actors", "correlations",
            "zeek_matches"} <= tables


def test_upsert_observation_dedupes_same_day():
    with store.connect() as con:
        _obs(con, "203.0.113.1", TODAY, hl_events=1)
        _obs(con, "203.0.113.1", TODAY, hl_events=9)
        _obs(con, "203.0.113.1", TODAY, source="rdap", asn=64512)
        count, events = con.execute(
            "SELECT count(*), max(hl_events) FROM observations "
            "WHERE source='honeylabs'").fetchone()
    assert (count, events) == (1, 9)


def test_upsert_actor_widens_and_unions():
    with store.connect() as con:
        store.upsert_actor(con, "A", NOW, asns=[1], ports=[80])
        store.upsert_actor(con, "A", NOW - timedelta(days=5), asns=[2])
        row = con.execute("SELECT first_observed, last_observed, known_asns, "
                          "known_ports FROM actors").fetchone()
    assert row[0] == NOW - timedelta(days=5)
    assert row[1] == NOW
    assert json.loads(row[2]) == [1, 2]
    assert json.loads(row[3]) == [80]


# ---------------------------------------------------------------- ingest

def test_ingest_csv_skips_bad_rows_and_archives(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "r.csv").write_text(
        "ip,actor,campaign,date_observed,source_url\n"
        "198.51.100.4,APT-X,c1,2026-08-19,https://example.com\n"
        "bogus,APT-X,,,\n"
        "198.51.100.5,,,,\n")
    with store.connect() as con:
        result = ingest.ingest_inbox(con)
        ips = [r[0] for r in con.execute(
            "SELECT indicator_value FROM observations").fetchall()]
        actors = [r[0] for r in con.execute(
            "SELECT actor_name FROM actors").fetchall()]
    assert result["rows_ingested"] == 1
    assert result["rows_skipped"] == 2
    assert ips == ["198.51.100.4"]
    assert actors == ["APT-X"]
    assert not list(inbox.iterdir())
    assert len(list((tmp_path / "archive").iterdir())) == 1


def test_ingest_json_and_rerun_is_idempotent(tmp_path):
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    rows = [{"ip": "198.51.100.6", "actor": "APT-Y",
             "date_observed": "2026-08-20"}]
    (inbox / "r.json").write_text(json.dumps(rows))
    with store.connect() as con:
        ingest.ingest_inbox(con)
        # same file dropped again later
        (inbox / "r.json").write_text(json.dumps(rows))
        ingest.ingest_inbox(con)
        count = con.execute("SELECT count(*) FROM observations").fetchone()[0]
    assert count == 1  # same (observed_at, ip, source) key upserts


def test_register_new_clusters_adds_only_untracked(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path / "clusters")
    core.DATA_DIR.mkdir()
    core.create_cluster("Existing Actor")
    core.add_observable("Existing Actor", "ips", "203.0.113.9", "test")
    core.create_cluster("New Actor")
    core.add_observable("New Actor", "ips", "198.51.100.10", "test")

    with store.connect() as con:
        # "Existing Actor" is already tracked from an earlier run/seed.
        store.upsert_actor(con, "Existing Actor", datetime(2026, 1, 1),
                           cluster_slug="existing-actor")
        result = ingest.register_new_clusters(con)
        rows = {r[0]: r for r in con.execute(
            "SELECT actor_name, first_observed, last_observed FROM actors").fetchall()}

    assert result == {"actors_registered": 1, "ips_by_actor": {"New Actor": 1}}
    assert set(rows) == {"Existing Actor", "New Actor"}
    # Untouched: register_new_clusters must not widen an already-tracked
    # actor's window just because the sweep ran today.
    assert rows["Existing Actor"][1] == datetime(2026, 1, 1)
    assert rows["Existing Actor"][2] == datetime(2026, 1, 1)


def test_register_new_clusters_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path / "clusters")
    core.DATA_DIR.mkdir()
    core.create_cluster("Solo Actor")
    core.add_observable("Solo Actor", "ips", "203.0.113.20", "test")

    with store.connect() as con:
        first = ingest.register_new_clusters(con)
        second = ingest.register_new_clusters(con)

    assert first["actors_registered"] == 1
    assert second == {"actors_registered": 0, "ips_by_actor": {}}


# ---------------------------------------------------------------- enrich

def _fake_hl(monkeypatch, lookup_fn, counts_fn=None):
    """Stand in for the HoneyLabs MCP session: open_session yields a
    dummy, lookup delegates to a sync per-IP function (which may raise
    PivotError, like the real one). By default the prefilter marks
    every IP active so tests exercise the per-IP path; pass counts_fn
    to control it."""
    @asynccontextmanager
    async def fake_session(api_key):
        yield None

    async def fake_lookup(session, ip):
        return lookup_fn(ip)

    async def fake_prefilter(session, ips):
        return counts_fn(ips) if counts_fn else {ip: 1 for ip in ips}

    monkeypatch.setattr(hl_mcp, "open_session", fake_session)
    monkeypatch.setattr(hl_mcp, "lookup", fake_lookup)
    monkeypatch.setattr(hl_mcp, "prefilter", fake_prefilter)


@pytest.fixture
def fake_net(monkeypatch):
    """Fake HoneyLabs/RIPEstat/RDAP in the live normalized shapes."""
    monkeypatch.setattr(enrich, "HL_MIN_INTERVAL", 0.0)
    monkeypatch.setenv("HONEYLABS_API_KEY", "k")
    hl = {"events": 120, "events_24h": 3, "events_7d": 20,
          "first_seen": "2026-07-01T00:00:00Z", "last_seen": "2026-08-20T12:00:00Z",
          "country": "NL", "asn": 64512, "as_org": "Test Org",
          "verdict": "malicious", "verdict_label": "scanner",
          "verdict_detail": None, "verdict_confidence": "high",
          "known_scanners": None,
          "ports": [{"port": 22, "count": 9}, {"port": 445, "count": 2}],
          "fingerprints": [], "cves": [], "malware": []}
    _fake_hl(monkeypatch, lambda ip: dict(hl))
    monkeypatch.setattr(pivot, "ripestat_lookup",
                        lambda ip: {"asn": [64512], "as_holder": "TEST-HOLDER",
                                    "geolocation": {"country": "NL"}})
    monkeypatch.setattr(pivot, "rdap_lookup",
                        lambda v, k: {"handle": "H", "name": "TEST-NET",
                                      "status": [], "events": [],
                                      "entities": [], "nameservers": None})
    return hl


def _seed_actor_ip(con, ip="203.0.113.7", actor="APT-X", day=None):
    _obs(con, ip, day or TODAY - timedelta(days=1), source="report:r.csv",
         actor=actor)
    store.upsert_actor(con, actor, NOW - timedelta(days=1))


def test_build_worklist_prioritizes_never_enriched():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _seed_actor_ip(con, "203.0.113.8")
        # .8 already enriched recently -> only .7 is due
        _obs(con, "203.0.113.8", TODAY, source="honeylabs", hl_events=1)
        worklist, rdap_due = enrich.build_worklist(con)
        assert worklist == ["203.0.113.7"]
        assert rdap_due == {"203.0.113.7"}
        # stale re-check joins the list behind never-enriched
        con.execute("UPDATE observations SET observed_at = ? "
                    "WHERE source = 'honeylabs'",
                    [NOW - timedelta(days=30)])
        worklist, _ = enrich.build_worklist(con)
        assert worklist == ["203.0.113.7", "203.0.113.8"]


def test_build_worklist_excludes_domain_observations():
    # pivot_cluster's Shodan/ThreatFox history logging writes domain
    # rows under the same actor as its IPs (indicator_type='domain');
    # HoneyLabs/RDAP/RIPEstat are IP-only, so a domain reaching the
    # worklist would blow up the HoneyLabs CIDR prefilter.
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "evil.example", TODAY, source="shodan",
             indicator_type="domain", actor="APT-X")
        worklist, rdap_due = enrich.build_worklist(con)
    assert worklist == ["203.0.113.7"]
    assert "evil.example" not in worklist
    assert rdap_due == {"203.0.113.7"}


def test_enrich_writes_rows_and_first_seen(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
    results, notes = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    # 2 = prefilter chunk + full lookup
    assert notes["hl_calls"] == 2 and notes["registry_calls"] == 1
    with store.connect() as con:
        summary = enrich.apply_results(con, results, TODAY)
        sources = {r[0] for r in con.execute(
            "SELECT source FROM observations").fetchall()}
        change = con.execute("SELECT change_type, new_asn, actor "
                             "FROM asn_changes").fetchone()
        ports = con.execute("SELECT known_ports FROM actors").fetchone()[0]
    assert summary["ips_enriched"] == 1
    assert {"honeylabs", "rdap"} <= sources
    assert change == ("first_seen", 64512, "APT-X")
    assert json.loads(ports) == [22, 445]


def test_asn_change_confidence_matrix(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
        # prior rdap-sourced baseline on a different ASN
        _obs(con, "203.0.113.7", TODAY - timedelta(days=2), source="rdap",
             asn=65000, netname="OLD-NET")
    results, _ = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    with store.connect() as con:
        summary = enrich.apply_results(con, results, TODAY)
    (change,) = summary["asn_changes"]
    assert change["change_type"] == "asn_change"
    assert change["old_asn"] == 65000 and change["new_asn"] == 64512
    assert change["confidence"] == "high"  # rdap both sides + HL corroborates


def test_asn_change_stale_baseline_downgrades(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
        _obs(con, "203.0.113.7", TODAY - timedelta(days=120), source="rdap",
             asn=65000, netname="OLD-NET")
    results, _ = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    with store.connect() as con:
        summary = enrich.apply_results(con, results, TODAY)
    assert summary["asn_changes"][0]["confidence"] == "medium"


def test_netname_change(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
        _obs(con, "203.0.113.7", TODAY - timedelta(days=2), source="rdap",
             asn=64512, netname="OLD-NET")
    results, _ = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    with store.connect() as con:
        summary = enrich.apply_results(con, results, TODAY)
    assert summary["asn_changes"][0]["change_type"] == "netname_change"


# ---------------------------------------------------- attribute_changes
# _record_port_change/_record_cert_change diff against the prior
# observations row for the same (indicator, source) - see
# store.latest_ports_for/latest_cert_for - so these helpers mirror the
# real call order _log_cluster_enrichment_history uses: write the dated
# shodan/certspotter observation first, then diff/record.

def _sweep_ports(con, ip, actor, day, ports):
    store.upsert_observation(con, observed_at=day, indicator_value=ip,
                             source="shodan", actor=actor, shodan_ports=ports or None)
    core._record_port_change(con, ip, actor, day, ports)


def _sweep_cert(con, domain, actor, day, issuer, hostnames):
    store.upsert_observation(con, observed_at=day, indicator_value=domain,
                             source="certspotter", actor=actor, cert_issuer=issuer,
                             cert_sibling_hostnames=hostnames or None)
    core._record_cert_change(con, domain, actor, day, {"issuer": issuer}, hostnames)


def test_record_port_change_first_seen_is_baseline_not_change():
    with store.connect() as con:
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW, [22, 443])
        row = con.execute(
            "SELECT change_type, confidence FROM attribute_changes").fetchone()
        recent = analytics.attribute_changes(con, days=1)
    assert row == ("first_seen", "medium")
    assert recent == []  # first_seen is excluded, like asn_changes'


def test_record_port_change_no_change_when_ports_identical():
    with store.connect() as con:
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), [22, 443])
        # order-independent: same set, different order, one day later
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW, [443, 22])
        count = con.execute("SELECT count(*) FROM attribute_changes").fetchone()[0]
    assert count == 1  # only the first_seen baseline - no spurious "change"


def test_record_port_change_detects_change():
    with store.connect() as con:
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), [22, 443])
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW, [8080])
        row = con.execute(
            "SELECT change_type, old_value, new_value, confidence "
            "FROM attribute_changes WHERE change_type = 'ports_changed'").fetchone()
    assert row[0] == "ports_changed"
    assert json.loads(row[1]) == [22, 443]
    assert json.loads(row[2]) == [8080]
    assert row[3] == "medium"


def test_record_port_change_stale_baseline_downgrades_confidence():
    with store.connect() as con:
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW - timedelta(days=120), [22])
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW, [8080])
        confidence = con.execute(
            "SELECT confidence FROM attribute_changes "
            "WHERE change_type = 'ports_changed'").fetchone()[0]
    assert confidence == "low"  # medium base, downgraded once for staleness


def test_record_cert_change_same_issuer_renewal_is_not_recorded():
    with store.connect() as con:
        _sweep_cert(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                   "Let's Encrypt", ["evil.example", "www.evil.example"])
        # same issuer, same siblings, just a later validity window - routine
        _sweep_cert(con, "evil.example", "APT-X", NOW,
                   "Let's Encrypt", ["evil.example", "www.evil.example"])
        count = con.execute(
            "SELECT count(*) FROM attribute_changes WHERE attribute = 'cert'"
            ).fetchone()[0]
    assert count == 1  # only the first_seen baseline


def test_record_cert_change_issuer_change_is_high_confidence():
    with store.connect() as con:
        _sweep_cert(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                   "Let's Encrypt", ["evil.example"])
        _sweep_cert(con, "evil.example", "APT-X", NOW, "ZeroSSL", ["evil.example"])
        row = con.execute(
            "SELECT change_type, confidence FROM attribute_changes "
            "WHERE attribute = 'cert' AND change_type <> 'first_seen'").fetchone()
    assert row == ("cert_issuer_changed", "high")


def test_record_cert_change_sans_changed_is_medium_confidence():
    with store.connect() as con:
        _sweep_cert(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                   "Let's Encrypt", ["evil.example"])
        _sweep_cert(con, "evil.example", "APT-X", NOW,
                   "Let's Encrypt", ["evil.example", "new.evil.example"])
        row = con.execute(
            "SELECT change_type, confidence FROM attribute_changes "
            "WHERE attribute = 'cert' AND change_type <> 'first_seen'").fetchone()
    assert row == ("cert_sans_changed", "medium")


def test_attribute_changes_excludes_reenrichment_of_unchanged_indicator():
    # Regression mirroring test_new_indicators_excludes_reenrichment_of_
    # old_indicator: re-running the sweep with identical Shodan/Cert
    # Spotter results on consecutive days must not produce a second
    # change row just because a new dated observation was inserted.
    with store.connect() as con:
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW - timedelta(days=2), [22])
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), [22])
        _sweep_ports(con, "203.0.113.7", "APT-X", NOW, [22])
        changes = analytics.attribute_changes(con, days=7)
    assert changes == []


def test_hl_budget_exhaustion_mid_loop(fake_net, monkeypatch):
    calls = []

    def hl(ip):
        calls.append(ip)
        if len(calls) >= 2:
            raise pivot.PivotError("HTTP 402: credits exhausted")
        return {"events": 1, "asn": 64512, "ports": []}

    _fake_hl(monkeypatch, hl)
    results, notes = enrich.enrich_ips(
        ["203.0.113.1", "203.0.113.2", "203.0.113.3"], set())
    assert notes["budget_exhausted"] is True
    assert calls == ["203.0.113.1", "203.0.113.2"]  # third never attempted
    assert results[0].honeylabs is not None
    assert results[2].honeylabs is None


def test_hl_rate_limit_retries_once(fake_net, monkeypatch):
    monkeypatch.setattr(enrich, "HL_RATE_RETRY_SECS", 0.0)
    calls = []

    def hl(ip):
        calls.append(ip)
        if len(calls) == 1:
            raise pivot.PivotError("HTTP 429: rate limited")
        return {"events": 1, "asn": 64512, "ports": []}

    _fake_hl(monkeypatch, hl)
    results, notes = enrich.enrich_ips(["203.0.113.1", "203.0.113.2"], set())
    # 3 = one prefilter chunk + two per-IP lookups (the 429'd attempt
    # doesn't count)
    assert notes["hl_calls"] == 3 and notes["budget_exhausted"] is False
    assert calls == ["203.0.113.1"] * 2 + ["203.0.113.2"]
    assert results[0].honeylabs is not None


def test_hl_prefilter_skips_absent_ips(fake_net, monkeypatch):
    calls = []

    def hl(ip):
        calls.append(ip)
        return {"events": 5, "asn": 64512, "ports": []}

    _fake_hl(monkeypatch, hl,
             counts_fn=lambda ips: {ip: (5 if ip == "203.0.113.2" else 0)
                                    for ip in ips})
    results, notes = enrich.enrich_ips(
        ["203.0.113.1", "203.0.113.2", "203.0.113.3"], set())
    assert calls == ["203.0.113.2"]  # absent IPs never looked up
    assert notes["hl_prefiltered_absent"] == 2
    assert notes["hl_calls"] == 2  # one prefilter + one full lookup
    assert results[0].honeylabs["events"] == 0
    assert results[0].honeylabs["verdict"] is None
    assert results[1].honeylabs["events"] == 5


def test_hl_session_failure_still_does_registry(monkeypatch):
    monkeypatch.setenv("HONEYLABS_API_KEY", "k")

    @asynccontextmanager
    async def broken_session(api_key):
        raise pivot.PivotError("honeylabs mcp session failed: boom")
        yield None

    monkeypatch.setattr(hl_mcp, "open_session", broken_session)
    monkeypatch.setattr(pivot, "ripestat_lookup",
                        lambda ip: {"asn": [65001], "as_holder": "X"})
    monkeypatch.setattr(pivot, "rdap_lookup",
                        lambda v, k: {"name": "N", "handle": "H"})
    results, notes = enrich.enrich_ips(["203.0.113.1"], {"203.0.113.1"})
    assert "hl_session_error" in notes and notes["hl_calls"] == 0
    assert results[0].honeylabs is None
    assert results[0].registry["asn"] == 65001


def test_hl_mcp_normalize_observed_and_not():
    raw = {"total_events": 28, "first_seen": "2026-07-20T17:24:39",
           "last_seen": "2026-07-21T00:29:47", "asn_number": 213790,
           "asn_org": "Limited Network LTD", "country_code": "IR",
           "ports_targeted": [1000], "scanner": None,
           "verdict": "Low-level probing", "verdict_key": "probing",
           "verdict_why": ["28 event(s)", "no exploit payloads"],
           "verdict_confidence": "low", "cve_probes": []}
    norm = hl_mcp.normalize(raw)
    assert norm["events"] == 28 and norm["asn"] == 213790
    assert norm["as_org"] == "Limited Network LTD" and norm["country"] == "IR"
    assert norm["verdict"] == "probing"
    assert norm["verdict_label"] == "Low-level probing"
    assert norm["ports"] == [1000] and norm["cves"] is None

    empty = hl_mcp.normalize(
        {"total_events": 0, "first_seen": "1970-01-01T00:00:00",
         "last_seen": "1970-01-01T00:00:00", "asn_number": 0, "asn_org": "",
         "country_code": "", "ports_targeted": [], "scanner": None,
         "verdict": "Not observed", "verdict_key": "none", "cve_probes": []})
    assert empty["events"] == 0
    assert empty["first_seen"] is None and empty["last_seen"] is None
    assert empty["asn"] is None and empty["verdict"] is None


def test_enrich_without_key_skips_honeylabs(monkeypatch):
    monkeypatch.delenv("HONEYLABS_API_KEY", raising=False)
    monkeypatch.setattr(pivot, "ripestat_lookup",
                        lambda ip: {"asn": [65001], "as_holder": "X"})
    monkeypatch.setattr(pivot, "rdap_lookup",
                        lambda v, k: {"name": "N", "handle": "H"})
    results, notes = enrich.enrich_ips(["203.0.113.1"], {"203.0.113.1"})
    assert notes["hl_skipped"] is True and notes["hl_calls"] == 0
    assert results[0].registry["asn"] == 65001


# ---------------------------------------------------------------- xref

class FakeOpenSearch:
    def __init__(self, buckets):
        self.buckets = buckets
        self.queries = []

    def search(self, query, *, size=50, aggs=None, source_fields=None,
               sort=None):
        self.queries.append(query)
        return {"aggregations": {"per_ip": {"buckets": self.buckets}}}


def test_daily_xref_parses_aggregations():
    buckets = [{"key": "203.0.113.7", "doc_count": 12,
                "ports": {"buckets": [{"key": 445, "doc_count": 10}]},
                "first_ts": {"value": 1_787_000_000.0},
                "last_ts": {"value": 1_787_003_600.0},
                "log_files": {"buckets": [{"key": "conn.log", "doc_count": 12}]}}]
    client = FakeOpenSearch(buckets)
    with store.connect() as con:
        _seed_actor_ip(con)
        result = opensearch_xref.run_daily_xref(con, TODAY, client=client)
        row = con.execute(
            "SELECT indicator_value, actor, direction, hit_count, ports, "
            "log_files FROM zeek_matches WHERE direction='src'").fetchone()
    assert result["matches"] == 2  # same bucket for src and dst directions
    assert row[0] == "203.0.113.7" and row[1] == "APT-X"
    assert row[3] == 12
    assert json.loads(row[4]) == [445]
    assert json.loads(row[5]) == ["conn.log"]
    # filters used the .keyword subfields
    fields = [list(f["terms"].keys())[0]
              for q in client.queries for f in q["bool"]["filter"]
              if "terms" in f]
    assert set(fields) == {"src_ip.keyword", "dst_ip.keyword"}


def test_daily_xref_unreachable_is_skip():
    class Down:
        def search(self, *a, **k):
            raise opensearch_xref.OpenSearchError("connection refused")

    with store.connect() as con:
        _seed_actor_ip(con)
        result = opensearch_xref.run_daily_xref(con, TODAY, client=Down())
    assert "skipped" in result


# ---------------------------------------------------------------- digest

def test_digest_no_activity(tmp_path):
    path = digest.write(TODAY, {"status": {"ingest": "ok"}})
    assert digest.NO_ACTIVITY in path.read_text()
    assert (tmp_path / "digests" / f"{TODAY.isoformat()}.json").exists()


def test_digest_new_cluster_is_a_signal_and_pivot_errors_surface():
    path = digest.write(TODAY, {
        "status": {"pivot_sweep": "ok"},
        "register": {"actors_registered": 1,
                     "ips_by_actor": {"Mustang Panda": 6}},
        "pivot_sweep": {"clusters_swept": 27,
                        "errors": {"turla": "failed to reach rdap.org: timeout"}}})
    text = path.read_text()
    assert digest.NO_ACTIVITY not in text
    assert "New clusters registered for tracking" in text
    assert "Mustang Panda: 6 IPs" in text
    assert "Pivot sweep issues" in text
    assert "turla: failed to reach rdap.org: timeout" in text


def test_digest_quiet_pivot_sweep_stays_no_activity():
    # A routine day - every cluster swept clean, nothing else changed -
    # must not wake Stage B just because the sweep phase ran.
    path = digest.write(TODAY, {
        "status": {"pivot_sweep": "ok"},
        "pivot_sweep": {"clusters_swept": 27, "errors": {}}})
    assert digest.NO_ACTIVITY in path.read_text()


def test_digest_caps_rows_and_notes_failures():
    changes = [{"ip": f"203.0.113.{i}", "actor": "A", "change_type": "asn_change",
                "old_asn": 1, "new_asn": 2, "new_netname": "N",
                "confidence": "medium"} for i in range(20)]
    path = digest.write(TODAY, {
        "status": {"zeek_xref": "FAILED: boom"},
        "enrich": {"ips_enriched": 20, "asn_changes": changes}})
    text = path.read_text()
    assert digest.NO_ACTIVITY not in text
    assert "...5 more, query the DB." in text
    assert "zeek_xref: FAILED: boom" in text
    assert text.count("203.0.113.") == digest.MAX_ROWS


def test_digest_renders_attribute_changes_section():
    changes = [{"detected_at": NOW, "indicator_value": "203.0.113.7",
               "actor": "APT-X", "attribute": "ports", "change_type": "ports_changed",
               "old_value": [22], "new_value": [8080], "confidence": "medium"}]
    path = digest.write(TODAY, {"attribute_changes": changes})
    text = path.read_text()
    assert digest.NO_ACTIVITY not in text
    assert "Indicator attribute changes" in text
    assert "203.0.113.7" in text and "ports_changed" in text


def test_digest_renders_port_patterns_section():
    # port_pattern_summary is computed by analytics.run_all every day but
    # was never actually rendered - regression for that gap.
    patterns = [{"actor": "APT-X", "port": 445, "ip_count": 3, "last_seen": NOW}]
    path = digest.write(TODAY, {
        "status": {"pivot_sweep": "ok"},
        "attribute_changes": [{"detected_at": NOW, "indicator_value": "x",
                               "actor": "APT-X", "attribute": "ports",
                               "change_type": "ports_changed", "old_value": [1],
                               "new_value": [2], "confidence": "low"}],
        "port_patterns": patterns})
    text = path.read_text()
    assert "Port scan patterns" in text
    assert "445" in text


def test_digest_attribute_change_alone_is_a_signal():
    # A day with only a port/cert change (no ASN change) must not
    # collapse to NO ACTIVITY.
    changes = [{"detected_at": NOW, "indicator_value": "evil.example",
               "actor": "APT-X", "attribute": "cert",
               "change_type": "cert_issuer_changed", "old_value": {"issuer": "A"},
               "new_value": {"issuer": "B"}, "confidence": "high"}]
    path = digest.write(TODAY, {"attribute_changes": changes})
    assert digest.NO_ACTIVITY not in path.read_text()


# ------------------------------------------------------------- MCP surface

def test_query_duckdb_read_only_and_truncation():
    with store.connect() as con:
        for i in range(250):
            _obs(con, f"10.0.{i // 256}.{i % 256}", TODAY, source=f"s{i}")
    result = store.run_readonly_query("SELECT * FROM observations")
    assert result["truncated"] is True
    assert len(result["rows"]) <= store.QUERY_MAX_ROWS
    denied = store.run_readonly_query(
        "INSERT INTO actors (actor_name) VALUES ('x')")
    assert "error" in denied


def test_query_duckdb_uninitialized_db_fails_fast():
    result = store.run_readonly_query("SELECT 1")
    assert "not initialized" in result["error"]


def test_save_correlation_and_summary(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
    results, _ = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    with store.connect() as con:
        enrich.apply_results(con, results, TODAY)
    saved = store.save_correlation("APT-X", "asn_pivot", ["203.0.113.7"],
                                   "moved to AS64512")
    assert saved == {"saved": True, "actor": "APT-X",
                     "correlation_type": "asn_pivot", "indicator_count": 1}
    assert "error" in store.save_correlation("APT-X", "nope", ["x"], "n")
    summary = store.actor_summary("APT-X")
    assert summary["known_asns"] == [64512]
    assert summary["correlation_count"] == 1
    assert summary["top_ports"][0]["port"] in (22, 445)
    assert "known_actors" in store.actor_summary("missing")


def test_save_correlation_busy_lock(monkeypatch):
    # In-process, DuckDB shares one database instance per path, so real
    # lock contention only happens across processes (cron vs MCP
    # server). Simulate the cross-process IOException instead.
    with store.connect():
        pass  # initialize the file
    monkeypatch.setattr(store.time, "sleep", lambda s: None)
    sleeps = []
    monkeypatch.setattr(store.time, "sleep", sleeps.append)

    def locked(*a, **k):
        raise duckdb.IOException("Could not set lock on file")

    monkeypatch.setattr(store.duckdb, "connect", locked)
    result = store.save_correlation("A", "zeek_hit", ["1.2.3.4"], "n")
    assert "busy" in result["error"]
    assert len(sleeps) == 3  # 4 attempts, backoff between them


# ------------------------------------------------------------- analytics

def test_analytics_on_seeded_data(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
        # unattributed IP inside APT-X's known ASN
        _obs(con, "203.0.113.99", TODAY, source="rdap", asn=64512)
    results, _ = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    with store.connect() as con:
        enrich.apply_results(con, results, TODAY)
        activity = analytics.recent_actor_activity(con)
        new_ips = analytics.new_indicators_in_known_asns(con, days=1)
    assert activity[0]["actor"] == "APT-X"
    assert [r["indicator_value"] for r in new_ips] == ["203.0.113.99"]


def test_new_indicators_excludes_reenrichment_of_old_indicator():
    # Regression for the 2026-08-27 Silver Fox/Alibaba false lead: a
    # daily re-check re-inserts a dated row for an indicator that's
    # been sitting there for days, which must not read as "new".
    with store.connect() as con:
        store.upsert_actor(con, "APT-X", NOW - timedelta(days=10), asns=[64512])
        _obs(con, "203.0.113.60", TODAY - timedelta(days=5), source="rdap",
             asn=64512)
        _obs(con, "203.0.113.60", TODAY, source="rdap", asn=64512)
        new_ips = analytics.new_indicators_in_known_asns(con, days=1)
    assert new_ips == []


def test_cross_actor_asn_overlap_flags_already_attributed_ip():
    # An IP already attributed to APT-X, whose ASN also happens to be
    # in APT-Y's known_asns, is a lead - never a "new IP" for either.
    with store.connect() as con:
        store.upsert_actor(con, "APT-X", NOW - timedelta(days=10), asns=[64512])
        store.upsert_actor(con, "APT-Y", NOW - timedelta(days=10), asns=[64512])
        _obs(con, "203.0.113.61", TODAY - timedelta(days=5),
             source="report:r.csv", asn=64512, actor="APT-X")
        _obs(con, "203.0.113.61", TODAY, source="rdap", asn=64512,
             actor="APT-X")
        overlap = analytics.cross_actor_asn_overlap(con, days=1)
        new_ips = analytics.new_indicators_in_known_asns(con, days=1)
    assert new_ips == []
    assert len(overlap) == 1
    assert overlap[0]["indicator_value"] == "203.0.113.61"
    assert overlap[0]["attributed_to"] == "APT-X"
    assert overlap[0]["matches_actor"] == "APT-Y"


def test_cross_actor_asn_overlap_excludes_shared_hosting_asns():
    # Same shape as above but on a shared-hosting ASN (Alibaba,
    # 45102) - two unrelated actors both touching it is expected
    # noise, not an overlap lead.
    with store.connect() as con:
        store.upsert_actor(con, "APT-X", NOW - timedelta(days=10), asns=[45102])
        store.upsert_actor(con, "APT-Y", NOW - timedelta(days=10), asns=[45102])
        _obs(con, "8.210.1.1", TODAY - timedelta(days=5),
             source="report:r.csv", asn=45102, actor="APT-X")
        _obs(con, "8.210.1.1", TODAY, source="rdap", asn=45102, actor="APT-X")
        overlap = analytics.cross_actor_asn_overlap(con, days=1)
    assert overlap == []


# --------------------------------------------------------- dashboard view
# These lean on the same NOW/TODAY-tracks-real-clock convention already
# used by test_build_worklist_prioritizes_never_enriched: status
# derivation compares stored timestamps against a real datetime.now()
# inside store.py, so freshness windows here are expressed as offsets
# from NOW rather than a mocked clock.

def _status_for(observables, ip):
    return next(o["status"] for o in observables if o["indicator_value"] == ip)


def test_tracked_observables_status_never_enriched():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")  # report-only observation, no honeylabs row
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "never-enriched"


def test_tracked_observables_status_absent():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=0)
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "absent"


def test_tracked_observables_status_quiet():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=5,
             hl_last_seen=NOW - timedelta(days=20))
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "quiet"


def test_tracked_observables_status_active():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=5,
             hl_last_seen=NOW - timedelta(days=3))
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "active"


def test_tracked_observables_status_moved():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        store.record_asn_change(
            con, detected_at=NOW - timedelta(days=10), indicator_value="203.0.113.7",
            actor="APT-X", change_type="asn_change", confidence="medium",
            old_asn=1, new_asn=2)
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "moved"


def test_tracked_observables_status_in_network_precedence():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=5,
             hl_last_seen=NOW - timedelta(days=3))  # would be "active" alone
        store.upsert_zeek_match(
            con, day=TODAY, indicator_value="203.0.113.7", direction="inbound",
            hit_count=3, actor="APT-X", last_ts=NOW - timedelta(hours=2))
    result = store.tracked_observables()
    assert _status_for(result["observables"], "203.0.113.7") == "in-network"


def test_tracked_observables_excludes_untracked_actor():
    with store.connect() as con:
        store.upsert_actor(con, "APT-Z", NOW)
        con.execute("UPDATE actors SET tracked = FALSE WHERE actor_name = 'APT-Z'")
        _obs(con, "198.51.100.9", TODAY, source="report:x.csv", actor="APT-Z")
    result = store.tracked_observables()
    assert "198.51.100.9" not in {o["indicator_value"] for o in result["observables"]}


def test_observable_history_status_matches_tracked_observables():
    # A first_seen row (fired on the indicator's first-ever enrichment,
    # see enrich.apply_results) must not make the detail view disagree
    # with the list view about status - both must ignore it the same way.
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=4,
             hl_last_seen=NOW - timedelta(days=20))
        store.record_asn_change(
            con, detected_at=NOW, indicator_value="203.0.113.7",
            actor="APT-X", change_type="first_seen", confidence="medium",
            new_asn=64512)
    list_status = _status_for(store.tracked_observables()["observables"], "203.0.113.7")
    detail_status = store.observable_history("203.0.113.7")["status"]
    assert list_status == detail_status == "quiet"


def test_observable_history_orders_by_time_and_includes_asn_changes():
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=5,
             hl_last_seen=NOW - timedelta(days=1))
        _obs(con, "203.0.113.7", TODAY - timedelta(days=5), source="honeylabs", hl_events=2)
        store.record_asn_change(
            con, detected_at=NOW - timedelta(days=3), indicator_value="203.0.113.7",
            actor="APT-X", change_type="asn_change", confidence="medium",
            old_asn=1, new_asn=2)
    result = store.observable_history("203.0.113.7")
    obs_dates = [o["observed_at"] for o in result["observations"]]
    assert obs_dates == sorted(obs_dates)
    assert len(result["asn_changes"]) == 1
    assert result["status"] == "active"

    empty = store.observable_history("203.0.113.250")
    assert empty == {"ip": "203.0.113.250", "status": "never-enriched",
                     "observations": [], "asn_changes": [], "zeek_matches": []}
