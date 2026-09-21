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

from cti import core
from cti.sources import pivot
from cti import store
from cti.tracking import analytics, digest, enrich, hl_mcp, ingest
from cti.tracking import opensearch_xref


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
    monkeypatch.setattr(pivot, "ptr_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr(core.vm_proxy, "tls_grab",
                        lambda host, port=443: {"cert": None, "resolved_ip": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "http_probe",
                        lambda url, insecure=False: {"status": None, "final_url": url, "title": None,
                                                     "server": None, "content_type": None,
                                                     "body_sha256": None, "autoindex": None, "error": None})
    monkeypatch.setattr(core.vm_proxy, "subfinder", lambda domain: {"subdomains": [], "error": None})
    monkeypatch.setattr(core.vm_proxy, "wayback_cdx",
                        lambda domain: {"urls": [], "subdomains": [], "error": None})
    monkeypatch.setattr(core.webamon, "search_domain",
                        lambda domain, size=5: {"total_hits": 0, "results": [], "latest": None})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 0, "domains": [], "results": []})
    monkeypatch.setattr(core.webamon, "infostealers",
                        lambda term, size=25: {"total_hits": 0, "results": []})


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
            "SELECT count(*), max(hl_events) FROM observations_wide "
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
            "SELECT indicator_value FROM observations_wide").fetchall()]
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
        count = con.execute("SELECT count(*) FROM observations_wide").fetchone()[0]
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
            "SELECT source FROM observations_wide").fetchall()}
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
# store.detect() diffs against the prior observations row for the same
# (indicator, source) - see the per-attribute specs in
# cti/store/changes.py - so these helpers mirror the real call order
# _log_cluster_enrichment_history uses: write the dated nmap/tls_live
# observation first, then diff/record.
#
# These exercise the same driver as tests/test_changes.py, from the
# caller's side rather than the spec's: the sweep writes an observation
# and then asks for a diff, which is where an ordering mistake would show
# up and a spec-level test would not.

def _sweep_ports(con, ip, actor, day, ports):
    store.upsert_observation(con, observed_at=day, indicator_value=ip,
                             source="nmap", actor=actor, nmap_ports=ports or None)
    store.detect(con, "ports", indicator_value=ip, actor=actor,
                 observed_at=day, new=ports)


def _sweep_cert(con, domain, actor, day, issuer, sans):
    store.upsert_observation(con, observed_at=day, indicator_value=domain,
                             source="tls_live", actor=actor, tls_issuer=issuer,
                             tls_sha256=f"sha-{issuer}-{','.join(sorted(sans))}",
                             tls_sans=sans or None)
    store.detect(con, "cert", indicator_value=domain, actor=actor,
                 observed_at=day, new={"issuer": issuer, "sans": sans})


def _sweep_ptr(con, ip, actor, day, hostname):
    store.upsert_observation(con, observed_at=day, indicator_value=ip,
                             source="ptr", actor=actor, ptr_hostname=hostname)
    store.detect(con, "ptr", indicator_value=ip, actor=actor,
                 observed_at=day, new=hostname)


def _sweep_resolved_ip(con, domain, actor, day, ips):
    store.upsert_observation(con, observed_at=day, indicator_value=domain,
                             source="dns_resolve", actor=actor, resolved_ip=ips)
    store.detect(con, "resolved_ip", indicator_value=domain, actor=actor,
                 observed_at=day, new=ips)


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


def test_record_ptr_change_first_seen_is_baseline_not_change():
    with store.connect() as con:
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW, "host.example")
        row = con.execute(
            "SELECT change_type, confidence FROM attribute_changes "
            "WHERE attribute = 'ptr'").fetchone()
        recent = analytics.attribute_changes(con, days=1)
    assert row == ("first_seen", "medium")
    assert recent == []  # first_seen is excluded, like ports'/asn's


def test_record_ptr_change_no_change_when_hostname_identical():
    with store.connect() as con:
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), "host.example")
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW, "host.example")
        count = con.execute(
            "SELECT count(*) FROM attribute_changes WHERE attribute = 'ptr'").fetchone()[0]
    assert count == 1  # only the first_seen baseline - no spurious "change"


def test_record_ptr_change_detects_change():
    with store.connect() as con:
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), "old.example")
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW, "new.example")
        row = con.execute(
            "SELECT change_type, old_value, new_value, confidence FROM attribute_changes "
            "WHERE attribute = 'ptr' AND change_type = 'ptr_changed'").fetchone()
    assert row[0] == "ptr_changed"
    assert json.loads(row[1]) == "old.example"
    assert json.loads(row[2]) == "new.example"
    assert row[3] == "medium"


def test_record_ptr_change_confirmed_absence_is_a_real_value():
    # None on either side is "confirmed no PTR record", not "no data" -
    # a flip to/from that state is still a recordable change.
    with store.connect() as con:
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW - timedelta(days=1), "host.example")
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW, None)
        row = con.execute(
            "SELECT old_value, new_value FROM attribute_changes "
            "WHERE attribute = 'ptr' AND change_type = 'ptr_changed'").fetchone()
    assert json.loads(row[0]) == "host.example"
    assert json.loads(row[1]) is None


def test_record_ptr_change_stale_baseline_downgrades_confidence():
    with store.connect() as con:
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW - timedelta(days=120), "old.example")
        _sweep_ptr(con, "203.0.113.7", "APT-X", NOW, "new.example")
        confidence = con.execute(
            "SELECT confidence FROM attribute_changes "
            "WHERE attribute = 'ptr' AND change_type = 'ptr_changed'").fetchone()[0]
    assert confidence == "low"  # medium base, downgraded once for staleness


def test_record_resolved_ip_change_first_seen_is_baseline_not_change():
    with store.connect() as con:
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW, ["203.0.113.7"])
        row = con.execute(
            "SELECT change_type, confidence FROM attribute_changes "
            "WHERE attribute = 'resolved_ip'").fetchone()
        recent = analytics.attribute_changes(con, days=1)
    assert row == ("first_seen", "medium")
    assert recent == []  # first_seen is excluded, like ports'/asn's


def test_record_resolved_ip_change_no_change_when_ips_identical():
    with store.connect() as con:
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                           ["203.0.113.7", "203.0.113.8"])
        # order-independent: same set, different order, one day later
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW,
                           ["203.0.113.8", "203.0.113.7"])
        count = con.execute(
            "SELECT count(*) FROM attribute_changes WHERE attribute = 'resolved_ip'").fetchone()[0]
    assert count == 1  # only the first_seen baseline - no spurious "change"


def test_record_resolved_ip_change_detects_hosting_shift():
    with store.connect() as con:
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                           ["203.0.113.7"])
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW, ["198.51.100.9"])
        row = con.execute(
            "SELECT change_type, old_value, new_value, confidence FROM attribute_changes "
            "WHERE attribute = 'resolved_ip' AND change_type = 'resolved_ip_changed'").fetchone()
    assert row[0] == "resolved_ip_changed"
    assert json.loads(row[1]) == ["203.0.113.7"]
    assert json.loads(row[2]) == ["198.51.100.9"]
    assert row[3] == "medium"


def test_record_resolved_ip_change_confirmed_dead_is_a_real_value():
    # [] is "confirmed no resolution" (dead/sinkholed), not "no data" - a
    # flip to/from that state is still a recordable change.
    with store.connect() as con:
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW - timedelta(days=1),
                           ["203.0.113.7"])
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW, [])
        row = con.execute(
            "SELECT old_value, new_value FROM attribute_changes "
            "WHERE attribute = 'resolved_ip' AND change_type = 'resolved_ip_changed'").fetchone()
    assert json.loads(row[0]) == ["203.0.113.7"]
    assert json.loads(row[1]) == []


def test_record_resolved_ip_change_stale_baseline_downgrades_confidence():
    with store.connect() as con:
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW - timedelta(days=120),
                           ["203.0.113.7"])
        _sweep_resolved_ip(con, "evil.example", "APT-X", NOW, ["198.51.100.9"])
        confidence = con.execute(
            "SELECT confidence FROM attribute_changes "
            "WHERE attribute = 'resolved_ip' AND change_type = 'resolved_ip_changed'").fetchone()[0]
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


def test_digest_renders_open_directories_section():
    open_dirs = [{"first_seen": NOW, "indicator_value": "203.0.113.7", "actor": "APT-X",
                  "url": "http://203.0.113.7/files/", "path": "http://203.0.113.7/files/b.exe",
                  "size": "2M"}]
    path = digest.write(TODAY, {"open_directories": open_dirs})
    text = path.read_text()
    assert digest.NO_ACTIVITY not in text  # an open-dir file alone is a signal
    assert "Open-directory files" in text
    assert "b.exe" in text


def test_digest_caps_oversized_hostname_list_in_attribute_change():
    # Regression for the 2026-09-10 blowup: a reverse-IP pivot on a
    # shared-hosting IP can carry thousands of hostnames in new_value.
    # old_value/new_value arrive as JSON text (as they do from the real
    # DB - see store.py's JSON column type), not Python lists.
    many_hostnames = [f"tenant-{i}.example" for i in range(500)]
    changes = [{"detected_at": NOW, "indicator_value": "203.0.113.7",
               "actor": "Fox Tempest", "attribute": "hostnames",
               "change_type": "hostnames_changed",
               "old_value": json.dumps(["a.example"]),
               "new_value": json.dumps({"hostnames": many_hostnames, "added": many_hostnames}),
               "confidence": "medium"}]
    path = digest.write(TODAY, {"attribute_changes": changes})
    text = path.read_text()
    assert "tenant-0.example" in text
    assert "tenant-499.example" not in text  # truncated well before 500 items
    assert "480 more" in text
    assert len(text) < 20_000  # digest stays bounded, not ~127KB like the incident


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
    result = store.run_readonly_query("SELECT * FROM observations_wide")
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
    #
    # Patched on cti.store.connection, which is where connect/retry moved
    # when the 1061-line store module was split.
    from cti.store import connection

    with store.connect():
        pass  # initialize the file
    sleeps = []
    monkeypatch.setattr(connection.time, "sleep", sleeps.append)

    def locked(*a, **k):
        raise duckdb.IOException("Could not set lock on file")

    monkeypatch.setattr(connection.duckdb, "connect", locked)
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
        # Real clock, not NOW. NOW is today at MIDNIGHT, so "NOW - 2 hours"
        # is yesterday at 22:00 - and the in-network rule compares against
        # the actual current time with a one-day window. The test therefore
        # passed all day and began failing after 22:00 UTC, which is a
        # property of when it runs rather than of what it tests.
        store.upsert_zeek_match(
            con, day=TODAY, indicator_value="203.0.113.7", direction="inbound",
            hit_count=3, actor="APT-X",
            last_ts=datetime.now() - timedelta(hours=2))
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


def test_observable_history_returns_the_payload_not_just_the_ip_columns():
    """The reason the portal looked empty.

    The SELECT named nineteen columns, every one from the IP enrichment
    path, and never touched `payload` - where the observe pass, InternetDB,
    mnemonic, the certificates, the body hashes and the DNS records all
    live. A domain came back as ~170 rows carrying nothing but a date, a
    source and an actor.
    """
    with store.connect() as con:
        _seed_actor_ip(con, "evil.example")
        _obs(con, "evil.example", TODAY, source="observe_tls",
             tls_sha256="c" * 64, tls_spki_sha256="d" * 64, tls_serial="0A:1B")
    result = store.observable_history("evil.example")
    payload = result["observations"][-1]["payload"]
    assert payload["tls_sha256"] == "c" * 64
    assert payload["tls_spki_sha256"] == "d" * 64
    assert result["observations"][-1]["indicator_type"] is not None


def test_observable_history_keeps_its_exact_empty_shape():
    """Pinned deliberately. dashboard/server.py hands this dict straight to
    the client and app.js reads profile.ip; a new top-level key here is a
    contract change. Richer answers belong in indicator_profile."""
    with store.connect():
        pass          # a read-only open needs the schema to exist first
    assert store.observable_history("203.0.113.250") == {
        "ip": "203.0.113.250", "status": "never-enriched",
        "observations": [], "asn_changes": [], "zeek_matches": []}


# --------------------------------------------------------------------------- #
# Domain status - the ladder that did not exist
# --------------------------------------------------------------------------- #

def _seed_domain(con, value, *, resolved, day=None, source="dns_resolve"):
    """Mirrors _seed_actor_ip: the actor row is what puts the indicator in
    tracked_observables' scope."""
    _obs(con, value, day or TODAY, source=source, actor="APT-X",
         indicator_type="domain", resolved_ip=resolved)
    store.upsert_actor(con, "APT-X", NOW - timedelta(days=1))


def test_a_domain_that_resolves_is_not_never_enriched():
    """The bug. _tracking_status' ladder below Zeek is HoneyLabs, then an
    ASN change, then whether a HoneyLabs row exists - all IP-only paths, so
    every domain fell off the end. 58 domains carrying dozens of
    observations each reported as untouched."""
    with store.connect() as con:
        _seed_domain(con, "evil.example", resolved=["203.0.113.9"])
    assert store.observable_history("evil.example")["status"] == "resolving"


def test_a_domain_resolving_to_nothing_is_unresolved_not_quiet():
    """The signal there was no way to see before: the domain went dark.
    An empty list is an answer; None means nobody asked."""
    with store.connect() as con:
        _seed_domain(con, "dead.example", resolved=[])
    assert store.observable_history("dead.example")["status"] == "unresolved"


def test_a_stale_resolution_does_not_still_count_as_resolving():
    with store.connect() as con:
        _seed_domain(con, "old.example", resolved=["203.0.113.9"],
                     day=TODAY - timedelta(days=30))
    assert store.observable_history("old.example")["status"] == "quiet"


def test_a_recent_address_change_makes_a_domain_moved():
    with store.connect() as con:
        _seed_domain(con, "moved.example", resolved=["203.0.113.9"],
                     day=TODAY - timedelta(days=30))
        store.record_attribute_change(
            con, detected_at=NOW - timedelta(days=2),
            indicator_value="moved.example", actor="APT-X",
            attribute="resolved_ip", change_type="resolved_ip_changed",
            confidence="medium", old_value=None, new_value={"ip": "x"})
    assert store.observable_history("moved.example")["status"] == "moved"


def test_a_first_seen_row_does_not_make_a_domain_moved():
    """Same rule the IP ladder applies: a baseline is not a pivot."""
    with store.connect() as con:
        _seed_domain(con, "fresh.example", resolved=["203.0.113.9"],
                     day=TODAY - timedelta(days=30))
        store.record_attribute_change(
            con, detected_at=NOW - timedelta(days=2),
            indicator_value="fresh.example", actor="APT-X",
            attribute="resolved_ip", change_type="first_seen",
            confidence="medium", old_value=None, new_value={"ip": "x"})
    assert store.observable_history("fresh.example")["status"] == "quiet"


def test_an_unobserved_domain_is_still_never_enriched():
    with store.connect():
        pass
    assert store.observable_history("unknown.example")["status"] == "never-enriched"


def test_list_and_detail_agree_for_domains_too():
    """tests/test_tracking.py already pinned this for IPs. The two ladders
    are fed from different places - one SQL, one Python over rows in hand -
    so they can drift apart silently."""
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
        _seed_domain(con, "b.example", resolved=[])
    listed = {o["indicator_value"]: o["status"]
              for o in store.tracked_observables()["observables"]}
    for value in ("a.example", "b.example"):
        assert listed[value] == store.observable_history(value)["status"], value


def test_the_ip_ladder_is_untouched():
    """Six existing tests depend on these labels; the domain work must not
    reach them."""
    with store.connect() as con:
        _seed_actor_ip(con, "203.0.113.7")
        _obs(con, "203.0.113.7", TODAY, source="honeylabs", hl_events=5,
             hl_last_seen=NOW - timedelta(days=3))
    assert store.observable_history("203.0.113.7")["status"] == "active"


# --------------------------------------------------------------------------- #
# indicator_profile
# --------------------------------------------------------------------------- #

def test_indicator_profile_folds_current_values_with_provenance():
    with store.connect() as con:
        _seed_domain(con, "evil.example", resolved=["203.0.113.9"],
                     day=TODAY - timedelta(days=2))
        _obs(con, "evil.example", TODAY - timedelta(days=2),
             source="observe_tls", indicator_type="domain", tls_sha256="a" * 64)
        _obs(con, "evil.example", TODAY, source="observe_tls",
             indicator_type="domain", tls_sha256="b" * 64)
    current = store.indicator_profile("evil.example")["current"]
    assert current["tls_sha256"]["value"] == "b" * 64, "newest wins"
    assert current["tls_sha256"]["source"] == "observe_tls"
    # An older field is not lost just because a newer row omitted it.
    assert current["resolved_ip"]["value"] == ["203.0.113.9"]


def test_current_is_built_from_the_schema_not_a_hardcoded_list():
    """The bug this whole change exists to fix, turned into a guard.

    observable_history named nineteen columns by hand, and every payload
    field added afterwards - the observe pass, InternetDB, mnemonic - was
    invisible. A list written out in _fold_current would rot the same way,
    so it iterates the schema's own key sets instead.
    """
    import inspect

    from cti.store import query, schema
    source = inspect.getsource(query._fold_current)
    assert "OBS_SCALAR_KEYS" in source and "OBS_JSON_KEYS" in source
    # A key added to the schema must need no edit here.
    assert "internetdb_ports" in schema.OBS_JSON_KEYS
    assert "internetdb_ports" not in source


def test_indicator_profile_carries_selector_meaning_and_rarity():
    """The taxonomy's means/never prose is written for a human and has
    never had anywhere to be shown."""
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
        store.selectors.record(
            con, indicator_value="a.example", selector_type="tls.cert_sha256",
            selector_value="c" * 64, observed_at=NOW, indicator_type="domain",
            actor="APT-X", source="observe")
        # What the daily corroborate node does. Without it local_count is
        # None - "not priced", which assess() deliberately distinguishes
        # from "rare" - so the profile would under-report rather than lie.
        from cti.store import rarity
        rarity.refresh(con)
    sel = store.indicator_profile("a.example")["selectors"][0]
    assert sel["selector_class"] == "identity"
    assert sel["means"] and sel["never"], "prose must reach the caller"
    assert sel["local_count"] == 1
    assert "can_promote" in sel and "why_not" in sel


def test_indicator_profile_reports_links_without_recomputing_them():
    """expand.candidates_for already applies the corroboration rule and the
    rarity gates. This function renders its verdict; it must not
    second-guess it."""
    with store.connect() as con:
        for host in ("a.example", "b.example"):
            _seed_domain(con, host, resolved=["203.0.113.9"])
            store.selectors.record(
                con, indicator_value=host, selector_type="tls.cert_sha256",
                selector_value="c" * 64, observed_at=NOW,
                indicator_type="domain", actor="APT-X", source="observe")
    links = store.indicator_profile("a.example")["links"]
    assert [l["indicator"] for l in links] == ["b.example"]
    assert links[0]["promoted"] is True
    assert "identity fact" in links[0]["reason"]


def test_indicator_profile_finds_correlations_naming_the_indicator():
    """correlations.indicators is a JSON array, so this is a containment
    test rather than a join. Nothing in the repo did this before."""
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
        store.insert_correlation(
            con, actor="APT-X", correlation_type="shared_fingerprint",
            indicators=["a.example", "b.example"], confidence="high",
            narrative="n")
    found = store.indicator_profile("a.example")["correlations"]
    assert len(found) == 1 and "a.example" in found[0]["indicators"]


def test_indicator_profile_status_matches_the_other_two_readers():
    with store.connect() as con:
        _seed_domain(con, "dead.example", resolved=[])
    assert store.indicator_profile("dead.example")["status"] == "unresolved"
    assert store.observable_history("dead.example")["status"] == "unresolved"


def test_indicator_profile_on_an_unknown_value_is_empty_not_an_error():
    with store.connect():
        pass
    p = store.indicator_profile("nothing.example")
    assert "error" not in p
    assert p["observation_count"] == 0 and p["status"] == "never-enriched"
    assert p["current"] == {} and p["selectors"] == [] and p["links"] == []


def test_indicator_index_is_wider_than_the_tracked_scope():
    """tracked_observables only returns indicators whose actor carries
    tracked = TRUE. An indicator can hold a hundred observations and a full
    selector bag while that flag is off, and it must still be findable."""
    with store.connect() as con:
        _obs(con, "untracked.example", TODAY, source="observe_dns",
             indicator_type="domain", actor="Nobody")
    index = store.indicator_index()
    assert "untracked.example" in {i["indicator_value"] for i in index["indicators"]}
    listed = {o["indicator_value"] for o in store.tracked_observables()["observables"]}
    assert "untracked.example" not in listed


def test_indicator_index_counts_observations_sources_and_selectors():
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
        _obs(con, "a.example", TODAY, source="observe_tls",
             indicator_type="domain", tls_sha256="c" * 64)
        store.selectors.record(
            con, indicator_value="a.example", selector_type="tls.cert_sha256",
            selector_value="c" * 64, observed_at=NOW, indicator_type="domain",
            actor="APT-X", source="observe")
    row = next(i for i in store.indicator_index()["indicators"]
               if i["indicator_value"] == "a.example")
    assert row["observations"] == 2 and row["sources"] == 2
    assert row["selectors"] == 1 and row["indicator_type"] == "domain"


def test_indicator_index_does_not_compute_a_third_status():
    """Two ladders already exist and a test pins that they agree. A third,
    derived from this aggregate, could disagree with both - which is the
    bug this change set exists to fix."""
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
    assert "status" not in store.indicator_index()["indicators"][0]


def test_selector_detail_answers_who_else_has_this():
    with store.connect() as con:
        for host in ("a.example", "b.example"):
            _seed_domain(con, host, resolved=["203.0.113.9"])
            store.selectors.record(
                con, indicator_value=host, selector_type="tls.cert_sha256",
                selector_value="c" * 64, observed_at=NOW,
                indicator_type="domain", actor="APT-X", source="observe")
    d = store.selector_detail("tls.cert_sha256", "c" * 64)
    assert {i["indicator_value"] for i in d["indicators"]} == {"a.example", "b.example"}
    assert d["selector_class"] == "identity"
    assert d["means"], "what a shared value proves must reach the page"


def test_selector_detail_normalizes_the_value_it_was_given():
    """A hash written upper-case by one tool and lower by another is one
    selector; the page must find it either way."""
    with store.connect() as con:
        _seed_domain(con, "a.example", resolved=["203.0.113.9"])
        store.selectors.record(
            con, indicator_value="a.example", selector_type="tls.cert_sha256",
            selector_value="c" * 64, observed_at=NOW, indicator_type="domain",
            actor="APT-X", source="observe")
    d = store.selector_detail("tls.cert_sha256", ("C" * 64))
    assert d["selector_value"] == "c" * 64
    assert len(d["indicators"]) == 1


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #

_FINDING = {"family": "cert_tls", "actor": "STAC4749",
            "headline": "New certificate on webconf.shop-api.workers.dev",
            "detail": "the cert changed",
            "indicators": ["webconf.shop-api.workers.dev",
                           "cert-sha256:" + "8" * 64],
            "correlation_type": None, "confidence": "medium"}


def test_every_finding_is_persisted_not_only_the_saved_ones():
    """The distinction is the point. On 2026-09-21, 1 of 5 findings carried
    a correlation_type; the other four existed nowhere but a debug trace.
    The leads worth clicking are usually among the ones not worth filing."""
    with store.connect() as con:
        store.record_findings(con, day=TODAY, findings=[
            _FINDING,
            {**_FINDING, "headline": "saved one", "correlation_type": "shared_fingerprint"},
        ])
    day = store.findings_for(TODAY.isoformat())
    assert day["count"] == 2
    assert sum(f["saved"] for f in day["findings"]) == 1


def test_findings_keep_indicator_values_at_full_length():
    """What makes the portal correct on a day the model abbreviates in
    prose. The narrative wrote `8ed8767a…`; this is the same finding."""
    with store.connect() as con:
        store.record_findings(con, day=TODAY, findings=[_FINDING])
    found = store.findings_for(TODAY.isoformat())["findings"][0]
    assert "cert-sha256:" + "8" * 64 in found["indicators"]
    assert "…" not in json.dumps(found["indicators"])


def test_recording_a_day_twice_updates_rather_than_duplicates():
    with store.connect() as con:
        assert store.record_findings(con, day=TODAY, findings=[_FINDING]) == 1
        assert store.record_findings(
            con, day=TODAY,
            findings=[{**_FINDING, "detail": "revised"}]) == 0
    found = store.findings_for(TODAY.isoformat())
    assert found["count"] == 1
    assert found["findings"][0]["detail"] == "revised"


def test_a_finding_with_no_headline_is_skipped():
    with store.connect() as con:
        assert store.record_findings(
            con, day=TODAY, findings=[{**_FINDING, "headline": "  "}]) == 0
    assert store.findings_for(TODAY.isoformat())["count"] == 0


def test_saved_findings_sort_before_noted_ones():
    with store.connect() as con:
        store.record_findings(con, day=TODAY, findings=[
            _FINDING,
            {**_FINDING, "headline": "aaa saved", "correlation_type": "shared_fingerprint"},
        ])
    families = [f["saved"] for f in store.findings_for(TODAY.isoformat())["findings"]]
    assert families == [True, False]


def test_finding_days_counts_saved_separately():
    with store.connect() as con:
        store.record_findings(con, day=TODAY, findings=[
            _FINDING,
            {**_FINDING, "headline": "saved", "correlation_type": "temporal_cluster"},
        ])
    day = store.finding_days()["days"][0]
    assert day["findings"] == 2 and day["saved"] == 1
