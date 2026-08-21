"""Tests for the cti_tools.tracking actor-tracking layer. Run with:

    cd mcp-server && source .venv/bin/activate && pip install -e '.[test]'
    pytest tests/test_tracking.py
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta

import duckdb
import pytest

from cti_tools import pivot
from cti_tools.tracking import analytics, digest, enrich, ingest, store
from cti_tools.tracking import opensearch_xref


TODAY = date(2026, 8, 21)
NOW = datetime(2026, 8, 21)


@pytest.fixture(autouse=True)
def isolated_tracking(tmp_path, monkeypatch):
    """Never touch the real data/tracking/ tree from tests."""
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "t.duckdb"))
    monkeypatch.setenv("CTI_TRACKING_INBOX", str(tmp_path / "inbox"))
    monkeypatch.setenv("CTI_TRACKING_ARCHIVE", str(tmp_path / "archive"))
    monkeypatch.setenv("CTI_TRACKING_DIGESTS", str(tmp_path / "digests"))
    yield tmp_path


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


# ---------------------------------------------------------------- enrich

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
    monkeypatch.setattr(pivot, "honeylabs_lookup", lambda ip, key: dict(hl))
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


def test_enrich_writes_rows_and_first_seen(fake_net):
    with store.connect() as con:
        _seed_actor_ip(con)
    results, notes = enrich.enrich_ips(["203.0.113.7"], {"203.0.113.7"})
    assert notes["hl_calls"] == 1 and notes["registry_calls"] == 1
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


def test_hl_budget_exhaustion_mid_loop(fake_net, monkeypatch):
    calls = []

    def hl(ip, key):
        calls.append(ip)
        if len(calls) >= 2:
            raise pivot.PivotError("HTTP 402: credits exhausted")
        return {"events": 1, "asn": 64512, "ports": []}

    monkeypatch.setattr(pivot, "honeylabs_lookup", hl)
    results, notes = enrich.enrich_ips(
        ["203.0.113.1", "203.0.113.2", "203.0.113.3"], set())
    assert notes["budget_exhausted"] is True
    assert calls == ["203.0.113.1", "203.0.113.2"]  # third never attempted
    assert results[0].honeylabs is not None
    assert results[2].honeylabs is None


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
    assert (tmp_path / "digests" / "2026-08-21.json").exists()


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
        new_ips = analytics.new_ips_in_known_asns(con, days=1)
    assert activity[0]["actor"] == "APT-X"
    assert [r["indicator_value"] for r in new_ips] == ["203.0.113.99"]
