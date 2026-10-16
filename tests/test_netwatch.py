"""netwatch: watchlist tiering, the probe spool/worker, and ingest."""
from __future__ import annotations

import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import duckdb
import pytest

from cti import core, store
from cti.store import entities
from cti.netwatch import ingest, jobs, watchlist

REPO = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat()


# --------------------------------------------------------------------------- #
# watchlist tiering
# --------------------------------------------------------------------------- #

def _cluster(ips=(), domains=()):
    return {"name": "APT-W",
            "observables": {"ips": list(ips), "domains": list(domains)}}


def _ip(value, lifecycle, since=None, ports=(443,)):
    e = {"value": value, "lifecycle": lifecycle, "ports": list(ports)}
    if since:
        e["lifecycle_since"] = since
    return e


def test_tiers_follow_lifecycle(monkeypatch):
    cl = _cluster(ips=[
        _ip("203.0.113.1", "active", since=_iso(NOW - timedelta(days=60))),   # full
        _ip("203.0.113.2", "active", since=_iso(NOW - timedelta(days=2))),    # hot (moved)
        _ip("203.0.113.3", "dormant"),                                        # hot
        _ip("203.0.113.4", "candidate"),                                      # hot
        _ip("203.0.113.5", "retired"),                                        # dropped
    ])
    monkeypatch.setattr(core, "list_clusters", lambda: ["c"])
    monkeypatch.setattr(core, "load_cluster", lambda n: cl)
    monkeypatch.setattr(watchlist.cdn, "available", lambda: False)
    tiers = {t["value"]: t["tier"] for t in watchlist.build()}
    assert tiers == {"203.0.113.1": "full", "203.0.113.2": "hot",
                     "203.0.113.3": "hot", "203.0.113.4": "hot"}
    assert "203.0.113.5" not in tiers


def test_cdn_ips_are_dropped(monkeypatch):
    cl = _cluster(ips=[_ip("1.1.1.1", "active")])
    monkeypatch.setattr(core, "list_clusters", lambda: ["c"])
    monkeypatch.setattr(core, "load_cluster", lambda n: cl)
    monkeypatch.setattr(watchlist.cdn, "available", lambda: True)
    monkeypatch.setattr(watchlist.cdn, "is_cdn", lambda ip: ip == "1.1.1.1")
    assert watchlist.build() == []


def test_strongest_tier_and_port_union_win(monkeypatch):
    a = _cluster(ips=[_ip("203.0.113.9", "dormant", ports=[443])])          # hot
    b = _cluster(ips=[_ip("203.0.113.9", "active",
                          since=_iso(NOW - timedelta(days=90)), ports=[8443])])  # full
    monkeypatch.setattr(core, "list_clusters", lambda: ["a", "b"])
    monkeypatch.setattr(core, "load_cluster", lambda n: a if n == "a" else b)
    monkeypatch.setattr(watchlist.cdn, "available", lambda: False)
    got = watchlist.build()
    assert len(got) == 1
    assert got[0]["tier"] == "full"
    assert got[0]["ports"] == [443, 8443]


def test_scored_candidates_join_the_hot_tier_above_the_floor(monkeypatch):
    cl = _cluster(ips=[_ip("203.0.113.1", "active", since=_iso(NOW - timedelta(days=60)))])
    monkeypatch.setattr(core, "list_clusters", lambda: ["apt-w"])
    monkeypatch.setattr(core, "load_cluster", lambda n: cl)
    monkeypatch.setattr(watchlist.cdn, "available", lambda: False)
    with store.connect() as con:
        for value, score, band in (("lead.example", 0.6, "probable"),
                                   ("198.51.100.9", 0.3, "weak"),
                                   ("stranger.example", 0.05, "noise")):
            entities.file_candidate(con, "apt-w", value, origin="t", decided_by="pivot")
            entities.record_score(con, "apt-w", value, score=score, band=band, evidence=[])
    targets = {t["value"]: t for t in watchlist.build()}
    assert targets["lead.example"]["tier"] == "hot"
    assert targets["198.51.100.9"]["kind"] == "ip"
    assert "stranger.example" not in targets
    assert targets["203.0.113.1"]["tier"] == "full"
    monkeypatch.setenv("CTI_CANDIDATE_SCAN_BAND", "probable")
    assert "198.51.100.9" not in {t["value"] for t in watchlist.build()}


# --------------------------------------------------------------------------- #
# the probe spool + worker (probe_helper.py runs standalone on the VM)
# --------------------------------------------------------------------------- #

@pytest.fixture
def probe_helper(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_NETWATCH_SPOOL", str(tmp_path / "spool"))
    spec = importlib.util.spec_from_file_location(
        "probe_helper", REPO / "probe_vm" / "probe_helper.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_worker_drains_a_submitted_job(probe_helper):
    ph = probe_helper
    ph._scan_target = lambda entry, vantage, profile, scan_id: [{
        "scan_id": scan_id, "ts": "2026-10-14T20:00:00+00:00", "vantage": vantage,
        "profile": profile, "target": entry["value"], "ip": "203.0.113.7",
        "port": 443, "open": True, "tls": {"cert_sha256": "a" * 64}}]
    ack = ph.action_netwatch_submit({"job": {
        "job_id": "job-1", "profile": "hot", "vantage": "probe",
        "targets": [{"value": "evil.example", "ports": [443]}]}})
    assert ack == {"job_id": "job-1", "queued": 1}
    assert ph.action_netwatch_status({"job_id": "job-1"})["state"] == "queued"

    ph.run_netwatch_worker(once=True)

    assert ph.action_netwatch_status({"job_id": "job-1"})["state"] == "done"
    pulled = ph.action_netwatch_collect({"job_id": "job-1", "purge": True})
    assert pulled["done"] is True
    assert len(pulled["records"]) == 1
    assert pulled["records"][0]["tls"]["cert_sha256"] == "a" * 64
    # purge removed the results
    assert ph.action_netwatch_collect({"job_id": "job-1"})["records"] == []


def test_a_crashing_scan_still_finishes_the_job(probe_helper):
    ph = probe_helper
    def boom(entry, vantage, profile, scan_id):
        raise RuntimeError("tool blew up")
    ph._scan_target = boom
    ph.action_netwatch_submit({"job": {"job_id": "job-2", "profile": "hot",
        "targets": [{"value": "evil.example"}]}})
    ph.run_netwatch_worker(once=True)
    rec = ph.action_netwatch_collect({"job_id": "job-2"})["records"]
    assert rec and "scan crashed" in rec[0]["error"]


# --------------------------------------------------------------------------- #
# ingest: spool -> snapshots, changes, selectors (passive join stubbed)
# --------------------------------------------------------------------------- #

def _spool(records):
    d = jobs.spool_dir()
    (d / "scanA.jsonl").write_text("\n".join(json.dumps(r) for r in records))


def _record(scan_id, target, port, **kw):
    base = {"scan_id": scan_id, "ts": "2026-10-14T20:00:00+00:00",
            "vantage": "probe", "profile": "hot", "target": target,
            "ip": target, "port": port, "open": True, "actor": "APT-W"}
    base.update(kw)
    return base


def test_ingest_writes_snapshots_and_selectors():
    _spool([_record("scanA", "203.0.113.7", 443,
                    tls={"cert_sha256": "c" * 64, "spki_sha256": "d" * 64,
                         "issuer": "CN = Evil CA", "ja3s": "e" * 32},
                    http={"jarm": "29d3fd00029d" + "a" * 50, "status": 200,
                          "title": "Panel", "body_sha256": "b" * 64,
                          "headers": {"server": "nginx", "x_kit": "v2"},
                          "raw_header": "HTTP/1.1 200 OK\r\nServer: nginx\r\nX-Kit: v2\r\n\r\n"},
                    c2_hits=["cobalt-strike-beacon"])])
    out = ingest.ingest(client=None)
    assert out["snapshots"] == 1 and out["selectors"] > 0
    with store.connect(read_only=True) as con:
        snap = con.execute(
            "SELECT cert_sha256, ja3s, jarm, c2_hits FROM service_snapshots "
            "WHERE target='203.0.113.7' AND port=443").fetchone()
        assert snap[0] == "c" * 64 and snap[1] == "e" * 32
        assert json.loads(snap[3]) == ["cobalt-strike-beacon"]
        sels = {t for (t,) in con.execute(
            "SELECT DISTINCT selector_type FROM selectors WHERE source='netwatch'").fetchall()}
    assert "tls.cert_sha256" in sels and "tls.ja3s" in sels
    assert "http.body_sha256" in sels and "http.header_set" in sels
    # c2 hit is recorded as a change even on first sight
    with store.connect(read_only=True) as con:
        kinds = {k for (k,) in con.execute(
            "SELECT change_type FROM service_changes").fetchall()}
    assert "c2_signature_hit" in kinds


def test_ingest_diffs_against_the_previous_scan():
    # hex hashes with letters: an all-digit value parses as a JSON number
    # and would hide that old/new are written to a JSON column.
    _spool([_record("scan1", "203.0.113.8", 443, tls={"cert_sha256": "ab" * 32})])
    ingest.ingest(client=None)
    _spool([_record("scan2", "203.0.113.8", 443, tls={"cert_sha256": "cd" * 32}),
            _record("scan2", "203.0.113.8", 8443, open=True,
                    tls={"cert_sha256": "ef" * 32})])
    ingest.ingest(client=None)
    with store.connect(read_only=True) as con:
        rows = con.execute(
            "SELECT port, change_type FROM service_changes ORDER BY port").fetchall()
    assert (443, "cert_changed") in rows


def test_ingest_records_a_dark_host():
    _spool([_record("scanA", "203.0.113.10", 0, open=False, ip="203.0.113.10")])
    out = ingest.ingest(client=None)
    assert out["snapshots"] == 1
    with store.connect(read_only=True) as con:
        assert con.execute("SELECT open FROM service_snapshots "
                           "WHERE target='203.0.113.10'").fetchone()[0] is False


class _FakeZeek:
    """A passive-join client returning one ssl and one conn hit."""
    def __init__(self):
        from cti.sources.opensearch import OpenSearchClient
        self._real = OpenSearchClient(backend="wazuh")
    def field(self, k):
        return self._real.field(k)
    def ts_range(self, **kw):
        return self._real.ts_range(**kw)
    def sources(self, query, size=50):
        return [
            {"log_file": "/opt/zeek/logs/current/ssl.log", "ja4s": "t1204h2_c030_abc"},
            {"log_file": "/opt/zeek/logs/current/conn.log",
             "ja4ts": "65535_2-1-3_1440_8", "ja4l": "108_128_756"}]


def test_ingest_joins_passive_zeek_fingerprints(monkeypatch):
    monkeypatch.setenv("CTI_PROBE_HOST", "10.99.0.74")
    _spool([_record("scanA", "203.0.113.11", 443,
                    tls={"cert_sha256": "c" * 64})])
    out = ingest.ingest(client=_FakeZeek())
    assert out["snapshots"] == 1
    with store.connect(read_only=True) as con:
        ja4s, ja4ts = con.execute(
            "SELECT ja4s, ja4ts FROM service_snapshots "
            "WHERE target='203.0.113.11' AND port=443").fetchone()
    assert ja4s == "t1204h2_c030_abc" and ja4ts == "65535_2-1-3_1440_8"
    with store.connect(read_only=True) as con:
        sels = {t for (t,) in con.execute(
            "SELECT selector_type FROM selectors WHERE source='netwatch'").fetchall()}
    assert "tls.ja4s" in sels
