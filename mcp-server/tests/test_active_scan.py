"""Tests for core.active_scan - the on-demand nmap + dirsearch/open-directory
scan. vm_proxy.nmap/dirsearch and the OpenSearch provenance snapshot are
stubbed so the suite runs offline."""
from __future__ import annotations

import pytest

from cti_tools import core
from cti_tools.tracking import store as tracking_store


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "DATA_DIR", tmp_path)
    monkeypatch.setenv("CTI_DUCKDB_PATH", str(tmp_path / "tracking.duckdb"))
    # No OpenSearch in tests - provenance snapshot returns None (best-effort).
    monkeypatch.setattr(core, "_opensearch_max_ts", lambda: None)
    yield


def _stub_nmap(monkeypatch, ports):
    monkeypatch.setattr(core.vm_proxy, "nmap", lambda target, top_ports=100, service_detection=True: {
        "ports": [{"port": p, "proto": "tcp", "service": "http"} for p in ports],
        "resolved_ip": "203.0.113.7", "error": None})


def _stub_dirsearch(monkeypatch, opendirs):
    monkeypatch.setattr(core.vm_proxy, "dirsearch",
                        lambda url, **kw: {"hits": [], "opendirs": opendirs,
                                          "baseline_404": {"status": 404, "size": 0}, "error": None})


def test_active_scan_nmap_records_ports_and_change(monkeypatch):
    _stub_nmap(monkeypatch, [80, 443])
    monkeypatch.setattr(core.vm_proxy, "dirsearch", lambda url, **kw: {"hits": [], "opendirs": [],
                                                                       "baseline_404": {}, "error": None})
    # Two scans must land on distinct days so the second diffs against the
    # first's baseline (real runs are days apart; _now() is second-granular).
    monkeypatch.setattr(core, "_now", lambda: "2026-09-10T00:00:00+00:00")
    r1 = core.active_scan("203.0.113.7", tools=["nmap"])
    assert r1["nmap"]["ports"][0]["port"] == 80

    # a later scan with a different port set is a recorded port change
    _stub_nmap(monkeypatch, [8080])
    monkeypatch.setattr(core, "_now", lambda: "2026-09-11T00:00:00+00:00")
    core.active_scan("203.0.113.7", tools=["nmap"])
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            "SELECT change_type FROM attribute_changes "
            "WHERE attribute = 'ports' AND change_type = 'ports_changed'").fetchone()
    assert row is not None


def test_active_scan_open_directory_listing_and_day_over_day_diff(monkeypatch):
    _stub_nmap(monkeypatch, [])
    _stub_dirsearch(monkeypatch, [{"url": "http://203.0.113.7/files/",
                                   "files": [{"name": "a.zip", "href": "http://203.0.113.7/files/a.zip",
                                              "is_dir": False, "size": "1K"}]}])
    r1 = core.active_scan("203.0.113.7", tools=["dirsearch"])
    # first scan is a baseline - the whole listing is not flagged as "new"
    assert r1["new_open_dir_files"] == []
    with tracking_store.connect(read_only=True) as con:
        n = con.execute("SELECT count(*) FROM opendir_files WHERE indicator_value = ?",
                        ["203.0.113.7"]).fetchone()[0]
    assert n == 1

    # second scan adds a file - flagged as new, and recorded as a change
    _stub_dirsearch(monkeypatch, [{"url": "http://203.0.113.7/files/", "files": [
        {"name": "a.zip", "href": "http://203.0.113.7/files/a.zip", "is_dir": False, "size": "1K"},
        {"name": "b.exe", "href": "http://203.0.113.7/files/b.exe", "is_dir": False, "size": "2M"}]}])
    r2 = core.active_scan("203.0.113.7", tools=["dirsearch"])
    assert [f["path"] for f in r2["new_open_dir_files"]] == ["http://203.0.113.7/files/b.exe"]
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            "SELECT change_type FROM attribute_changes WHERE attribute = 'opendir_files'").fetchone()
    assert row == ("opendir_files",)


def test_active_scan_records_audit_row(monkeypatch):
    _stub_nmap(monkeypatch, [443])
    monkeypatch.setattr(core.vm_proxy, "dirsearch", lambda url, **kw: {"hits": [], "opendirs": [],
                                                                       "baseline_404": {}, "error": None})
    core.active_scan("203.0.113.7", tools=["nmap"])
    with tracking_store.connect(read_only=True) as con:
        n = con.execute("SELECT count(*) FROM active_scans WHERE indicator_value = ?",
                        ["203.0.113.7"]).fetchone()[0]
    assert n == 1


def test_active_scan_stamps_cluster_observable(monkeypatch):
    # Stub the add-time enrichment sweep boundaries so seeding is hermetic.
    monkeypatch.setattr(core.pivot, "rdap_lookup", lambda v, k: {"nameservers": []})
    monkeypatch.setattr(core.pivot, "resolve_host", lambda h: [])
    monkeypatch.setattr(core.pivot, "ripestat_lookup", lambda ip: {"asn": []})
    monkeypatch.setattr(core.pivot, "ptr_lookup", lambda ip: {"hostname": None})
    monkeypatch.setattr(core.webamon, "search_ip",
                        lambda ip, size=50: {"total_hits": 0, "domains": [], "results": []})
    core.create_cluster("Scan Cluster")
    core.add_observable("Scan Cluster", "ips", "203.0.113.7", "seed")

    _stub_nmap(monkeypatch, [22, 443])
    _stub_dirsearch(monkeypatch, [{"url": "http://203.0.113.7/", "files": [
        {"name": "x.txt", "href": "http://203.0.113.7/x.txt", "is_dir": False, "size": "1K"}]}])
    result = core.active_scan("203.0.113.7", cluster="Scan Cluster")
    ip = next(o for o in result["cluster_state"]["observables"]["ips"]
              if o["value"] == "203.0.113.7")
    assert ip["ports"] == [22, 443]
    assert ip["opendir"][0]["url"] == "http://203.0.113.7/"
    assert any("active_scan on 203.0.113.7" in h["entry"]
               for h in result["cluster_state"]["hunt_log"])


def test_active_scan_rejects_hash():
    with pytest.raises(ValueError):
        core.active_scan("098f6bcd4621d373cade4e832627b4f6")


def test_active_scan_rejects_unknown_tool(monkeypatch):
    with pytest.raises(ValueError):
        core.active_scan("203.0.113.7", tools=["nuclei"])


def test_active_scan_skips_ipv6():
    r = core.active_scan("2a10:1fc0:6::de96:9634")
    assert "skipped" in r
