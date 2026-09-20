"""Tests for core.active_scan - the on-demand nmap + dirsearch/open-directory
scan. vm_proxy.nmap/dirsearch and the OpenSearch provenance snapshot are
stubbed so the suite runs offline."""
from __future__ import annotations

import pytest

from cti import core
from cti import store as tracking_store


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
    # first's baseline (real runs are days apart; now_iso() is second-granular).
    monkeypatch.setattr(core, "now_iso", lambda: "2026-09-10T00:00:00+00:00")
    r1 = core.active_scan("203.0.113.7", tools=["nmap"])
    assert r1["nmap"]["ports"][0]["port"] == 80

    # a later scan with a different port set is a recorded port change
    _stub_nmap(monkeypatch, [8080])
    monkeypatch.setattr(core, "now_iso", lambda: "2026-09-11T00:00:00+00:00")
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


def test_active_scan_records_the_port_set_as_a_selector(monkeypatch):
    """nmap is the ONLY path that discovers ports.

    The observe pass takes known ports as input and never scans, so without
    this write `net.port_set` only ever appeared in offline backfills - and
    the source reporting's high-port pivot (RDP on 64350, 65111, ports no
    top-100 scan reaches) had no live source at all.
    """
    _stub_nmap(monkeypatch, [443, 64350, 65111])
    monkeypatch.setattr(core.vm_proxy, "dirsearch", lambda url, **kw: {
        "hits": [], "opendirs": [], "baseline_404": {}, "error": None})
    core.active_scan("203.0.113.7", tools=["nmap"], cluster="TestActor")

    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            "SELECT selector_value, actor, source FROM selectors "
            "WHERE selector_type = 'net.port_set' "
            "AND indicator_value = '203.0.113.7'").fetchone()
    # One selector whose value is the whole set, sorted numerically - not
    # three selectors, or two hosts would "share" a port set by both having
    # 443 open.
    assert row == ("443,64350,65111", "TestActor", "nmap")


# --------------------------------------------------------------------------- #
# Open directories, found without the loud path
# --------------------------------------------------------------------------- #

_LISTING = {"url": "https://evil.example/files/",
            "files": [{"path": "/files/loader.exe", "size": 1024},
                      {"path": "/files/readme.txt", "size": 12}]}


def _opendir_rows(indicator: str) -> list[str]:
    with tracking_store.connect(read_only=True) as con:
        return sorted(r[0] for r in con.execute(
            "SELECT path FROM opendir_files WHERE indicator_value = ?",
            [indicator]).fetchall())


def _log(http: dict, *, actor="TestActor", value="evil.example", when="2026-09-20T06:00:00"):
    from datetime import datetime
    core._log_cluster_enrichment_history(
        actor, datetime.fromisoformat(when),
        {("domains", value): ("active", {}, {"http": http})})


def test_an_autoindex_page_files_open_directories_without_a_scan():
    """The probe already parsed the listing on a page it fetched anyway.
    It was returned and thrown away, so open directories could only ever be
    found by active_scan's dirsearch - a path brute-force, on request only."""
    _log({"status": 200, "autoindex": _LISTING})
    assert _opendir_rows("evil.example") == ["/files/loader.exe", "/files/readme.txt"]


def test_the_first_passive_listing_is_a_baseline_not_an_event():
    """Every file in a first-ever listing is 'new' and none of them is a
    change - the same rule the loud path applies."""
    _log({"status": 200, "autoindex": _LISTING})
    with tracking_store.connect(read_only=True) as con:
        assert con.execute(
            "SELECT count(*) FROM attribute_changes WHERE attribute = 'opendir_files'"
        ).fetchone()[0] == 0


def test_a_file_added_to_a_known_directory_is_an_event():
    _log({"status": 200, "autoindex": _LISTING})
    grown = {**_LISTING, "files": _LISTING["files"] + [{"path": "/files/new.dll", "size": 9}]}
    _log({"status": 200, "autoindex": grown}, when="2026-09-21T06:00:00")
    with tracking_store.connect(read_only=True) as con:
        row = con.execute(
            "SELECT new_value FROM attribute_changes "
            "WHERE attribute = 'opendir_files'").fetchone()
    assert row is not None and "/files/new.dll" in row[0]


def test_a_page_with_no_listing_files_nothing():
    _log({"status": 200, "autoindex": None})
    _log({"status": 200})
    _log({"status": 200, "autoindex": {"url": "https://evil.example/", "files": []}})
    assert _opendir_rows("evil.example") == []


def test_a_failed_probe_files_nothing():
    _log({"error": "connection reset"})
    assert _opendir_rows("evil.example") == []
